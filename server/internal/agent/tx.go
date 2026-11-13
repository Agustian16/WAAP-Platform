package agent

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	agentv1 "github.com/Agustian16/WAAP-Platform/server/gen/agent/v1"
	"github.com/Agustian16/WAAP-Platform/server/internal/waf"
)

// MaxInspectBody is how much of a request or response body is buffered for inspection.
const MaxInspectBody = 1 << 20

// Request is one HTTP request as an integration sees it.
type Request struct {
	Host, Method, URI, Proto string
	Client                   netip.Addr
	ClientPort               int
	Header                   http.Header
	Body                     []byte // at most MaxInspectBody
}

// Tx is one inspected transaction. Integrations call Begin, Blocked, optionally ResponseHeaders and
// ResponseBody, and always Finish. A Tx is not safe for concurrent use.
type Tx struct {
	c     *Core
	ev    *agentv1.AuditEvent
	tx    types.Transaction // nil when the IP lists decided
	it    *types.Interruption
	ipHit string // "allow" or "block" when the IP lists decided
	waf   time.Duration
	done  bool
}

func blockStatus(it *types.Interruption) int {
	if it.Status >= 400 {
		return it.Status
	}
	return http.StatusForbidden
}

func (c *Core) timed(t *Tx, f func()) {
	start := time.Now()
	f()
	t.waf += time.Since(start)
}

// Begin runs IP reputation and the request phases (1 and 2).
func (c *Core) Begin(r Request) *Tx {
	start := time.Now()
	c.requests.Add(1)
	rt := c.cur.Load()
	host := strings.ToLower(r.Host)
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.Contains(h, "]") {
		host = h
	}
	t := &Tx{c: c, ev: &agentv1.AuditEvent{TimestampMs: start.UnixMilli(), Host: host, SiteId: rt.siteIDs[host], ClientIp: r.Client.String(),
		ClientPort: uint32(r.ClientPort), Method: r.Method, Uri: r.URI, HttpVersion: r.Proto, RequestHeaders: MaskHeaders(r.Header)}}
	defer func() { t.waf += time.Since(start) }()

	// IP reputation runs before the engine: allowlisted sources skip inspection, blocklisted ones never reach it.
	if r.Client.IsValid() && inAny(rt.allow, r.Client) {
		t.ipHit = "allow"
		return t
	}
	if r.Client.IsValid() && inAny(rt.block, r.Client) {
		t.ipHit = "block"
		t.it = &types.Interruption{Action: "deny", Status: http.StatusForbidden, RuleID: waf.BlocklistRuleID}
		return t
	}
	engine := rt.sites[host]
	if engine == nil {
		engine = rt.def
	}
	t.tx = engine.NewTransaction()
	t.ev.TransactionId = t.tx.ID()
	t.ev.RequestBody = MaskBody(string(r.Body))
	u, err := url.ParseRequestURI(r.URI)
	if err != nil {
		u = &url.URL{Path: "/", RawQuery: ""}
	}
	hr := &http.Request{Method: r.Method, URL: u, Proto: r.Proto, Header: r.Header, Host: r.Host}
	if hr.Header == nil {
		hr.Header = http.Header{}
	}
	t.it = waf.ProcessRequest(t.tx, hr, r.Client.String(), r.ClientPort, r.Body)
	return t
}

// Blocked reports whether the request must be refused, and with which status.
func (t *Tx) Blocked() (int, bool) {
	if t.it == nil {
		return 0, false
	}
	return blockStatus(t.it), true
}

// ResponseHeaders runs phase 3. Integrations that cannot see responses skip it.
func (t *Tx) ResponseHeaders(code int, proto string, h http.Header) (int, bool) {
	if t.tx == nil || t.it != nil {
		return t.Blocked()
	}
	t.c.timed(t, func() {
		for k, vs := range h {
			for _, v := range vs {
				t.tx.AddResponseHeader(k, v)
			}
		}
		t.it = t.tx.ProcessResponseHeaders(code, proto)
	})
	return t.Blocked()
}

// WantsResponseBody reports whether phase 4 applies to this response (body access on, inspectable type).
func (t *Tx) WantsResponseBody() bool {
	return t.tx != nil && t.it == nil && t.tx.IsResponseBodyAccessible() && t.tx.IsResponseBodyProcessable()
}

// ResponseBody runs phase 4 on a buffered response body.
func (t *Tx) ResponseBody(b []byte) (int, bool) {
	if !t.WantsResponseBody() {
		return t.Blocked()
	}
	t.c.timed(t, func() {
		if it, _, _ := t.tx.WriteResponseBody(b); it != nil {
			t.it = it
		} else if it, _ := t.tx.ProcessResponseBody(); it != nil {
			t.it = it
		}
	})
	return t.Blocked()
}

// Finish logs the transaction and reports it to the control plane. code is the status the client got; 0 when
// the integration never sees the response.
func (t *Tx) Finish(code int) {
	if t.done {
		return
	}
	t.done = true
	var rules []*agentv1.MatchedRule
	switch t.ipHit {
	case "block":
		rules = []*agentv1.MatchedRule{{Id: waf.BlocklistRuleID, Message: "Client IP is on the blocklist", Data: t.ev.ClientIp,
			Variable: "REMOTE_ADDR", Severity: "CRITICAL", Tags: []string{"ip-reputation"}}}
	case "":
		t.c.timed(t, t.tx.ProcessLogging)
		for _, m := range waf.Matches(t.tx) {
			rules = append(rules, &agentv1.MatchedRule{Id: uint32(m.RuleID), Message: m.Message, Data: MaskMatch(m.Variable, m.Data), Variable: m.Variable, Severity: m.Severity, Tags: m.Tags})
		}
		t.tx.Close()
	}
	action := "ALLOW"
	switch {
	case t.it != nil:
		action = "DENY"
		t.c.blocked.Add(1)
	case len(rules) > 0:
		action = "LOG"
	}
	t.c.emit(t.ev, action, code, t.waf, rules)
}
