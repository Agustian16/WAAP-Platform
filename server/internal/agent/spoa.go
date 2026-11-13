package agent

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"github.com/dropmorepackets/haproxy-go/pkg/encoding"
	"github.com/dropmorepackets/haproxy-go/spop"
)

// SPOA is the HAProxy integration: a Stream Processing Offload Agent. HAProxy sends the "corazium-req" message
// on each request and "corazium-res" on each response (both carry the request's unique-id); the agent answers
// by setting txn.corazium.action to "allow" or "deny" and txn.corazium.status, which HAProxy rules act on.
// deploy/integrations/haproxy.cfg and spoe.conf have the matching HAProxy configuration.
type SPOA struct {
	core   *Core
	listen string

	mu      sync.Mutex
	pending map[string]*pendingTx // unique-id -> request awaiting its response message
}

type pendingTx struct {
	t  *Tx
	at time.Time
}

func NewSPOA(core *Core, listen string) *SPOA {
	return &SPOA{core: core, listen: listen, pending: map[string]*pendingTx{}}
}

// kv reads every argument of a message into a map of typed values.
func kv(m *encoding.Message) map[string]any {
	out := map[string]any{}
	e := encoding.AcquireKVEntry()
	defer encoding.ReleaseKVEntry(e)
	for m.KV.Next(e) {
		v := e.Value()
		if b, ok := v.([]byte); ok {
			v = append([]byte(nil), b...) // the scanner reuses its buffer
		}
		out[string(e.NameBytes())] = v
	}
	return out
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	}
	return ""
}

func num(v any) int {
	switch x := v.(type) {
	case int32:
		return int(x)
	case int64:
		return int(x)
	case uint32:
		return int(x)
	case uint64:
		return int(x)
	}
	return 0
}

// parseHeaders reads HAProxy's req.hdrs / res.hdrs, the raw header block ("Name: value\r\n...").
func parseHeaders(raw string) http.Header {
	if !strings.HasSuffix(raw, "\r\n\r\n") {
		raw = strings.TrimRight(raw, "\r\n") + "\r\n\r\n"
	}
	h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(raw))).ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return http.Header{}
	}
	return http.Header(h)
}

func verdict(w *encoding.ActionWriter, code int, blocked bool) {
	if blocked {
		_ = w.SetString(encoding.VarScopeTransaction, "action", "deny")
		_ = w.SetInt32(encoding.VarScopeTransaction, "status", int32(code))
		return
	}
	_ = w.SetString(encoding.VarScopeTransaction, "action", "allow")
}

func (s *SPOA) HandleSPOE(_ context.Context, w *encoding.ActionWriter, m *encoding.Message) {
	args := kv(m)
	id := str(args["id"])
	switch string(m.NameBytes()) {
	case "corazium-req":
		ip, _ := args["src-ip"].(netip.Addr)
		uri := str(args["path"])
		if q := str(args["query"]); q != "" {
			uri += "?" + q
		}
		h := parseHeaders(str(args["headers"]))
		body := []byte(str(args["body"]))
		if len(body) > MaxInspectBody {
			body = body[:MaxInspectBody]
		}
		proto := "HTTP/" + str(args["version"])
		t := s.core.Begin(Request{Host: h.Get("Host"), Method: str(args["method"]), URI: uri, Proto: proto, Client: ip.Unmap(),
			ClientPort: num(args["src-port"]), Header: h, Body: body})
		code, blocked := t.Blocked()
		verdict(w, code, blocked)
		if blocked || id == "" {
			// HAProxy answers a denied request itself, so no response message follows.
			t.Finish(map[bool]int{true: code, false: 0}[blocked])
			return
		}
		s.mu.Lock()
		s.pending[id] = &pendingTx{t: t, at: time.Now()}
		s.mu.Unlock()
	case "corazium-res":
		s.mu.Lock()
		p := s.pending[id]
		delete(s.pending, id)
		s.mu.Unlock()
		if p == nil {
			verdict(w, 0, false)
			return
		}
		code := num(args["status"])
		code2, blocked := p.t.ResponseHeaders(code, "HTTP/"+str(args["version"]), parseHeaders(str(args["headers"])))
		if !blocked && p.t.WantsResponseBody() {
			if body := []byte(str(args["body"])); len(body) <= MaxInspectBody {
				code2, blocked = p.t.ResponseBody(body)
			}
		}
		verdict(w, code2, blocked)
		if blocked {
			code = code2
		}
		p.t.Finish(code)
	}
}

// janitor finishes requests whose response message never came (HAProxy timeout, client gone).
func (s *SPOA) janitor(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		var stale []*pendingTx
		s.mu.Lock()
		for id, p := range s.pending {
			if time.Since(p.at) > 30*time.Second {
				stale = append(stale, p)
				delete(s.pending, id)
			}
		}
		s.mu.Unlock()
		for _, p := range stale {
			p.t.Finish(0)
		}
	}
}

// Run serves SPOP until ctx ends.
func (s *SPOA) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); lis.Close() }()
	go s.janitor(ctx)
	slog.Info("haproxy SPOA listening", "addr", s.listen, "config", s.core.ConfigVersion())
	a := spop.Agent{Handler: s, BaseContext: ctx}
	if err := a.Serve(lis); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
