// Package waf wraps the OWASP Coraza engine: policy compilation to SecLang, rule validation, the test
// sandbox, and the request-inspection helper shared by the control plane and the edge agent.
package waf

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// Rule id ranges reserved by the control plane. Custom rules may not use them.
const (
	SetupRuleID      = 1900  // per-site CRS tuning SecAction
	BlocklistRuleID  = 1001  // synthetic id reported for IP blocklist hits
	ExceptionIDFirst = 10000 // generated exception rules
	ExceptionIDLast  = 19999
)

// NewEngine builds a Coraza WAF from SecLang directives. CRS files resolve through the embedded rule set
// (Include @owasp_crs/*.conf).
func NewEngine(directives string) (coraza.WAF, error) {
	return coraza.NewWAF(coraza.NewWAFConfig().WithRootFS(coreruleset.FS).WithDirectives(directives))
}

// ModuleVersion reports the version of a linked Go module, e.g. the Coraza engine or the embedded CRS.
func ModuleVersion(path string) string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == path {
				return d.Version
			}
		}
	}
	return "unknown"
}

func EngineVersion() string { return "Coraza " + ModuleVersion("github.com/corazawaf/coraza/v3") }
func CRSVersion() string {
	return "CRS " + ModuleVersion("github.com/corazawaf/coraza-coreruleset/v4")
}

// ---------- Policy compilation ----------

// Policy is everything that shapes the deployed configuration.
type Policy struct {
	Sites      []model.Site
	Rules      []model.CustomRule
	Exceptions []model.RuleException
}

func siteDirectives(pl, inbound, outbound int, categories map[string]bool, rules []model.CustomRule, exc []model.RuleException) string {
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\nSecRuleEngine On\nSecRequestBodyAccess On\nSecResponseBodyAccess On\n")
	b.WriteString("SecResponseBodyMimeType text/plain text/html text/xml application/json\n")
	fmt.Fprintf(&b, "SecAction \"id:%d,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d,setvar:tx.detection_paranoia_level=%d,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=%d\"\n",
		SetupRuleID, pl, pl, inbound, outbound)
	// Runtime exceptions (ctl:) must run before the rules they suppress; config-time ones come after the CRS include.
	var after []string
	for _, e := range exc {
		s := BuildException(e)
		if strings.Contains(s, "SecRule REQUEST_FILENAME") {
			b.WriteString(s + "\n")
		} else {
			after = append(after, s)
		}
	}
	for _, r := range rules {
		if r.IsActive {
			b.WriteString(r.SecLangRaw + "\n")
		}
	}
	b.WriteString("Include @crs-setup.conf.example\nInclude @owasp_crs/*.conf\n")
	keys := make([]string, 0, len(categories))
	for k, on := range categories {
		if !on {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		n, err := strconv.Atoi(k)
		if err != nil {
			continue
		}
		to := n*1000 + 999
		if n == 950 { // the data-leakage switch covers 950xxx-954xxx
			to = 954999
		}
		fmt.Fprintf(&b, "SecRuleRemoveById %d-%d\n", n*1000, to)
	}
	for _, s := range after {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// Compile turns the stored policy into per-host SecLang plus a default for hosts without a site.
func Compile(p Policy) (def string, perHost map[string]string, siteIDs map[string]string) {
	var global []model.CustomRule
	for _, r := range p.Rules {
		if r.SiteID == nil {
			global = append(global, r)
		}
	}
	def = siteDirectives(1, 5, 4, nil, global, nil)
	perHost, siteIDs = map[string]string{}, map[string]string{}
	for _, s := range p.Sites {
		var rules []model.CustomRule
		for _, r := range p.Rules {
			if r.SiteID == nil || *r.SiteID == s.ID {
				rules = append(rules, r)
			}
		}
		var exc []model.RuleException
		for _, e := range p.Exceptions {
			if e.SiteID == s.ID {
				exc = append(exc, e)
			}
		}
		perHost[s.DomainName] = siteDirectives(s.ParanoiaLevel, s.InboundThreshold, s.OutboundThreshold, s.CRSCategories, rules, exc)
		siteIDs[s.DomainName] = s.ID
	}
	return
}

// Validate builds an engine for every compiled policy, so a broken rule is rejected before it is deployed.
func Validate(def string, perHost map[string]string) error {
	if _, err := NewEngine(def); err != nil {
		return fmt.Errorf("default policy: %w", err)
	}
	for host, d := range perHost {
		if _, err := NewEngine(d); err != nil {
			return fmt.Errorf("%s: %w", host, err)
		}
	}
	return nil
}

// BuildException renders the SecLang for a rule exception (FR-3.3). Mirrors buildException in web/lib/seclang.ts.
func BuildException(e model.RuleException) string {
	target := e.PathPattern
	if target == "*" {
		target = "all paths"
	}
	param := ""
	if e.ParameterName != nil && *e.ParameterName != "" {
		param = *e.ParameterName
	}
	header := fmt.Sprintf("# Exception: rule %d on %s", e.RuleID, target)
	if param != "" {
		header += " for " + param
	}
	if e.PathPattern == "*" {
		if param == "" {
			return fmt.Sprintf("%s\nSecRuleRemoveById %d", header, e.RuleID)
		}
		return fmt.Sprintf("%s\nSecRuleUpdateTargetById %d \"!%s\"", header, e.RuleID, param)
	}
	op := "@streq " + e.PathPattern
	if strings.HasSuffix(e.PathPattern, "*") {
		op = "@beginsWith " + strings.TrimSuffix(e.PathPattern, "*")
	}
	ctl := fmt.Sprintf("ctl:ruleRemoveById=%d", e.RuleID)
	if param != "" {
		ctl = fmt.Sprintf("ctl:ruleRemoveTargetById=%d;%s", e.RuleID, param)
	}
	return fmt.Sprintf("%s\nSecRule REQUEST_FILENAME \"%s\" \\\n    \"id:%d,phase:1,pass,nolog,%s\"", header, op, e.ExceptionRuleID, ctl)
}

// ---------- Rule validation ----------

var ruleIDRe = regexp.MustCompile(`\bid:\s*'?(\d+)`)

// RuleID extracts the first id: action from a rule.
func RuleID(seclang string) (int, bool) {
	m := ruleIDRe.FindStringSubmatch(seclang)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// LintRule parses a custom rule with the real engine and checks its id against reserved ranges.
func LintRule(seclang string) error {
	id, ok := RuleID(seclang)
	if !ok {
		return fmt.Errorf("rule needs an id")
	}
	if id < 1 || (id >= 1000 && id <= 1999) || (id >= ExceptionIDFirst && id <= ExceptionIDLast) || (id >= 901000 && id <= 999999) {
		return fmt.Errorf("id %d is reserved (1000-1999 control plane, 10000-19999 exceptions, 901000-999999 OWASP CRS)", id)
	}
	if _, err := NewEngine("SecRuleEngine On\n" + seclang); err != nil {
		return fmt.Errorf("SecLang: %s", firstLine(err.Error()))
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------- Inspection ----------

// Match is one rule that fired on a transaction.
type Match struct {
	RuleID   int
	Message  string
	Data     string
	Variable string
	Severity string
	Tags     []string
}

// ProcessRequest runs phases 1 and 2. It returns the interruption, if any.
func ProcessRequest(tx types.Transaction, r *http.Request, clientIP string, clientPort int, body []byte) *types.Interruption {
	tx.ProcessConnection(clientIP, clientPort, "", 0)
	tx.ProcessURI(r.URL.RequestURI(), r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return it
	}
	if tx.IsRequestBodyAccessible() && len(body) > 0 {
		if it, _, err := tx.WriteRequestBody(body); it != nil || err != nil {
			return it
		}
	}
	it, _ := tx.ProcessRequestBody()
	return it
}

// Matches lists the rules that fired and log. Engine bookkeeping rules (nolog) are left out.
func Matches(tx types.Transaction) []Match {
	var out []Match
	for _, mr := range tx.MatchedRules() {
		if l, ok := mr.(interface{ Log() bool }); (ok && !l.Log()) || mr.Rule().ID() == 0 {
			continue
		}
		m := Match{RuleID: mr.Rule().ID(), Message: mr.Message(), Severity: severity(mr.Rule().Severity()), Tags: mr.Rule().Tags()}
		if ds := mr.MatchedDatas(); len(ds) > 0 {
			m.Variable = ds[0].Variable().Name()
			if k := ds[0].Key(); k != "" {
				m.Variable += ":" + k
			}
			m.Data = ds[0].Value()
		}
		if len(m.Data) > 512 {
			m.Data = m.Data[:512]
		}
		out = append(out, m)
	}
	return out
}

func severity(s types.RuleSeverity) string {
	switch s {
	case types.RuleSeverityEmergency, types.RuleSeverityAlert, types.RuleSeverityCritical:
		return "CRITICAL"
	case types.RuleSeverityError:
		return "ERROR"
	case types.RuleSeverityWarning:
		return "WARNING"
	}
	return "NOTICE"
}

// ---------- Test sandbox (FR-2.4) ----------

type SandboxRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type SandboxMatch struct {
	RuleID   int    `json:"ruleId"`
	Variable string `json:"variable"`
	Data     string `json:"data"`
	Msg      string `json:"msg"`
}

type SandboxResult struct {
	Status  string         `json:"status"` // MATCHED | PASSED
	Matched []SandboxMatch `json:"matched"`
	Skipped []string       `json:"skipped"`
	Engine  string         `json:"engine"`
}

// Sandbox evaluates one request against the given rules in an isolated engine and reports which rules matched.
func Sandbox(seclang string, req SandboxRequest) (SandboxResult, error) {
	res := SandboxResult{Status: "PASSED", Matched: []SandboxMatch{}, Skipped: []string{}, Engine: EngineVersion() + " (dry run on the control plane)"}
	engine, err := NewEngine("SecRuleEngine On\nSecRequestBodyAccess On\n" + seclang)
	if err != nil {
		return res, fmt.Errorf("SecLang: %s", firstLine(err.Error()))
	}
	u, err := url.Parse(req.URL)
	if err != nil || !strings.HasPrefix(u.RequestURI(), "/") {
		return res, fmt.Errorf("request URL must be a path such as /api/v1/login?x=1")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	r, err := http.NewRequest(method, "http://sandbox.local"+u.RequestURI(), bytes.NewReader([]byte(req.Body)))
	if err != nil {
		return res, fmt.Errorf("request: %w", err)
	}
	for k, v := range req.Headers {
		r.Header.Set(k, v)
	}
	if h := r.Header.Get("Host"); h != "" {
		r.Host = h
	}
	if req.Body != "" && r.Header.Get("Content-Length") == "" {
		r.Header.Set("Content-Length", strconv.Itoa(len(req.Body)))
	}
	tx := engine.NewTransaction()
	defer tx.Close()
	ProcessRequest(tx, r, "192.0.2.1", 40000, []byte(req.Body))
	tx.ProcessLogging()
	seen := map[int]bool{}
	for _, mr := range tx.MatchedRules() {
		id := mr.Rule().ID()
		if id == 0 || seen[id] {
			continue
		}
		seen[id] = true
		m := SandboxMatch{RuleID: id, Msg: mr.Message()}
		if ds := mr.MatchedDatas(); len(ds) > 0 {
			m.Variable = ds[0].Variable().Name()
			if k := ds[0].Key(); k != "" {
				m.Variable += ":" + k
			}
			m.Data = ds[0].Value()
		}
		res.Matched = append(res.Matched, m)
	}
	if len(res.Matched) > 0 {
		res.Status = "MATCHED"
	}
	return res, nil
}
