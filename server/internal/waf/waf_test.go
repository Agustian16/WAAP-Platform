package waf

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

func ids(ms []Match) (out []int) {
	for _, m := range ms {
		out = append(out, m.RuleID)
	}
	return
}

func has(xs []int, from, to int) bool {
	for _, x := range xs {
		if x >= from && x <= to {
			return true
		}
	}
	return false
}

func inspect(t *testing.T, directives, method, target, body string) (blocked bool, matched []int) {
	t.Helper()
	e, err := NewEngine(directives)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	r, _ := http.NewRequest(method, "http://api.domain.com"+target, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0 test")
	r.Header.Set("Accept", "*/*")
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	tx := e.NewTransaction()
	defer tx.Close()
	it := ProcessRequest(tx, r, "192.0.2.9", 4000, []byte(body))
	tx.ProcessLogging()
	return it != nil, ids(Matches(tx))
}

func TestCompiledPolicyBlocksSQLiAndHonoursSwitches(t *testing.T) {
	site := model.Site{ID: "s1", DomainName: "api.domain.com", ParanoiaLevel: 2, InboundThreshold: 5, OutboundThreshold: 4, CRSCategories: map[string]bool{"942": true}}
	_, per, _ := Compile(Policy{Sites: []model.Site{site}})
	blocked, m := inspect(t, per["api.domain.com"], "POST", "/api/v1/login", "username=' OR '1'='1&password=x")
	if !blocked || !has(m, 942000, 942999) {
		t.Fatalf("SQLi should be blocked by a 942xxx rule, blocked=%v matched=%v", blocked, m)
	}
	if blocked, m := inspect(t, per["api.domain.com"], "GET", "/products?id=7", ""); blocked || len(m) != 0 {
		t.Fatalf("benign request must pass clean, blocked=%v matched=%v", blocked, m)
	}

	// FR-2.1: switching the SQLi category off removes its rules.
	site.CRSCategories = map[string]bool{"942": false}
	_, per, _ = Compile(Policy{Sites: []model.Site{site}})
	if _, m := inspect(t, per["api.domain.com"], "POST", "/api/v1/login", "username=' OR '1'='1&password=x"); has(m, 942000, 942999) {
		t.Fatalf("942xxx still matched with the category off: %v", m)
	}
}

func TestExceptionSuppressesRuleOnEndpointOnly(t *testing.T) {
	site := model.Site{ID: "s1", DomainName: "api.domain.com", ParanoiaLevel: 1, InboundThreshold: 5, OutboundThreshold: 4}
	base, per, _ := Compile(Policy{Sites: []model.Site{site}})
	_ = base
	_, m := inspect(t, per["api.domain.com"], "POST", "/api/v1/login", "username=' OR '1'='1")
	if !has(m, 942000, 942999) {
		t.Fatalf("precondition: expected a 942xxx match, got %v", m)
	}
	var exc []model.RuleException
	n := ExceptionIDFirst
	for _, id := range m { // suppress every SQLi rule that fired, on /api/v1/login only
		if id >= 942000 && id <= 942999 {
			exc = append(exc, model.RuleException{SiteID: "s1", RuleID: id, PathPattern: "/api/v1/login", ExceptionRuleID: n})
			n++
		}
	}
	_, per, _ = Compile(Policy{Sites: []model.Site{site}, Exceptions: exc})
	if blocked, m := inspect(t, per["api.domain.com"], "POST", "/api/v1/login", "username=' OR '1'='1"); blocked || has(m, 942000, 942999) {
		t.Fatalf("exception did not suppress: blocked=%v matched=%v", blocked, m)
	}
	if blocked, _ := inspect(t, per["api.domain.com"], "POST", "/other", "username=' OR '1'='1"); !blocked {
		t.Fatal("exception leaked to another endpoint")
	}
}

func TestCustomRuleAndLint(t *testing.T) {
	rule := `SecRule ARGS:user_id "@rx (?i)(union\s+select|select\s+@@version)" \
    "id:900001,phase:2,deny,status:403,msg:'Custom SQL Injection Pattern Detected',severity:'CRITICAL'"`
	if err := LintRule(rule); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if err := LintRule(`SecRule ARGS "@rx (" "id:900002,deny"`); err == nil {
		t.Fatal("broken regex accepted")
	}
	if err := LintRule(`SecRule ARGS "@contains x" "id:942100,deny"`); err == nil {
		t.Fatal("CRS id accepted for a custom rule")
	}
	res, err := Sandbox(rule, SandboxRequest{Method: "GET", URL: "/x?user_id=1 UNION SELECT 1"})
	if err != nil || res.Status != "MATCHED" || len(res.Matched) != 1 || res.Matched[0].RuleID != 900001 || res.Matched[0].Variable != "ARGS:user_id" {
		t.Fatalf("sandbox: %+v err=%v", res, err)
	}
	if res.FTW == nil || len(res.FTW.Passed) != 1 || len(res.FTW.Failed) != 0 {
		t.Fatalf("Go FTW verdict: %+v", res.FTW)
	}
	if res, _ := Sandbox(rule, SandboxRequest{Method: "GET", URL: "/x?user_id=42"}); res.Status != "PASSED" || len(res.FTW.Failed) != 1 {
		t.Fatalf("sandbox should pass: %+v", res)
	}
}

func TestFTWSuite(t *testing.T) {
	rule := `SecRule ARGS:q "@contains <script" "id:900050,phase:2,deny,status:403,log,msg:'Script tag in q'"`
	suite := `
meta: {author: test}
rule_id: 900050
tests:
  - test_id: 1
    stages:
      - input: {dest_addr: 192.0.2.1, port: 1, uri: "/s?q=%3Cscript%3Ealert(1)", headers: {Host: localhost, User-Agent: t, Accept: "*/*"}}
        output: {status: 403, log: {expect_ids: [900050]}}
  - test_id: 2
    stages:
      - input: {dest_addr: 192.0.2.1, port: 1, uri: "/s?q=shoes", headers: {Host: localhost, User-Agent: t, Accept: "*/*"}}
        output: {log: {no_expect_ids: [900050]}}
  - test_id: 3
    stages:
      - input: {dest_addr: 192.0.2.1, port: 1, uri: "/s?q=shoes", headers: {Host: localhost, User-Agent: t, Accept: "*/*"}}
        output: {log: {expect_ids: [900050]}}
`
	rep, err := SandboxFTW(rule, suite)
	if err != nil {
		t.Fatal(err)
	}
	// Test 3 is wrong on purpose: FTW must report it as failed. dest_addr/port are overridden to the sandbox.
	if rep.Run != 3 || len(rep.Passed) != 2 || len(rep.Failed) != 1 {
		t.Fatalf("suite: %+v", rep)
	}
	if _, err := SandboxFTW(rule, "tests: [this is not a test"); err == nil {
		t.Fatal("broken YAML accepted")
	}
}
