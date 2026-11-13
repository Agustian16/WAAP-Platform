package waf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/coreruleset/go-ftw/config"
	"github.com/coreruleset/go-ftw/output"
	"github.com/coreruleset/go-ftw/runner"
	"github.com/coreruleset/go-ftw/test"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

// FR-2.4: the test sandbox runs Go FTW (the OWASP CRS project's Framework for Testing WAFs) against a throwaway
// Coraza instance loaded with the rules under test. FTW sends real HTTP requests and decides pass/fail from the
// WAF's error log, bracketed by marker requests, exactly as the CRS regression suite does.

func init() { zerolog.SetGlobalLevel(zerolog.ErrorLevel) } // go-ftw logs through zerolog; keep it quiet

// markerRuleID is the sandbox's log-marker rule. go-ftw finds each stage's log lines between two marker
// requests carrying the X-CRS-Test header; this rule writes that header into the log.
const markerRuleID = 1999

const markerRule = `SecRule REQUEST_HEADERS:X-CRS-Test "@rx ^.*$" "id:1999,phase:1,pass,log,t:none,msg:'x-crs-test %{MATCHED_VAR}'"`

// ftwMu serializes runs: go-ftw keeps package-level state (its logger, the HTTP client's connection reuse).
var ftwMu sync.Mutex

// FTWReport is a suite run.
type FTWReport struct {
	Run       int               `json:"run"`
	Passed    []string          `json:"passed"`
	Failed    []string          `json:"failed"`
	Skipped   []string          `json:"skipped"`
	Triggered map[string][]uint `json:"triggered"` // test id -> rule ids seen, all stages
	Engine    string            `json:"engine"`
}

type sandboxWAF struct {
	srv     *httptest.Server
	logFile string
	mu      sync.Mutex
	matches []SandboxMatch // from non-marker requests, in order
}

func (s *sandboxWAF) Close() { s.srv.Close(); os.RemoveAll(filepath.Dir(s.logFile)) }

func startSandboxWAF(seclang string) (*sandboxWAF, error) {
	dir, err := os.MkdirTemp("", "corazium-ftw-")
	if err != nil {
		return nil, err
	}
	s := &sandboxWAF{logFile: filepath.Join(dir, "waf.log")}
	f, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	var logMu sync.Mutex
	cfg := coraza.NewWAFConfig().WithDirectives("SecRuleEngine On\nSecRequestBodyAccess On\n" + markerRule + "\n" + seclang).
		WithErrorCallback(func(mr types.MatchedRule) {
			logMu.Lock()
			defer logMu.Unlock()
			_, _ = f.WriteString(mr.ErrorLog() + "\n")
		})
	engine, err := coraza.NewWAF(cfg)
	if err != nil {
		f.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("SecLang: %s", firstLine(err.Error()))
	}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		tx := engine.NewTransaction()
		defer tx.Close()
		host, port, _ := net.SplitHostPort(r.RemoteAddr)
		p, _ := strconv.Atoi(port)
		it := ProcessRequest(tx, r, host, p, body)
		tx.ProcessLogging()
		if r.Header.Get("X-CRS-Test") == "" {
			s.mu.Lock()
			for _, mr := range tx.MatchedRules() {
				id := mr.Rule().ID()
				if id == 0 || id == markerRuleID {
					continue
				}
				m := SandboxMatch{RuleID: id, Msg: mr.Message()}
				if ds := mr.MatchedDatas(); len(ds) > 0 {
					m.Variable = ds[0].Variable().Name()
					if k := ds[0].Key(); k != "" {
						m.Variable += ":" + k
					}
					m.Data = ds[0].Value()
				}
				s.matches = append(s.matches, m)
			}
			s.mu.Unlock()
		}
		if it != nil {
			w.WriteHeader(blockStatus(it))
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	return s, nil
}

func blockStatus(it *types.Interruption) int {
	if it.Status >= 400 {
		return it.Status
	}
	return http.StatusForbidden
}

func runFTW(s *sandboxWAF, suite []byte) (FTWReport, error) {
	rep := FTWReport{Passed: []string{}, Failed: []string{}, Skipped: []string{}, Triggered: map[string][]uint{},
		Engine: "Go FTW " + ModuleVersion("github.com/coreruleset/go-ftw") + " + " + EngineVersion()}
	t, err := test.GetTestFromYaml(suite, "sandbox.yaml")
	if err != nil {
		return rep, fmt.Errorf("FTW test YAML: %s", firstLine(err.Error()))
	}
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(s.srv.URL, "http://"))
	p, _ := strconv.Atoi(port)
	cfg := config.NewDefaultConfig()
	cfg.WithLogfile(s.logFile)
	// Every test goes to the sandbox, whatever address the YAML names.
	cfg.TestOverride.Overrides.DestAddr, cfg.TestOverride.Overrides.Port = &host, &p
	ftwMu.Lock()
	ctx, err := runner.Run(cfg, []*test.FTWTest{t}, &runner.RunnerConfig{ShowOnlyFailed: true}, output.NewOutput("quiet", io.Discard))
	ftwMu.Unlock()
	if err != nil {
		return rep, fmt.Errorf("FTW: %s", firstLine(err.Error()))
	}
	st := ctx.Stats
	rep.Run, rep.Passed, rep.Failed, rep.Skipped = st.Run, append(rep.Passed, st.Success...), append(rep.Failed, st.Failed...), append(rep.Skipped, st.Skipped...)
	for id, stages := range st.TriggeredRules {
		seen := map[uint]bool{}
		for _, ids := range stages {
			for _, r := range ids {
				if r != markerRuleID && !seen[r] {
					seen[r] = true
					rep.Triggered[id] = append(rep.Triggered[id], r)
				}
			}
		}
		sort.Slice(rep.Triggered[id], func(i, j int) bool { return rep.Triggered[id][i] < rep.Triggered[id][j] })
	}
	return rep, nil
}

// SandboxFTW runs an FTW test suite (FTW YAML, schema v2) against the given rules.
func SandboxFTW(seclang, suite string) (FTWReport, error) {
	s, err := startSandboxWAF(seclang)
	if err != nil {
		return FTWReport{}, err
	}
	defer s.Close()
	if len(suite) > 1<<20 {
		return FTWReport{}, fmt.Errorf("FTW suite is larger than 1 MB")
	}
	return runFTW(s, []byte(suite))
}

// RequestToFTW turns one sandbox request into an FTW test that expects the rules under test to fire.
func RequestToFTW(ruleIDs []uint, req SandboxRequest) (string, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = "GET"
	}
	headers := map[string]string{"Host": "localhost", "User-Agent": "corazium-sandbox", "Accept": "*/*"}
	for k, v := range req.Headers {
		headers[k] = v
	}
	if req.Body != "" {
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}
	input := map[string]any{"dest_addr": "127.0.0.1", "port": 80, "method": method, "uri": escapeTarget(req.URL), "version": "HTTP/1.1", "headers": headers}
	if req.Body != "" {
		input["data"] = req.Body
	}
	var rid uint
	if len(ruleIDs) > 0 {
		rid = ruleIDs[0]
	}
	doc := map[string]any{
		"meta":    map[string]any{"author": "corazium-console", "description": "Generated from the console test sandbox"},
		"rule_id": rid,
		"tests": []any{map[string]any{"test_id": 1, "stages": []any{map[string]any{
			"input": input, "output": map[string]any{"log": map[string]any{"expect_ids": ruleIDs}},
		}}}},
	}
	b, err := yaml.Marshal(doc)
	return string(b), err
}

// escapeTarget percent-encodes bytes that cannot appear in an HTTP request target (spaces, quotes, controls),
// so a payload typed into the console the way a browser would send it arrives intact. Existing %XX escapes
// are left alone. FTW suites written by hand are sent exactly as written.
func escapeTarget(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte(`"<>\^`+"`{|}", c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
