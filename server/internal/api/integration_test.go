package api_test

// End-to-end test of the control plane against real PostgreSQL and ClickHouse, with a real edge agent enrolled
// over mTLS gRPC in front of a demo upstream. Run with the dev stack up:
//
//	CORAZIUM_TEST_DATABASE_URL=postgres://corazium:corazium-dev@127.0.0.1:55432/corazium \
//	CORAZIUM_TEST_CLICKHOUSE_ADDR=127.0.0.1:59000 go test ./internal/api/
//
// It creates and uses its own databases (corazium_test) and never touches the dev data.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	agentv1 "github.com/Agustian16/WAAP-Platform/server/gen/agent/v1"
	"github.com/Agustian16/WAAP-Platform/server/internal/agent"
	"github.com/Agustian16/WAAP-Platform/server/internal/agentrpc"
	"github.com/Agustian16/WAAP-Platform/server/internal/api"
	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

const webOrigin = "http://console.test"

type harness struct {
	t        *testing.T
	pg       *store.PG
	ch       *store.CH
	app      *api.App
	api      *httptest.Server
	grpcAddr string
	edge     string // base URL of the edge agent
	tokens   map[model.Role]string
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func setup(t *testing.T) *harness {
	dsn, chAddr := os.Getenv("CORAZIUM_TEST_DATABASE_URL"), os.Getenv("CORAZIUM_TEST_CLICKHOUSE_ADDR")
	if dsn == "" || chAddr == "" {
		t.Skip("set CORAZIUM_TEST_DATABASE_URL and CORAZIUM_TEST_CLICKHOUSE_ADDR to run the integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Fresh databases every run.
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	for _, q := range []string{"DROP DATABASE IF EXISTS corazium_test WITH (FORCE)", "CREATE DATABASE corazium_test"} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	admin.Close(ctx)
	u, _ := url.Parse(dsn)
	u.Path = "/corazium_test"
	chUser, chPass := "corazium", "corazium-dev"
	chAdmin, err := clickhouse.Open(&clickhouse.Options{Addr: []string{chAddr}, Auth: clickhouse.Auth{Database: "corazium", Username: chUser, Password: chPass}})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DROP DATABASE IF EXISTS corazium_test", "CREATE DATABASE corazium_test"} {
		if err := chAdmin.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	chAdmin.Close()

	h := &harness{t: t, tokens: map[model.Role]string{}}
	if h.pg, err = store.OpenPG(ctx, u.String(), true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.pg.Close)
	if h.ch, err = store.OpenCH(ctx, chAddr, "corazium_test", chUser, chPass); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.ch.Close)

	hub := api.NewHub(webOrigin)
	geo, _ := correlate.NewGeo(mustV(h.pg.GeoOverrides(ctx)), "", "")
	engine := correlate.NewEngine(h.pg, h.ch, geo, hub.Publish, nil)
	go engine.Run(ctx)
	certPEM, keyPEM, err := h.pg.PKI(ctx, agentrpc.GenerateCA)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := agentrpc.ParseCA(certPEM, keyPEM)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.grpcAddr = lis.Addr().String()
	fleet := agentrpc.NewServer(h.pg, h.ch, engine, ca, h.grpcAddr)
	go fleet.Serve(ctx, lis, []string{"127.0.0.1"})

	auth, _ := api.NewAuth(ctx, api.AuthConfig{PublicURL: "http://api.test", WebURL: webOrigin, SessionTTL: time.Hour}, h.pg)
	h.app = &api.App{PG: h.pg, CH: h.ch, Engine: engine, Hub: hub, Fleet: fleet, Auth: auth, PushWait: 3 * time.Second}
	h.app.LoadCorrelation(ctx)
	if err := h.app.EnsureBundle(ctx); err != nil {
		t.Fatal(err)
	}
	h.api = httptest.NewServer(h.app.Router())
	t.Cleanup(h.api.Close)

	// One signed-in user per role. Sessions are created the way the OIDC callback creates them.
	for role, name := range map[model.Role]string{model.Admin: "Budi", model.Analyst: "Ahmad", model.Auditor: "Auditor"} {
		usr, err := h.pg.UserLogin(ctx, "test|"+name, name, strings.ToLower(name)+"@domain.com", role, true)
		if err != nil {
			t.Fatal(err)
		}
		tok := "tok-" + name
		sum := sha256.Sum256([]byte(tok))
		if err := h.pg.CreateSession(ctx, sum[:], usr.ID, time.Hour); err != nil {
			t.Fatal(err)
		}
		h.tokens[role] = tok
	}

	// A demo application behind the agent.
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)

	// Enroll a real agent with a token from the API, exactly as an operator would.
	var enr struct{ Token, Command string }
	h.do(model.Admin, "POST", "/api/v1/nodes/enrollment-tokens", map[string]string{"name": "edge-test-01"}, 200, &enr)
	_, pin := fleet.EnrollHint()
	if !strings.Contains(enr.Command, pin) || !strings.Contains(enr.Command, enr.Token) {
		t.Fatalf("enrollment command lacks token or CA pin: %s", enr.Command)
	}
	listen := freeAddr(t)
	ag, err := agent.New(agent.Config{ControlPlane: h.grpcAddr, CAPin: pin, Token: enr.Token, StateDir: t.TempDir(), Listen: listen, Upstream: up.URL,
		Region: "Test", Lon: 106.8, Lat: -6.2, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, LogAllowed: true, Heartbeat: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := ag.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("agent: %v", err)
		}
	}()
	h.edge = "http://" + listen
	h.eventually("agent online", func() bool {
		var nodes []model.EdgeNode
		h.do(model.Auditor, "GET", "/api/v1/nodes", nil, 200, &nodes)
		return len(nodes) == 1 && nodes[0].Status != "OFFLINE" && nodes[0].CurrentConfigVersion >= 1
	})
	return h
}

func mustV[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// do calls the API as a role ("" = anonymous), checks the status and decodes JSON into out when given.
func (h *harness) do(role model.Role, method, path string, body any, want int, out any) string {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.api.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", webOrigin)
	if role != "" {
		req.AddCookie(&http.Cookie{Name: "cz_session", Value: h.tokens[role]})
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		h.t.Fatalf("%s %s as %q: status %d, want %d. Body: %s", method, path, role, res.StatusCode, want, raw)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			h.t.Fatalf("%s %s: decode %v. Body: %s", method, path, err, raw)
		}
	}
	return string(raw)
}

func (h *harness) eventually(what string, ok func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for: %s", what)
}

// hit sends a request through the edge agent as a simulated client address and returns the status.
func (h *harness) hit(ip, method, host, path, body string, hdr ...string) int {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.edge+path, strings.NewReader(body))
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 integration-test")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Forwarded-For", ip)
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("edge request: %v", err)
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}

func (h *harness) logs(q store.LogQuery) (rows []model.AuditLog) {
	h.t.Helper()
	h.ch.Flush(context.Background())
	var out struct {
		Rows  []model.AuditLog
		Total int
	}
	h.do(model.Auditor, "POST", "/api/v1/logs/query", q, 200, &out)
	return out.Rows
}

func (h *harness) deploy() (version int64) {
	h.t.Helper()
	var out struct {
		Version     int64
		Synced      int
		Unreachable []string
	}
	h.do(model.Admin, "POST", "/api/v1/config/deploy", map[string]any{}, 200, &out)
	if out.Synced != 1 || len(out.Unreachable) != 0 {
		h.t.Fatalf("deploy did not reach the node: %+v", out)
	}
	return out.Version
}

const sqli = "username=%27+OR+%271%27%3D%271&password=hunter2"

func TestControlPlaneEndToEnd(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	var sites []model.Site
	h.do(model.Auditor, "GET", "/api/v1/sites", nil, 200, &sites)
	if len(sites) != 4 {
		t.Fatalf("seeded sites: %d", len(sites))
	}
	var apiSite model.Site
	for _, s := range sites {
		if s.DomainName == "api.domain.com" {
			apiSite = s
		}
	}

	t.Run("authentication and RBAC", func(t *testing.T) {
		h.do("", "GET", "/api/v1/sites", nil, 401, nil)
		var me model.User
		h.do(model.Analyst, "GET", "/api/v1/me", nil, 200, &me)
		if me.Name != "Ahmad" || me.Role != model.Analyst {
			t.Fatalf("me: %+v", me)
		}
		h.do(model.Auditor, "POST", "/api/v1/rules", map[string]any{"name": "x", "seclang_raw": `SecRule ARGS "@contains x" "id:900100,phase:2,deny"`}, 403, nil)
		h.do(model.Analyst, "POST", "/api/v1/config/deploy", map[string]any{}, 403, nil)
		h.do(model.Analyst, "PATCH", "/api/v1/sites/"+apiSite.ID, map[string]any{"paranoia_level": 3}, 403, nil)

		// A browser on another origin is refused before authentication is even looked at (CSRF).
		req, _ := http.NewRequest("POST", h.api.URL+"/api/v1/config/deploy", strings.NewReader("{}"))
		req.Header.Set("Origin", "http://evil.test")
		req.AddCookie(&http.Cookie{Name: "cz_session", Value: h.tokens[model.Admin]})
		res, _ := http.DefaultClient.Do(req)
		if res.StatusCode != 403 {
			t.Fatalf("cross-origin POST: %d", res.StatusCode)
		}
	})

	t.Run("inspection, logs, masking", func(t *testing.T) {
		if code := h.hit("198.51.100.200", "GET", "api.domain.com", "/api/v1/users?page=2", ""); code != 200 {
			t.Fatalf("benign request: %d", code)
		}
		if code := h.hit("203.0.113.24", "POST", "api.domain.com", "/api/v1/login", sqli, "Authorization", "Bearer secret-token", "Cookie", "session_id=abc123; theme=dark"); code != 403 {
			t.Fatalf("SQL injection was not blocked: %d", code)
		}
		var rows []model.AuditLog
		h.eventually("blocked transaction in ClickHouse", func() bool {
			rows = h.logs(store.LogQuery{IP: "203.0.113.24", Action: "DENY"})
			return len(rows) == 1
		})
		l := rows[0]
		if l.Host != "api.domain.com" || l.SiteID != apiSite.ID || l.ResponseStatus != 403 || l.CountryCode != "CN" || l.ASN != 64516 {
			t.Fatalf("log fields: %+v", l)
		}
		hasSQLi := false
		for _, id := range l.MatchedRuleIDs {
			hasSQLi = hasSQLi || (id >= 942000 && id <= 942999)
		}
		if !hasSQLi {
			t.Fatalf("no 942xxx rule on the log: %v", l.MatchedRuleIDs)
		}
		// NFR-2.3: secrets are masked before they are stored.
		blob := l.RequestBody + fmt.Sprint(l.RequestHeaders)
		for _, secret := range []string{"hunter2", "secret-token", "abc123"} {
			if strings.Contains(blob, secret) {
				t.Fatalf("%q leaked into the stored log: %s", secret, blob)
			}
		}
		if !strings.Contains(l.RequestBody, "password=[masked]") || l.RequestHeaders["Authorization"] != "[masked]" {
			t.Fatalf("masking: body=%q headers=%v", l.RequestBody, l.RequestHeaders)
		}
		// Filters: rule id prefix, URI substring, status; and the ALLOW row for the benign request.
		if got := h.logs(store.LogQuery{RuleID: "942", URI: "/login", Status: "403"}); len(got) != 1 {
			t.Fatalf("filtered query returned %d rows", len(got))
		}
		if got := h.logs(store.LogQuery{Action: "ALLOW", IP: "198.51.100.200"}); len(got) != 1 || len(got[0].MatchedRuleIDs) != 0 {
			t.Fatalf("ALLOW row: %+v", got)
		}
		var one model.AuditLog
		h.do(model.Auditor, "GET", "/api/v1/logs/"+l.ID, nil, 200, &one)
		if one.TransactionID != l.TransactionID || one.CampaignID == "" {
			t.Fatalf("log detail: %+v", one)
		}
		h.do(model.Auditor, "GET", "/api/v1/logs/log_missing", nil, 404, nil)
	})

	var campaignID string
	t.Run("correlation, live stream, campaign workflow", func(t *testing.T) {
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.api.URL, "http")+"/ws/attacks", &websocket.DialOptions{
			HTTPHeader: http.Header{"Cookie": {"cz_session=" + h.tokens[model.Analyst]}, "Origin": {webOrigin}}})
		if err != nil {
			t.Fatalf("websocket: %v", err)
		}
		defer ws.CloseNow()
		// One SQLi event exists already; min_events_to_open is 3, so the third event opens the campaign.
		h.hit("203.0.113.24", "GET", "api.domain.com", "/api/v1/search?filter=1%27+UNION+SELECT+password+FROM+users--", "")
		h.hit("203.0.113.24", "POST", "api.domain.com", "/api/v1/login", sqli)
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		_, frame, err := ws.Read(rctx)
		if err != nil {
			t.Fatalf("no stream frame: %v", err)
		}
		var msg model.StreamMsg
		if err := json.Unmarshal(frame, &msg); err != nil {
			t.Fatal(err)
		}
		if !msg.IsNewCampaign || msg.Campaign.ActorKey != "203.0.113.24" || msg.Event.RuleCategory != "SQLI" || msg.Event.KillchainStage != "EXPLOIT" || msg.Event.Outcome != "BLOCKED" {
			t.Fatalf("stream frame: %+v", msg)
		}
		campaignID = msg.Campaign.ID

		var list []model.Campaign
		h.do(model.Auditor, "GET", "/api/v1/campaigns", nil, 200, &list)
		if len(list) != 1 || list[0].ID != campaignID || list[0].EventCount != 3 || list[0].HighestStage != "EXPLOIT" || list[0].RiskScore < 50 {
			t.Fatalf("campaign list: %+v", list)
		}
		var detail struct {
			Campaign model.Campaign
			Events   []model.AttackEvent
		}
		h.eventually("campaign events in ClickHouse", func() bool {
			h.ch.Flush(ctx)
			h.do(model.Auditor, "GET", "/api/v1/campaigns/"+campaignID, nil, 200, &detail)
			return len(detail.Events) == 3
		})
		var evs []model.AttackEvent
		h.do(model.Auditor, "GET", fmt.Sprintf("/api/v1/attack-events?from=%d&to=", time.Now().Add(-time.Hour).UnixMilli()), nil, 200, &evs)
		if len(evs) != 3 || evs[0].Geo != [2]float64{116.4, 39.9} {
			t.Fatalf("attack events: %+v", evs)
		}

		// Analyst workflow: assign, note, contain. Auditors may not.
		h.do(model.Auditor, "PATCH", "/api/v1/campaigns/"+campaignID, map[string]any{"status": "CLOSED"}, 403, nil)
		var c model.Campaign
		h.do(model.Analyst, "PATCH", "/api/v1/campaigns/"+campaignID, map[string]any{"assignee": "Ahmad", "note": "Confirmed credential stuffing."}, 200, &c)
		h.do(model.Analyst, "PATCH", "/api/v1/campaigns/"+campaignID, map[string]any{"status": "CONTAINED"}, 200, &c)
		if c.Assignee == nil || *c.Assignee != "Ahmad" || len(c.Notes) != 1 || c.Notes[0].Author != "Ahmad" || c.Status != "CONTAINED" {
			t.Fatalf("patched campaign: %+v", c)
		}
		h.do(model.Analyst, "PATCH", "/api/v1/campaigns/"+campaignID, map[string]any{"assignee": nil}, 200, &c)
		if c.Assignee != nil || len(c.Notes) != 1 {
			t.Fatalf("unassign: %+v", c)
		}
		h.do(model.Analyst, "PATCH", "/api/v1/campaigns/"+campaignID, map[string]any{"status": "BOGUS"}, 422, nil)

		var ov struct {
			Blocked            int
			PossiblySuccessful int
			TopRules           []struct{ ID, N int }
			TopIps             []struct{ IP, CC string }
			Series             []any
		}
		h.eventually("analytics overview", func() bool {
			h.ch.Flush(ctx)
			h.do(model.Auditor, "GET", "/api/v1/analytics/overview?hours=1", nil, 200, &ov)
			return len(ov.TopRules) > 0 && ov.Blocked >= 3
		})
		if ov.TopIps[0].IP != "203.0.113.24" || ov.TopIps[0].CC != "CN" || len(ov.Series) != 12 {
			t.Fatalf("overview: %+v", ov)
		}
	})

	t.Run("policy, rules and zero-downtime deploy", func(t *testing.T) {
		// Analysts write drafts; an Admin activates. The engine refuses broken SecLang.
		rule := `SecRule REQUEST_HEADERS:X-Probe "@streq blockme" "id:900100,phase:1,deny,status:403,msg:'Probe header',severity:'CRITICAL'"`
		var r model.CustomRule
		h.do(model.Analyst, "POST", "/api/v1/rules", map[string]any{"name": "BLOCK_PROBE", "site_id": nil, "seclang_raw": rule, "is_active": true}, 200, &r)
		if r.IsActive || r.RuleID != 900100 || r.CreatedBy != "Ahmad" {
			t.Fatalf("analyst save must be an inactive draft: %+v", r)
		}
		h.do(model.Admin, "POST", "/api/v1/rules", map[string]any{"name": "dup", "seclang_raw": rule}, 422, nil)
		h.do(model.Admin, "POST", "/api/v1/rules", map[string]any{"name": "bad", "seclang_raw": `SecRule ARGS "@rx (" "id:900101,deny"`}, 422, nil)
		h.do(model.Admin, "POST", "/api/v1/rules", map[string]any{"name": "crs id", "seclang_raw": `SecRule ARGS "@contains x" "id:942100,deny"`}, 422, nil)

		var sb struct {
			Status  string
			Matched []struct{ RuleID int }
			Engine  string
		}
		h.do(model.Analyst, "POST", "/api/v1/sandbox/ftw", map[string]any{"seclang": rule, "request": map[string]any{"method": "GET", "url": "/x", "headers": map[string]string{"X-Probe": "blockme"}}}, 200, &sb)
		if sb.Status != "MATCHED" || len(sb.Matched) != 1 || sb.Matched[0].RuleID != 900100 || !strings.Contains(sb.Engine, "Coraza") {
			t.Fatalf("sandbox: %+v", sb)
		}

		if code := h.hit("198.51.100.201", "GET", "shop.domain.com", "/", "", "X-Probe", "blockme"); code != 200 {
			t.Fatalf("draft rule must not be enforced: %d", code)
		}
		h.do(model.Admin, "PATCH", "/api/v1/rules/"+r.ID, map[string]any{"is_active": true}, 200, &r)
		var nodes []model.EdgeNode
		h.do(model.Auditor, "GET", "/api/v1/nodes", nil, 200, &nodes)
		if nodes[0].SyncStatus != "PENDING_UPDATE" {
			t.Fatalf("node should be pending after a policy change: %+v", nodes[0].SyncStatus)
		}
		if code := h.hit("198.51.100.201", "GET", "shop.domain.com", "/", "", "X-Probe", "blockme"); code != 200 {
			t.Fatalf("activated but undeployed rule must not be enforced: %d", code)
		}
		v := h.deploy()
		if code := h.hit("198.51.100.201", "GET", "shop.domain.com", "/", "", "X-Probe", "blockme"); code != 403 {
			t.Fatalf("deployed rule not enforced: %d", code)
		}
		h.eventually("node in sync", func() bool {
			h.do(model.Auditor, "GET", "/api/v1/nodes", nil, 200, &nodes)
			return nodes[0].SyncStatus == "IN_SYNC" && nodes[0].CurrentConfigVersion == v
		})
		if n := nodes[0]; n.NodeName != "edge-test-01" || n.Region != "Test" || n.Proxy != "Standalone" || !strings.HasPrefix(n.CRSVersion, "CRS ") {
			t.Fatalf("node registration: %+v", n)
		}
		h.eventually("node metrics history", func() bool {
			h.ch.Flush(ctx)
			h.do(model.Auditor, "GET", "/api/v1/nodes", nil, 200, &nodes)
			return len(nodes[0].History) > 0
		})

		// FR-2.1: switching the SQLi category off for one site stops the blocking there, and only there.
		var s model.Site
		h.do(model.Admin, "PATCH", "/api/v1/sites/"+apiSite.ID, map[string]any{"crs_categories": map[string]bool{"942": false}, "paranoia_level": 1, "inbound_threshold": 1000}, 422, nil)
		h.do(model.Admin, "PATCH", "/api/v1/sites/"+apiSite.ID, map[string]any{"crs_categories": map[string]bool{"942": false}}, 200, &s)
		if s.CRSCategories["942"] {
			t.Fatalf("category not saved: %+v", s.CRSCategories)
		}
		h.deploy()
		h.hit("198.51.100.202", "POST", "api.domain.com", "/api/v1/login", sqli)
		h.hit("198.51.100.202", "POST", "shop.domain.com", "/api/v1/login", sqli)
		h.eventually("category switch honoured per site", func() bool {
			rows := h.logs(store.LogQuery{IP: "198.51.100.202"})
			if len(rows) != 2 {
				return false
			}
			for _, l := range rows {
				sq := false
				for _, id := range l.MatchedRuleIDs {
					sq = sq || (id >= 942000 && id <= 942999)
				}
				if sq != (l.Host == "shop.domain.com") {
					t.Fatalf("942xxx on %s = %v: %v", l.Host, sq, l.MatchedRuleIDs)
				}
			}
			return true
		})

		// Exception (FR-3.3): generated SecLang, stored, and part of the next bundle.
		var ex struct {
			Exception model.RuleException
			SecLang   string
		}
		h.do(model.Analyst, "POST", "/api/v1/exceptions", map[string]any{"siteId": apiSite.ID, "ruleId": 941100, "path": "/api/v1/search", "parameter": "ARGS:q", "scope": "endpoint", "reason": ""}, 422, nil)
		h.do(model.Analyst, "POST", "/api/v1/exceptions", map[string]any{"siteId": apiSite.ID, "ruleId": 941100, "path": "/x\" \"evil", "scope": "endpoint", "reason": "r"}, 422, nil)
		h.do(model.Analyst, "POST", "/api/v1/exceptions", map[string]any{"siteId": apiSite.ID, "ruleId": 941100, "path": "/api/v1/search", "parameter": "ARGS:q", "scope": "endpoint", "reason": "Search accepts markup"}, 200, &ex)
		if !strings.Contains(ex.SecLang, "ctl:ruleRemoveTargetById=941100;ARGS:q") || !strings.Contains(ex.SecLang, "id:10000") {
			t.Fatalf("exception SecLang: %s", ex.SecLang)
		}
		h.deploy()
		h.do(model.Analyst, "DELETE", "/api/v1/exceptions/"+ex.Exception.ID, nil, 403, nil)
		h.do(model.Admin, "DELETE", "/api/v1/exceptions/"+ex.Exception.ID, nil, 200, nil)
		h.do(model.Admin, "DELETE", "/api/v1/rules/"+r.ID, nil, 200, nil)
		h.do(model.Admin, "GET", "/api/v1/rules/"+r.ID, nil, 404, nil)
	})

	t.Run("IP reputation is enforced at once", func(t *testing.T) {
		var imp struct{ LegitRequests, AttackEvents, Campaigns int }
		h.do(model.Analyst, "GET", "/api/v1/ip-lists/impact?cidr=203.0.113.24", nil, 200, &imp)
		if imp.AttackEvents != 3 || imp.Campaigns != 1 {
			t.Fatalf("impact: %+v", imp)
		}
		h.do(model.Analyst, "POST", "/api/v1/ip-lists", map[string]any{"cidr": "not-an-ip", "list": "block", "reason": "x", "ttlHours": nil}, 422, nil)
		var e model.IPListEntry
		h.do(model.Analyst, "POST", "/api/v1/ip-lists", map[string]any{"cidr": "203.0.113.24", "list": "block", "reason": "SQLi campaign", "ttlHours": 24}, 200, &e)
		if e.CIDR != "203.0.113.24/32" || e.ExpiresAt == nil || e.CreatedBy != "Ahmad" {
			t.Fatalf("list entry: %+v", e)
		}
		h.do(model.Analyst, "POST", "/api/v1/ip-lists", map[string]any{"cidr": "203.0.113.24/32", "list": "block", "reason": "again", "ttlHours": nil}, 409, nil)
		// No deploy: an analyst's block reaches the node by itself.
		if code := h.hit("203.0.113.24", "GET", "shop.domain.com", "/", ""); code != 403 {
			t.Fatalf("blocklisted client got %d", code)
		}
		h.eventually("blocklist hit logged", func() bool {
			rows := h.logs(store.LogQuery{RuleID: "1001"})
			return len(rows) == 1 && rows[0].ClientIP == "203.0.113.24" && rows[0].ActionTaken == "DENY"
		})
		h.do(model.Analyst, "DELETE", "/api/v1/ip-lists/"+e.ID, nil, 200, nil)
		if code := h.hit("203.0.113.24", "GET", "shop.domain.com", "/", ""); code != 200 {
			t.Fatalf("unblocked client got %d", code)
		}

		// Threat feed: validation, a real pull over TLS, entries land on the blocklist and are enforced.
		h.do(model.Admin, "POST", "/api/v1/threat-feeds", map[string]any{"name": "plain", "url": "http://feeds.test/x.txt", "format": "text", "interval_minutes": 60}, 422, nil)
		feedSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "# sample feed\n192.0.2.200\n192.0.2.208/29 ; scanners\nnot-an-address\n")
		}))
		defer feedSrv.Close()
		var f model.ThreatFeed
		h.do(model.Admin, "POST", "/api/v1/threat-feeds", map[string]any{"name": "Test feed", "url": feedSrv.URL + "/list.txt", "format": "text", "interval_minutes": 60}, 200, &f)
		h.do(model.Admin, "POST", "/api/v1/threat-feeds/"+f.ID+"/pull", map[string]any{}, 200, &f)
		if f.Status != "ERROR" || f.Error == nil || !strings.Contains(*f.Error, "non-public") {
			t.Fatalf("the default feed client must refuse loopback targets (SSRF guard): %+v", f)
		}
		h.app.FeedHTTP = feedSrv.Client()
		h.do(model.Admin, "POST", "/api/v1/threat-feeds/"+f.ID+"/pull", map[string]any{}, 200, &f)
		if f.Status != "OK" || f.Entries != 2 {
			t.Fatalf("feed pull: %+v", f)
		}
		if code := h.hit("192.0.2.210", "GET", "shop.domain.com", "/", ""); code != 403 {
			t.Fatalf("feed-listed client got %d", code)
		}
		h.do(model.Admin, "DELETE", "/api/v1/threat-feeds/"+f.ID, nil, 200, nil)
		if code := h.hit("192.0.2.210", "GET", "shop.domain.com", "/", ""); code != 200 {
			t.Fatalf("client still blocked after the feed was removed: %d", code)
		}
	})

	t.Run("admin: users, mapping, correlation, GitOps, audit trail", func(t *testing.T) {
		var users []model.User
		h.do(model.Admin, "GET", "/api/v1/users", nil, 200, &users)
		var adminID, analystID string
		for _, u := range users {
			switch u.Role {
			case model.Admin:
				adminID = u.ID
			case model.Analyst:
				analystID = u.ID
			}
		}
		h.do(model.Analyst, "PATCH", "/api/v1/users/"+analystID, map[string]any{"role": "Admin"}, 403, nil)
		h.do(model.Admin, "PATCH", "/api/v1/users/"+adminID, map[string]any{"role": "Auditor"}, 409, nil) // last Admin
		var u model.User
		h.do(model.Admin, "PATCH", "/api/v1/users/"+analystID, map[string]any{"role": "Admin"}, 200, &u)
		h.do(model.Admin, "PATCH", "/api/v1/users/"+analystID, map[string]any{"role": "SecOps Analyst"}, 200, &u)

		var mapping []model.KillchainMapping
		h.do(model.Admin, "GET", "/api/v1/killchain-mapping", nil, 200, &mapping)
		m := mapping[len(mapping)-1]
		m.KillchainStage = "WEAPON"
		h.do(model.Admin, "PUT", "/api/v1/killchain-mapping/"+m.ID, m, 422, nil)
		m.KillchainStage = "OBJECTIVES"
		h.do(model.Admin, "PUT", "/api/v1/killchain-mapping/"+m.ID, m, 200, &m)

		cs := model.CorrelationSettings{ActorKeyMode: "CIDR24", IdleTimeoutMinutes: 45, MinEventsToOpen: 1}
		h.do(model.Admin, "PUT", "/api/v1/correlation-settings/"+apiSite.ID, model.CorrelationSettings{ActorKeyMode: "IP", IdleTimeoutMinutes: 0, MinEventsToOpen: 1}, 422, nil)
		h.do(model.Admin, "PUT", "/api/v1/correlation-settings/"+apiSite.ID, cs, 200, nil)
		var all []model.CorrelationSettings
		h.do(model.Admin, "GET", "/api/v1/correlation-settings", nil, 200, &all)
		persisted := false
		for _, x := range all {
			persisted = persisted || (x.SiteID == apiSite.ID && x.ActorKeyMode == "CIDR24" && x.IdleTimeoutMinutes == 45)
		}
		if !persisted {
			t.Fatalf("correlation settings not persisted: %+v", all)
		}
		// The engine picks the change up without a restart: two addresses in one /24 now form one campaign.
		h.hit("192.0.2.31", "GET", "api.domain.com", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "")
		h.hit("192.0.2.32", "GET", "api.domain.com", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "")
		h.eventually("CIDR24 campaign", func() bool {
			var list []model.Campaign
			h.do(model.Auditor, "GET", "/api/v1/campaigns", nil, 200, &list)
			for _, c := range list {
				if c.ActorKey == "192.0.2.0/24" && c.EventCount == 2 && c.ActorMode == "CIDR24" && c.CorrelationConfidence == "MEDIUM" {
					return true
				}
			}
			return false
		})

		var yamlText string
		h.do(model.Auditor, "GET", "/api/v1/gitops/export", nil, 200, &yamlText)
		if !strings.Contains(yamlText, "kind: CorazaPolicy") || !strings.Contains(yamlText, "domain: api.domain.com") || !strings.Contains(yamlText, "- 942xxx") {
			t.Fatalf("export:\n%s", yamlText)
		}
		var val struct {
			OK      bool
			Errors  []string
			Summary []string
		}
		h.do(model.Auditor, "POST", "/api/v1/gitops/validate", map[string]string{"text": yamlText}, 200, &val)
		if !val.OK || len(val.Summary) != 1 || val.Summary[0] != "No changes against the running policy" {
			t.Fatalf("round trip validate: %+v", val)
		}
		broken := "apiVersion: coraza.console/v1\nkind: CorazaPolicy\nsites:\n  - domain: api.domain.com\n    paranoiaLevel: 9\ncustomRules:\n  - id: 900200\n    name: bad\n    site: '*'\n    active: true\n    seclang: 'SecRule ARGS \"@rx (\" \"id:900200,deny\"'\n"
		h.do(model.Auditor, "POST", "/api/v1/gitops/validate", map[string]string{"text": broken}, 200, &val)
		if val.OK || len(val.Errors) != 2 {
			t.Fatalf("broken policy accepted: %+v", val)
		}

		// FR-5.2: everything above is on the trail, with who and from where, and the trail cannot be rewritten.
		var trail []model.AuditTrailEntry
		h.do(model.Auditor, "GET", "/api/v1/audit-trail", nil, 200, &trail)
		seen := map[string]bool{}
		for _, e := range trail {
			seen[e.Action] = true
			if e.Actor == "" || e.SourceIP == "" {
				t.Fatalf("incomplete audit entry: %+v", e)
			}
		}
		for _, a := range []string{"Enrollment token issued", "Rule drafted", "Rule enabled", "Policy deployed", "Policy changed", "Exception created", "IP blocked", "IP unblocked",
			"Threat feed pulled", "Campaign assigned", "Note added", "Campaign contained", "Role changed", "Kill chain mapping changed", "Correlation settings changed", "Rule deleted"} {
			if !seen[a] {
				t.Errorf("audit trail is missing %q", a)
			}
		}
		if _, err := h.pg.Exec(ctx, `UPDATE audit_trail SET actor = 'nobody'`); err == nil {
			t.Fatal("audit trail accepted an UPDATE")
		}
		if _, err := h.pg.Exec(ctx, `DELETE FROM audit_trail`); err == nil {
			t.Fatal("audit trail accepted a DELETE")
		}
	})

	t.Run("gRPC requires a node certificate", func(t *testing.T) {
		creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) // no client cert; server identity is not what this checks
		conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(creds))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		client := agentv1.NewAgentServiceClient(conn)
		stream, err := client.AuditStream(ctx)
		if err == nil {
			_ = stream.Send(&agentv1.AuditEvent{Action: "DENY", ClientIp: "203.0.113.99"})
			_, err = stream.CloseAndRecv()
		}
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("audit stream without a certificate: %v", err)
		}
		if _, err := client.Enroll(ctx, &agentv1.EnrollRequest{Token: "cze_wrong"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("enroll with a bad token: %v", err)
		}
	})
}
