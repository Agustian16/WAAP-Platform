package correlate

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

type fake struct {
	n      int
	saved  map[string]model.Campaign
	logs   []model.AuditLog
	events []model.AttackEvent
	msgs   []model.StreamMsg
	alerts []string
}

func (f *fake) NextCampaignID(context.Context, time.Time) (string, error) {
	f.n++
	return fmt.Sprintf("cmp_%d", f.n), nil
}
func (f *fake) SaveCampaign(_ context.Context, c model.Campaign) error { f.saved[c.ID] = c; return nil }
func (f *fake) AddLog(l model.AuditLog)                                { f.logs = append(f.logs, l) }
func (f *fake) AddEvent(e model.AttackEvent)                           { f.events = append(f.events, e) }

func str(s string) *string { return &s }

var table = []model.KillchainMapping{
	{RuleIDFrom: 913000, RuleIDTo: 913999, RuleCategory: "SCANNER", KillchainStage: "RECON"},
	{RuleIDFrom: 942000, RuleIDTo: 942999, RuleCategory: "SQLI", KillchainStage: "EXPLOIT"},
	{RuleIDFrom: 955000, RuleIDTo: 955999, RuleCategory: "RCE", KillchainStage: "INSTALL"},
	{RuleIDFrom: 932000, RuleIDTo: 932999, RuleCategory: "RCE", KillchainStage: "EXPLOIT"},
	{RuleIDFrom: 900000, RuleIDTo: 909999, RuleCategory: "SQLI", KillchainStage: "EXPLOIT"},
	{RuleIDFrom: 900500, RuleIDTo: 900500, RuleCategory: "LEAKAGE", KillchainStage: "OBJECTIVES"},
	{RuleIDFrom: 1, RuleIDTo: 1, Tag: str("attack-xss"), RuleCategory: "XSS", KillchainStage: "EXPLOIT"},
}

func setup(t *testing.T, min int) (*Engine, *fake) {
	t.Helper()
	f := &fake{saved: map[string]model.Campaign{}}
	geo, err := NewGeo([]store.GeoOverride{{CIDR: "203.0.113.0/24", CountryCode: "CN", ASN: 64516, ASName: "Sample", Lon: 116.4, Lat: 39.9}}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(f, f, geo, func(m model.StreamMsg) { f.msgs = append(f.msgs, m) }, func(c model.Campaign, s string) { f.alerts = append(f.alerts, c.ID+">"+s) })
	e.Configure(table, []model.CorrelationSettings{{SiteID: "s1", ActorKeyMode: "IP", IdleTimeoutMinutes: 30, MinEventsToOpen: min}})
	return e, f
}

func tx(ip string, at time.Time, uri, action string, status uint16, rules ...Rule) Tx {
	return Tx{NodeID: "n1", TransactionID: fmt.Sprint(at.UnixNano(), uri), Host: "api.domain.com", SiteID: "s1", ClientIP: ip, At: at,
		Method: "GET", URI: uri, Action: action, Status: status, Rules: rules}
}

func TestMapRule(t *testing.T) {
	if m := MapRule(table, 900500, nil); m == nil || m.KillchainStage != "OBJECTIVES" {
		t.Fatalf("narrowest range must win, got %+v", m)
	}
	if m := MapRule(table, 77, []string{"attack-xss"}); m == nil || m.RuleCategory != "XSS" {
		t.Fatalf("tag fallback failed, got %+v", m)
	}
	if MapRule(table, 77, nil) != nil {
		t.Fatal("unmapped rule must return nil")
	}
}

func TestRiskAndOutcome(t *testing.T) {
	// Same numbers as riskScore() in web/lib/killchain.ts.
	if got := RiskScore("EXPLOIT", 2, 2, 2, 38); got != 50+3+3+17+4 {
		t.Fatalf("risk = %d", got)
	}
	if got := RiskScore("RECON", 1, 1, 0, 1); got != 8 {
		t.Fatalf("risk = %d", got)
	}
	if Outcome("DENY", 403) != "BLOCKED" || Outcome("LOG", 200) != "POSSIBLY_SUCCESSFUL" || Outcome("LOG", 404) != "DETECTED" {
		t.Fatal("outcome classification")
	}
}

func TestCampaignLifecycle(t *testing.T) {
	e, f := setup(t, 3)
	ctx := context.Background()
	t0 := time.Now().Add(-time.Hour)
	recon := Rule{ID: 913100, Message: "Scanner", Severity: "CRITICAL"}
	sqli := Rule{ID: 942100, Message: "SQLi", Severity: "CRITICAL"}
	block := Rule{ID: 949110, Message: "Inbound Anomaly Score Exceeded", Severity: "CRITICAL"}

	e.Process(ctx, tx("203.0.113.9", t0, "/ok", "ALLOW", 200)) // clean traffic: logged, never an attack event
	if len(f.logs) != 1 || len(f.events) != 0 {
		t.Fatalf("ALLOW handling: logs=%d events=%d", len(f.logs), len(f.events))
	}

	e.Process(ctx, tx("203.0.113.9", t0.Add(1*time.Second), "/.env", "DENY", 403, recon))
	e.Process(ctx, tx("203.0.113.9", t0.Add(2*time.Second), "/.git/config", "DENY", 403, recon))
	if len(f.msgs) != 0 {
		t.Fatal("campaign announced before min_events_to_open")
	}
	e.Process(ctx, tx("203.0.113.9", t0.Add(3*time.Second), "/admin", "DENY", 403, recon))
	if len(f.msgs) != 1 || !f.msgs[0].IsNewCampaign || f.msgs[0].Campaign.HighestStage != "RECON" {
		t.Fatalf("third event should open the campaign: %+v", f.msgs)
	}
	c := f.msgs[0].Campaign
	if c.CountryCode != "CN" || c.ASN != 64516 || c.Geo != [2]float64{116.4, 39.9} || c.ActorKey != "203.0.113.9" || c.CorrelationConfidence != "HIGH" {
		t.Fatalf("enrichment: %+v", c)
	}

	// Escalation Recon -> Exploitation (FR-6.3). The scoring rule 949110 must not be picked as the describing rule.
	e.Process(ctx, tx("203.0.113.9", t0.Add(time.Minute), "/api/v1/login", "DENY", 403, block, sqli))
	m := f.msgs[len(f.msgs)-1]
	if m.EscalatedTo == nil || *m.EscalatedTo != "EXPLOIT" || m.Event.RuleID != 942100 || m.Event.RuleCategory != "SQLI" || m.Event.Outcome != "BLOCKED" {
		t.Fatalf("escalation: %+v", m)
	}
	if len(f.alerts) != 1 || f.alerts[0] != c.ID+">EXPLOIT" {
		t.Fatalf("alerts: %v", f.alerts)
	}
	if got := f.saved[c.ID]; got.EventCount != 4 || got.HighestStage != "EXPLOIT" || len(got.Stages) != 2 {
		t.Fatalf("persisted campaign: %+v", got)
	}

	// A payload that got a 2xx is the triage priority (FR-6.4) and raises the score.
	before := m.Campaign.RiskScore
	e.Process(ctx, tx("203.0.113.9", t0.Add(2*time.Minute), "/reports", "LOG", 200, sqli))
	m = f.msgs[len(f.msgs)-1]
	if m.Event.Outcome != "POSSIBLY_SUCCESSFUL" || m.Campaign.PossiblySuccessful != 1 || m.Campaign.RiskScore <= before {
		t.Fatalf("possibly successful: %+v", m)
	}

	// Web shell upload, then a request to the same path: Installation, then Command & Control.
	e.Process(ctx, tx("203.0.113.9", t0.Add(3*time.Minute), "/uploads/x.php", "LOG", 200, Rule{ID: 955110, Severity: "CRITICAL"}))
	e.Process(ctx, tx("203.0.113.9", t0.Add(4*time.Minute), "/uploads/x.php?c=id", "LOG", 200, Rule{ID: 932160, Severity: "CRITICAL"}))
	m = f.msgs[len(f.msgs)-1]
	if m.Event.KillchainStage != "C2" || m.Campaign.HighestStage != "C2" {
		t.Fatalf("C2 detection: stage=%s highest=%s", m.Event.KillchainStage, m.Campaign.HighestStage)
	}

	// Idle timeout: 31 minutes of silence starts a new campaign for the same actor.
	e.Process(ctx, tx("203.0.113.9", t0.Add(40*time.Minute), "/.env", "DENY", 403, recon))
	if last := f.events[len(f.events)-1]; last.CampaignID == c.ID {
		t.Fatal("event after idle timeout joined the old campaign")
	}

	// A closed campaign is never extended.
	e2, f2 := setup(t, 1)
	e2.Process(ctx, tx("203.0.113.50", t0, "/a", "DENY", 403, recon))
	closed := f2.msgs[0].Campaign
	closed.Status = "CLOSED"
	e2.Sync(closed)
	e2.Process(ctx, tx("203.0.113.50", t0.Add(time.Second), "/b", "DENY", 403, recon))
	if f2.msgs[1].Campaign.ID == closed.ID || !f2.msgs[1].IsNewCampaign {
		t.Fatal("closed campaign was extended")
	}
}

func TestActorKeyModes(t *testing.T) {
	e, f := setup(t, 1)
	e.Configure(table, []model.CorrelationSettings{{SiteID: "s1", ActorKeyMode: "CIDR24", IdleTimeoutMinutes: 30, MinEventsToOpen: 1}})
	now := time.Now()
	r := Rule{ID: 913100, Severity: "CRITICAL"}
	e.Process(context.Background(), tx("203.0.113.9", now, "/a", "DENY", 403, r))
	e.Process(context.Background(), tx("203.0.113.77", now.Add(time.Second), "/b", "DENY", 403, r))
	if f.msgs[0].Campaign.ID != f.msgs[1].Campaign.ID || f.msgs[1].Campaign.ActorKey != "203.0.113.0/24" || f.msgs[1].Campaign.CorrelationConfidence != "MEDIUM" {
		t.Fatalf("CIDR24 grouping: %+v", f.msgs[1].Campaign)
	}
}
