package correlate

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// Rule is one matched rule on a transaction, as reported by the edge node.
type Rule struct {
	ID       int
	Message  string
	Data     string
	Variable string
	Severity string
	Tags     []string
}

// Tx is one inspected HTTP transaction from the audit stream.
type Tx struct {
	NodeID, TransactionID, Host, SiteID, ClientIP string
	ClientPort                                    uint16
	At                                            time.Time
	Method, URI, HTTPVersion, Action              string
	Status                                        uint16
	Rules                                         []Rule
	Headers                                       map[string]string
	Body                                          string
	LatencyUs                                     uint64
}

// CampaignStore persists campaign state (PostgreSQL in production).
type CampaignStore interface {
	NextCampaignID(ctx context.Context, at time.Time) (string, error)
	SaveCampaign(ctx context.Context, c model.Campaign) error
}

// Sink receives enriched rows (ClickHouse in production).
type Sink interface {
	AddLog(model.AuditLog)
	AddEvent(model.AttackEvent)
}

type Engine struct {
	store   CampaignStore
	sink    Sink
	geo     *Geo
	publish func(model.StreamMsg)        // WebSocket fan-out
	notify  func(model.Campaign, string) // escalation alert (FR-6.3)

	mu       sync.Mutex
	mapping  []model.KillchainMapping
	settings map[string]model.CorrelationSettings // by site id
	live     map[string]*model.Campaign           // by actor key
	dirty    map[string]bool                      // campaign ids with unsaved counters
}

func NewEngine(store CampaignStore, sink Sink, geo *Geo, publish func(model.StreamMsg), notify func(model.Campaign, string)) *Engine {
	return &Engine{store: store, sink: sink, geo: geo, publish: publish, notify: notify,
		settings: map[string]model.CorrelationSettings{}, live: map[string]*model.Campaign{}, dirty: map[string]bool{}}
}

// Configure swaps the mapping table and per-site settings (called at start and whenever an Admin edits them).
func (e *Engine) Configure(mapping []model.KillchainMapping, settings []model.CorrelationSettings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mapping = mapping
	e.settings = map[string]model.CorrelationSettings{}
	for _, s := range settings {
		e.settings[s.SiteID] = s
	}
}

// Restore loads campaigns that may still be extended (after a control-plane restart).
func (e *Engine) Restore(cs []model.Campaign) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range cs {
		c := cs[i]
		if cur, ok := e.live[c.ActorKey]; !ok || cur.LastSeen < c.LastSeen {
			e.live[c.ActorKey] = &c
		}
	}
}

// Sync applies analyst-owned fields after a PATCH so the live copy and the next stream frame stay current.
func (e *Engine) Sync(c model.Campaign) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if cur, ok := e.live[c.ActorKey]; ok && cur.ID == c.ID {
		cur.Status, cur.Assignee, cur.Notes = c.Status, c.Assignee, c.Notes
	}
}

// Run flushes debounced campaign counters once a second until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			e.flush()
			return
		case <-t.C:
			e.flush()
		}
	}
}

func (e *Engine) flush() {
	e.mu.Lock()
	var save []model.Campaign
	for id := range e.dirty {
		for _, c := range e.live {
			if c.ID == id {
				save = append(save, *c)
			}
		}
	}
	e.dirty = map[string]bool{}
	e.mu.Unlock()
	for _, c := range save {
		if err := e.store.SaveCampaign(context.Background(), c); err != nil {
			slog.Error("save campaign", "id", c.ID, "err", err)
		}
	}
}

var sevRank = map[string]int{"CRITICAL": 3, "ERROR": 2, "WARNING": 1, "NOTICE": 0}

// scoring reports CRS anomaly-evaluation and correlation rules, which say "blocked", not what the attack was.
func scoring(id int) bool {
	return (id >= 949000 && id <= 949999) || (id >= 959000 && id <= 959999) || (id >= 980000 && id <= 980999)
}

// classify picks the rule that best describes the transaction. The furthest kill chain stage wins; within it,
// the category most of the matched rules agree on (one stray RCE match must not relabel a SQL injection that
// seven SQLi rules fired on); within that, the most severe rule.
func (e *Engine) classify(rules []Rule) (r Rule, category, stage string) {
	type mapped struct {
		rule       Rule
		cat, stage string
	}
	var ms []mapped
	top := -1
	for _, x := range rules {
		if scoring(x.ID) {
			continue
		}
		m := mapped{x, "PROTOCOL", "DELIVERY"} // unmapped rules still describe a malformed or unwanted request
		if row := MapRule(e.mapping, x.ID, x.Tags); row != nil {
			m.cat, m.stage = row.RuleCategory, row.KillchainStage
		}
		ms = append(ms, m)
		top = max(top, StageIndex(m.stage))
	}
	if len(ms) == 0 { // only scoring rules matched (their detection rules were nolog)
		return rules[0], "PROTOCOL", "DELIVERY"
	}
	votes := map[string]int{}
	for _, m := range ms {
		if StageIndex(m.stage) == top {
			votes[m.cat]++
		}
	}
	found := false
	for _, m := range ms {
		if StageIndex(m.stage) != top {
			continue
		}
		better := votes[m.cat] > votes[category] || (votes[m.cat] == votes[category] && m.cat == category && sevRank[m.rule.Severity] > sevRank[r.Severity])
		if !found || better {
			found, r, category, stage = true, m.rule, m.cat, m.stage
		}
	}
	return
}

func pathOf(uri string) string {
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		return uri[:i]
	}
	return uri
}

func (e *Engine) actorKey(mode, ip, ua string, loc Loc) (key, usedMode, confidence string) {
	switch mode {
	case "CIDR24":
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			p, _ := a.Prefix(24)
			return p.String(), "CIDR24", "MEDIUM"
		}
	case "ASN":
		if loc.ASN != 0 {
			return fmt.Sprintf("AS%d", loc.ASN), "ASN", "LOW"
		}
	case "FINGERPRINT":
		// No TLS/JA3 fingerprint reaches the control plane, so this is User-Agent only: low confidence.
		if ua != "" {
			h := sha1.Sum([]byte(ua))
			if len(ua) > 60 {
				ua = ua[:60]
			}
			return "ua:" + hex.EncodeToString(h[:4]) + " " + ua, "FINGERPRINT", "LOW"
		}
	}
	return ip, "IP", "HIGH"
}

// Process handles one transaction end to end. It is safe for concurrent use; transactions are correlated in arrival order.
func (e *Engine) Process(ctx context.Context, tx Tx) {
	loc := e.geo.Lookup(tx.ClientIP)
	log := model.AuditLog{
		ID: "log_" + tx.TransactionID, Timestamp: tx.At.UTC(), TransactionID: tx.TransactionID, NodeID: tx.NodeID, SiteID: tx.SiteID, Host: tx.Host,
		ClientIP: tx.ClientIP, ClientPort: tx.ClientPort, CountryCode: loc.CountryCode, ASN: loc.ASN, HTTPMethod: tx.Method, URI: tx.URI,
		HTTPVersion: tx.HTTPVersion, ResponseStatus: tx.Status, ActionTaken: tx.Action, MatchedRuleIDs: []uint32{}, MatchedMessages: []string{},
		MatchedData: []string{}, MatchedVars: []string{}, Severity: "NOTICE", RequestHeaders: tx.Headers, RequestBody: tx.Body, LatencyUs: tx.LatencyUs,
	}
	if log.RequestHeaders == nil {
		log.RequestHeaders = map[string]string{}
	}
	for _, r := range tx.Rules {
		log.MatchedRuleIDs = append(log.MatchedRuleIDs, uint32(r.ID))
		log.MatchedMessages = append(log.MatchedMessages, r.Message)
		log.MatchedData = append(log.MatchedData, r.Data)
		log.MatchedVars = append(log.MatchedVars, r.Variable)
	}
	if len(tx.Rules) == 0 {
		e.sink.AddLog(log)
		return
	}

	e.mu.Lock()
	rule, category, stage := e.classify(tx.Rules)
	log.Severity = rule.Severity
	if log.Severity == "" {
		log.Severity = "NOTICE"
	}
	set, ok := e.settings[tx.SiteID]
	if !ok {
		set = model.CorrelationSettings{ActorKeyMode: "IP", IdleTimeoutMinutes: 30, MinEventsToOpen: 3}
	}
	key, mode, conf := e.actorKey(set.ActorKeyMode, tx.ClientIP, tx.Headers["User-Agent"], loc)
	ts := tx.At.UnixMilli()
	path := pathOf(tx.URI)

	c := e.live[key]
	if c != nil && (c.Status == "CLOSED" || c.Status == "FALSE_POSITIVE" || ts-c.LastSeen >= int64(set.IdleTimeoutMinutes)*60_000) {
		c = nil // outside the sliding window, or the analyst closed it: this starts a new campaign (FR-6.2)
	}
	created := c == nil
	if created {
		id, err := e.store.NextCampaignID(ctx, tx.At)
		if err != nil {
			e.mu.Unlock()
			slog.Error("campaign id", "err", err)
			e.sink.AddLog(log)
			return
		}
		c = &model.Campaign{ID: id, ActorKey: key, ActorMode: mode, SiteID: tx.SiteID, CountryCode: loc.CountryCode, ASN: loc.ASN, ASName: loc.ASName,
			Geo: [2]float64{loc.Lon, loc.Lat}, CorrelationConfidence: conf, FirstSeen: ts, LastSeen: ts, HighestStage: stage,
			Stages: []string{}, Categories: []string{}, Targets: []string{}, ShellPaths: []string{}, Notes: []model.Note{}, Status: "ACTIVE"}
		e.live[key] = c
	}
	// C2 (PRD 4.6.2): a later request to a path where a web shell was installed is the actor driving that shell.
	if stage != "INSTALL" && contains(c.ShellPaths, path) {
		stage = "C2"
	}
	if stage == "INSTALL" && !contains(c.ShellPaths, path) && len(c.ShellPaths) < 50 {
		c.ShellPaths = append(c.ShellPaths, path)
	}
	outcome := Outcome(tx.Action, tx.Status)

	var escalated *string
	if !created && StageIndex(stage) > StageIndex(c.HighestStage) {
		s := stage
		escalated = &s
	}
	if StageIndex(stage) > StageIndex(c.HighestStage) {
		c.HighestStage = stage
	}
	c.EventCount++
	if ts > c.LastSeen {
		c.LastSeen = ts
	}
	if !contains(c.Stages, stage) {
		c.Stages = append(c.Stages, stage)
		sort.Slice(c.Stages, func(i, j int) bool { return StageIndex(c.Stages[i]) < StageIndex(c.Stages[j]) })
	}
	if !contains(c.Categories, category) {
		c.Categories = append(c.Categories, category)
	}
	if target := tx.Host + path; !contains(c.Targets, target) && len(c.Targets) < 200 {
		c.Targets = append(c.Targets, target)
	}
	if outcome == "POSSIBLY_SUCCESSFUL" {
		c.PossiblySuccessful++
	}
	c.RiskScore = RiskScore(c.HighestStage, len(c.Targets), len(c.Categories), c.PossiblySuccessful, c.EventCount)
	opening := !c.Opened && c.EventCount >= int64(set.MinEventsToOpen)
	if opening {
		c.Opened = true
	}
	snapshot := *c
	snapshot.Stages = append([]string{}, c.Stages...)
	snapshot.Targets = append([]string{}, c.Targets...)
	saveNow := created || opening || escalated != nil
	if !saveNow {
		e.dirty[c.ID] = true
	}
	e.mu.Unlock()

	if saveNow {
		if err := e.store.SaveCampaign(ctx, snapshot); err != nil {
			slog.Error("save campaign", "id", snapshot.ID, "err", err)
		}
	}
	ev := model.AttackEvent{ID: log.ID, Timestamp: ts, TransactionID: tx.TransactionID, CampaignID: snapshot.ID, NodeID: tx.NodeID, SiteID: tx.SiteID,
		Host: tx.Host, ClientIP: tx.ClientIP, CountryCode: loc.CountryCode, ASN: loc.ASN, Geo: [2]float64{loc.Lon, loc.Lat}, Method: tx.Method, URI: tx.URI,
		RuleID: uint32(rule.ID), RuleCategory: category, KillchainStage: stage, Severity: log.Severity, Outcome: outcome, ResponseStatus: tx.Status}
	log.CampaignID = snapshot.ID
	e.sink.AddLog(log)
	e.sink.AddEvent(ev)
	if !snapshot.Opened {
		return // below min_events_to_open: stored, but not yet a campaign anyone is told about
	}
	if e.publish != nil {
		e.publish(model.StreamMsg{Event: ev, Log: log, Campaign: snapshot, IsNewCampaign: opening, EscalatedTo: escalated})
	}
	if escalated != nil && e.notify != nil {
		e.notify(snapshot, *escalated)
	}
}
