package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/gin-gonic/gin"

	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

// ---------- Logs (Module 3) ----------

func (a *App) queryLogs(c *gin.Context) {
	var q store.LogQuery
	if !bind(c, &q) {
		return
	}
	t0 := time.Now()
	rows, total, err := a.CH.QueryLogs(c, q)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, gin.H{"rows": rows, "total": total, "tookMs": math.Round(float64(time.Since(t0).Microseconds())/100) / 10})
}

func (a *App) getLog(c *gin.Context) {
	l, err := a.CH.Log(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Log not found or past retention")
		return
	}
	c.JSON(200, l)
}

// ---------- Analytics (FR-4.1) ----------

func (a *App) overview(c *gin.Context) {
	hours, _ := strconv.Atoi(c.Query("hours"))
	if hours < 1 || hours > 24*30 {
		hours = 24
	}
	o, err := a.CH.Overview(c, hours)
	if err != nil {
		fail(c, err, "")
		return
	}
	nodes, err := a.PG.Nodes(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	mapping, err := a.PG.Mapping(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	var rps, latency float64
	live := 0
	for _, n := range nodes {
		if n.LastHeartbeat != nil && time.Since(*n.LastHeartbeat) <= offlineAfter {
			rps += n.RPS
			latency += n.LatencyMs
			live++
		}
	}
	ids := make([]uint32, 0, len(o.TopRules))
	for _, r := range o.TopRules {
		id, _ := strconv.Atoi(r.Key)
		ids = append(ids, uint32(id))
	}
	msgs, err := a.CH.RuleMessages(c, ids)
	if err != nil {
		fail(c, err, "")
		return
	}
	topRules := []gin.H{}
	for i, r := range o.TopRules {
		row := gin.H{"id": ids[i], "n": r.N, "msg": msgs[ids[i]]}
		if msgs[ids[i]] == "" {
			row["msg"] = "Rule " + r.Key
		}
		if m := correlate.MapRule(mapping, int(ids[i]), nil); m != nil {
			row["category"] = m.RuleCategory
		}
		topRules = append(topRules, row)
	}
	topEndpoints := []gin.H{}
	for _, e := range o.TopEndpoints {
		topEndpoints = append(topEndpoints, gin.H{"endpoint": e.Key, "n": e.N})
	}
	topIPs := []gin.H{}
	for _, x := range o.TopIPs {
		topIPs = append(topIPs, gin.H{"ip": x.IP, "n": x.N, "cc": x.CC, "asn": x.ASN})
	}
	ratio := 0.0
	if o.TotalRequests > 0 {
		ratio = float64(o.Blocked) / float64(o.TotalRequests) * 100
	}
	if live > 0 {
		latency /= float64(live)
	}
	c.JSON(200, gin.H{"rps": math.Round(rps), "totalRequests": o.TotalRequests, "blocked": o.Blocked, "blockRatio": ratio, "avgLatencyMs": latency,
		"series": o.Series, "topRules": topRules, "topEndpoints": topEndpoints, "topIps": topIPs, "possiblySuccessful": o.PossiblySuccessful})
}

// ---------- Attack mapping (Module 6) ----------

func (a *App) campaigns(c *gin.Context) {
	out, err := a.PG.Campaigns(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) campaign(c *gin.Context) {
	cmp, err := a.PG.Campaign(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Campaign not found")
		return
	}
	evs, err := a.CH.Events(c, "campaign_id = ?", cmp.ID)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, gin.H{"campaign": cmp, "events": evs})
}

func (a *App) attackEvents(c *gin.Context) {
	where, args := []string{"1"}, []any{}
	if v, _ := strconv.ParseInt(c.Query("from"), 10, 64); v > 0 {
		where, args = append(where, "timestamp >= ?"), append(args, time.UnixMilli(v))
	}
	if v, _ := strconv.ParseInt(c.Query("to"), 10, 64); v > 0 {
		where, args = append(where, "timestamp <= ?"), append(args, time.UnixMilli(v))
	}
	if s := c.Query("siteId"); s != "" {
		where, args = append(where, "site_id = ?"), append(args, s)
	}
	evs, err := a.CH.Events(c, strings.Join(where, " AND "), args...)
	if err != nil {
		fail(c, err, "")
		return
	}
	// Events of actors still below min_events_to_open are stored but belong to no visible campaign yet.
	open, err := a.PG.Campaigns(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	known := make(map[string]bool, len(open))
	for _, x := range open {
		known[x.ID] = true
	}
	out := evs[:0]
	for _, e := range evs {
		if known[e.CampaignID] {
			out = append(out, e)
		}
	}
	c.JSON(200, out)
}

var campaignStatuses = map[string]string{
	"ACTIVE": "Campaign active", "CONTAINED": "Campaign contained", "CLOSED": "Campaign closed", "FALSE_POSITIVE": "Campaign marked false positive",
}

func (a *App) patchCampaign(c *gin.Context) {
	// assignee distinguishes "absent" from null (unassign), so it is decoded by hand.
	var raw map[string]json.RawMessage
	if !bind(c, &raw) {
		return
	}
	id := c.Param("id")
	u := userOf(c)
	var status, assignee *string
	var note *model.Note
	var audits [][2]string
	if v, ok := raw["status"]; ok {
		var s string
		if json.Unmarshal(v, &s) != nil || campaignStatuses[s] == "" {
			bad(c, "Unknown campaign status")
			return
		}
		status = &s
		audits = append(audits, [2]string{campaignStatuses[s], id})
	}
	if v, ok := raw["assignee"]; ok {
		var s *string
		if json.Unmarshal(v, &s) != nil {
			bad(c, "Assignee must be a name or null")
			return
		}
		name := ""
		if s != nil {
			name = strings.TrimSpace(*s)
		}
		if len(name) > 100 {
			bad(c, "Assignee is too long")
			return
		}
		assignee = &name
		label := name
		if label == "" {
			label = "unassigned"
		}
		audits = append(audits, [2]string{"Campaign assigned", id + " -> " + label})
	}
	if v, ok := raw["note"]; ok {
		var s string
		_ = json.Unmarshal(v, &s)
		if s = strings.TrimSpace(s); s != "" {
			if len(s) > 4000 {
				bad(c, "Note is too long (4000 characters at most)")
				return
			}
			note = &model.Note{Author: u.Name, At: time.Now().UnixMilli(), Text: s}
			audits = append(audits, [2]string{"Note added", id})
		}
	}
	cmp, err := a.PG.PatchCampaign(c, id, status, assignee, note)
	if err != nil {
		fail(c, err, "Campaign not found")
		return
	}
	a.Engine.Sync(cmp)
	for _, x := range audits {
		a.audit(c, x[0], x[1], "-")
	}
	c.JSON(200, cmp)
}

// ---------- Live stream: WebSocket /ws/attacks (FR-6.6) ----------

// Hub fans correlated events out to every connected console.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]bool
	origins []string
}

func NewHub(allowedOrigins ...string) *Hub {
	h := &Hub{clients: map[chan []byte]bool{}}
	for _, o := range allowedOrigins {
		if i := strings.Index(o, "://"); i >= 0 {
			h.origins = append(h.origins, o[i+3:]) // coder/websocket matches on host
		}
	}
	return h
}

// Publish never blocks the correlation engine: a console that cannot keep up loses frames, not the pipeline.
func (h *Hub) Publish(m model.StreamMsg) {
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- b:
		default:
		}
	}
}

func (h *Hub) serve(c *gin.Context) {
	conn, err := websocket.Accept(c.Writer, c.Request, &websocket.AcceptOptions{OriginPatterns: h.origins})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ch := make(chan []byte, 256)
	h.mu.Lock()
	h.clients[ch] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}()
	ctx := conn.CloseRead(c.Request.Context()) // the console never sends; this also notices disconnects
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-ch:
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := conn.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		case <-ping.C:
			if conn.Ping(ctx) != nil {
				return
			}
		}
	}
}

// Notifier posts kill chain escalations to a webhook (FR-6.3). The body has a "text" field, so Slack-compatible
// incoming webhooks accept it as is; SIEM receivers get the structured fields beside it.
func Notifier(url string) func(model.Campaign, string) {
	if url == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	return func(c model.Campaign, stage string) {
		body, _ := json.Marshal(gin.H{
			"text":     "Kill chain escalation: " + c.ActorKey + " reached " + stage + " (campaign " + c.ID + ", risk " + strconv.Itoa(c.RiskScore) + ")",
			"campaign": c.ID, "actor": c.ActorKey, "stage": stage, "risk_score": c.RiskScore, "targets": c.Targets,
		})
		go func() {
			res, err := client.Post(url, "application/json", strings.NewReader(string(body)))
			if err != nil {
				slog.Warn("escalation webhook failed", "err", err)
				return
			}
			res.Body.Close()
			if res.StatusCode >= 300 {
				slog.Warn("escalation webhook rejected", "status", res.StatusCode)
			}
		}()
	}
}
