package store

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

// ClickHouse schema (PRD 6.2, 6.3). Ids are strings so transactions for hosts without a site can be stored.
var chSchema = []string{
	`CREATE TABLE IF NOT EXISTS coraza_audit_logs (
		timestamp DateTime64(3, 'UTC'),
		id String,
		transaction_id String,
		node_id String,
		site_id String,
		host String,
		client_ip String,
		client_port UInt16,
		country_code LowCardinality(String),
		asn UInt32,
		http_method LowCardinality(String),
		uri String,
		http_version String,
		response_status UInt16,
		action_taken LowCardinality(String),
		matched_rule_ids Array(UInt32),
		matched_messages Array(String),
		matched_data Array(String),
		matched_vars Array(String),
		severity LowCardinality(String),
		request_headers Map(String, String),
		request_body String,
		latency_us UInt64,
		campaign_id String,
		INDEX idx_id id TYPE bloom_filter GRANULARITY 4
	) ENGINE = MergeTree() PARTITION BY toYYYYMM(timestamp) ORDER BY (timestamp, site_id, action_taken, client_ip)`,
	`CREATE TABLE IF NOT EXISTS attack_events (
		timestamp DateTime64(3, 'UTC'),
		id String,
		transaction_id String,
		campaign_id String,
		node_id String,
		site_id String,
		host String,
		client_ip String,
		country_code LowCardinality(String),
		asn UInt32,
		geo_lat Float32,
		geo_lon Float32,
		method LowCardinality(String),
		uri String,
		rule_id UInt32,
		rule_category LowCardinality(String),
		killchain_stage LowCardinality(String),
		severity LowCardinality(String),
		outcome LowCardinality(String),
		response_status UInt16
	) ENGINE = MergeTree() PARTITION BY toYYYYMM(timestamp) ORDER BY (campaign_id, timestamp)`,
	`CREATE TABLE IF NOT EXISTS node_metrics (
		timestamp DateTime('UTC'),
		node_id String,
		rps Float32,
		latency_ms Float32,
		cpu Float32,
		memory Float32,
		requests UInt64,
		blocked UInt64
	) ENGINE = MergeTree() PARTITION BY toYYYYMM(timestamp) ORDER BY (node_id, timestamp) TTL timestamp + INTERVAL 90 DAY`,
}

type NodeMetric struct {
	At                       time.Time
	NodeID                   string
	RPS, LatencyMs, CPU, Mem float64
	Requests, Blocked        uint64
}

type CH struct {
	conn driver.Conn

	mu      sync.Mutex
	logs    []model.AuditLog
	events  []model.AttackEvent
	metrics []NodeMetric
	stop    chan struct{}
	done    chan struct{}
}

// OpenCH connects, creates the tables and starts the insert batcher.
func OpenCH(ctx context.Context, addr, database, user, password string) (*CH, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr}, Auth: clickhouse.Auth{Database: database, Username: user, Password: password},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	for _, q := range chSchema {
		if err := conn.Exec(ctx, q); err != nil {
			return nil, fmt.Errorf("clickhouse schema: %w", err)
		}
	}
	c := &CH{conn: conn, stop: make(chan struct{}), done: make(chan struct{})}
	go c.loop()
	return c, nil
}

// Close flushes buffered rows and closes the connection.
func (c *CH) Close() {
	close(c.stop)
	<-c.done
	c.conn.Close()
}

// Rows are buffered and written in batches (NFR-1.3: ClickHouse wants few large inserts, not many small ones).
func (c *CH) AddLog(l model.AuditLog) { c.mu.Lock(); c.logs = append(c.logs, l); c.mu.Unlock() }
func (c *CH) AddEvent(e model.AttackEvent) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}
func (c *CH) AddMetric(m NodeMetric) { c.mu.Lock(); c.metrics = append(c.metrics, m); c.mu.Unlock() }

func (c *CH) loop() {
	defer close(c.done)
	t := time.NewTicker(time.Second) // each flush is a part per table; fewer, larger inserts merge better
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.Flush(context.Background())
		case <-c.stop:
			c.Flush(context.Background())
			return
		}
	}
}

// Flush writes everything buffered so far. Tests call it to read their own writes.
func (c *CH) Flush(ctx context.Context) {
	c.mu.Lock()
	logs, events, metrics := c.logs, c.events, c.metrics
	c.logs, c.events, c.metrics = nil, nil, nil
	c.mu.Unlock()
	if len(logs) > 0 {
		c.insert(ctx, "coraza_audit_logs", len(logs), func(b driver.Batch, i int) error {
			l := logs[i]
			return b.Append(l.Timestamp, l.ID, l.TransactionID, l.NodeID, l.SiteID, l.Host, l.ClientIP, l.ClientPort, l.CountryCode, l.ASN,
				l.HTTPMethod, l.URI, l.HTTPVersion, l.ResponseStatus, l.ActionTaken, l.MatchedRuleIDs, l.MatchedMessages, l.MatchedData,
				l.MatchedVars, l.Severity, l.RequestHeaders, l.RequestBody, l.LatencyUs, l.CampaignID)
		})
	}
	if len(events) > 0 {
		c.insert(ctx, "attack_events", len(events), func(b driver.Batch, i int) error {
			e := events[i]
			return b.Append(time.UnixMilli(e.Timestamp), e.ID, e.TransactionID, e.CampaignID, e.NodeID, e.SiteID, e.Host, e.ClientIP, e.CountryCode,
				e.ASN, float32(e.Geo[1]), float32(e.Geo[0]), e.Method, e.URI, e.RuleID, e.RuleCategory, e.KillchainStage, e.Severity, e.Outcome, e.ResponseStatus)
		})
	}
	if len(metrics) > 0 {
		c.insert(ctx, "node_metrics", len(metrics), func(b driver.Batch, i int) error {
			m := metrics[i]
			return b.Append(m.At, m.NodeID, float32(m.RPS), float32(m.LatencyMs), float32(m.CPU), float32(m.Mem), m.Requests, m.Blocked)
		})
	}
}

func (c *CH) insert(ctx context.Context, table string, n int, add func(driver.Batch, int) error) {
	b, err := c.conn.PrepareBatch(ctx, "INSERT INTO "+table)
	if err == nil {
		for i := 0; i < n && err == nil; i++ {
			err = add(b, i)
		}
		if err == nil {
			err = b.Send()
		}
	}
	if err != nil {
		slog.Error("clickhouse insert failed, rows dropped", "table", table, "rows", n, "err", err)
	}
}

// ---------- Log explorer (Module 3) ----------

type LogQuery struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	IP     string `json:"ip"`
	Host   string `json:"host"`
	URI    string `json:"uri"`
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
	Status string `json:"status"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

const logCols = `id, timestamp, transaction_id, node_id, site_id, host, client_ip, client_port, country_code, asn, http_method, uri, http_version,
	response_status, action_taken, matched_rule_ids, matched_messages, matched_data, matched_vars, severity, request_headers, request_body, latency_us, campaign_id`

func scanLog(rows driver.Rows) (l model.AuditLog, err error) {
	err = rows.Scan(&l.ID, &l.Timestamp, &l.TransactionID, &l.NodeID, &l.SiteID, &l.Host, &l.ClientIP, &l.ClientPort, &l.CountryCode, &l.ASN,
		&l.HTTPMethod, &l.URI, &l.HTTPVersion, &l.ResponseStatus, &l.ActionTaken, &l.MatchedRuleIDs, &l.MatchedMessages, &l.MatchedData,
		&l.MatchedVars, &l.Severity, &l.RequestHeaders, &l.RequestBody, &l.LatencyUs, &l.CampaignID)
	return
}

func (c *CH) QueryLogs(ctx context.Context, q LogQuery) (rows []model.AuditLog, total uint64, err error) {
	where, args := []string{"1"}, []any{}
	add := func(cond string, v any) { where = append(where, cond); args = append(args, v) }
	if q.From > 0 {
		add("timestamp >= ?", time.UnixMilli(q.From))
	}
	if q.To > 0 {
		add("timestamp <= ?", time.UnixMilli(q.To))
	}
	if s := strings.TrimSpace(q.IP); s != "" {
		add("startsWith(client_ip, ?)", s)
	}
	if q.Host != "" {
		add("host = ?", q.Host)
	}
	if q.URI != "" {
		add("position(uri, ?) > 0", q.URI)
	}
	if s := strings.TrimSpace(q.RuleID); s != "" {
		add("arrayExists(x -> startsWith(toString(x), ?), matched_rule_ids)", s)
	}
	if q.Action != "" {
		add("action_taken = ?", q.Action)
	}
	if s := strings.TrimSpace(q.Status); s != "" {
		add("toString(response_status) = ?", s)
	}
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	w := strings.Join(where, " AND ")
	if err = c.conn.QueryRow(ctx, "SELECT count() FROM coraza_audit_logs WHERE "+w, args...).Scan(&total); err != nil {
		return
	}
	r, err := c.conn.Query(ctx, fmt.Sprintf("SELECT %s FROM coraza_audit_logs WHERE %s ORDER BY timestamp DESC LIMIT %d OFFSET %d", logCols, w, q.Limit, q.Offset), args...)
	if err != nil {
		return
	}
	defer r.Close()
	rows = []model.AuditLog{}
	for r.Next() {
		l, err := scanLog(r)
		if err != nil {
			return nil, 0, err
		}
		rows = append(rows, l)
	}
	return rows, total, r.Err()
}

func (c *CH) Log(ctx context.Context, id string) (model.AuditLog, error) {
	r, err := c.conn.Query(ctx, "SELECT "+logCols+" FROM coraza_audit_logs WHERE id = ? LIMIT 1", id)
	if err != nil {
		return model.AuditLog{}, err
	}
	defer r.Close()
	if !r.Next() {
		return model.AuditLog{}, ErrNotFound
	}
	return scanLog(r)
}

// ---------- Attack events (Module 6) ----------

func (c *CH) Events(ctx context.Context, where string, args ...any) ([]model.AttackEvent, error) {
	// ponytail: capped at the newest 50k events per request; add server-side aggregation if graphs need more.
	r, err := c.conn.Query(ctx, `SELECT * FROM (SELECT toUnixTimestamp64Milli(timestamp), id, transaction_id, campaign_id, node_id, site_id, host, client_ip,
		country_code, asn, geo_lon, geo_lat, method, uri, rule_id, rule_category, killchain_stage, severity, outcome, response_status
		FROM attack_events WHERE `+where+` ORDER BY timestamp DESC LIMIT 50000) ORDER BY 1`, args...)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := []model.AttackEvent{}
	for r.Next() {
		var e model.AttackEvent
		var lon, lat float32
		if err := r.Scan(&e.Timestamp, &e.ID, &e.TransactionID, &e.CampaignID, &e.NodeID, &e.SiteID, &e.Host, &e.ClientIP, &e.CountryCode, &e.ASN,
			&lon, &lat, &e.Method, &e.URI, &e.RuleID, &e.RuleCategory, &e.KillchainStage, &e.Severity, &e.Outcome, &e.ResponseStatus); err != nil {
			return nil, err
		}
		e.Geo = [2]float64{math.Round(float64(lon)*1e4) / 1e4, math.Round(float64(lat)*1e4) / 1e4} // Float32 columns: drop float noise
		out = append(out, e)
	}
	return out, r.Err()
}

// ---------- Analytics (Module 4) ----------

type SeriesPoint struct {
	T        int64   `json:"t"`
	Total    float64 `json:"total"` // requests per second, all nodes
	Blocked  uint64  `json:"blocked"`
	Detected uint64  `json:"detected"`
}

type Count struct {
	Key string
	N   uint64
}

type Overview struct {
	Series             []SeriesPoint
	TotalRequests      uint64
	Blocked            uint64
	PossiblySuccessful uint64
	TopRules           []Count // key = rule id
	TopEndpoints       []Count
	TopIPs             []struct {
		IP, CC string
		ASN    uint32
		N      uint64
	}
}

func (c *CH) Overview(ctx context.Context, hours int) (o Overview, err error) {
	const bucket = 300
	now := time.Now().Unix() / bucket * bucket
	from := time.Unix(now-int64(hours)*3600, 0)
	idx := map[int64]int{}
	for t := from.Unix() + bucket; t <= now; t += bucket {
		idx[t*1000] = len(o.Series)
		o.Series = append(o.Series, SeriesPoint{T: t * 1000})
	}
	// Fleet RPS per bucket = sum over nodes of that node's mean rps in the bucket.
	r, err := c.conn.Query(ctx, `SELECT b, sum(r), sum(req), sum(blk) FROM (
		SELECT toInt64(toUnixTimestamp(toStartOfFiveMinutes(timestamp))) * 1000 AS b, node_id, avg(rps) AS r, sum(requests) AS req, sum(blocked) AS blk
		FROM node_metrics WHERE timestamp >= ? GROUP BY b, node_id) GROUP BY b`, from)
	if err != nil {
		return
	}
	for r.Next() {
		var b int64
		var rps float64
		var req, blk uint64
		if err = r.Scan(&b, &rps, &req, &blk); err != nil {
			r.Close()
			return
		}
		o.TotalRequests += req
		o.Blocked += blk
		if i, ok := idx[b]; ok {
			o.Series[i].Total = rps
		}
	}
	r.Close()
	r, err = c.conn.Query(ctx, `SELECT toInt64(toUnixTimestamp(toStartOfFiveMinutes(timestamp))) * 1000 AS b, countIf(outcome = 'BLOCKED'), countIf(outcome != 'BLOCKED'),
		countIf(outcome = 'POSSIBLY_SUCCESSFUL') FROM attack_events WHERE timestamp >= ? GROUP BY b`, from)
	if err != nil {
		return
	}
	for r.Next() {
		var b int64
		var blk, det, ps uint64
		if err = r.Scan(&b, &blk, &det, &ps); err != nil {
			r.Close()
			return
		}
		o.PossiblySuccessful += ps
		if i, ok := idx[b]; ok {
			o.Series[i].Blocked, o.Series[i].Detected = blk, det
		}
	}
	r.Close()
	top := func(expr string, limit int) ([]Count, error) {
		r, err := c.conn.Query(ctx, fmt.Sprintf(`SELECT toString(%s) AS k, count() AS n FROM attack_events WHERE timestamp >= ? GROUP BY k ORDER BY n DESC, k LIMIT %d`, expr, limit), from)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		out := []Count{}
		for r.Next() {
			var x Count
			if err := r.Scan(&x.Key, &x.N); err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, r.Err()
	}
	if o.TopRules, err = top("rule_id", 10); err != nil {
		return
	}
	if o.TopEndpoints, err = top("concat(host, path(uri))", 8); err != nil {
		return
	}
	r, err = c.conn.Query(ctx, `SELECT client_ip, any(country_code), any(asn), count() AS n FROM attack_events WHERE timestamp >= ? GROUP BY client_ip ORDER BY n DESC, client_ip LIMIT 8`, from)
	if err != nil {
		return
	}
	defer r.Close()
	for r.Next() {
		var x struct {
			IP, CC string
			ASN    uint32
			N      uint64
		}
		if err = r.Scan(&x.IP, &x.CC, &x.ASN, &x.N); err != nil {
			return
		}
		o.TopIPs = append(o.TopIPs, x)
	}
	return o, r.Err()
}

// RuleMessage returns the most recent message logged for a rule id (for the Top rules chart).
func (c *CH) RuleMessages(ctx context.Context, ids []uint32) (map[uint32]string, error) {
	out := map[uint32]string{}
	if len(ids) == 0 {
		return out, nil
	}
	r, err := c.conn.Query(ctx, `SELECT rid, anyLast(msg) FROM (SELECT rid, msg FROM coraza_audit_logs ARRAY JOIN matched_rule_ids AS rid, matched_messages AS msg
		WHERE timestamp >= now() - INTERVAL 30 DAY AND rid IN ?) GROUP BY rid`, ids)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for r.Next() {
		var id uint32
		var msg string
		if err := r.Scan(&id, &msg); err != nil {
			return nil, err
		}
		out[id] = msg
	}
	return out, r.Err()
}

// NodeHistory returns per-minute metrics for the last hour, keyed by node id.
func (c *CH) NodeHistory(ctx context.Context) (map[string][]model.NodeHistory, error) {
	r, err := c.conn.Query(ctx, `SELECT node_id, toInt64(toUnixTimestamp(toStartOfMinute(timestamp))) * 1000 AS t, avg(rps), avg(latency_ms), avg(cpu)
		FROM node_metrics WHERE timestamp >= now() - INTERVAL 60 MINUTE GROUP BY node_id, t ORDER BY node_id, t`)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := map[string][]model.NodeHistory{}
	for r.Next() {
		var id string
		var h model.NodeHistory
		if err := r.Scan(&id, &h.T, &h.RPS, &h.Latency, &h.CPU); err != nil {
			return nil, err
		}
		out[id] = append(out[id], h)
	}
	return out, r.Err()
}

// Impact supports the block confirmation (FR-6.15): what this source did in the last 30 days.
func (c *CH) Impact(ctx context.Context, cidr string) (legit, attacks, campaigns uint64, err error) {
	err = c.conn.QueryRow(ctx, `SELECT countIf(action_taken = 'ALLOW') FROM coraza_audit_logs
		WHERE timestamp >= now() - INTERVAL 30 DAY AND isIPAddressInRange(client_ip, ?)`, cidr).Scan(&legit)
	if err != nil {
		return
	}
	err = c.conn.QueryRow(ctx, `SELECT count(), uniqExact(campaign_id) FROM attack_events
		WHERE timestamp >= now() - INTERVAL 30 DAY AND isIPAddressInRange(client_ip, ?)`, cidr).Scan(&attacks, &campaigns)
	return
}
