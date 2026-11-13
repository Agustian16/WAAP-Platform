// Package store is the persistence layer: PostgreSQL for configuration and investigation state (PRD 6.1, 6.3),
// ClickHouse for audit logs, attack events and node metrics (PRD 6.2, 6.3).
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
)

//go:embed migrations/*.sql
var migrations embed.FS

//go:embed seed_dev.sql
var seedDev string

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type PG struct{ *pgxpool.Pool }

// OpenPG connects, applies pending migrations and, when asked, the idempotent dev seed.
func OpenPG(ctx context.Context, dsn string, seed bool) (*PG, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	p := &PG{pool}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	files, _ := migrations.ReadDir("migrations")
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	for _, f := range files {
		var done bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name=$1)`, f.Name()).Scan(&done); err != nil {
			return nil, err
		}
		if done {
			continue
		}
		sql, _ := migrations.ReadFile("migrations/" + f.Name())
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return nil, fmt.Errorf("migration %s: %w", f.Name(), err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, f.Name()); err != nil {
			tx.Rollback(ctx)
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	if seed {
		if _, err := pool.Exec(ctx, seedDev); err != nil {
			return nil, fmt.Errorf("dev seed: %w", err)
		}
	}
	return p, nil
}

// norm maps driver errors onto ErrNotFound / ErrConflict so handlers can answer 404 / 409.
func norm(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "22P02": // malformed uuid in a path parameter
			return ErrNotFound
		case "23505":
			return ErrConflict
		}
	}
	return err
}

func collect[T any](rows pgx.Rows, err error, scan func(pgx.Row) (T, error)) ([]T, error) {
	if err != nil {
		return nil, norm(err)
	}
	defer rows.Close()
	out := []T{}
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------- Sites ----------

const siteCols = `id::text, name, domain_name, paranoia_level, inbound_threshold, outbound_threshold, crs_categories, updated_at`

func scanSite(r pgx.Row) (s model.Site, err error) {
	err = r.Scan(&s.ID, &s.Name, &s.DomainName, &s.ParanoiaLevel, &s.InboundThreshold, &s.OutboundThreshold, &s.CRSCategories, &s.UpdatedAt)
	return s, norm(err)
}

func (p *PG) Sites(ctx context.Context) ([]model.Site, error) {
	rows, err := p.Query(ctx, `SELECT `+siteCols+` FROM sites ORDER BY created_at, name`)
	return collect(rows, err, scanSite)
}

func (p *PG) Site(ctx context.Context, id string) (model.Site, error) {
	return scanSite(p.QueryRow(ctx, `SELECT `+siteCols+` FROM sites WHERE id=$1`, id))
}

func (p *PG) CreateSite(ctx context.Context, name, domain string) (model.Site, error) {
	s, err := scanSite(p.QueryRow(ctx, `INSERT INTO sites (name, domain_name) VALUES ($1,$2) RETURNING `+siteCols, name, domain))
	if err == nil {
		_, err = p.Exec(ctx, `INSERT INTO correlation_settings (site_id) VALUES ($1) ON CONFLICT DO NOTHING`, s.ID)
	}
	return s, err
}

func (p *PG) SaveSite(ctx context.Context, s model.Site) (model.Site, error) {
	cats, _ := json.Marshal(s.CRSCategories)
	return scanSite(p.QueryRow(ctx, `UPDATE sites SET paranoia_level=$2, inbound_threshold=$3, outbound_threshold=$4, crs_categories=$5, updated_at=now()
		WHERE id=$1 RETURNING `+siteCols, s.ID, s.ParanoiaLevel, s.InboundThreshold, s.OutboundThreshold, cats))
}

// ---------- Nodes ----------

func scanNode(r pgx.Row) (n model.EdgeNode, err error) {
	err = r.Scan(&n.ID, &n.NodeName, &n.Hostname, &n.IPAddress, &n.Proxy, &n.Version, &n.CRSVersion, &n.Region, &n.Geo[0], &n.Geo[1],
		&n.CurrentConfigVersion, &n.CPU, &n.Memory, &n.RPS, &n.LatencyMs, &n.LastHeartbeat)
	return n, norm(err)
}

func (p *PG) Nodes(ctx context.Context) ([]model.EdgeNode, error) {
	rows, err := p.Query(ctx, `SELECT id::text, node_name, hostname, ip_address, proxy, version, crs_version, region, lon, lat,
		current_config_version, cpu, memory, rps, latency_ms, last_heartbeat FROM nodes ORDER BY node_name`)
	return collect(rows, err, scanNode)
}

func (p *PG) NodeNameTaken(ctx context.Context, name string) (bool, error) {
	var taken bool
	err := p.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE node_name=$1)
		OR EXISTS (SELECT 1 FROM enrollment_tokens WHERE node_name=$1 AND used_at IS NULL AND expires_at > now())`, name).Scan(&taken)
	return taken, err
}

func (p *PG) CreateEnrollmentToken(ctx context.Context, hash []byte, name, by string, ttl time.Duration) error {
	_, err := p.Exec(ctx, `INSERT INTO enrollment_tokens (token_hash, node_name, created_by, expires_at) VALUES ($1,$2,$3,$4)`, hash, name, by, time.Now().Add(ttl))
	return norm(err)
}

// Enroll consumes a one-time token and creates the node row, atomically.
func (p *PG) Enroll(ctx context.Context, hash []byte, hostname string) (id, name string, err error) {
	tx, err := p.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)
	if err = tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=now() WHERE token_hash=$1 AND used_at IS NULL AND expires_at > now() RETURNING node_name`, hash).Scan(&name); err != nil {
		return "", "", norm(err)
	}
	if err = tx.QueryRow(ctx, `INSERT INTO nodes (node_name, hostname) VALUES ($1,$2) RETURNING id::text`, name, hostname).Scan(&id); err != nil {
		return "", "", norm(err)
	}
	return id, name, tx.Commit(ctx)
}

func (p *PG) NodeHello(ctx context.Context, id, hostname, ip, version, crs, proxy, region string, lon, lat float64, cfg int64) (string, error) {
	var name string
	err := p.QueryRow(ctx, `UPDATE nodes SET hostname=$2, ip_address=$3, version=$4, crs_version=$5, proxy=$6, region=$7, lon=$8, lat=$9,
		current_config_version=$10, last_heartbeat=now() WHERE id=$1 RETURNING node_name`, id, hostname, ip, version, crs, proxy, region, lon, lat, cfg).Scan(&name)
	return name, norm(err)
}

func (p *PG) NodeHeartbeat(ctx context.Context, id string, cpu, mem, rps, latency float64, cfg int64) error {
	_, err := p.Exec(ctx, `UPDATE nodes SET cpu=$2, memory=$3, rps=$4, latency_ms=$5, current_config_version=$6, last_heartbeat=now() WHERE id=$1`, id, cpu, mem, rps, latency, cfg)
	return err
}

type NodeVersion struct {
	ID      string
	Version int64
	Online  bool // heartbeat in the last 20 s
}

func (p *PG) NodeVersions(ctx context.Context) ([]NodeVersion, error) {
	rows, err := p.Query(ctx, `SELECT id::text, current_config_version, COALESCE(last_heartbeat > now() - interval '20 seconds', false) FROM nodes`)
	return collect(rows, err, func(r pgx.Row) (n NodeVersion, err error) { err = r.Scan(&n.ID, &n.Version, &n.Online); return })
}

func (p *PG) NodeConfigVersion(ctx context.Context, id string, v int64) error {
	_, err := p.Exec(ctx, `UPDATE nodes SET current_config_version=$2 WHERE id=$1`, id, v)
	return err
}

// ---------- Custom rules ----------

const ruleCols = `id::text, rule_id, site_id::text, name, seclang_raw, is_active, created_by, updated_at`

func scanRule(r pgx.Row) (x model.CustomRule, err error) {
	err = r.Scan(&x.ID, &x.RuleID, &x.SiteID, &x.Name, &x.SecLangRaw, &x.IsActive, &x.CreatedBy, &x.UpdatedAt)
	return x, norm(err)
}

func (p *PG) Rules(ctx context.Context) ([]model.CustomRule, error) {
	rows, err := p.Query(ctx, `SELECT `+ruleCols+` FROM custom_rules ORDER BY updated_at DESC`)
	return collect(rows, err, scanRule)
}

func (p *PG) Rule(ctx context.Context, id string) (model.CustomRule, error) {
	return scanRule(p.QueryRow(ctx, `SELECT `+ruleCols+` FROM custom_rules WHERE id=$1`, id))
}

func (p *PG) InsertRule(ctx context.Context, x model.CustomRule) (model.CustomRule, error) {
	return scanRule(p.QueryRow(ctx, `INSERT INTO custom_rules (rule_id, site_id, name, seclang_raw, is_active, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING `+ruleCols,
		x.RuleID, x.SiteID, x.Name, x.SecLangRaw, x.IsActive, x.CreatedBy))
}

func (p *PG) UpdateRule(ctx context.Context, x model.CustomRule) (model.CustomRule, error) {
	return scanRule(p.QueryRow(ctx, `UPDATE custom_rules SET rule_id=$2, site_id=$3, name=$4, seclang_raw=$5, is_active=$6, updated_at=now() WHERE id=$1 RETURNING `+ruleCols,
		x.ID, x.RuleID, x.SiteID, x.Name, x.SecLangRaw, x.IsActive))
}

func (p *PG) SetRuleActive(ctx context.Context, id string, active bool) (model.CustomRule, error) {
	return scanRule(p.QueryRow(ctx, `UPDATE custom_rules SET is_active=$2, updated_at=now() WHERE id=$1 RETURNING `+ruleCols, id, active))
}

func (p *PG) DeleteRule(ctx context.Context, id string) (model.CustomRule, error) {
	return scanRule(p.QueryRow(ctx, `DELETE FROM custom_rules WHERE id=$1 RETURNING `+ruleCols, id))
}

// ---------- Exceptions ----------

const excCols = `id::text, site_id::text, rule_id, path_pattern, parameter_name, reason, created_by, created_at, exception_rule_id`

func scanExc(r pgx.Row) (x model.RuleException, err error) {
	err = r.Scan(&x.ID, &x.SiteID, &x.RuleID, &x.PathPattern, &x.ParameterName, &x.Reason, &x.CreatedBy, &x.CreatedAt, &x.ExceptionRuleID)
	return x, norm(err)
}

func (p *PG) Exceptions(ctx context.Context) ([]model.RuleException, error) {
	rows, err := p.Query(ctx, `SELECT `+excCols+` FROM rule_exceptions ORDER BY created_at DESC`)
	return collect(rows, err, scanExc)
}

// InsertException allocates the lowest free generated-rule id in [first,last].
func (p *PG) InsertException(ctx context.Context, x model.RuleException, first, last int) (model.RuleException, error) {
	return scanExc(p.QueryRow(ctx, `INSERT INTO rule_exceptions (site_id, rule_id, path_pattern, parameter_name, reason, created_by, exception_rule_id)
		SELECT $1,$2,$3,$4,$5,$6, g FROM generate_series($7::int, $8::int) g
		WHERE NOT EXISTS (SELECT 1 FROM rule_exceptions e WHERE e.exception_rule_id = g) ORDER BY g LIMIT 1 RETURNING `+excCols,
		x.SiteID, x.RuleID, x.PathPattern, x.ParameterName, x.Reason, x.CreatedBy, first, last))
}

func (p *PG) DeleteException(ctx context.Context, id string) (model.RuleException, error) {
	return scanExc(p.QueryRow(ctx, `DELETE FROM rule_exceptions WHERE id=$1 RETURNING `+excCols, id))
}

// ---------- IP lists and threat feeds ----------

const ipCols = `id::text, cidr::text, list, source, reason, expires_at, created_by, created_at`

func scanIP(r pgx.Row) (x model.IPListEntry, err error) {
	err = r.Scan(&x.ID, &x.CIDR, &x.List, &x.Source, &x.Reason, &x.ExpiresAt, &x.CreatedBy, &x.CreatedAt)
	return x, norm(err)
}

func (p *PG) IPList(ctx context.Context) ([]model.IPListEntry, error) {
	rows, err := p.Query(ctx, `SELECT `+ipCols+` FROM ip_list WHERE expires_at IS NULL OR expires_at > now() ORDER BY created_at DESC LIMIT 5000`)
	return collect(rows, err, scanIP)
}

// ActiveCIDRs returns every unexpired entry of one list, for the deployed bundle.
func (p *PG) ActiveCIDRs(ctx context.Context, list string) ([]string, error) {
	rows, err := p.Query(ctx, `SELECT cidr::text FROM ip_list WHERE list=$1 AND (expires_at IS NULL OR expires_at > now()) ORDER BY cidr`, list)
	return collect(rows, err, func(r pgx.Row) (s string, err error) { err = r.Scan(&s); return })
}

func (p *PG) InsertIP(ctx context.Context, x model.IPListEntry) (model.IPListEntry, error) {
	return scanIP(p.QueryRow(ctx, `INSERT INTO ip_list (cidr, list, source, reason, expires_at, created_by) VALUES ($1::cidr,$2,$3,$4,$5,$6) RETURNING `+ipCols,
		x.CIDR, x.List, x.Source, x.Reason, x.ExpiresAt, x.CreatedBy))
}

func (p *PG) DeleteIP(ctx context.Context, id string) (model.IPListEntry, error) {
	return scanIP(p.QueryRow(ctx, `DELETE FROM ip_list WHERE id=$1 RETURNING `+ipCols, id))
}

func (p *PG) DeleteExpiredIPs(ctx context.Context) (int64, error) {
	t, err := p.Exec(ctx, `DELETE FROM ip_list WHERE expires_at <= now()`)
	return t.RowsAffected(), err
}

// ReplaceFeedEntries swaps the blocklist entries owned by one feed. Returns how many were stored.
func (p *PG) ReplaceFeedEntries(ctx context.Context, feed string, cidrs []string) (int, error) {
	tx, err := p.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM ip_list WHERE source=$1 AND list='block'`, feed); err != nil {
		return 0, err
	}
	t, err := tx.Exec(ctx, `INSERT INTO ip_list (cidr, list, source, reason, created_by)
		SELECT DISTINCT c::cidr, 'block', $1, 'Feed import', 'system' FROM unnest($2::text[]) c ON CONFLICT (cidr, list) DO NOTHING`, feed, cidrs)
	if err != nil {
		return 0, err
	}
	return int(t.RowsAffected()), tx.Commit(ctx)
}

const feedCols = `id::text, name, url, format, interval_minutes, last_pulled, entries, status, error`

func scanFeed(r pgx.Row) (x model.ThreatFeed, err error) {
	err = r.Scan(&x.ID, &x.Name, &x.URL, &x.Format, &x.IntervalMinutes, &x.LastPulled, &x.Entries, &x.Status, &x.Error)
	return x, norm(err)
}

func (p *PG) Feeds(ctx context.Context) ([]model.ThreatFeed, error) {
	rows, err := p.Query(ctx, `SELECT `+feedCols+` FROM threat_feeds ORDER BY name`)
	return collect(rows, err, scanFeed)
}

func (p *PG) Feed(ctx context.Context, id string) (model.ThreatFeed, error) {
	return scanFeed(p.QueryRow(ctx, `SELECT `+feedCols+` FROM threat_feeds WHERE id=$1`, id))
}

func (p *PG) InsertFeed(ctx context.Context, x model.ThreatFeed) (model.ThreatFeed, error) {
	return scanFeed(p.QueryRow(ctx, `INSERT INTO threat_feeds (name, url, format, interval_minutes) VALUES ($1,$2,$3,$4) RETURNING `+feedCols, x.Name, x.URL, x.Format, x.IntervalMinutes))
}

func (p *PG) FeedPulled(ctx context.Context, id string, entries int, pullErr string) (model.ThreatFeed, error) {
	if pullErr != "" {
		return scanFeed(p.QueryRow(ctx, `UPDATE threat_feeds SET last_pulled=now(), status='ERROR', error=$2 WHERE id=$1 RETURNING `+feedCols, id, pullErr))
	}
	return scanFeed(p.QueryRow(ctx, `UPDATE threat_feeds SET last_pulled=now(), status='OK', error=NULL, entries=$2 WHERE id=$1 RETURNING `+feedCols, id, entries))
}

func (p *PG) DeleteFeed(ctx context.Context, id string) (model.ThreatFeed, error) {
	f, err := scanFeed(p.QueryRow(ctx, `DELETE FROM threat_feeds WHERE id=$1 RETURNING `+feedCols, id))
	if err == nil {
		_, err = p.Exec(ctx, `DELETE FROM ip_list WHERE source=$1`, f.Name)
	}
	return f, err
}

// ---------- Users and sessions ----------

const userCols = `id::text, name, email, role, mfa, last_login`

func scanUser(r pgx.Row) (u model.User, err error) {
	err = r.Scan(&u.ID, &u.Name, &u.Email, &u.Role, &u.MFA, &u.LastLogin)
	return u, norm(err)
}

func (p *PG) Users(ctx context.Context) ([]model.User, error) {
	rows, err := p.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	return collect(rows, err, scanUser)
}

// UserLogin creates the user on first sign-in (with firstRole) and stamps last_login. The stored role wins afterwards.
func (p *PG) UserLogin(ctx context.Context, subject, name, email string, firstRole model.Role, mfa bool) (model.User, error) {
	return scanUser(p.QueryRow(ctx, `INSERT INTO users (subject, name, email, role, mfa, last_login) VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (subject) DO UPDATE SET name=EXCLUDED.name, email=EXCLUDED.email, mfa=EXCLUDED.mfa, last_login=now() RETURNING `+userCols,
		subject, name, email, string(firstRole), mfa))
}

// SetRole changes a role but refuses to demote the last Admin (checked in the same statement).
func (p *PG) SetRole(ctx context.Context, id string, role model.Role) (before, after model.User, err error) {
	before, err = scanUser(p.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err != nil {
		return
	}
	after, err = scanUser(p.QueryRow(ctx, `UPDATE users SET role=$2 WHERE id=$1
		AND ($2 = 'Admin' OR role <> 'Admin' OR (SELECT count(*) FROM users WHERE role='Admin') > 1) RETURNING `+userCols, id, string(role)))
	if errors.Is(err, ErrNotFound) {
		err = ErrConflict
	}
	return
}

func (p *PG) CreateSession(ctx context.Context, hash []byte, userID string, ttl time.Duration) error {
	_, err := p.Exec(ctx, `INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1,$2,$3)`, hash, userID, time.Now().Add(ttl))
	return err
}

func (p *PG) SessionUser(ctx context.Context, hash []byte) (model.User, error) {
	return scanUser(p.QueryRow(ctx, `SELECT u.id::text, u.name, u.email, u.role, u.mfa, u.last_login FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash=$1 AND s.expires_at > now()`, hash))
}

func (p *PG) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := p.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1 OR expires_at <= now()`, hash)
	return err
}

// ---------- Audit trail (FR-5.2) ----------

func (p *PG) Audit(ctx context.Context, e model.AuditTrailEntry) error {
	_, err := p.Exec(ctx, `INSERT INTO audit_trail (actor, role, action, target, source_ip, target_nodes) VALUES ($1,$2,$3,$4,$5,$6)`,
		e.Actor, string(e.Role), e.Action, e.Target, e.SourceIP, e.TargetNodes)
	return err
}

func (p *PG) AuditTrail(ctx context.Context) ([]model.AuditTrailEntry, error) {
	rows, err := p.Query(ctx, `SELECT id::text, at, actor, role, action, target, source_ip, target_nodes FROM audit_trail ORDER BY at DESC LIMIT 2000`)
	return collect(rows, err, func(r pgx.Row) (e model.AuditTrailEntry, err error) {
		err = r.Scan(&e.ID, &e.At, &e.Actor, &e.Role, &e.Action, &e.Target, &e.SourceIP, &e.TargetNodes)
		return
	})
}

// ---------- Campaigns ----------

const campCols = `id, actor_key, actor_mode, COALESCE(site_id::text,''), country_code, asn, as_name, lon, lat, correlation_confidence,
	first_seen, last_seen, highest_stage, stages, categories, targets, shell_paths, risk_score, event_count, possibly_successful, opened, status, assignee, notes`

func scanCampaign(r pgx.Row) (c model.Campaign, err error) {
	var first, last time.Time
	err = r.Scan(&c.ID, &c.ActorKey, &c.ActorMode, &c.SiteID, &c.CountryCode, &c.ASN, &c.ASName, &c.Geo[0], &c.Geo[1], &c.CorrelationConfidence,
		&first, &last, &c.HighestStage, &c.Stages, &c.Categories, &c.Targets, &c.ShellPaths, &c.RiskScore, &c.EventCount, &c.PossiblySuccessful,
		&c.Opened, &c.Status, &c.Assignee, &c.Notes)
	c.FirstSeen, c.LastSeen = first.UnixMilli(), last.UnixMilli()
	if c.Notes == nil {
		c.Notes = []model.Note{}
	}
	return c, norm(err)
}

// Campaigns lists opened campaigns, newest activity first.
func (p *PG) Campaigns(ctx context.Context) ([]model.Campaign, error) {
	rows, err := p.Query(ctx, `SELECT `+campCols+` FROM attack_campaigns WHERE opened ORDER BY last_seen DESC LIMIT 2000`)
	return collect(rows, err, scanCampaign)
}

// LiveCampaigns loads the campaigns the correlation engine may still extend after a restart.
func (p *PG) LiveCampaigns(ctx context.Context) ([]model.Campaign, error) {
	rows, err := p.Query(ctx, `SELECT `+campCols+` FROM attack_campaigns WHERE status IN ('ACTIVE','CONTAINED') AND last_seen > now() - interval '24 hours'`)
	return collect(rows, err, scanCampaign)
}

func (p *PG) Campaign(ctx context.Context, id string) (model.Campaign, error) {
	return scanCampaign(p.QueryRow(ctx, `SELECT `+campCols+` FROM attack_campaigns WHERE id=$1 AND opened`, id))
}

func (p *PG) NextCampaignID(ctx context.Context, at time.Time) (string, error) {
	var n int64
	err := p.QueryRow(ctx, `SELECT nextval('campaign_seq')`).Scan(&n)
	return fmt.Sprintf("cmp_%s_%04d", at.UTC().Format("20060102"), n), err
}

// SaveCampaign writes the correlation engine's view. Analyst-owned fields (status, assignee, notes) are not touched on update.
func (p *PG) SaveCampaign(ctx context.Context, c model.Campaign) error {
	var site *string
	if c.SiteID != "" {
		site = &c.SiteID
	}
	_, err := p.Exec(ctx, `INSERT INTO attack_campaigns (id, actor_key, actor_mode, site_id, country_code, asn, as_name, lon, lat, correlation_confidence,
			first_seen, last_seen, highest_stage, stages, categories, targets, shell_paths, risk_score, event_count, possibly_successful, opened, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT (id) DO UPDATE SET last_seen=EXCLUDED.last_seen, highest_stage=EXCLUDED.highest_stage, stages=EXCLUDED.stages,
			categories=EXCLUDED.categories, targets=EXCLUDED.targets, shell_paths=EXCLUDED.shell_paths, risk_score=EXCLUDED.risk_score,
			event_count=EXCLUDED.event_count, possibly_successful=EXCLUDED.possibly_successful, opened=EXCLUDED.opened, updated_at=now()
		WHERE attack_campaigns.event_count <= EXCLUDED.event_count`, // event_count only grows: an older snapshot never wins
		c.ID, c.ActorKey, c.ActorMode, site, c.CountryCode, c.ASN, c.ASName, c.Geo[0], c.Geo[1], c.CorrelationConfidence,
		time.UnixMilli(c.FirstSeen), time.UnixMilli(c.LastSeen), c.HighestStage, c.Stages, c.Categories, c.Targets, c.ShellPaths,
		c.RiskScore, c.EventCount, c.PossiblySuccessful, c.Opened, c.Status)
	return err
}

// PatchCampaign applies analyst changes. nil pointers leave a field alone; assignee "" clears it.
func (p *PG) PatchCampaign(ctx context.Context, id string, status, assignee *string, note *model.Note) (model.Campaign, error) {
	var noteJSON []byte
	if note != nil {
		noteJSON, _ = json.Marshal([]model.Note{*note})
	}
	return scanCampaign(p.QueryRow(ctx, `UPDATE attack_campaigns SET
			status = COALESCE($2, status),
			assignee = CASE WHEN $3::text IS NULL THEN assignee WHEN $3 = '' THEN NULL ELSE $3 END,
			notes = CASE WHEN $4::jsonb IS NULL THEN notes ELSE notes || $4::jsonb END,
			updated_at = now()
		WHERE id=$1 AND opened RETURNING `+campCols, id, status, assignee, noteJSON))
}

// ---------- Kill chain mapping and correlation settings ----------

func (p *PG) Mapping(ctx context.Context) ([]model.KillchainMapping, error) {
	rows, err := p.Query(ctx, `SELECT id::text, rule_id_from, rule_id_to, tag, rule_category, killchain_stage, mitre_technique FROM killchain_rule_mapping ORDER BY rule_id_from, rule_id_to`)
	return collect(rows, err, func(r pgx.Row) (m model.KillchainMapping, err error) {
		err = r.Scan(&m.ID, &m.RuleIDFrom, &m.RuleIDTo, &m.Tag, &m.RuleCategory, &m.KillchainStage, &m.MitreTechnique)
		return
	})
}

// SaveMapping updates a row by id, or inserts it when the id is unknown (new override rows get a fresh uuid).
func (p *PG) SaveMapping(ctx context.Context, m model.KillchainMapping) (model.KillchainMapping, error) {
	scan := func(r pgx.Row) (model.KillchainMapping, error) {
		err := r.Scan(&m.ID, &m.RuleIDFrom, &m.RuleIDTo, &m.Tag, &m.RuleCategory, &m.KillchainStage, &m.MitreTechnique)
		return m, norm(err)
	}
	const ret = ` RETURNING id::text, rule_id_from, rule_id_to, tag, rule_category, killchain_stage, mitre_technique`
	out, err := scan(p.QueryRow(ctx, `UPDATE killchain_rule_mapping SET rule_id_from=$2, rule_id_to=$3, tag=$4, rule_category=$5, killchain_stage=$6, mitre_technique=$7 WHERE id=$1`+ret,
		m.ID, m.RuleIDFrom, m.RuleIDTo, m.Tag, m.RuleCategory, m.KillchainStage, m.MitreTechnique))
	if errors.Is(err, ErrNotFound) {
		return scan(p.QueryRow(ctx, `INSERT INTO killchain_rule_mapping (rule_id_from, rule_id_to, tag, rule_category, killchain_stage, mitre_technique) VALUES ($1,$2,$3,$4,$5,$6)`+ret,
			m.RuleIDFrom, m.RuleIDTo, m.Tag, m.RuleCategory, m.KillchainStage, m.MitreTechnique))
	}
	return out, err
}

func (p *PG) Correlation(ctx context.Context) ([]model.CorrelationSettings, error) {
	rows, err := p.Query(ctx, `SELECT c.site_id::text, c.actor_key_mode, c.idle_timeout_minutes, c.min_events_to_open FROM correlation_settings c JOIN sites s ON s.id = c.site_id ORDER BY s.created_at, s.name`)
	return collect(rows, err, func(r pgx.Row) (c model.CorrelationSettings, err error) {
		err = r.Scan(&c.SiteID, &c.ActorKeyMode, &c.IdleTimeoutMinutes, &c.MinEventsToOpen)
		return
	})
}

func (p *PG) SaveCorrelation(ctx context.Context, c model.CorrelationSettings) error {
	t, err := p.Exec(ctx, `UPDATE correlation_settings SET actor_key_mode=$2, idle_timeout_minutes=$3, min_events_to_open=$4 WHERE site_id=$1`,
		c.SiteID, c.ActorKeyMode, c.IdleTimeoutMinutes, c.MinEventsToOpen)
	if err == nil && t.RowsAffected() == 0 {
		return ErrNotFound
	}
	return norm(err)
}

// ---------- Deployed configuration ----------

// LatestBundle returns the newest deployed bundle, or ErrNotFound before the first deploy.
func (p *PG) LatestBundle(ctx context.Context) (model.Bundle, error) {
	var b model.Bundle
	var raw []byte
	if err := p.QueryRow(ctx, `SELECT version, bundle FROM config_versions ORDER BY version DESC LIMIT 1`).Scan(&b.Version, &raw); err != nil {
		return b, norm(err)
	}
	v := b.Version
	err := json.Unmarshal(raw, &b)
	b.Version = v
	return b, err
}

func (p *PG) ConfigVersion(ctx context.Context) (version int64, dirty bool, err error) {
	err = p.QueryRow(ctx, `SELECT COALESCE((SELECT max(version) FROM config_versions), 0), (SELECT dirty FROM config_state)`).Scan(&version, &dirty)
	return
}

// InsertBundle stores a new version. clearDirty is true for a policy deploy and false for an IP-list-only push,
// which leaves undeployed policy edits pending.
func (p *PG) InsertBundle(ctx context.Context, b model.Bundle, by string, clearDirty bool) (int64, error) {
	raw, _ := json.Marshal(b)
	var v int64
	err := p.QueryRow(ctx, `WITH ins AS (INSERT INTO config_versions (bundle, created_by) VALUES ($1,$2) RETURNING version),
		upd AS (UPDATE config_state SET dirty = dirty AND NOT $3) SELECT version FROM ins`, raw, by, clearDirty).Scan(&v)
	return v, err
}

func (p *PG) MarkDirty(ctx context.Context) error {
	_, err := p.Exec(ctx, `UPDATE config_state SET dirty = TRUE`)
	return err
}

// ---------- Geo overrides and PKI ----------

type GeoOverride struct {
	CIDR, CountryCode, ASName string
	ASN                       uint32
	Lon, Lat                  float64
}

func (p *PG) GeoOverrides(ctx context.Context) ([]GeoOverride, error) {
	rows, err := p.Query(ctx, `SELECT cidr::text, country_code, asn, as_name, lon, lat FROM geoip_overrides`)
	return collect(rows, err, func(r pgx.Row) (g GeoOverride, err error) {
		err = r.Scan(&g.CIDR, &g.CountryCode, &g.ASN, &g.ASName, &g.Lon, &g.Lat)
		return
	})
}

// PKI returns the stored CA, creating it with gen on first use.
func (p *PG) PKI(ctx context.Context, gen func() (certPEM, keyPEM string, err error)) (certPEM, keyPEM string, err error) {
	err = p.QueryRow(ctx, `SELECT ca_cert_pem, ca_key_pem FROM pki`).Scan(&certPEM, &keyPEM)
	if err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if certPEM, keyPEM, err = gen(); err != nil {
		return
	}
	if _, err = p.Exec(ctx, `INSERT INTO pki (ca_cert_pem, ca_key_pem) VALUES ($1,$2) ON CONFLICT DO NOTHING`, certPEM, keyPEM); err != nil {
		return
	}
	err = p.QueryRow(ctx, `SELECT ca_cert_pem, ca_key_pem FROM pki`).Scan(&certPEM, &keyPEM)
	return
}
