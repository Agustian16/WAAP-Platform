package api

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
	"github.com/Agustian16/WAAP-Platform/server/internal/waf"
)

// ---------- IP reputation (FR-4.2) ----------

// parseCIDR accepts an address or a network and returns the canonical network ("192.0.2.7" -> "192.0.2.7/32").
func parseCIDR(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String(), true
	}
	return "", false
}

func (a *App) ipLists(c *gin.Context) {
	out, err := a.PG.IPList(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

// pushLists ships a list change to the fleet and describes the reach for the audit trail.
func (a *App) pushLists(c *gin.Context) string {
	n, err := a.PushIPLists(c, userOf(c).Name)
	if err != nil {
		slog.Error("push ip lists", "err", err)
		return "push failed, applies on next deploy"
	}
	return fmt.Sprintf("%d node(s)", n)
}

func (a *App) addIP(c *gin.Context) {
	var in struct {
		CIDR     string   `json:"cidr"`
		List     string   `json:"list"`
		Reason   string   `json:"reason"`
		TTLHours *float64 `json:"ttlHours"`
	}
	if !bind(c, &in) {
		return
	}
	cidr, ok := parseCIDR(in.CIDR)
	if !ok {
		bad(c, "%q is not a valid IP address or CIDR", in.CIDR)
		return
	}
	if in.List != "block" && in.List != "allow" {
		bad(c, "List must be block or allow")
		return
	}
	if p := netip.MustParsePrefix(cidr); in.List == "block" && p.Bits() < 8 {
		bad(c, "Refusing to block a network wider than /8")
		return
	}
	e := model.IPListEntry{CIDR: cidr, List: in.List, Source: "manual", Reason: strings.TrimSpace(in.Reason), CreatedBy: userOf(c).Name}
	if e.Reason == "" {
		e.Reason = "-"
	}
	ttl := ""
	if in.TTLHours != nil && *in.TTLHours > 0 {
		t := time.Now().Add(time.Duration(*in.TTLHours * float64(time.Hour)))
		e.ExpiresAt = &t
		ttl = fmt.Sprintf(" (TTL %gh)", *in.TTLHours)
	}
	e, err := a.PG.InsertIP(c, e)
	if errors.Is(err, store.ErrConflict) {
		c.String(http.StatusConflict, "%s is already on the %slist", cidr, in.List)
		return
	}
	if err != nil {
		fail(c, err, "")
		return
	}
	a.audit(c, map[string]string{"block": "IP blocked", "allow": "IP allowed"}[in.List], cidr+ttl, a.pushLists(c))
	c.JSON(200, e)
}

func (a *App) removeIP(c *gin.Context) {
	x, err := a.PG.DeleteIP(c, c.Param("id"))
	if err != nil {
		fail(c, err, "List entry not found")
		return
	}
	a.audit(c, map[string]string{"block": "IP unblocked", "allow": "Allowlist entry removed"}[x.List], x.CIDR, a.pushLists(c))
	c.JSON(200, gin.H{"ok": true})
}

func (a *App) ipImpact(c *gin.Context) {
	cidr, ok := parseCIDR(c.Query("cidr"))
	if !ok {
		c.JSON(200, gin.H{"legitRequests": 0, "attackEvents": 0, "campaigns": 0})
		return
	}
	legit, attacks, campaigns, err := a.CH.Impact(c, cidr)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, gin.H{"legitRequests": legit, "attackEvents": attacks, "campaigns": campaigns})
}

// ---------- Threat feeds ----------

func (a *App) feeds(c *gin.Context) {
	out, err := a.PG.Feeds(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) addFeed(c *gin.Context) {
	var in model.ThreatFeed
	if !bind(c, &in) {
		return
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" {
		bad(c, "Enter a full URL, including https://")
		return
	}
	if u.Scheme != "https" {
		bad(c, "Feeds must be served over HTTPS")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || in.Name == "manual" {
		bad(c, "Name is required")
		return
	}
	if in.Format != "text" && in.Format != "csv" {
		bad(c, "Format must be text or csv")
		return
	}
	if in.IntervalMinutes < 5 || in.IntervalMinutes > 10080 {
		bad(c, "Pull interval must be between 5 minutes and 7 days")
		return
	}
	f, err := a.PG.InsertFeed(c, in)
	if errors.Is(err, store.ErrConflict) {
		c.String(http.StatusConflict, "A feed named %q already exists", in.Name)
		return
	}
	if err != nil {
		fail(c, err, "")
		return
	}
	a.audit(c, "Threat feed added", fmt.Sprintf("%s (%s)", f.Name, u.Host), "-")
	c.JSON(200, f)
}

func (a *App) pullFeed(c *gin.Context) {
	f, err := a.PG.Feed(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Feed not found")
		return
	}
	f, changed, err := a.pull(c, f)
	if err != nil {
		fail(c, err, "Feed not found")
		return
	}
	nodes := "-"
	if changed {
		nodes = a.pushLists(c)
	}
	a.audit(c, "Threat feed pulled", f.Name, nodes)
	c.JSON(200, f)
}

func (a *App) removeFeed(c *gin.Context) {
	f, err := a.PG.DeleteFeed(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Feed not found")
		return
	}
	a.audit(c, "Threat feed removed", f.Name, a.pushLists(c))
	c.JSON(200, gin.H{"ok": true})
}

const (
	feedMaxBytes   = 16 << 20
	feedMaxEntries = 200_000
)

// feedClient refuses to connect to non-public addresses. The check runs on the resolved address at dial time,
// so a hostname cannot pass validation and then rebind to an internal service.
func (a *App) feedClient() *http.Client {
	if a.FeedHTTP != nil {
		return a.FeedHTTP
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	if !a.AllowPrivateFeeds {
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if ip := ap.Addr().Unmap(); ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("feed host resolves to a non-public address (%s)", ip)
			}
			return nil
		}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, Proxy: nil}}
}

// pull fetches one feed and replaces its blocklist entries. A failed pull keeps the previous entries.
func (a *App) pull(ctx context.Context, f model.ThreatFeed) (out model.ThreatFeed, changed bool, err error) {
	cidrs, perr := a.fetchFeed(ctx, f)
	if perr != nil {
		out, err = a.PG.FeedPulled(ctx, f.ID, 0, perr.Error())
		return out, false, err
	}
	n, err := a.PG.ReplaceFeedEntries(ctx, f.Name, cidrs)
	if err != nil {
		return f, false, err
	}
	out, err = a.PG.FeedPulled(ctx, f.ID, n, "")
	return out, true, err
}

func (a *App) fetchFeed(ctx context.Context, f model.ThreatFeed) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, errors.New("invalid feed URL")
	}
	req.Header.Set("User-Agent", "corazium-feed-puller")
	res, err := a.feedClient().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("fetch failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from feed URL", res.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(res.Body, feedMaxBytes))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		field := line
		if f.Format == "csv" {
			field = strings.Trim(strings.SplitN(line, ",", 2)[0], `" `)
		} else if i := strings.IndexAny(line, " \t#;"); i > 0 {
			field = line[:i]
		}
		if cidr, ok := parseCIDR(field); ok { // header rows and junk are skipped, not fatal
			if p := netip.MustParsePrefix(cidr); p.Bits() >= 8 {
				out = append(out, cidr)
			}
		}
		if len(out) > feedMaxEntries {
			return nil, fmt.Errorf("feed has more than %d entries", feedMaxEntries)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read failed: %v", err)
	}
	if len(out) == 0 {
		return nil, errors.New("no IP addresses or CIDRs found in the feed")
	}
	return out, nil
}

// RunJobs pulls due feeds and drops expired list entries (block TTLs) until ctx ends.
func (a *App) RunJobs(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		changed := false
		if n, err := a.PG.DeleteExpiredIPs(ctx); err == nil && n > 0 {
			changed = true
		}
		if feeds, err := a.PG.Feeds(ctx); err == nil {
			for _, f := range feeds {
				if f.LastPulled == nil || time.Since(*f.LastPulled) >= time.Duration(f.IntervalMinutes)*time.Minute {
					if _, ch, err := a.pull(ctx, f); err != nil {
						slog.Error("feed pull", "feed", f.Name, "err", err)
					} else if ch {
						changed = true
					}
				}
			}
		}
		if changed {
			if _, err := a.PushIPLists(ctx, "system"); err != nil && !errors.Is(err, store.ErrNotFound) {
				slog.Error("push ip lists", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------- Audit trail, users (Module 5) ----------

func (a *App) auditTrail(c *gin.Context) {
	out, err := a.PG.AuditTrail(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) users(c *gin.Context) {
	out, err := a.PG.Users(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) setRole(c *gin.Context) {
	var in struct{ Role model.Role }
	if !bind(c, &in) {
		return
	}
	if in.Role != model.Admin && in.Role != model.Analyst && in.Role != model.Auditor {
		bad(c, "Unknown role")
		return
	}
	before, after, err := a.PG.SetRole(c, c.Param("id"), in.Role)
	if errors.Is(err, store.ErrConflict) {
		c.String(http.StatusConflict, "At least one Admin must remain")
		return
	}
	if err != nil {
		fail(c, err, "User not found")
		return
	}
	if before.Role != after.Role {
		a.audit(c, "Role changed", fmt.Sprintf("%s: %s -> %s", after.Email, before.Role, after.Role), "-")
	}
	c.JSON(200, after)
}

// ---------- Kill chain mapping, correlation settings ----------

func (a *App) reloadCorrelation(ctx context.Context) {
	m, err1 := a.PG.Mapping(ctx)
	s, err2 := a.PG.Correlation(ctx)
	if err1 != nil || err2 != nil {
		slog.Error("reload correlation config", "mapping", err1, "settings", err2)
		return
	}
	a.Engine.Configure(m, s)
}

// LoadCorrelation primes the engine at startup.
func (a *App) LoadCorrelation(ctx context.Context) { a.reloadCorrelation(ctx) }

func (a *App) mapping(c *gin.Context) {
	out, err := a.PG.Mapping(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) saveMapping(c *gin.Context) {
	var m model.KillchainMapping
	if !bind(c, &m) {
		return
	}
	m.ID = c.Param("id")
	if m.RuleIDFrom < 1 || m.RuleIDFrom > m.RuleIDTo {
		bad(c, "Range start must be <= end")
		return
	}
	if correlate.StageIndex(m.KillchainStage) < 0 || m.KillchainStage == "WEAPON" {
		bad(c, "Weaponization cannot be observed by a WAF; pick an observable stage")
		return
	}
	ok := false
	for _, k := range correlate.Categories {
		ok = ok || k == m.RuleCategory
	}
	if !ok {
		bad(c, "Unknown rule category")
		return
	}
	out, err := a.PG.SaveMapping(c, m)
	if errors.Is(err, store.ErrConflict) {
		c.String(http.StatusConflict, "That rule range is already mapped")
		return
	}
	if err != nil {
		fail(c, err, "")
		return
	}
	a.audit(c, "Kill chain mapping changed", fmt.Sprintf("%d-%d -> %s", out.RuleIDFrom, out.RuleIDTo, out.KillchainStage), "-")
	a.reloadCorrelation(c)
	c.JSON(200, out)
}

func (a *App) correlation(c *gin.Context) {
	out, err := a.PG.Correlation(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) saveCorrelation(c *gin.Context) {
	var in model.CorrelationSettings
	if !bind(c, &in) {
		return
	}
	in.SiteID = c.Param("id")
	if in.IdleTimeoutMinutes < 1 || in.IdleTimeoutMinutes > 1440 {
		bad(c, "Idle timeout must be 1-1440 minutes")
		return
	}
	if in.MinEventsToOpen < 1 || in.MinEventsToOpen > 1000 {
		bad(c, "Minimum events must be 1-1000")
		return
	}
	switch in.ActorKeyMode {
	case "IP", "CIDR24", "ASN", "FINGERPRINT":
	default:
		bad(c, "Unknown actor key mode")
		return
	}
	site, err := a.PG.Site(c, in.SiteID)
	if err == nil {
		err = a.PG.SaveCorrelation(c, in)
	}
	if err != nil {
		fail(c, err, "Site not found")
		return
	}
	a.audit(c, "Correlation settings changed", fmt.Sprintf("%s: %s, %dm, min %d", site.DomainName, in.ActorKeyMode, in.IdleTimeoutMinutes, in.MinEventsToOpen), "-")
	a.reloadCorrelation(c)
	c.JSON(200, in)
}

// ---------- GitOps (FR-5.3) ----------

// PolicyDoc is coraza-policy.yaml.
type PolicyDoc struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		ConfigVersion int64  `yaml:"configVersion"`
		ExportedAt    string `yaml:"exportedAt"`
	} `yaml:"metadata"`
	Sites       []PolicySite `yaml:"sites"`
	CustomRules []PolicyRule `yaml:"customRules"`
	IPLists     struct {
		Block []string `yaml:"block"`
		Allow []string `yaml:"allow"`
	} `yaml:"ipLists"`
}

type PolicySite struct {
	Domain           string `yaml:"domain"`
	Name             string `yaml:"name"`
	ParanoiaLevel    int    `yaml:"paranoiaLevel"`
	AnomalyThreshold struct {
		Inbound  int `yaml:"inbound"`
		Outbound int `yaml:"outbound"`
	} `yaml:"anomalyThreshold"`
	CRS struct {
		DisabledCategories []string `yaml:"disabledCategories"`
	} `yaml:"crs"`
	Exceptions []PolicyException `yaml:"exceptions"`
}

type PolicyException struct {
	RuleID    int    `yaml:"ruleId"`
	Path      string `yaml:"path"`
	Parameter string `yaml:"parameter,omitempty"`
	Reason    string `yaml:"reason"`
}

type PolicyRule struct {
	ID      int    `yaml:"id"`
	Name    string `yaml:"name"`
	Site    string `yaml:"site"`
	Active  bool   `yaml:"active"`
	SecLang string `yaml:"seclang"`
}

// Running is the policy currently stored, used both for export and as the baseline of a validation diff.
type Running struct {
	Sites      []model.Site
	Rules      []model.CustomRule
	Exceptions []model.RuleException
	Block      []string
	Allow      []string
	Version    int64
}

func (a *App) running(ctx context.Context) (r Running, err error) {
	if r.Sites, err = a.PG.Sites(ctx); err != nil {
		return
	}
	if r.Rules, err = a.PG.Rules(ctx); err != nil {
		return
	}
	if r.Exceptions, err = a.PG.Exceptions(ctx); err != nil {
		return
	}
	// Only operator-managed entries are exported; feed entries are re-derived from the feeds.
	list, err := a.PG.IPList(ctx)
	if err != nil {
		return
	}
	for _, e := range list {
		if e.Source == "manual" && e.ExpiresAt == nil {
			if e.List == "block" {
				r.Block = append(r.Block, e.CIDR)
			} else {
				r.Allow = append(r.Allow, e.CIDR)
			}
		}
	}
	r.Version, _, err = a.PG.ConfigVersion(ctx)
	return
}

// ExportPolicy renders the running policy as coraza-policy.yaml.
func ExportPolicy(r Running, now time.Time) (string, error) {
	var d PolicyDoc
	d.APIVersion, d.Kind = "coraza.console/v1", "CorazaPolicy"
	d.Metadata.ConfigVersion, d.Metadata.ExportedAt = r.Version, now.UTC().Format(time.RFC3339)
	domains := map[string]string{}
	d.Sites = make([]PolicySite, len(r.Sites))
	for i, s := range r.Sites {
		domains[s.ID] = s.DomainName
		o := &d.Sites[i]
		o.Domain, o.Name, o.ParanoiaLevel = s.DomainName, s.Name, s.ParanoiaLevel
		o.AnomalyThreshold.Inbound, o.AnomalyThreshold.Outbound = s.InboundThreshold, s.OutboundThreshold
		o.CRS.DisabledCategories = []string{}
		for _, k := range []string{"913", "920", "921", "930", "931", "932", "933", "941", "942", "944", "950", "955"} {
			if on, ok := s.CRSCategories[k]; ok && !on {
				o.CRS.DisabledCategories = append(o.CRS.DisabledCategories, k+"xxx")
			}
		}
		for _, e := range r.Exceptions {
			if e.SiteID != s.ID {
				continue
			}
			x := PolicyException{RuleID: e.RuleID, Path: e.PathPattern, Reason: e.Reason}
			if e.ParameterName != nil {
				x.Parameter = *e.ParameterName
			}
			o.Exceptions = append(o.Exceptions, x)
		}
	}
	for _, x := range r.Rules {
		site := "*"
		if x.SiteID != nil {
			site = domains[*x.SiteID]
		}
		d.CustomRules = append(d.CustomRules, PolicyRule{x.RuleID, x.Name, site, x.IsActive, x.SecLangRaw})
	}
	d.IPLists.Block, d.IPLists.Allow = r.Block, r.Allow
	if d.IPLists.Block == nil {
		d.IPLists.Block = []string{}
	}
	if d.IPLists.Allow == nil {
		d.IPLists.Allow = []string{}
	}
	b, err := yaml.Marshal(d)
	return string(b), err
}

// ValidatePolicy checks a coraza-policy.yaml the way CI does (cmd/corazium-ctl) and, given the running policy,
// summarizes what applying it would change. It never applies anything.
func ValidatePolicy(text string, running *Running) (errs, summary []string) {
	errs, summary = []string{}, []string{}
	var d PolicyDoc
	if err := yaml.Unmarshal([]byte(text), &d); err != nil {
		return []string{"YAML: " + strings.SplitN(err.Error(), "\n", 2)[0]}, summary
	}
	if d.Kind != "CorazaPolicy" {
		errs = append(errs, `kind must be "CorazaPolicy"`)
	}
	cur := map[string]model.Site{}
	if running != nil {
		for _, s := range running.Sites {
			cur[s.DomainName] = s
		}
	}
	for i, s := range d.Sites {
		if s.ParanoiaLevel < 1 || s.ParanoiaLevel > 4 {
			errs = append(errs, fmt.Sprintf("sites[%d].paranoiaLevel must be 1-4", i))
		}
		if s.Domain == "" {
			errs = append(errs, fmt.Sprintf("sites[%d].domain is required", i))
		}
		for _, t := range []int{s.AnomalyThreshold.Inbound, s.AnomalyThreshold.Outbound} {
			if t != 0 && (t < 1 || t > 100) {
				errs = append(errs, fmt.Sprintf("sites[%d].anomalyThreshold values must be 1-100", i))
				break
			}
		}
		if running == nil {
			continue
		}
		if c, ok := cur[s.Domain]; !ok {
			summary = append(summary, "+ new site "+s.Domain)
		} else if c.ParanoiaLevel != s.ParanoiaLevel {
			summary = append(summary, fmt.Sprintf("~ %s: PL%d -> PL%d", s.Domain, c.ParanoiaLevel, s.ParanoiaLevel))
		}
	}
	seen := map[int]bool{}
	for i, r := range d.CustomRules {
		if err := waf.LintRule(r.SecLang); err != nil {
			errs = append(errs, fmt.Sprintf("customRules[%d] (id %d): %s", i, r.ID, err))
		} else if id, _ := waf.RuleID(r.SecLang); id != r.ID {
			errs = append(errs, fmt.Sprintf("customRules[%d]: id %d does not match id:%d in its SecLang", i, r.ID, id))
		}
		if seen[r.ID] {
			errs = append(errs, fmt.Sprintf("customRules[%d]: duplicate rule id %d", i, r.ID))
		}
		seen[r.ID] = true
	}
	for _, l := range [][]string{d.IPLists.Block, d.IPLists.Allow} {
		for _, c := range l {
			if _, ok := parseCIDR(c); !ok {
				errs = append(errs, fmt.Sprintf("ipLists: %q is not an IP address or CIDR", c))
			}
		}
	}
	if running != nil {
		have := map[int]bool{}
		for _, x := range running.Rules {
			have[x.RuleID] = true
			if !seen[x.RuleID] {
				summary = append(summary, fmt.Sprintf("- rule %d", x.RuleID))
			}
		}
		for _, r := range d.CustomRules {
			if !have[r.ID] {
				summary = append(summary, fmt.Sprintf("+ rule %d", r.ID))
			}
		}
		if len(summary) == 0 && len(errs) == 0 {
			summary = append(summary, "No changes against the running policy")
		}
	}
	return
}

func (a *App) exportPolicy(c *gin.Context) {
	r, err := a.running(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	out, err := ExportPolicy(r, time.Now())
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) validatePolicy(c *gin.Context) {
	var in struct{ Text string }
	if !bind(c, &in) {
		return
	}
	if len(in.Text) > 4<<20 {
		bad(c, "Policy file is larger than 4 MB")
		return
	}
	r, err := a.running(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	errs, summary := ValidatePolicy(in.Text, &r)
	c.JSON(200, gin.H{"ok": len(errs) == 0, "errors": errs, "summary": summary})
}
