// Package api is the REST and WebSocket surface of the control plane. Paths and JSON shapes match web/lib/api.ts.
// Error bodies are plain text: the console shows them verbatim.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
	"github.com/Agustian16/WAAP-Platform/server/internal/waf"
)

// Fleet is the gRPC side of the control plane, as the API needs it.
type Fleet interface {
	// Push sends a bundle to every connected node and waits up to wait for acks. It returns node id -> applied.
	Push(b model.Bundle, wait time.Duration) map[string]bool
	// EnrollHint returns the address and CA pin an agent needs to enroll.
	EnrollHint() (addr, caPin string)
}

type App struct {
	PG     *store.PG
	CH     *store.CH
	Engine *correlate.Engine
	Hub    *Hub
	Fleet  Fleet
	Auth   *Auth
	// PushWait bounds how long a deploy waits for node acks (NFR-1.2: under one second).
	PushWait time.Duration
	// AllowPrivateFeeds permits threat feed URLs that resolve to private addresses (dev only).
	AllowPrivateFeeds bool
	// Leader reports whether this instance runs the background jobs (feed pulls, list expiry). Nil means always.
	Leader func(context.Context) bool
	// FeedHTTP overrides the feed HTTP client (tests). Nil means the SSRF-guarded default.
	FeedHTTP *http.Client
}

func (a *App) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), a.Auth.cors)
	_ = r.SetTrustedProxies(nil) // source_ip in the audit trail is the direct peer, never a client-supplied header

	r.GET("/healthz", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })
	r.GET("/auth/providers", a.Auth.providers)
	r.GET("/auth/oidc/login", a.Auth.login)
	r.GET("/auth/oidc/callback", a.Auth.callback)
	r.POST("/auth/logout", a.Auth.logout)
	r.GET("/ws/attacks", a.Auth.session, a.Hub.serve)

	v := r.Group("/api/v1", a.Auth.session)
	admin, responder := allow(model.Admin), allow(model.Admin, model.Analyst)

	v.GET("/me", func(c *gin.Context) { c.JSON(200, userOf(c)) })

	v.GET("/nodes", a.nodes)
	v.GET("/config/version", a.configVersion)
	v.POST("/nodes/enrollment-tokens", admin, a.enrollmentToken)
	v.POST("/config/deploy", admin, a.deploy)

	v.GET("/sites", a.sites)
	v.POST("/sites", admin, a.createSite)
	v.PATCH("/sites/:id", admin, a.patchSite)

	v.GET("/rules", a.rules)
	v.GET("/rules/ids", a.ruleIDs)
	v.GET("/rules/:id", a.rule)
	v.POST("/rules", responder, a.saveRule)
	v.PUT("/rules/:id", responder, a.saveRule)
	v.PATCH("/rules/:id", admin, a.setRuleActive)
	v.DELETE("/rules/:id", admin, a.deleteRule)
	v.POST("/sandbox/ftw", a.sandbox)

	v.GET("/exceptions", a.exceptions)
	v.POST("/exceptions", responder, a.createException)
	v.DELETE("/exceptions/:id", admin, a.deleteException)

	v.POST("/logs/query", a.queryLogs)
	v.GET("/logs/:id", a.getLog)
	v.GET("/analytics/overview", a.overview)

	v.GET("/ip-lists", a.ipLists)
	v.GET("/ip-lists/impact", a.ipImpact)
	v.POST("/ip-lists", responder, a.addIP)
	v.DELETE("/ip-lists/:id", responder, a.removeIP)
	v.GET("/threat-feeds", a.feeds)
	v.POST("/threat-feeds", admin, a.addFeed)
	v.POST("/threat-feeds/:id/pull", admin, a.pullFeed)
	v.DELETE("/threat-feeds/:id", admin, a.removeFeed)

	v.GET("/audit-trail", a.auditTrail)
	v.GET("/users", a.users)
	v.PATCH("/users/:id", admin, a.setRole)
	v.GET("/gitops/export", a.exportPolicy)
	v.POST("/gitops/validate", a.validatePolicy)
	v.GET("/killchain-mapping", a.mapping)
	v.PUT("/killchain-mapping/:id", admin, a.saveMapping)
	v.GET("/correlation-settings", a.correlation)
	v.PUT("/correlation-settings/:id", admin, a.saveCorrelation)

	v.GET("/campaigns", a.campaigns)
	v.GET("/campaigns/:id", a.campaign)
	v.PATCH("/campaigns/:id", responder, a.patchCampaign)
	v.GET("/attack-events", a.attackEvents)
	return r
}

// ---------- helpers ----------

// fail answers with a plain-text message. Store errors map to 404/409; anything else is a 500 that is logged, not leaked.
func fail(c *gin.Context, err error, notFound string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		c.String(http.StatusNotFound, notFound)
	case errors.Is(err, store.ErrConflict):
		c.String(http.StatusConflict, "Conflicts with an existing record")
	default:
		slog.Error("request failed", "path", c.FullPath(), "err", err)
		c.String(http.StatusInternalServerError, "Internal error")
	}
}

func bad(c *gin.Context, format string, args ...any) {
	c.String(http.StatusUnprocessableEntity, format, args...)
}

func bind(c *gin.Context, v any) bool {
	if err := c.ShouldBindJSON(v); err != nil {
		c.String(http.StatusBadRequest, "Malformed request body")
		return false
	}
	return true
}

// audit appends to the immutable trail (FR-5.2). A failed write is an error worth paging on, so it is logged loudly.
func (a *App) audit(c *gin.Context, action, target, nodes string) {
	u := userOf(c)
	if err := a.PG.Audit(c, model.AuditTrailEntry{Actor: u.Name, Role: u.Role, Action: action, Target: target, SourceIP: c.ClientIP(), TargetNodes: nodes}); err != nil {
		slog.Error("AUDIT TRAIL WRITE FAILED", "action", action, "target", target, "actor", u.Email, "err", err)
	}
}

func (a *App) markDirty(c *gin.Context) {
	if err := a.PG.MarkDirty(c); err != nil {
		slog.Error("mark dirty", "err", err)
	}
}

// ---------- Fleet (Module 1) ----------

const offlineAfter = 20 * time.Second

func (a *App) nodes(c *gin.Context) {
	nodes, err := a.PG.Nodes(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	version, dirty, err := a.PG.ConfigVersion(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	hist, err := a.CH.NodeHistory(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	for i := range nodes {
		n := &nodes[i]
		n.History = hist[n.ID]
		if n.History == nil {
			n.History = []model.NodeHistory{}
		}
		switch {
		case n.LastHeartbeat == nil || time.Since(*n.LastHeartbeat) > offlineAfter:
			n.Status, n.CPU, n.Memory, n.RPS, n.LatencyMs = "OFFLINE", 0, 0, 0, 0
		case n.LatencyMs > 5 || n.CPU > 85 || n.Memory > 92: // degraded: over the 2 ms budget with margin, or starved
			n.Status = "WARN"
		default:
			n.Status = "ONLINE"
		}
		// Same precision the console renders: whole percent and req/s, latency to 0.01 ms.
		n.CPU, n.Memory, n.RPS, n.LatencyMs = math.Round(n.CPU), math.Round(n.Memory), math.Round(n.RPS), math.Round(n.LatencyMs*100)/100
		for j := range n.History {
			h := &n.History[j]
			h.RPS, h.CPU, h.Latency = math.Round(h.RPS), math.Round(h.CPU), math.Round(h.Latency*100)/100
		}
		n.SyncStatus = "PENDING_UPDATE"
		if !dirty && n.CurrentConfigVersion == version {
			n.SyncStatus = "IN_SYNC"
		}
	}
	c.JSON(200, nodes)
}

func (a *App) configVersion(c *gin.Context) {
	v, _, err := a.PG.ConfigVersion(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, v)
}

var nodeNameRe = regexp.MustCompile(`^[a-z0-9-]{3,63}$`)

func (a *App) enrollmentToken(c *gin.Context) {
	var in struct{ Name string }
	if !bind(c, &in) {
		return
	}
	if !nodeNameRe.MatchString(in.Name) {
		bad(c, "Use 3-63 lowercase letters, digits or dashes")
		return
	}
	taken, err := a.PG.NodeNameTaken(c, in.Name)
	if err != nil {
		fail(c, err, "")
		return
	}
	if taken {
		c.String(http.StatusConflict, "Node %s already exists or has a pending enrollment", in.Name)
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fail(c, err, "")
		return
	}
	addr, pin := a.Fleet.EnrollHint()
	token := "cze_" + hex.EncodeToString(secret)
	if err := a.PG.CreateEnrollmentToken(c, hashToken(token), in.Name, userOf(c).Name, 24*time.Hour); err != nil {
		fail(c, err, "")
		return
	}
	a.audit(c, "Enrollment token issued", in.Name, "-")
	// The CA pin lets the agent authenticate the control plane before it holds any certificate.
	c.JSON(200, gin.H{"token": token, "command": fmt.Sprintf("edge-agent \\\n  --control-plane %s \\\n  --ca-pin %s \\\n  --token %s \\\n  --upstream http://127.0.0.1:8000 \\\n  --listen :8080", addr, pin, token)})
}

// buildBundle compiles the stored policy and proves every engine builds before anything is pushed.
func (a *App) buildBundle(ctx context.Context) (model.Bundle, error) {
	var b model.Bundle
	sites, err := a.PG.Sites(ctx)
	if err != nil {
		return b, err
	}
	rules, err := a.PG.Rules(ctx)
	if err != nil {
		return b, err
	}
	exc, err := a.PG.Exceptions(ctx)
	if err != nil {
		return b, err
	}
	b.DefaultDirectives, b.SiteDirectives, b.SiteIDs = waf.Compile(waf.Policy{Sites: sites, Rules: rules, Exceptions: exc})
	if err := waf.Validate(b.DefaultDirectives, b.SiteDirectives); err != nil {
		return b, &compileError{err}
	}
	return b, a.fillIPLists(ctx, &b)
}

type compileError struct{ error }

func (a *App) fillIPLists(ctx context.Context, b *model.Bundle) (err error) {
	if b.BlockCIDRs, err = a.PG.ActiveCIDRs(ctx, "block"); err != nil {
		return
	}
	b.AllowCIDRs, err = a.PG.ActiveCIDRs(ctx, "allow")
	return
}

// EnsureBundle creates version 1 from the stored policy on a fresh install, so nodes have a config to run.
func (a *App) EnsureBundle(ctx context.Context) error {
	if _, err := a.PG.LatestBundle(ctx); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	b, err := a.buildBundle(ctx)
	if err != nil {
		return err
	}
	_, err = a.PG.InsertBundle(ctx, b, "system", true)
	return err
}

func (a *App) deploy(c *gin.Context) {
	b, err := a.buildBundle(c)
	var ce *compileError
	if errors.As(err, &ce) {
		bad(c, "Policy does not compile, nothing was deployed. %s", ce.Error())
		return
	}
	if err != nil {
		fail(c, err, "")
		return
	}
	if b.Version, err = a.PG.InsertBundle(c, b, userOf(c).Name, true); err != nil {
		fail(c, err, "")
		return
	}
	acked := a.Fleet.Push(b, a.PushWait)
	nodes, err := a.PG.Nodes(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	unreachable := []string{}
	for _, n := range nodes {
		if !acked[n.ID] {
			unreachable = append(unreachable, n.NodeName)
		}
	}
	synced := len(nodes) - len(unreachable)
	target := fmt.Sprintf("%d of %d", synced, len(nodes))
	if len(unreachable) > 0 {
		target += " (" + strings.Join(unreachable, ", ") + " unreachable)"
	}
	a.audit(c, "Policy deployed", fmt.Sprintf("config v%d", b.Version), target)
	c.JSON(200, gin.H{"version": b.Version, "synced": synced, "unreachable": unreachable})
}

// PushIPLists ships block/allow list changes at once, on top of the policy that is already deployed. Draft
// policy edits stay undeployed: an analyst blocking an attacker must not publish someone's half-finished rule.
func (a *App) PushIPLists(ctx context.Context, by string) (int, error) {
	b, err := a.PG.LatestBundle(ctx)
	if err != nil {
		return 0, err
	}
	if err := a.fillIPLists(ctx, &b); err != nil {
		return 0, err
	}
	if b.Version, err = a.PG.InsertBundle(ctx, b, by, false); err != nil {
		return 0, err
	}
	n := 0
	for _, ok := range a.Fleet.Push(b, a.PushWait) {
		if ok {
			n++
		}
	}
	return n, nil
}

// ---------- Policies (FR-2.1, FR-2.2) ----------

func (a *App) sites(c *gin.Context) {
	out, err := a.PG.Sites(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func (a *App) createSite(c *gin.Context) {
	var in struct {
		Name       string `json:"name"`
		DomainName string `json:"domain_name"`
	}
	if !bind(c, &in) {
		return
	}
	in.DomainName = strings.ToLower(strings.TrimSpace(in.DomainName))
	if strings.TrimSpace(in.Name) == "" || !domainRe.MatchString(in.DomainName) {
		bad(c, "A site needs a name and a valid domain name")
		return
	}
	s, err := a.PG.CreateSite(c, strings.TrimSpace(in.Name), in.DomainName)
	if errors.Is(err, store.ErrConflict) {
		c.String(http.StatusConflict, "%s is already a site", in.DomainName)
		return
	}
	if err != nil {
		fail(c, err, "")
		return
	}
	a.audit(c, "Site added", s.DomainName, "-")
	a.markDirty(c)
	a.reloadCorrelation(c)
	c.JSON(200, s)
}

var crsKeyRe = regexp.MustCompile(`^9\d\d$`)

func (a *App) patchSite(c *gin.Context) {
	var in struct {
		ParanoiaLevel     *int            `json:"paranoia_level"`
		InboundThreshold  *int            `json:"inbound_threshold"`
		OutboundThreshold *int            `json:"outbound_threshold"`
		CRSCategories     map[string]bool `json:"crs_categories"`
	}
	if !bind(c, &in) {
		return
	}
	s, err := a.PG.Site(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Site not found")
		return
	}
	var changes []string
	if v := in.ParanoiaLevel; v != nil {
		if *v < 1 || *v > 4 {
			bad(c, "Paranoia level must be 1-4")
			return
		}
		if *v != s.ParanoiaLevel {
			changes = append(changes, fmt.Sprintf("PL%d -> PL%d", s.ParanoiaLevel, *v))
			s.ParanoiaLevel = *v
		}
	}
	for _, t := range []struct {
		v    *int
		cur  *int
		name string
	}{{in.InboundThreshold, &s.InboundThreshold, "inbound"}, {in.OutboundThreshold, &s.OutboundThreshold, "outbound"}} {
		if t.v == nil {
			continue
		}
		if *t.v < 1 || *t.v > 100 {
			bad(c, "Thresholds must be whole numbers between 1 and 100")
			return
		}
		if *t.v != *t.cur {
			changes = append(changes, fmt.Sprintf("%s %d -> %d", t.name, *t.cur, *t.v))
			*t.cur = *t.v
		}
	}
	for k, v := range in.CRSCategories {
		if !crsKeyRe.MatchString(k) {
			bad(c, "Unknown CRS category %q", k)
			return
		}
		if cur, ok := s.CRSCategories[k]; !ok || cur != v {
			changes = append(changes, fmt.Sprintf("%sxxx %s", k, map[bool]string{true: "on", false: "off"}[v]))
			s.CRSCategories[k] = v
		}
	}
	if len(changes) == 0 {
		c.JSON(200, s)
		return
	}
	if s, err = a.PG.SaveSite(c, s); err != nil {
		fail(c, err, "Site not found")
		return
	}
	a.audit(c, "Policy changed", s.DomainName+": "+strings.Join(changes, ", "), "-")
	a.markDirty(c)
	c.JSON(200, s)
}

// ---------- Custom rules (FR-2.3, FR-2.4) ----------

func (a *App) rules(c *gin.Context) {
	out, err := a.PG.Rules(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

func (a *App) ruleIDs(c *gin.Context) {
	rs, err := a.PG.Rules(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	ids := make([]int, len(rs))
	for i, r := range rs {
		ids[i] = r.RuleID
	}
	c.JSON(200, ids)
}

func (a *App) rule(c *gin.Context) {
	r, err := a.PG.Rule(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Rule not found")
		return
	}
	c.JSON(200, r)
}

func (a *App) saveRule(c *gin.Context) {
	var in struct {
		Name       string  `json:"name"`
		SiteID     *string `json:"site_id"`
		SecLangRaw string  `json:"seclang_raw"`
		IsActive   bool    `json:"is_active"`
	}
	if !bind(c, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		bad(c, "Name is required")
		return
	}
	if err := waf.LintRule(in.SecLangRaw); err != nil {
		bad(c, "%s", err.Error())
		return
	}
	u := userOf(c)
	id, _ := waf.RuleID(in.SecLangRaw)
	// Analysts write drafts (FR-5.1): their saves stay inactive until an Admin activates them.
	x := model.CustomRule{ID: c.Param("id"), RuleID: id, SiteID: in.SiteID, Name: strings.TrimSpace(in.Name), SecLangRaw: in.SecLangRaw,
		IsActive: in.IsActive && u.Role == model.Admin, CreatedBy: u.Name}
	if x.SiteID != nil && *x.SiteID == "" {
		x.SiteID = nil
	}
	var err error
	action := "Rule updated"
	if x.ID == "" {
		action = map[bool]string{true: "Rule added", false: "Rule drafted"}[u.Role == model.Admin]
		x, err = a.PG.InsertRule(c, x)
	} else {
		x, err = a.PG.UpdateRule(c, x)
	}
	if errors.Is(err, store.ErrConflict) {
		bad(c, "Rule id %d is already used by another rule", id)
		return
	}
	if err != nil {
		fail(c, err, "Rule not found")
		return
	}
	a.audit(c, action, fmt.Sprintf("%d %s", x.RuleID, x.Name), "-")
	a.markDirty(c)
	c.JSON(200, x)
}

func (a *App) setRuleActive(c *gin.Context) {
	var in struct {
		IsActive bool `json:"is_active"`
	}
	if !bind(c, &in) {
		return
	}
	x, err := a.PG.SetRuleActive(c, c.Param("id"), in.IsActive)
	if err != nil {
		fail(c, err, "Rule not found")
		return
	}
	a.audit(c, map[bool]string{true: "Rule enabled", false: "Rule disabled"}[in.IsActive], fmt.Sprintf("%d %s", x.RuleID, x.Name), "-")
	a.markDirty(c)
	c.JSON(200, x)
}

func (a *App) deleteRule(c *gin.Context) {
	x, err := a.PG.DeleteRule(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Rule not found")
		return
	}
	a.audit(c, "Rule deleted", fmt.Sprintf("%d %s", x.RuleID, x.Name), "-")
	a.markDirty(c)
	c.JSON(200, gin.H{"ok": true})
}

// sandbox runs Go FTW (FR-2.4): either one request from the console, turned into an FTW test, or a whole FTW
// YAML suite.
func (a *App) sandbox(c *gin.Context) {
	var in struct {
		SecLang string             `json:"seclang"`
		Request waf.SandboxRequest `json:"request"`
		Suite   string             `json:"suite"`
	}
	if !bind(c, &in) {
		return
	}
	if strings.TrimSpace(in.Suite) != "" {
		rep, err := waf.SandboxFTW(in.SecLang, in.Suite)
		if err != nil {
			bad(c, "%s", err.Error())
			return
		}
		c.JSON(200, rep)
		return
	}
	res, err := waf.Sandbox(in.SecLang, in.Request)
	if err != nil {
		bad(c, "%s", err.Error())
		return
	}
	c.JSON(200, res)
}

// ---------- Exceptions (FR-3.3) ----------

func (a *App) exceptions(c *gin.Context) {
	out, err := a.PG.Exceptions(c)
	if err != nil {
		fail(c, err, "")
		return
	}
	c.JSON(200, out)
}

var paramRe = regexp.MustCompile(`^[A-Z_]+(:[^\s"';,]{1,80})?$`)
var pathRe = regexp.MustCompile(`^/[^\s"\\]{0,250}$`)

func (a *App) createException(c *gin.Context) {
	var in struct {
		SiteID    string  `json:"siteId"`
		RuleID    int     `json:"ruleId"`
		Path      string  `json:"path"`
		Parameter *string `json:"parameter"`
		Scope     string  `json:"scope"`
		Reason    string  `json:"reason"`
	}
	if !bind(c, &in) {
		return
	}
	if strings.TrimSpace(in.Reason) == "" {
		bad(c, "Give a reason so reviewers know why this rule is suppressed")
		return
	}
	if in.RuleID < 1 || in.RuleID > 999999 {
		bad(c, "Rule id is out of range")
		return
	}
	path := "*"
	if in.Scope != "global" {
		// The path and parameter are written into SecLang, so their alphabet is restricted here.
		if !pathRe.MatchString(in.Path) {
			bad(c, "Path must start with / and contain no spaces or quotes")
			return
		}
		path = in.Path
	}
	if in.Parameter != nil && *in.Parameter == "" {
		in.Parameter = nil
	}
	if in.Parameter != nil && !paramRe.MatchString(*in.Parameter) {
		bad(c, "Parameter must look like ARGS:name")
		return
	}
	site, err := a.PG.Site(c, in.SiteID)
	if err != nil {
		fail(c, err, "Site not found")
		return
	}
	e, err := a.PG.InsertException(c, model.RuleException{SiteID: in.SiteID, RuleID: in.RuleID, PathPattern: path, ParameterName: in.Parameter,
		Reason: strings.TrimSpace(in.Reason), CreatedBy: userOf(c).Name}, waf.ExceptionIDFirst, waf.ExceptionIDLast)
	if err != nil {
		fail(c, err, "No free exception rule id left (10000-19999)")
		return
	}
	target := fmt.Sprintf("%d @ %s", in.RuleID, site.DomainName)
	if path == "*" {
		target += " (global)"
	} else {
		target += path
	}
	if in.Parameter != nil {
		target += " " + *in.Parameter
	}
	a.audit(c, "Exception created", target, "all")
	a.markDirty(c)
	c.JSON(200, gin.H{"exception": e, "seclang": waf.BuildException(e)})
}

func (a *App) deleteException(c *gin.Context) {
	x, err := a.PG.DeleteException(c, c.Param("id"))
	if err != nil {
		fail(c, err, "Exception not found")
		return
	}
	a.audit(c, "Exception removed", fmt.Sprintf("%d %s", x.RuleID, x.PathPattern), "-")
	a.markDirty(c)
	c.JSON(200, gin.H{"ok": true})
}
