package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

// AuthConfig configures OIDC sign-in (NFR-2.2).
type AuthConfig struct {
	ProviderID   string // "keycloak", "okta", ...: the id the login page sends
	ProviderName string
	Issuer       string
	ClientID     string
	ClientSecret string
	// RoleClaim is a dotted path in the ID token holding role names, e.g. "realm_access.roles".
	RoleClaim string
	// MFAMode "claim" requires MFA evidence in the token (amr/acr). "idp" trusts the IdP's own policy to enforce
	// MFA, for providers that do not emit amr; the IdP must then make MFA mandatory.
	MFAMode         string
	BootstrapAdmins []string // emails that become Admin on first sign-in
	PublicURL       string   // this API's external base URL (for the redirect URI)
	WebURL          string   // the console's origin: redirect target and the only allowed browser origin
	SessionTTL      time.Duration
}

const (
	sessionCookie = "cz_session"
	flowCookie    = "cz_oidc"
)

type Auth struct {
	cfg AuthConfig
	pg  *store.PG

	mu  sync.Mutex
	idp *idp // nil until discovery succeeds
}

type idp struct {
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	endSession string // the IdP's RP-initiated logout endpoint, when it has one
}

var errNoIdP = errors.New("no identity provider is configured on the control plane (set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET)")

// NewAuth tries provider discovery once. An unreachable IdP does not stop the control plane (node enforcement
// and existing sessions do not depend on it); discovery is retried on the next sign-in.
func NewAuth(ctx context.Context, cfg AuthConfig, pg *store.PG) *Auth {
	a := &Auth{cfg: cfg, pg: pg}
	if cfg.Issuer != "" {
		if _, err := a.provider(ctx); err != nil {
			slog.Warn("identity provider unreachable, sign-in will retry discovery", "issuer", cfg.Issuer, "err", err)
		}
	}
	return a
}

func (a *Auth) provider(ctx context.Context) (*idp, error) {
	if a.cfg.Issuer == "" {
		return nil, errNoIdP
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.idp != nil {
		return a.idp, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, a.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&meta)
	a.idp = &idp{verifier: p.Verifier(&oidc.Config{ClientID: a.cfg.ClientID}), endSession: meta.EndSession,
		oauth: &oauth2.Config{ClientID: a.cfg.ClientID, ClientSecret: a.cfg.ClientSecret, Endpoint: p.Endpoint(),
			RedirectURL: strings.TrimRight(a.cfg.PublicURL, "/") + "/auth/oidc/callback", Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}}
	return a.idp, nil
}

func randToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) []byte { h := sha256.Sum256([]byte(t)); return h[:] }

func (a *Auth) secure() bool { return strings.HasPrefix(a.cfg.PublicURL, "https://") }

func (a *Auth) setCookie(c *gin.Context, name, value, path string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{Name: name, Value: value, Path: path, MaxAge: maxAge, HttpOnly: true, Secure: a.secure(), SameSite: http.SameSiteLaxMode})
}

func (a *Auth) providers(c *gin.Context) {
	out := []gin.H{}
	if a.cfg.Issuer != "" {
		out = append(out, gin.H{"id": a.cfg.ProviderID, "name": a.cfg.ProviderName})
	}
	c.JSON(200, out)
}

func (a *Auth) login(c *gin.Context) {
	if !strings.EqualFold(c.Query("provider"), a.cfg.ProviderID) {
		c.String(404, "Unknown identity provider")
		return
	}
	p, err := a.provider(c)
	if errors.Is(err, errNoIdP) {
		c.String(503, "Sign-in unavailable: %s.", err)
		return
	}
	if err != nil {
		c.String(503, "The identity provider is not reachable right now. Try again in a moment.")
		return
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	a.setCookie(c, flowCookie, state+"."+nonce+"."+verifier, "/auth", 600)
	c.Redirect(http.StatusFound, p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
}

// claimPath walks a dotted path ("realm_access.roles") through decoded token claims.
func claimPath(claims map[string]any, path string) any {
	var cur any = claims
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func stringsOf(v any) (out []string) {
	switch x := v.(type) {
	case string:
		out = append(out, x)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return
}

// roleFor maps IdP role names onto console roles; unknown users start as read-only Auditor (least privilege).
func (a *Auth) roleFor(email string, idpRoles []string) model.Role {
	for _, e := range a.cfg.BootstrapAdmins {
		if strings.EqualFold(strings.TrimSpace(e), email) {
			return model.Admin
		}
	}
	role := model.Auditor
	for _, r := range idpRoles {
		switch strings.ToLower(strings.NewReplacer("_", "-", " ", "-").Replace(r)) {
		case "admin", "corazium-admin":
			return model.Admin
		case "secops-analyst", "analyst", "corazium-analyst":
			role = model.Analyst
		}
	}
	return role
}

var mfaMethods = map[string]bool{"mfa": true, "otp": true, "hwk": true, "swk": true, "sms": true, "fpt": true, "face": true, "pin": true}

func (a *Auth) callback(c *gin.Context) {
	fail := func(status int, msg string) { c.String(status, "Sign-in failed: "+msg) }
	p, err := a.provider(c)
	if err != nil {
		fail(503, "the identity provider is not reachable")
		return
	}
	raw, _ := c.Cookie(flowCookie)
	a.setCookie(c, flowCookie, "", "/auth", -1)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || c.Query("state") == "" || c.Query("state") != parts[0] {
		fail(400, "state mismatch, start again from the sign-in page")
		return
	}
	if e := c.Query("error"); e != "" {
		fail(403, e+" "+c.Query("error_description"))
		return
	}
	tok, err := p.oauth.Exchange(c, c.Query("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		fail(502, "code exchange with the identity provider failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := p.verifier.Verify(c, rawID)
	if err != nil || idt.Nonce != parts[1] {
		fail(403, "ID token did not verify")
		return
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		fail(403, "unreadable ID token")
		return
	}
	email, _ := claims["email"].(string)
	if email == "" {
		fail(403, "the identity provider did not release an email address")
		return
	}
	if v, ok := claims["email_verified"].(bool); ok && !v {
		fail(403, "email address is not verified at the identity provider")
		return
	}
	mfa := a.cfg.MFAMode == "idp"
	for _, m := range stringsOf(claims["amr"]) {
		mfa = mfa || mfaMethods[strings.ToLower(m)]
	}
	if !mfa {
		fail(403, "multi-factor authentication is required; sign in with a second factor")
		return
	}
	name, _ := claims["name"].(string)
	if name == "" {
		name, _ = claims["preferred_username"].(string)
	}
	if name == "" {
		name = email
	}
	u, err := a.pg.UserLogin(c, idt.Issuer+"|"+idt.Subject, name, email, a.roleFor(email, stringsOf(claimPath(claims, a.cfg.RoleClaim))), mfa)
	if err != nil {
		fail(500, "could not record the user")
		return
	}
	token := randToken()
	if err := a.pg.CreateSession(c, hashToken(token), u.ID, a.cfg.SessionTTL); err != nil {
		fail(500, "could not create the session")
		return
	}
	a.setCookie(c, sessionCookie, token, "/", int(a.cfg.SessionTTL.Seconds()))
	c.Redirect(http.StatusFound, a.cfg.WebURL)
}

func (a *Auth) logout(c *gin.Context) {
	if t, err := c.Cookie(sessionCookie); err == nil {
		_ = a.pg.DeleteSession(c, hashToken(t))
	}
	a.setCookie(c, sessionCookie, "", "/", -1)
	// Ending only our session would let the IdP's SSO session sign the next person straight back in.
	out := gin.H{"ok": true}
	if p, err := a.provider(c); err == nil && p.endSession != "" {
		out["logoutUrl"] = p.endSession + "?client_id=" + url.QueryEscape(a.cfg.ClientID) + "&post_logout_redirect_uri=" + url.QueryEscape(strings.TrimRight(a.cfg.WebURL, "/")+"/login")
	}
	c.JSON(200, out)
}

// ---------- Middleware ----------

// cors allows the console origin only, with credentials. Browser requests from any other origin are refused,
// which is also the CSRF defence for cookie-authenticated state changes.
func (a *Auth) cors(c *gin.Context) {
	origin := c.GetHeader("Origin")
	if origin != "" {
		if !sameOrigin(origin, a.cfg.WebURL) && !sameOrigin(origin, a.cfg.PublicURL) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Vary", "Origin")
		if c.Request.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Max-Age", "600")
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
	}
	c.Next()
}

func sameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host && ua.Host != ""
}

// session authenticates the request from the session cookie.
func (a *Auth) session(c *gin.Context) {
	t, err := c.Cookie(sessionCookie)
	if err != nil || t == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not signed in"})
		return
	}
	u, err := a.pg.SessionUser(c, hashToken(t))
	if errors.Is(err, store.ErrNotFound) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
		return
	}
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	c.Set("user", u)
	c.Next()
}

func userOf(c *gin.Context) model.User { return c.MustGet("user").(model.User) }

// allow restricts a route to roles (FR-5.1). The body is plain text because the console shows it verbatim.
func allow(roles ...model.Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		u := userOf(c)
		for _, r := range roles {
			if u.Role == r {
				c.Next()
				return
			}
		}
		c.String(http.StatusForbidden, "%s cannot perform this action", u.Role)
		c.Abort()
	}
}
