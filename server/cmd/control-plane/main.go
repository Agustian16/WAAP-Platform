// control-plane is the Corazium backend: REST + WebSocket for the console, gRPC for edge nodes, the attack
// correlation engine, and the stores behind them. Configuration is by environment (see deploy/dev.env).
package main

import (
	"fmt"

	"bufio"
	"context"
	"errors"
	"flag"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/agentrpc"
	"github.com/Agustian16/WAAP-Platform/server/internal/api"
	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("missing required setting", "env", k)
		os.Exit(2)
	}
	return v
}

// loadEnvFile reads KEY=VALUE lines; variables already set in the environment win.
func loadEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") && os.Getenv(k) == "" {
			os.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return sc.Err()
}

func main() {
	var envFiles []string
	flag.Func("env-file", "file of KEY=VALUE settings (repeatable; earlier files and the real environment win)", func(v string) error {
		envFiles = append(envFiles, v)
		return nil
	})
	flag.Parse()
	for _, f := range envFiles {
		if err := loadEnvFile(f); err != nil {
			slog.Error("env file", "err", err)
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("control plane stopped", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	pg, err := store.OpenPG(ctx, must("DATABASE_URL"), env("SEED_DEV", "") == "true")
	if err != nil {
		return err
	}
	defer pg.Close()
	ch, err := store.OpenCH(ctx, must("CLICKHOUSE_ADDR"), env("CLICKHOUSE_DB", "default"), env("CLICKHOUSE_USER", "default"), os.Getenv("CLICKHOUSE_PASSWORD"))
	if err != nil {
		return err
	}
	defer ch.Close()

	webURL, publicURL := env("WEB_URL", "http://localhost:3000"), env("PUBLIC_URL", "http://localhost:8080")
	ttl, err := time.ParseDuration(env("SESSION_TTL", "12h"))
	if err != nil {
		return err
	}
	var admins []string
	if v := os.Getenv("BOOTSTRAP_ADMINS"); v != "" {
		admins = strings.Split(v, ",")
	}
	auth := api.NewAuth(ctx, api.AuthConfig{
		ProviderID: env("OIDC_PROVIDER_ID", "keycloak"), ProviderName: env("OIDC_PROVIDER_NAME", "Keycloak"),
		Issuer: os.Getenv("OIDC_ISSUER"), ClientID: os.Getenv("OIDC_CLIENT_ID"), ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RoleClaim: env("OIDC_ROLE_CLAIM", "realm_access.roles"), MFAMode: env("OIDC_MFA_MODE", "claim"),
		BootstrapAdmins: admins, PublicURL: publicURL, WebURL: webURL, SessionTTL: ttl,
	}, pg)
	if os.Getenv("OIDC_ISSUER") == "" {
		slog.Warn("OIDC_ISSUER is not set: nobody can sign in until an identity provider is configured")
	}

	overrides, err := pg.GeoOverrides(ctx)
	if err != nil {
		return err
	}
	cityDB, asnDB := os.Getenv("GEOIP_CITY_DB"), os.Getenv("GEOIP_ASN_DB")
	var geoUpd *correlate.GeoUpdater
	if key := os.Getenv("MAXMIND_LICENSE_KEY"); cityDB == "" && key != "" {
		geoUpd = &correlate.GeoUpdater{Dir: env("GEOIP_DIR", "data/geoip"), AccountID: os.Getenv("MAXMIND_ACCOUNT_ID"), LicenseKey: key, MaxAge: 7 * 24 * time.Hour}
		c, a, _, err := geoUpd.Ensure(ctx)
		if err != nil {
			slog.Warn("GeoLite2 update failed", "err", err)
		}
		cityDB, asnDB = c, a
	}
	geo, err := correlate.NewGeo(overrides, cityDB, asnDB)
	if err != nil {
		return err
	}
	if cityDB == "" {
		slog.Warn("no GeoIP database (set MAXMIND_LICENSE_KEY or GEOIP_CITY_DB): addresses outside geoip_overrides resolve to country ZZ")
	} else {
		slog.Info("GeoIP enrichment on", "city", cityDB, "asn", asnDB)
	}

	hub := api.NewHub(webURL)
	var mailTo []string
	for _, a := range strings.Split(os.Getenv("ALERT_EMAIL_TO"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			mailTo = append(mailTo, a)
		}
	}
	notify := api.Notifiers(api.Notifier(os.Getenv("ESCALATION_WEBHOOK_URL")), api.EmailNotifier(api.EmailConfig{
		Addr: os.Getenv("SMTP_ADDR"), Security: env("SMTP_SECURITY", "starttls"), Username: os.Getenv("SMTP_USERNAME"), Password: os.Getenv("SMTP_PASSWORD"),
		From: os.Getenv("SMTP_FROM"), To: mailTo, WebURL: webURL}))
	engine := correlate.NewEngine(pg, ch, geo, hub.Publish, notify)
	var rdb *redis.Client
	if u := os.Getenv("REDIS_URL"); u != "" {
		opt, err := redis.ParseURL(u)
		if err != nil {
			return fmt.Errorf("REDIS_URL: %w", err)
		}
		rdb = redis.NewClient(opt)
		defer rdb.Close()
		if err := rdb.Ping(ctx).Err(); err != nil {
			return fmt.Errorf("redis: %w", err)
		}
		engine.UseLive(correlate.NewRedisLive(rdb))
		hub.UseRedis(ctx, rdb)
		slog.Info("cluster mode: campaign state, live stream and config pushes shared through Redis")
	} else {
		slog.Info("single-instance mode (set REDIS_URL to run several control planes)")
	}
	if geoUpd != nil {
		go refreshGeo(ctx, geoUpd, engine, pg)
	}
	live, err := pg.LiveCampaigns(ctx)
	if err != nil {
		return err
	}
	engine.Restore(ctx, live)
	go engine.Run(ctx)

	certPEM, keyPEM, err := pg.PKI(ctx, agentrpc.GenerateCA)
	if err != nil {
		return err
	}
	ca, err := agentrpc.ParseCA(certPEM, keyPEM)
	if err != nil {
		return err
	}
	grpcAddr := env("GRPC_ADDR", ":8443")
	fleet := agentrpc.NewServer(pg, ch, engine, ca, env("GRPC_PUBLIC_ADDR", "localhost:8443"))
	if rdb != nil {
		fleet.UseRedis(ctx, rdb)
	}

	app := &api.App{PG: pg, CH: ch, Engine: engine, Hub: hub, Fleet: fleet, Auth: auth, PushWait: time.Second,
		AllowPrivateFeeds: env("ALLOW_PRIVATE_FEEDS", "") == "true"}
	app.LoadCorrelation(ctx)
	if err := app.EnsureBundle(ctx); err != nil {
		return errors.Join(errors.New("the stored policy does not compile"), err)
	}
	if rdb != nil {
		app.Leader = api.RedisLeader(rdb)
	}
	go app.RunJobs(ctx)

	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return err
	}
	errc := make(chan error, 2)
	go func() { errc <- fleet.Serve(ctx, lis, strings.Split(env("GRPC_SANS", "localhost,127.0.0.1"), ",")) }()

	srv := &http.Server{Addr: env("HTTP_ADDR", ":8080"), Handler: app.Router(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	slog.Info("control plane up", "http", srv.Addr, "grpc", grpcAddr, "web", webURL)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// refreshGeo checks once a day for newer GeoLite2 builds and swaps them in without a restart.
func refreshGeo(ctx context.Context, u *correlate.GeoUpdater, engine *correlate.Engine, pg *store.PG) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		city, asn, changed, err := u.Ensure(ctx)
		if err != nil {
			slog.Warn("GeoLite2 update failed, keeping the current databases", "err", err)
		}
		if !changed {
			continue
		}
		ov, err := pg.GeoOverrides(ctx)
		if err == nil {
			var g *correlate.Geo
			if g, err = correlate.NewGeo(ov, city, asn); err == nil {
				engine.SetGeo(g)
				slog.Info("GeoLite2 databases updated")
			}
		}
		if err != nil {
			slog.Error("GeoLite2 reload failed", "err", err)
		}
	}
}
