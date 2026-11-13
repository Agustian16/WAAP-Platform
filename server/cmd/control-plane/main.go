// control-plane is the Corazium backend: REST + WebSocket for the console, gRPC for edge nodes, the attack
// correlation engine, and the stores behind them. Configuration is by environment (see deploy/dev.env).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
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
	envFile := flag.String("env-file", "", "optional file of KEY=VALUE settings")
	flag.Parse()
	if *envFile != "" {
		if err := loadEnvFile(*envFile); err != nil {
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
	auth, err := api.NewAuth(ctx, api.AuthConfig{
		ProviderID: env("OIDC_PROVIDER_ID", "keycloak"), ProviderName: env("OIDC_PROVIDER_NAME", "Keycloak"),
		Issuer: os.Getenv("OIDC_ISSUER"), ClientID: os.Getenv("OIDC_CLIENT_ID"), ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		RoleClaim: env("OIDC_ROLE_CLAIM", "realm_access.roles"), MFAMode: env("OIDC_MFA_MODE", "claim"),
		BootstrapAdmins: admins, PublicURL: publicURL, WebURL: webURL, SessionTTL: ttl,
	}, pg)
	if err != nil {
		return errors.Join(errors.New("OIDC discovery failed; is the identity provider at OIDC_ISSUER reachable?"), err)
	}
	if os.Getenv("OIDC_ISSUER") == "" {
		slog.Warn("OIDC_ISSUER is not set: nobody can sign in until an identity provider is configured")
	}

	overrides, err := pg.GeoOverrides(ctx)
	if err != nil {
		return err
	}
	geo, err := correlate.NewGeo(overrides, os.Getenv("GEOIP_CITY_DB"), os.Getenv("GEOIP_ASN_DB"))
	if err != nil {
		return err
	}
	if os.Getenv("GEOIP_CITY_DB") == "" {
		slog.Warn("GEOIP_CITY_DB is not set: addresses outside geoip_overrides resolve to country ZZ")
	}

	hub := api.NewHub(webURL)
	engine := correlate.NewEngine(pg, ch, geo, hub.Publish, api.Notifier(os.Getenv("ESCALATION_WEBHOOK_URL")))
	live, err := pg.LiveCampaigns(ctx)
	if err != nil {
		return err
	}
	engine.Restore(live)
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

	app := &api.App{PG: pg, CH: ch, Engine: engine, Hub: hub, Fleet: fleet, Auth: auth, PushWait: time.Second,
		AllowPrivateFeeds: env("ALLOW_PRIVATE_FEEDS", "") == "true"}
	app.LoadCorrelation(ctx)
	if err := app.EnsureBundle(ctx); err != nil {
		return errors.Join(errors.New("the stored policy does not compile"), err)
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
