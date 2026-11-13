// edge-agent is the Coraza enforcer node. One binary, three integrations (see internal/agent):
//
//	--mode proxy   standalone reverse proxy in front of --upstream (default)
//	--mode envoy   Envoy External Processing (ext_proc) gRPC service
//	--mode spoa    HAProxy SPOE agent
//
// The Caddy integration is a Caddy module instead: integrations/caddy.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Agustian16/WAAP-Platform/server/internal/agent"
)

func main() {
	var c agent.Config
	var mode, listen, upstream, trusted string
	flag.StringVar(&mode, "mode", "proxy", "integration: proxy, envoy or spoa")
	flag.StringVar(&c.ControlPlane, "control-plane", "", "control plane gRPC address, host:port")
	flag.StringVar(&c.CAPin, "ca-pin", "", "SHA-256 of the control plane CA (first run only)")
	flag.StringVar(&c.Token, "token", "", "one-time enrollment token (first run only)")
	flag.StringVar(&c.StateDir, "state-dir", "./corazium-node", "directory for the node key, certificate and cached config")
	flag.StringVar(&listen, "listen", "", "listen address (default :8080 proxy, :9002 envoy, :9000 spoa)")
	flag.StringVar(&upstream, "upstream", "", "proxy mode: URL of the application to protect")
	flag.StringVar(&c.Region, "region", "", "region label shown in Fleet")
	flag.Float64Var(&c.Lon, "lon", 0, "longitude of this node (attack map)")
	flag.Float64Var(&c.Lat, "lat", 0, "latitude of this node (attack map)")
	flag.StringVar(&c.AdvertiseIP, "advertise-ip", "", "IP address reported to the control plane (default: outbound interface)")
	flag.StringVar(&trusted, "trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is trusted")
	flag.BoolVar(&c.LogAllowed, "log-allowed", true, "report transactions that matched no rule")
	flag.DurationVar(&c.Heartbeat, "heartbeat", 5*time.Second, "heartbeat interval")
	flag.Parse()

	var proxies []netip.Prefix
	for _, s := range strings.Split(trusted, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			fail("bad --trusted-proxies entry", "value", s)
		}
		proxies = append(proxies, p)
	}
	if c.ControlPlane == "" {
		flag.Usage()
		os.Exit(2)
	}
	def := map[string]string{"proxy": ":8080", "envoy": ":9002", "spoa": ":9000"}[mode]
	if def == "" {
		fail("unknown --mode", "mode", mode)
	}
	if listen == "" {
		listen = def
	}
	c.Proxy = map[string]string{"proxy": "Standalone", "envoy": "Envoy", "spoa": "SPOA"}[mode]

	core, err := agent.NewCore(c)
	if err != nil {
		fail("start", "err", err)
	}
	var run func(context.Context) error
	switch mode {
	case "proxy":
		if upstream == "" {
			fail("--upstream is required in proxy mode")
		}
		p, err := agent.NewProxy(core, listen, upstream, proxies)
		if err != nil {
			fail("start", "err", err)
		}
		run = p.Run
	case "envoy":
		run = agent.NewEnvoy(core, listen, proxies).Run
	case "spoa":
		run = agent.NewSPOA(core, listen).Run
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := core.Start(ctx); err != nil {
		fail("control plane link", "err", err)
	}
	if err := run(ctx); err != nil {
		fail("agent stopped", "err", err)
	}
}

func fail(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
