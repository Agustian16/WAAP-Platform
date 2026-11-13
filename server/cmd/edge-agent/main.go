// edge-agent is the Coraza enforcer node. See internal/agent.
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
	var trusted string
	flag.StringVar(&c.ControlPlane, "control-plane", "", "control plane gRPC address, host:port")
	flag.StringVar(&c.CAPin, "ca-pin", "", "SHA-256 of the control plane CA (first run only)")
	flag.StringVar(&c.Token, "token", "", "one-time enrollment token (first run only)")
	flag.StringVar(&c.StateDir, "state-dir", "./corazium-node", "directory for the node key, certificate and cached config")
	flag.StringVar(&c.Listen, "listen", ":8080", "address to serve protected traffic on")
	flag.StringVar(&c.Upstream, "upstream", "", "URL of the application to protect")
	flag.StringVar(&c.Region, "region", "", "region label shown in Fleet")
	flag.Float64Var(&c.Lon, "lon", 0, "longitude of this node (attack map)")
	flag.Float64Var(&c.Lat, "lat", 0, "latitude of this node (attack map)")
	flag.StringVar(&c.AdvertiseIP, "advertise-ip", "", "IP address reported to the control plane (default: outbound interface)")
	flag.StringVar(&trusted, "trusted-proxies", "", "comma-separated CIDRs whose X-Forwarded-For is trusted")
	flag.BoolVar(&c.LogAllowed, "log-allowed", true, "report transactions that matched no rule")
	flag.DurationVar(&c.Heartbeat, "heartbeat", 5*time.Second, "heartbeat interval")
	flag.Parse()
	if c.ControlPlane == "" || c.Upstream == "" {
		flag.Usage()
		os.Exit(2)
	}
	for _, s := range strings.Split(trusted, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			slog.Error("bad --trusted-proxies entry", "value", s)
			os.Exit(2)
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	a, err := agent.New(c)
	if err != nil {
		slog.Error("start", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		slog.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
