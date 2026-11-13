// Package agent is the Coraza enforcer node (PRD 2.1 item 4). Core holds what every integration shares: the
// enrollment and mTLS link to the control plane, config hot-swap without dropping traffic, the cached config,
// and the audit event stream. The integrations (proxy.go standalone reverse proxy, envoy.go ext_proc, spoa.go
// HAProxy, and the Caddy module in integrations/caddy) only translate their request model into Tx calls.
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	agentv1 "github.com/Agustian16/WAAP-Platform/server/gen/agent/v1"
	"github.com/Agustian16/WAAP-Platform/server/internal/agentrpc"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/waf"
)

const Version = "0.1.0"

// Config is what every integration (standalone proxy, Caddy, Envoy, HAProxy) needs to reach the control plane.
type Config struct {
	ControlPlane string // host:port of the gRPC listener
	CAPin        string // SHA-256 of the control plane CA, needed only to enroll
	Token        string // one-time enrollment token, needed only to enroll
	StateDir     string // node key, certificate and the cached config live here
	Proxy        string // integration name shown in Fleet: Standalone, Caddy, Envoy, SPOA
	Region       string
	Lon, Lat     float64
	AdvertiseIP  string
	LogAllowed   bool // also report transactions that matched no rule
	Heartbeat    time.Duration
}

// runtime is one applied configuration. It is swapped atomically, so in-flight requests finish on the engines
// they started with and new requests see the new ones: a hot reload with no dropped traffic.
type runtime struct {
	version      int64
	def          coraza.WAF
	sites        map[string]coraza.WAF
	siteIDs      map[string]string
	block, allow []netip.Prefix
}

// Core is the part of an enforcer node shared by every proxy integration.
type Core struct {
	cfg     Config
	cur     atomic.Pointer[runtime]
	events  chan *agentv1.AuditEvent
	dropped atomic.Uint64

	requests, blocked, wafNanos atomic.Uint64
	// lastBeat is when the counters were last reported. It survives reconnects, so traffic counted during a
	// control plane outage is spread over the whole outage, not over the first interval after it.
	lastBeat time.Time
	// unsent is an event whose stream died under it; auditStream runs one at a time (see retry), so no lock.
	unsent *agentv1.AuditEvent
}

func build(b model.Bundle) (*runtime, error) {
	rt := &runtime{version: b.Version, sites: map[string]coraza.WAF{}, siteIDs: b.SiteIDs}
	var err error
	if rt.def, err = waf.NewEngine(b.DefaultDirectives); err != nil {
		return nil, fmt.Errorf("default policy: %w", err)
	}
	for host, d := range b.SiteDirectives {
		if rt.sites[host], err = waf.NewEngine(d); err != nil {
			return nil, fmt.Errorf("%s: %w", host, err)
		}
	}
	for _, l := range []struct {
		in  []string
		out *[]netip.Prefix
	}{{b.BlockCIDRs, &rt.block}, {b.AllowCIDRs, &rt.allow}} {
		for _, c := range l.in {
			if p, err := netip.ParsePrefix(c); err == nil {
				*l.out = append(*l.out, p)
			}
		}
	}
	return rt, nil
}

// NewCore loads the last applied config, or the baseline CRS policy on a node that has never had one.
func NewCore(cfg Config) (*Core, error) {
	if cfg.Heartbeat <= 0 {
		cfg.Heartbeat = 5 * time.Second
	}
	if cfg.Proxy == "" {
		cfg.Proxy = "Standalone"
	}
	a := &Core{cfg: cfg, events: make(chan *agentv1.AuditEvent, 8192), lastBeat: time.Now()}
	// NFR-3.1: start from the last config this node applied; with none cached, from the baseline CRS policy.
	// Either way the node inspects traffic before, and without, the control plane.
	b, ok := a.loadCache()
	if !ok {
		b.DefaultDirectives, b.SiteDirectives, b.SiteIDs = waf.Compile(waf.Policy{})
	}
	rt, err := build(b)
	if err != nil {
		return nil, err
	}
	a.cur.Store(rt)
	return a, nil
}

func (a *Core) cachePath() string { return filepath.Join(a.cfg.StateDir, "bundle.json") }

func (a *Core) loadCache() (b model.Bundle, ok bool) {
	raw, err := os.ReadFile(a.cachePath())
	return b, err == nil && json.Unmarshal(raw, &b) == nil && b.DefaultDirectives != ""
}

// apply builds engines for a pushed bundle and swaps them in. A bundle that does not build is rejected and the
// node keeps running what it has.
func (a *Core) apply(c *agentv1.ConfigBundle) error {
	b := model.Bundle{Version: c.Version, DefaultDirectives: c.DefaultDirectives, SiteDirectives: c.SiteDirectives, SiteIDs: c.SiteIds, BlockCIDRs: c.BlockCidrs, AllowCIDRs: c.AllowCidrs}
	rt, err := build(b)
	if err != nil {
		return err
	}
	a.cur.Store(rt)
	if raw, err := json.Marshal(b); err == nil {
		tmp := a.cachePath() + ".tmp"
		if os.WriteFile(tmp, raw, 0o600) == nil {
			_ = os.Rename(tmp, a.cachePath())
		}
	}
	return nil
}

func inAny(ps []netip.Prefix, a netip.Addr) bool {
	// ponytail: linear scan, fine for thousands of entries; switch to a radix tree if feeds grow past ~50k.
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (a *Core) emit(ev *agentv1.AuditEvent, action string, code int, wafTime time.Duration, rules []*agentv1.MatchedRule) {
	a.wafNanos.Add(uint64(wafTime))
	if action == "ALLOW" && !a.cfg.LogAllowed {
		return
	}
	if ev.TransactionId == "" {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		ev.TransactionId = fmt.Sprintf("%x", b)
	}
	ev.Action, ev.ResponseStatus, ev.LatencyUs, ev.Rules = action, uint32(code), uint64(wafTime.Microseconds()), rules
	select {
	case a.events <- ev:
	default: // the control plane is unreachable and the buffer is full: enforcement continues, this event is lost
		a.dropped.Add(1)
	}
}

// ---------- Control plane link ----------

func (a *Core) file(name string) string { return filepath.Join(a.cfg.StateDir, name) }

// enroll runs once: it proves the control plane's identity with the CA pin, sends a CSR with the one-time
// token, and stores the signed certificate. The private key never leaves the node.
func (a *Core) enroll(ctx context.Context) error {
	if a.cfg.Token == "" || a.cfg.CAPin == "" {
		return errors.New("this node is not enrolled: pass --token and --ca-pin from Fleet > Register node")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "corazium-node"}}, key)
	if err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(a.cfg.ControlPlane)
	// Chain verification is replaced, not skipped: the server must present the CA whose hash is pinned, and its
	// leaf must verify against that CA for this host name.
	tc := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: host, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			pool := x509.NewCertPool()
			for _, c := range cs.PeerCertificates {
				if agentrpc.PinOf(c.Raw) == strings.ToLower(a.cfg.CAPin) {
					pool.AddCert(c)
				}
			}
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, DNSName: host})
			if err != nil {
				return fmt.Errorf("control plane does not match --ca-pin: %w", err)
			}
			return nil
		}}
	conn, err := grpc.NewClient(a.cfg.ControlPlane, grpc.WithTransportCredentials(credentials.NewTLS(tc)))
	if err != nil {
		return err
	}
	defer conn.Close()
	hostname, _ := os.Hostname()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	res, err := agentv1.NewAgentServiceClient(conn).Enroll(ctx, &agentv1.EnrollRequest{Token: a.cfg.Token, Hostname: hostname,
		CsrPem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})})
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"node.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), "node.crt": res.CertPem, "ca.crt": res.CaPem} {
		if err := os.WriteFile(a.file(name), data, 0o600); err != nil {
			return err
		}
	}
	slog.Info("enrolled", "node_id", res.NodeId)
	return nil
}

func (a *Core) dial() (*grpc.ClientConn, error) {
	cert, err := tls.LoadX509KeyPair(a.file("node.crt"), a.file("node.key"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(a.file("ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca.crt is not a certificate")
	}
	host, _, _ := net.SplitHostPort(a.cfg.ControlPlane)
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13})
	return grpc.NewClient(a.cfg.ControlPlane, grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}))
}

func (a *Core) advertiseIP() string {
	if a.cfg.AdvertiseIP != "" {
		return a.cfg.AdvertiseIP
	}
	if c, err := net.Dial("udp", a.cfg.ControlPlane); err == nil {
		defer c.Close()
		if h, _, err := net.SplitHostPort(c.LocalAddr().String()); err == nil {
			return h
		}
	}
	return ""
}

// configStream holds the Connect stream open: hello, then heartbeats up and config bundles down.
func (a *Core) configStream(ctx context.Context, client agentv1.AgentServiceClient) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	send := make(chan *agentv1.NodeMessage, 4)
	send <- &agentv1.NodeMessage{Msg: &agentv1.NodeMessage_Hello{Hello: &agentv1.Hello{Hostname: hostname, IpAddress: a.advertiseIP(),
		Version: "corazium-edge " + Version + " (" + waf.EngineVersion() + ")", CrsVersion: waf.CRSVersion(), Proxy: a.cfg.Proxy,
		Region: a.cfg.Region, Lon: a.cfg.Lon, Lat: a.cfg.Lat, ConfigVersion: a.cur.Load().version}}}
	errc := make(chan error, 2)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			if c := m.GetConfig(); c != nil {
				ack := &agentv1.ConfigAck{Version: c.Version, Ok: true}
				if err := a.apply(c); err != nil {
					ack.Ok, ack.Error = false, err.Error()
					slog.Error("config rejected, keeping the running config", "version", c.Version, "err", err)
				} else {
					slog.Info("config applied", "version", c.Version)
				}
				select {
				case send <- &agentv1.NodeMessage{Msg: &agentv1.NodeMessage_Ack{Ack: ack}}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	tick := time.NewTicker(a.cfg.Heartbeat)
	defer tick.Stop()
	_, _ = cpu.Percent(0, false) // prime: the first call has no interval to measure
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case m := <-send:
			if err := stream.Send(m); err != nil {
				return err
			}
		case now := <-tick.C:
			hb := &agentv1.Heartbeat{Requests: a.requests.Swap(0), Blocked: a.blocked.Swap(0), IntervalS: now.Sub(a.lastBeat).Seconds(), ConfigVersion: a.cur.Load().version}
			if n := a.wafNanos.Swap(0); hb.Requests > 0 {
				hb.LatencyMs = float64(n) / float64(hb.Requests) / 1e6
			}
			if p, err := cpu.Percent(0, false); err == nil && len(p) > 0 {
				hb.Cpu = p[0]
			}
			if v, err := mem.VirtualMemory(); err == nil {
				hb.Memory = v.UsedPercent
			}
			a.lastBeat = now // configStream runs one at a time (see retry), so no lock is needed
			if err := stream.Send(&agentv1.NodeMessage{Msg: &agentv1.NodeMessage_Heartbeat{Heartbeat: hb}}); err != nil {
				return err
			}
		}
	}
}

func (a *Core) auditStream(ctx context.Context, client agentv1.AgentServiceClient) error {
	stream, err := client.AuditStream(ctx)
	if err != nil {
		return err
	}
	send := func(ev *agentv1.AuditEvent) error {
		if err := stream.Send(ev); err != nil {
			a.unsent = ev // the stream was already dead: deliver this one first on the next stream
			if _, rerr := stream.CloseAndRecv(); rerr != nil {
				err = rerr // Send only reports EOF; the real cause comes back here
			}
			return err
		}
		return nil
	}
	if ev := a.unsent; ev != nil {
		a.unsent = nil
		if err := send(ev); err != nil {
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return ctx.Err()
		case <-stream.Context().Done():
			// The connection broke while this node was idle. Without this a quiet node would only find out on its
			// next event, after the control plane restarted, and lose that event.
			return context.Cause(stream.Context())
		case ev := <-a.events:
			if err := send(ev); err != nil {
				return err
			}
		}
	}
}

// retry keeps one stream alive with capped backoff. Traffic inspection never depends on it (NFR-3.1).
func retry(ctx context.Context, name string, run func() error) {
	backoff := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		err := run()
		if ctx.Err() != nil {
			return
		}
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		slog.Warn("control plane link down, retrying", "stream", name, "in", backoff, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// Start enrolls if needed and opens the control plane link. The streams run until ctx ends and reconnect on
// their own; traffic inspection never waits for them (NFR-3.1).
func (a *Core) Start(ctx context.Context) error {
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(a.file("node.crt")); err != nil {
		if err := a.enroll(ctx); err != nil {
			return err
		}
	}
	conn, err := a.dial()
	if err != nil {
		return err
	}
	client := agentv1.NewAgentServiceClient(conn)
	go retry(ctx, "config", func() error { return a.configStream(ctx, client) })
	go retry(ctx, "audit", func() error { return a.auditStream(ctx, client) })
	go func() { <-ctx.Done(); conn.Close() }()
	return nil
}

// ConfigVersion is the version of the configuration currently enforced.
func (a *Core) ConfigVersion() int64 { return a.cur.Load().version }
