package agentrpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	agentv1 "github.com/Agustian16/WAAP-Platform/server/gen/agent/v1"
	"github.com/Agustian16/WAAP-Platform/server/internal/correlate"
	"github.com/Agustian16/WAAP-Platform/server/internal/model"
	"github.com/Agustian16/WAAP-Platform/server/internal/store"
)

type Server struct {
	agentv1.UnimplementedAgentServiceServer
	pg         *store.PG
	ch         *store.CH
	engine     *correlate.Engine
	ca         *CA
	publicAddr string

	mu      sync.Mutex
	conns   map[string]chan *agentv1.ControlMessage // node id -> outbound queue
	waiters map[int64]chan ack                      // config version -> acks from nodes
}

type ack struct {
	node string
	ok   bool
}

func NewServer(pg *store.PG, ch *store.CH, engine *correlate.Engine, ca *CA, publicAddr string) *Server {
	return &Server{pg: pg, ch: ch, engine: engine, ca: ca, publicAddr: publicAddr,
		conns: map[string]chan *agentv1.ControlMessage{}, waiters: map[int64]chan ack{}}
}

func (s *Server) EnrollHint() (addr, caPin string) { return s.publicAddr, s.ca.Pin() }

// Serve listens with TLS 1.3. A client certificate is optional at the handshake so Enroll can run without one;
// the interceptors require a CA-verified certificate for everything else.
func (s *Server) Serve(ctx context.Context, lis net.Listener, sans []string) error {
	cert, err := s.ca.ServerCert(sans)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.ca.Cert)
	creds := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13})
	g := grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(s.unaryAuth), grpc.StreamInterceptor(s.streamAuth),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 20 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}))
	agentv1.RegisterAgentServiceServer(g, s)
	go func() { <-ctx.Done(); g.Stop() }()
	return g.Serve(lis)
}

type nodeKey struct{}

// nodeID returns the identity from a verified client certificate.
func nodeID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return "", status.Error(codes.Unauthenticated, "a node certificate is required")
	}
	return ti.State.VerifiedChains[0][0].Subject.CommonName, nil
}

func (s *Server) unaryAuth(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if info.FullMethod == agentv1.AgentService_Enroll_FullMethodName {
		return h(ctx, req)
	}
	id, err := nodeID(ctx)
	if err != nil {
		return nil, err
	}
	return h(context.WithValue(ctx, nodeKey{}, id), req)
}

type authedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (a *authedStream) Context() context.Context { return a.ctx }

func (s *Server) streamAuth(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	id, err := nodeID(ss.Context())
	if err != nil {
		return err
	}
	return h(srv, &authedStream{ss, context.WithValue(ss.Context(), nodeKey{}, id)})
}

// Enroll trades a one-time token for a node certificate.
func (s *Server) Enroll(ctx context.Context, req *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	h := sha256.Sum256([]byte(req.Token))
	id, name, err := s.pg.Enroll(ctx, h[:], req.Hostname)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Error(codes.PermissionDenied, "enrollment token is invalid, expired or already used")
	}
	if errors.Is(err, store.ErrConflict) {
		return nil, status.Error(codes.AlreadyExists, "a node with this name is already enrolled")
	}
	if err != nil {
		slog.Error("enroll", "err", err)
		return nil, status.Error(codes.Internal, "enrollment failed")
	}
	cert, err := s.ca.SignNode(req.CsrPem, id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "CSR rejected")
	}
	slog.Info("node enrolled", "node", name, "id", id)
	return &agentv1.EnrollResponse{NodeId: id, CertPem: cert, CaPem: []byte(s.ca.PEM)}, nil
}

func toProto(b model.Bundle) *agentv1.ControlMessage {
	return &agentv1.ControlMessage{Msg: &agentv1.ControlMessage_Config{Config: &agentv1.ConfigBundle{Version: b.Version,
		DefaultDirectives: b.DefaultDirectives, SiteDirectives: b.SiteDirectives, SiteIds: b.SiteIDs, BlockCidrs: b.BlockCIDRs, AllowCidrs: b.AllowCIDRs}}}
}

// Connect is the config stream: hello and heartbeats up, config bundles down.
func (s *Server) Connect(stream agentv1.AgentService_ConnectServer) error {
	ctx := stream.Context()
	id := ctx.Value(nodeKey{}).(string)
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be hello")
	}
	ip := hello.IpAddress
	if ip == "" {
		if p, ok := peer.FromContext(ctx); ok {
			ip, _, _ = net.SplitHostPort(p.Addr.String())
		}
	}
	name, err := s.pg.NodeHello(ctx, id, hello.Hostname, ip, hello.Version, hello.CrsVersion, hello.Proxy, hello.Region, hello.Lon, hello.Lat, hello.ConfigVersion)
	if errors.Is(err, store.ErrNotFound) {
		return status.Error(codes.PermissionDenied, "node is not registered")
	}
	if err != nil {
		return status.Error(codes.Internal, "registration failed")
	}
	out := make(chan *agentv1.ControlMessage, 8)
	s.mu.Lock()
	s.conns[id] = out // a reconnect replaces the previous stream's queue
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.conns[id] == out {
			delete(s.conns, id)
		}
		s.mu.Unlock()
		slog.Info("node disconnected", "node", name)
	}()
	slog.Info("node connected", "node", name, "config", hello.ConfigVersion)

	// Bring a node that is behind (new, or back from an outage) to the deployed version straight away.
	if b, err := s.pg.LatestBundle(ctx); err == nil && b.Version != hello.ConfigVersion {
		out <- toProto(b)
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-out:
				if stream.Send(m) != nil {
					return
				}
			}
		}
	}()
	for {
		m, err := stream.Recv()
		if err == io.EOF || status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return err
		}
		switch x := m.Msg.(type) {
		case *agentv1.NodeMessage_Heartbeat:
			hb := x.Heartbeat
			rps := 0.0
			if hb.IntervalS > 0 {
				rps = float64(hb.Requests) / hb.IntervalS
			}
			if err := s.pg.NodeHeartbeat(ctx, id, hb.Cpu, hb.Memory, rps, hb.LatencyMs, hb.ConfigVersion); err != nil {
				slog.Error("heartbeat", "node", name, "err", err)
			}
			s.ch.AddMetric(store.NodeMetric{At: time.Now().UTC(), NodeID: id, RPS: rps, LatencyMs: hb.LatencyMs, CPU: hb.Cpu, Mem: hb.Memory, Requests: hb.Requests, Blocked: hb.Blocked})
		case *agentv1.NodeMessage_Ack:
			if x.Ack.Ok {
				if err := s.pg.NodeConfigVersion(ctx, id, x.Ack.Version); err != nil {
					slog.Error("ack", "node", name, "err", err)
				}
			} else {
				slog.Error("node rejected config", "node", name, "version", x.Ack.Version, "err", x.Ack.Error)
			}
			s.mu.Lock()
			w := s.waiters[x.Ack.Version]
			s.mu.Unlock()
			if w != nil {
				select {
				case w <- ack{id, x.Ack.Ok}:
				default:
				}
			}
		}
	}
}

// Push sends a bundle to every connected node and collects acks for up to wait (NFR-1.2).
func (s *Server) Push(b model.Bundle, wait time.Duration) map[string]bool {
	msg := toProto(b)
	s.mu.Lock()
	w := make(chan ack, len(s.conns)+1)
	s.waiters[b.Version] = w
	sent := 0
	for _, out := range s.conns {
		select {
		case out <- msg:
			sent++
		default: // queue full: the node is not reading; it will catch up on reconnect
		}
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiters, b.Version)
		s.mu.Unlock()
	}()
	res := map[string]bool{}
	deadline := time.After(wait)
	for len(res) < sent {
		select {
		case a := <-w:
			res[a.node] = a.ok
		case <-deadline:
			return res
		}
	}
	return res
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// AuditStream feeds node transactions into the correlation engine.
func (s *Server) AuditStream(stream agentv1.AgentService_AuditStreamServer) error {
	ctx := stream.Context()
	id := ctx.Value(nodeKey{}).(string)
	var n uint64
	for {
		ev, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&agentv1.AuditAck{Received: n})
		}
		if err != nil {
			return err
		}
		n++
		action := ev.Action
		if action != "DENY" && action != "LOG" && action != "ALLOW" {
			continue
		}
		tx := correlate.Tx{NodeID: id, TransactionID: clip(ev.TransactionId, 64), Host: clip(ev.Host, 255), SiteID: clip(ev.SiteId, 36), ClientIP: clip(ev.ClientIp, 45),
			ClientPort: uint16(ev.ClientPort), At: time.UnixMilli(ev.TimestampMs), Method: clip(ev.Method, 16), URI: clip(ev.Uri, 4096), HTTPVersion: clip(ev.HttpVersion, 16),
			Action: action, Status: uint16(ev.ResponseStatus), Headers: ev.RequestHeaders, Body: clip(ev.RequestBody, 8192), LatencyUs: ev.LatencyUs}
		for _, r := range ev.Rules {
			tx.Rules = append(tx.Rules, correlate.Rule{ID: int(r.Id), Message: clip(r.Message, 512), Data: clip(r.Data, 512), Variable: clip(r.Variable, 255), Severity: r.Severity, Tags: r.Tags})
		}
		s.engine.Process(ctx, tx)
	}
}
