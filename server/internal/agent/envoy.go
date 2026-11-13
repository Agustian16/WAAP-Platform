package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Envoy is the Envoy integration: an External Processing (ext_proc) gRPC service. Envoy sends each request's
// headers and buffered body, then the response's; the node answers "continue" or an immediate 403. Seeing the
// response lets outbound rules (data leakage, web shell output) work as they do in the standalone proxy.
// deploy/integrations/envoy.yaml has the matching Envoy filter configuration.
type Envoy struct {
	extprocv3.UnimplementedExternalProcessorServer
	core   *Core
	listen string
	// TrustedProxies are peers (normally Envoy itself) whose X-Forwarded-For names the client. Envoy also
	// sends the client address as the source.address attribute when configured to, which is preferred.
	TrustedProxies []netip.Prefix
}

func NewEnvoy(core *Core, listen string, trusted []netip.Prefix) *Envoy {
	return &Envoy{core: core, listen: listen, TrustedProxies: trusted}
}

func headerMap(m *corev3.HeaderMap) (pseudo map[string]string, h http.Header) {
	pseudo, h = map[string]string{}, http.Header{}
	for _, kv := range m.GetHeaders() {
		v := kv.GetValue()
		if v == "" && len(kv.GetRawValue()) > 0 {
			v = string(kv.GetRawValue())
		}
		if strings.HasPrefix(kv.GetKey(), ":") {
			pseudo[kv.GetKey()] = v
			continue
		}
		h.Add(kv.GetKey(), v)
	}
	return
}

func (e *Envoy) client(req *extprocv3.ProcessingRequest, h http.Header) (netip.Addr, int) {
	for _, attrs := range req.GetAttributes() {
		if v, ok := attrs.GetFields()["source.address"]; ok {
			if ap, err := netip.ParseAddrPort(v.GetStringValue()); err == nil {
				return ap.Addr().Unmap(), int(ap.Port())
			}
			if a, err := netip.ParseAddr(v.GetStringValue()); err == nil {
				return a.Unmap(), 0
			}
		}
	}
	// Without the attribute, Envoy's own X-Forwarded-For (use_remote_address: true) names the client.
	hops := strings.Split(h.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if ip, err := netip.ParseAddr(strings.TrimSpace(hops[i])); err == nil && !inAny(e.TrustedProxies, ip.Unmap()) {
			return ip.Unmap(), 0
		}
	}
	return netip.Addr{}, 0
}

// protocol reads the request.protocol attribute ("HTTP/2", "HTTP/1.1") when Envoy is configured to send it.
func protocol(req *extprocv3.ProcessingRequest) string {
	for _, attrs := range req.GetAttributes() {
		if v := attrs.GetFields()["request.protocol"].GetStringValue(); strings.HasPrefix(v, "HTTP/") {
			return v
		}
	}
	return "HTTP/1.1"
}

func deny(code int) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &extprocv3.ImmediateResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode(code)}, Body: []byte("Request blocked"), Details: "corazium_waf"}}}
}

var (
	continueReqHeaders  = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{}}}
	continueReqBody     = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}}
	continueRespHeaders = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}}
	continueRespBody    = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{}}}
	continueReqTrailer  = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}}
	continueRespTrailer = &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}}
)

// Process handles one HTTP stream (one request/response exchange).
func (e *Envoy) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var (
		t       *Tx
		pending *Request // headers seen, body still to come
		code    int      // response status, once known
		resp    http.Header
		proto   string
	)
	defer func() {
		if t != nil {
			t.Finish(code)
		}
	}()
	begin := func(r *Request) *extprocv3.ProcessingResponse {
		t = e.core.Begin(*r)
		if c, blocked := t.Blocked(); blocked {
			code = c
			return deny(c)
		}
		return nil
	}
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) || status.Code(err) == codes.Canceled {
			return nil
		}
		if err != nil {
			return err
		}
		var out *extprocv3.ProcessingResponse
		switch r := req.GetRequest().(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			ps, h := headerMap(r.RequestHeaders.GetHeaders())
			ip, port := e.client(req, h)
			host := ps[":authority"]
			if host == "" {
				host = h.Get("Host")
			}
			rq := &Request{Host: host, Method: ps[":method"], URI: ps[":path"], Proto: protocol(req), Client: ip, ClientPort: port, Header: h}
			if r.RequestHeaders.GetEndOfStream() {
				out = begin(rq)
			} else {
				pending = rq // inspect once the buffered body arrives
			}
			if out == nil {
				out = continueReqHeaders
			}
		case *extprocv3.ProcessingRequest_RequestBody:
			if pending != nil {
				body := r.RequestBody.GetBody()
				if len(body) > MaxInspectBody {
					body = body[:MaxInspectBody]
				}
				pending.Body = body
				// HTTP/2 and chunked requests reach Envoy without Content-Length; the body is fully buffered here, so
				// give the engine its real length instead of letting protocol rules flag a missing header.
				if pending.Header.Get("Content-Length") == "" && pending.Header.Get("Transfer-Encoding") == "" {
					pending.Header.Set("Content-Length", strconv.Itoa(len(r.RequestBody.GetBody())))
				}
				out = begin(pending)
				pending = nil
			}
			if out == nil {
				out = continueReqBody
			}
		case *extprocv3.ProcessingRequest_RequestTrailers:
			if pending != nil { // body mode was not BUFFERED: inspect without it
				out = begin(pending)
				pending = nil
			}
			if out == nil {
				out = continueReqTrailer
			}
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			if pending != nil {
				if out = begin(pending); out != nil {
					break
				}
				pending = nil
			}
			ps, h := headerMap(r.ResponseHeaders.GetHeaders())
			code, _ = strconv.Atoi(ps[":status"])
			resp, proto = h, "HTTP/1.1"
			if t != nil {
				if c, blocked := t.ResponseHeaders(code, proto, resp); blocked {
					code, out = c, deny(c)
					break
				}
			}
			out = continueRespHeaders
		case *extprocv3.ProcessingRequest_ResponseBody:
			if t != nil && t.WantsResponseBody() && len(r.ResponseBody.GetBody()) <= MaxInspectBody {
				if c, blocked := t.ResponseBody(r.ResponseBody.GetBody()); blocked {
					code, out = c, deny(c)
					break
				}
			}
			out = continueRespBody
		case *extprocv3.ProcessingRequest_ResponseTrailers:
			out = continueRespTrailer
		default:
			continue
		}
		if err := stream.Send(out); err != nil {
			return err
		}
		if _, immediate := out.GetResponse().(*extprocv3.ProcessingResponse_ImmediateResponse); immediate {
			return nil
		}
	}
}

// Run serves the ext_proc API until ctx ends. Envoy reaches it over its own cluster (plaintext on a private
// network or loopback; put it behind mTLS in Envoy if it crosses hosts).
func (e *Envoy) Run(ctx context.Context) error {
	lis, err := net.Listen("tcp", e.listen)
	if err != nil {
		return err
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, e)
	go func() { <-ctx.Done(); g.GracefulStop() }()
	slog.Info("envoy ext_proc listening", "addr", e.listen, "config", e.core.ConfigVersion())
	return g.Serve(lis)
}
