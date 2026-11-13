package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Proxy is the standalone integration: a reverse proxy in front of one upstream.
type Proxy struct {
	core           *Core
	listen         string
	trustedProxies []netip.Prefix // peers whose X-Forwarded-For is believed
	rp             *httputil.ReverseProxy
}

func NewProxy(core *Core, listen, upstream string, trusted []netip.Prefix) (*Proxy, error) {
	up, err := url.Parse(upstream)
	if err != nil || up.Host == "" {
		return nil, fmt.Errorf("upstream %q is not a URL", upstream)
	}
	p := &Proxy{core: core, listen: listen, trustedProxies: trusted}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        func(r *httputil.ProxyRequest) { r.SetURL(up); r.Out.Host = r.In.Host; r.SetXForwarded() },
		ModifyResponse: p.inspectResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if code, blocked := txOf(r).Blocked(); blocked {
				http.Error(w, "Request blocked", code)
				return
			}
			http.Error(w, "Upstream unavailable", http.StatusBadGateway)
		},
	}
	return p, nil
}

type txKey struct{}

func txOf(r *http.Request) *Tx { return r.Context().Value(txKey{}).(*Tx) }

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ClientAddr returns the peer address, or the nearest untrusted X-Forwarded-For hop when the peer is a trusted proxy.
func ClientAddr(remoteAddr, xff string, trusted []netip.Prefix) (netip.Addr, int) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, 0
	}
	peer := ap.Addr().Unmap()
	if !inAny(trusted, peer) {
		return peer, int(ap.Port())
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		if ip, err := netip.ParseAddr(strings.TrimSpace(hops[i])); err == nil && !inAny(trusted, ip.Unmap()) {
			return ip.Unmap(), 0
		}
	}
	return peer, int(ap.Port())
}

// BufferBody reads up to MaxInspectBody of r.Body and puts it back, so a large upload is inspected up to the
// limit and then streamed through instead of being held in memory.
func BufferBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	head, _ := io.ReadAll(io.LimitReader(r.Body, MaxInspectBody))
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(head), r.Body), r.Body}
	return head
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, port := ClientAddr(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), p.trustedProxies)
	t := p.core.Begin(Request{Host: r.Host, Method: r.Method, URI: r.URL.RequestURI(), Proto: r.Proto, Client: ip, ClientPort: port, Header: r.Header, Body: BufferBody(r)})
	rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
	defer func() { t.Finish(rec.code) }()
	if code, blocked := t.Blocked(); blocked {
		http.Error(rec, "Request blocked", code)
		return
	}
	p.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), txKey{}, t)))
}

// inspectResponse runs the response phases (outbound rules such as data leakage, 95xxxx).
func (p *Proxy) inspectResponse(resp *http.Response) error {
	t := txOf(resp.Request)
	if _, blocked := t.ResponseHeaders(resp.StatusCode, resp.Proto, resp.Header); blocked {
		return errors.New("blocked by response headers rule")
	}
	if !t.WantsResponseBody() {
		return nil
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, MaxInspectBody+1))
	if err != nil {
		return err
	}
	if len(head) > MaxInspectBody { // too large to buffer: pass through uninspected
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(head))
	if _, blocked := t.ResponseBody(head); blocked {
		return errors.New("blocked by response body rule")
	}
	return nil
}

// Run serves traffic until ctx ends.
func (p *Proxy) Run(ctx context.Context) error {
	srv := &http.Server{Addr: p.listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	slog.Info("standalone proxy listening", "addr", p.listen, "config", p.core.ConfigVersion())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
