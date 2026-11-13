// Package caddy is the Caddy integration: an HTTP handler module (http.handlers.corazium) that inspects every
// request and response with the node core in internal/agent. Build a Caddy with it:
//
//	cd server/integrations/caddy && go build -o caddy ./cmd/caddy
//
// or with xcaddy: xcaddy build --with github.com/Agustian16/WAAP-Platform/server/integrations/caddy=./server/integrations/caddy
//
// Caddyfile:
//
//	shop.example.com {
//		corazium {
//			control_plane cp.example.com:8443
//			ca_pin   <from Fleet > Register node>
//			token    <from Fleet > Register node>   # first start only
//			state_dir /var/lib/corazium
//			region   Singapore
//			location 103.82 1.35
//		}
//		reverse_proxy app:8000
//	}
//
// Client addresses come from Caddy itself, so Caddy's own trusted_proxies setting decides when
// X-Forwarded-For is believed.
package caddy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/Agustian16/WAAP-Platform/server/internal/agent"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("corazium", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("corazium", httpcaddyfile.Before, "rewrite")
}

// Handler is the module. One node core is shared by every handler with the same state_dir, and it survives
// config reloads, so a reload neither re-enrolls nor drops the control plane link.
type Handler struct {
	ControlPlane string  `json:"control_plane"`
	CAPin        string  `json:"ca_pin,omitempty"`
	Token        string  `json:"token,omitempty"`
	StateDir     string  `json:"state_dir"`
	Region       string  `json:"region,omitempty"`
	Lon          float64 `json:"lon,omitempty"`
	Lat          float64 `json:"lat,omitempty"`
	LogAllowed   *bool   `json:"log_allowed,omitempty"`

	core *agent.Core
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.corazium", New: func() caddy.Module { return new(Handler) }}
}

var cores = caddy.NewUsagePool()

type sharedCore struct {
	core   *agent.Core
	cancel context.CancelFunc
}

func (s sharedCore) Destruct() error { s.cancel(); return nil }

func (h *Handler) Provision(caddy.Context) error {
	if h.ControlPlane == "" || h.StateDir == "" {
		return errors.New("corazium: control_plane and state_dir are required")
	}
	val, _, err := cores.LoadOrNew(h.StateDir, func() (caddy.Destructor, error) {
		logAllowed := h.LogAllowed == nil || *h.LogAllowed
		core, err := agent.NewCore(agent.Config{ControlPlane: h.ControlPlane, CAPin: h.CAPin, Token: h.Token, StateDir: h.StateDir,
			Proxy: "Caddy", Region: h.Region, Lon: h.Lon, Lat: h.Lat, LogAllowed: logAllowed})
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := core.Start(ctx); err != nil {
			cancel()
			return nil, err
		}
		return sharedCore{core, cancel}, nil
	})
	if err != nil {
		return fmt.Errorf("corazium: %w", err)
	}
	h.core = val.(sharedCore).core
	return nil
}

func (h *Handler) Cleanup() error {
	_, err := cores.Delete(h.StateDir)
	return err
}

func blockedResponse(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte("Request blocked\n"))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	client, _ := netip.ParseAddr(ip)
	t := h.core.Begin(agent.Request{Host: r.Host, Method: r.Method, URI: r.URL.RequestURI(), Proto: r.Proto, Client: client.Unmap(),
		Header: r.Header, Body: agent.BufferBody(r)})
	if code, blocked := t.Blocked(); blocked {
		blockedResponse(w, code)
		t.Finish(code)
		return nil
	}
	// Buffer the response only when it must be inspected or replaced; everything else streams through.
	buf := new(bytes.Buffer)
	rec := caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		if _, blocked := t.ResponseHeaders(status, r.Proto, header); blocked {
			return true
		}
		if !t.WantsResponseBody() {
			return false
		}
		n, err := strconv.Atoi(header.Get("Content-Length"))
		return err != nil || n <= agent.MaxInspectBody // ponytail: unknown-length responses are buffered whole
	})
	if err := next.ServeHTTP(rec, r); err != nil {
		code := http.StatusInternalServerError
		var he caddyhttp.HandlerError
		if errors.As(err, &he) {
			code = he.StatusCode
		}
		t.Finish(code)
		return err
	}
	if !rec.Buffered() {
		t.Finish(rec.Status())
		return nil
	}
	code, blocked := t.Blocked()
	if !blocked && t.WantsResponseBody() && buf.Len() <= agent.MaxInspectBody {
		code, blocked = t.ResponseBody(buf.Bytes())
	}
	if blocked {
		blockedResponse(w, code)
		t.Finish(code)
		return nil
	}
	t.Finish(rec.Status())
	return rec.WriteResponse()
}

// UnmarshalCaddyfile reads the corazium { ... } block.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // directive name
	for d.NextBlock(0) {
		key := d.Val()
		args := d.RemainingArgs()
		one := func() (string, error) {
			if len(args) != 1 {
				return "", d.ArgErr()
			}
			return args[0], nil
		}
		var err error
		switch key {
		case "control_plane":
			h.ControlPlane, err = one()
		case "ca_pin", "token":
			// Needed on the first start only, so an unset {$ENV} placeholder (no argument) is allowed.
			if len(args) > 1 {
				return d.ArgErr()
			}
			if len(args) == 1 {
				if key == "ca_pin" {
					h.CAPin = args[0]
				} else {
					h.Token = args[0]
				}
			}
		case "state_dir":
			h.StateDir, err = one()
		case "region":
			h.Region, err = one()
		case "location":
			if len(args) != 2 {
				return d.Err("location takes longitude and latitude")
			}
			if h.Lon, err = strconv.ParseFloat(args[0], 64); err == nil {
				h.Lat, err = strconv.ParseFloat(args[1], 64)
			}
		case "log_allowed":
			var v string
			if v, err = one(); err == nil {
				var b bool
				b, err = strconv.ParseBool(v)
				h.LogAllowed = &b
			}
		default:
			return d.Errf("unknown corazium option %q", key)
		}
		if err != nil {
			return d.Errf("%s: %v", key, err)
		}
	}
	return nil
}

func parseCaddyfile(hp httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := new(Handler)
	err := h.UnmarshalCaddyfile(hp.Dispenser)
	return h, err
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
