# Corazium control plane (server)

Go backend for the console in `../web`, built to `../Coraza_WAF_Management_Dashboard_PRD.md`.

| Binary | What it is |
| --- | --- |
| `cmd/control-plane` | REST + WebSocket API for the console, gRPC (mTLS) for edge nodes, the attack correlation engine |
| `cmd/edge-agent` | Coraza enforcer node with OWASP Coraza v3 and CRS v4 embedded. `--mode proxy` (standalone reverse proxy), `--mode envoy` (Envoy ext_proc service), `--mode spoa` (HAProxy SPOE agent) |
| `integrations/caddy` | Caddy module `http.handlers.corazium` and a Caddy build that includes it (its own Go module) |
| `cmd/corazium-ctl` | `corazium-ctl validate coraza-policy.yaml` for CI (FR-5.3), same checks as the console |
| `cmd/devsim` | Development only: a demo upstream app and a traffic generator (benign + scripted attackers) |

## Run it locally

Needs Go 1.25, Docker, Node 20+.

```bash
cd server
docker compose -f deploy/docker-compose.yml up -d        # PostgreSQL 16, ClickHouse 24, Redis 7, Keycloak 26, Mailpit
go build -o bin/ ./cmd/...
./bin/control-plane --env-file deploy/local.env --env-file deploy/dev.env   # http :8080, gRPC :8443
./bin/devsim upstream --listen 127.0.0.1:9000             # app to protect
```

`deploy/local.env` is for your own secrets and is git-ignored. Put `MAXMIND_LICENSE_KEY=...` there (a free MaxMind account) and the control plane downloads GeoLite2 City and ASN into `data/geoip` on start and refreshes them weekly. It works without the file, minus GeoIP.

```bash
cd web
echo NEXT_PUBLIC_API_URL=http://localhost:8080 > .env.local
npm run dev -- -p 3210
```

Sign in at http://localhost:3210 with Keycloak. The dev realm (`deploy/keycloak/corazium-realm.json`) has `budi` (Admin), `ahmad` (SecOps Analyst) and `auditor` (Auditor), password `corazium-dev`, and a TOTP second factor whose seed is in that file (add it to an authenticator app, or compute the code from the base32 secret `MNXXEYL2NF2W2LLEMV3C25DPORYC2MBR`). These are development credentials only.

Then, in the console, **Fleet > Register node** gives a one-time token and the CA pin. Run a node with them; afterwards the node uses the certificate in its `--state-dir` and needs neither.

```bash
./bin/edge-agent --control-plane localhost:8443 --ca-pin <pin> --token <token> \
  --upstream http://127.0.0.1:9000 --listen 127.0.0.1:9081 --state-dir .run/edge-1 \
  --region Singapore --lon 103.82 --lat 1.35 --trusted-proxies 127.0.0.1/32
./bin/devsim traffic --targets http://127.0.0.1:9081
```

Every request the simulator sends is inspected by the real engine on the agent; nothing is written to the databases directly. `--trusted-proxies 127.0.0.1/32` lets the simulator's `X-Forwarded-For` stand in for client addresses.

Escalation emails land in Mailpit: http://localhost:58025.

### Proxy integrations

All four share one node core (`internal/agent/core.go`, `tx.go`): enrollment, mTLS link, hot config swap, cached config, masking, audit events. Each integration inspects requests and responses, so outbound rules (SQL error leakage, web shell output) work everywhere.

| Proxy | How | Dev config |
| --- | --- | --- |
| Standalone | `edge-agent --mode proxy --upstream ...` | above |
| Envoy | ext_proc filter; `edge-agent --mode envoy --listen :9002` | `deploy/integrations/envoy.yaml` |
| HAProxy | SPOE filter; `edge-agent --mode spoa --listen :9003` | `deploy/integrations/haproxy.cfg`, `spoe.conf` |
| Caddy | module in the Caddy binary; `corazium { ... }` in the Caddyfile | `deploy/integrations/Caddyfile` |

```bash
docker compose -f deploy/docker-compose.yml --profile integrations up -d   # Envoy on :10000, HAProxy on :8088
cd integrations/caddy && go build -o ../../bin/caddy ./cmd/caddy          # or: xcaddy build --with .../integrations/caddy
CORAZIUM_CA_PIN=... CORAZIUM_TOKEN=... ./bin/caddy run --config deploy/integrations/Caddyfile
```

### Several control plane instances

With `REDIS_URL` set (dev.env does), instances share live campaign state (per-actor lock, so one attacker across instances builds one campaign), the WebSocket stream (every console sees every event) and config pushes (a deploy reaches nodes connected to any instance; acks are read from PostgreSQL). One instance at a time runs the background jobs (feed pulls, list expiry) under a Redis lease. Without `REDIS_URL` it runs as a single instance with the same state in memory.

## Tests

```bash
go test ./...                                             # unit tests (WAF, Go FTW sandbox, correlation, email)
CORAZIUM_TEST_DATABASE_URL=postgres://corazium:corazium-dev@127.0.0.1:55432/corazium \
CORAZIUM_TEST_CLICKHOUSE_ADDR=127.0.0.1:59000 \
CORAZIUM_TEST_REDIS_URL=redis://127.0.0.1:56379/15 go test ./internal/api/
```

The integration test creates its own `corazium_test` databases (and flushes Redis database 15), enrolls a real agent over mTLS and covers authentication, RBAC and CSRF, inspection and masking, correlation and the live stream, the campaign workflow, rule drafts and deploys, CRS switches, exceptions, the block list and threat feeds, users, kill chain mapping, correlation settings, GitOps export and validation, the immutable audit trail, the Envoy ext_proc integration, gRPC certificate checks and, with Redis, a second control plane instance (shared stream, shared campaigns, cross-instance deploy). Without the Redis variable the cluster part is skipped.

On a machine with little free memory, build with `GOFLAGS=-p=1 GOMAXPROCS=2`; the Caddy build also needs `-gcflags=all=-c=1`.

## How it maps to the PRD

| PRD | Where |
| --- | --- |
| 2.1 control plane, gRPC config + audit streams | `internal/agentrpc`, `proto/agent/v1/agent.proto` (regenerate with `go run ./tools/protogen`) |
| 2.1 item 4, Caddy / Envoy / SPOA | `internal/agent` (`proxy.go`, `envoy.go`, `spoa.go`), `integrations/caddy` |
| 5.2 NFR-2.1 mTLS | Built-in CA in PostgreSQL; nodes enroll with a one-time token and a CA pin, then hold a client certificate |
| NFR-1.2 config push | `POST /api/v1/config/deploy` compiles and validates every site's policy, pushes it, waits up to 1 s for acks |
| NFR-3.1 fail-safe | Nodes keep the last config on disk and keep enforcing while the control plane is down; streams reconnect and an event caught by a dead stream is resent |
| NFR-3.2 stateless control plane | `REDIS_URL`: shared campaign state, stream and pushes (`internal/correlate/live.go`) |
| NFR-2.2 OIDC + MFA | `internal/api/auth.go`: authorization code + PKCE, sessions are opaque cookies stored hashed |
| NFR-2.3 masking | `internal/agent/mask.go`: secrets are masked on the node, before they leave it |
| FR-2.4 test sandbox | `internal/waf/ftw.go`: Go FTW against a throwaway Coraza holding only the rules under test; single requests or whole FTW YAML suites |
| FR-6.1 enrichment | `internal/correlate`: GeoLite2 City + ASN (auto-downloaded with `MAXMIND_LICENSE_KEY`), `geoip_overrides` table first |
| FR-6.3 alerts | `internal/api/notify.go`: webhook (Slack-compatible) and email (SMTP, STARTTLS required by default) |
| 6.1 / 6.3 PostgreSQL | `internal/store/migrations/001_init.sql`; the audit trail rejects UPDATE and DELETE by trigger |
| 6.2 / 6.3 ClickHouse | `internal/store/ch.go`: `coraza_audit_logs`, `attack_events`, `node_metrics` |
| Module 6 correlation | `internal/correlate`: enrichment, kill chain mapping, campaigns, risk score, escalation alerts |

## Configuration

All settings are environment variables; `deploy/dev.env` lists them. Production needs at least:

- `DATABASE_URL`, `CLICKHOUSE_ADDR` (+ `CLICKHOUSE_DB`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`)
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ROLE_CLAIM`. `OIDC_MFA_MODE=claim` (the default) requires MFA evidence in the token's `amr`; use `idp` only when the IdP enforces MFA and does not emit `amr`. An unreachable IdP does not stop the control plane; sign-in retries discovery.
- `PUBLIC_URL` (https in production, so cookies are `Secure`), `WEB_URL` (the console origin; the only origin the API accepts)
- `GRPC_PUBLIC_ADDR` and `GRPC_SANS` (the name nodes dial must be in the server certificate)

Optional:

- GeoIP: `MAXMIND_LICENSE_KEY` (+ `MAXMIND_ACCOUNT_ID`, `GEOIP_DIR`), or fixed files with `GEOIP_CITY_DB` / `GEOIP_ASN_DB`.
- Cluster: `REDIS_URL`.
- Alerts: `ESCALATION_WEBHOOK_URL`; `SMTP_ADDR`, `SMTP_SECURITY` (`starttls` default, `tls`, `none`), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_EMAIL_TO` (comma separated).
- `BOOTSTRAP_ADMINS`.

## Known gaps and next phase

- **Throughput (POC phase):** the NFR-1.3/1.4 rates (10,000 events/s into ClickHouse, 30 FPS at 5,000 graph nodes) have not been load-tested. Planned for the proof-of-concept phase.
- **Request-only fields over Envoy:** without `source.address` in `request_attributes`, the Envoy integration reads the client from `X-Forwarded-For`; production configs should send the attribute.
- **Alerts:** webhook and email. No SIEM-specific formats (CEF, syslog) yet.
