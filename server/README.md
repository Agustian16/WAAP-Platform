# Corazium control plane (server)

Go backend for the console in `../web`, built to `../Coraza_WAF_Management_Dashboard_PRD.md`.

| Binary | What it is |
| --- | --- |
| `cmd/control-plane` | REST + WebSocket API for the console, gRPC (mTLS) for edge nodes, the attack correlation engine |
| `cmd/edge-agent` | Coraza enforcer node: a reverse proxy with OWASP Coraza v3 and CRS v4 embedded |
| `cmd/corazium-ctl` | `corazium-ctl validate coraza-policy.yaml` for CI (FR-5.3), same checks as the console |
| `cmd/devsim` | Development only: a demo upstream app and a traffic generator (benign + scripted attackers) |

## Run it locally

Needs Go 1.25, Docker, Node 20+.

```bash
cd server
docker compose -f deploy/docker-compose.yml up -d        # PostgreSQL 16, ClickHouse 24, Keycloak 26
go build -o bin/ ./cmd/...
./bin/control-plane --env-file deploy/dev.env             # http :8080, gRPC :8443
./bin/devsim upstream --listen 127.0.0.1:9000             # app to protect
```

```bash
cd web
echo NEXT_PUBLIC_API_URL=http://localhost:8080 > .env.local
npm run dev -- -p 3210
```

Sign in at http://localhost:3210 with Keycloak. The dev realm (`deploy/keycloak/corazium-realm.json`) has `budi` (Admin), `ahmad` (SecOps Analyst) and `auditor` (Auditor), password `corazium-dev`, and a TOTP second factor whose seed is in that file (add it to an authenticator app, or compute the code from the base32 secret `MNXXEYL2NF2W2LLEMV3C25DPORYC2MBR`). These are development credentials only.

Then, in the console, **Fleet > Register node** gives an `edge-agent` command with a one-time token and the CA pin. Run it with your own ports:

```bash
./bin/edge-agent --control-plane localhost:8443 --ca-pin <pin> --token <token> \
  --upstream http://127.0.0.1:9000 --listen 127.0.0.1:9081 --state-dir .run/edge-1 \
  --region Singapore --lon 103.82 --lat 1.35 --trusted-proxies 127.0.0.1/32
./bin/devsim traffic --targets http://127.0.0.1:9081
```

Every request the simulator sends is inspected by the real engine on the agent; nothing is written to the databases directly. `--trusted-proxies 127.0.0.1/32` lets the simulator's `X-Forwarded-For` stand in for client addresses.

## Tests

```bash
go test ./...                                             # unit tests (WAF compile/sandbox, correlation)
CORAZIUM_TEST_DATABASE_URL=postgres://corazium:corazium-dev@127.0.0.1:55432/corazium \
CORAZIUM_TEST_CLICKHOUSE_ADDR=127.0.0.1:59000 go test ./internal/api/
```

The integration test creates its own `corazium_test` databases, enrolls a real agent over mTLS and covers authentication, RBAC and CSRF, inspection and masking, correlation and the live stream, the campaign workflow, rule drafts and deploys, CRS switches, exceptions, the block list and threat feeds, users, kill chain mapping, correlation settings, GitOps export and validation, the immutable audit trail, and gRPC certificate checks.

## How it maps to the PRD

| PRD | Where |
| --- | --- |
| 2.1 control plane, gRPC config + audit streams | `internal/agentrpc`, `proto/agent/v1/agent.proto` (regenerate with `go run ./tools/protogen`) |
| 5.2 NFR-2.1 mTLS | Built-in CA in PostgreSQL; nodes enroll with a one-time token and a CA pin, then hold a client certificate |
| NFR-1.2 config push | `POST /api/v1/config/deploy` compiles and validates every site's policy, pushes it, waits up to 1 s for acks |
| NFR-3.1 fail-safe | Agents keep the last config on disk and keep enforcing while the control plane is down; streams reconnect |
| NFR-2.2 OIDC + MFA | `internal/api/auth.go`: authorization code + PKCE, sessions are opaque cookies stored hashed |
| NFR-2.3 masking | `internal/agent/mask.go`: secrets are masked on the node, before they leave it |
| 6.1 / 6.3 PostgreSQL | `internal/store/migrations/001_init.sql`; the audit trail rejects UPDATE and DELETE by trigger |
| 6.2 / 6.3 ClickHouse | `internal/store/ch.go`: `coraza_audit_logs`, `attack_events`, `node_metrics` |
| Module 6 correlation | `internal/correlate`: enrichment, kill chain mapping, campaigns, risk score, escalation alerts |

## Configuration

All settings are environment variables; `deploy/dev.env` lists them. Production needs at least:

- `DATABASE_URL`, `CLICKHOUSE_ADDR` (+ `CLICKHOUSE_DB`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`)
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_ROLE_CLAIM`. `OIDC_MFA_MODE=claim` (the default) requires MFA evidence in the token's `amr`; use `idp` only when the IdP enforces MFA and does not emit `amr`.
- `PUBLIC_URL` (https in production, so cookies are `Secure`), `WEB_URL` (the console origin; the only origin the API accepts)
- `GRPC_PUBLIC_ADDR` and `GRPC_SANS` (the name nodes dial must be in the server certificate)

Optional: `GEOIP_CITY_DB` / `GEOIP_ASN_DB` (MaxMind `.mmdb`), `ESCALATION_WEBHOOK_URL`, `BOOTSTRAP_ADMINS`.

## Known gaps

Stated so nobody mistakes them for working features:

- **GeoIP:** no MaxMind database ships with this repo (its licence needs a free account). Without `GEOIP_CITY_DB`, addresses outside the `geoip_overrides` table resolve to country `ZZ` and do not appear on the geo map.
- **Edge integration:** the agent is a standalone reverse proxy. Caddy, Envoy and HAProxy SPOA plugins are not built; the gRPC contract is what such a plugin would implement.
- **Test sandbox:** dry-runs the rule in the real Coraza engine on the control plane. Go FTW YAML test suites are not run.
- **Scaling:** campaign state lives in the control plane's memory and is persisted to PostgreSQL. A single control plane instance must run the correlation engine. No Redis-backed sharing has been built.
- **Notifications:** one webhook with a Slack-compatible body. No email or SIEM-specific formats.
- **Sites:** `POST /api/v1/sites` exists, but the console has no form for it yet. The dev seed creates the four demo sites.
- **Throughput:** the NFR-1.3/1.4 rates (10,000 events/s) have not been load-tested.
