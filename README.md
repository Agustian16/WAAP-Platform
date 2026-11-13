# Corazium WAAP Platform

Control plane and observability hub for OWASP Coraza WAF fleets.

| Path | What |
| --- | --- |
| `Coraza_WAF_Management_Dashboard_PRD.md` | Product requirements (source of truth) |
| `web/` | Next.js 14 console. Talks to the control plane when `NEXT_PUBLIC_API_URL` is set, otherwise runs on an in-browser mock. See `web/README.md`. |
| `server/` | Go control plane, edge agent, CI validator; PostgreSQL, ClickHouse and Keycloak via Docker Compose. See `server/README.md`. |
| `brand/` | Corazium logo source file |

Full stack (backend, databases, identity provider, edge nodes): `server/README.md`. Console alone, on sample data:

```bash
cd web
npm install
npm run dev
```
