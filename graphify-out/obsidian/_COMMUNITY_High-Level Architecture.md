---
type: community
members: 17
---

# High-Level Architecture

**Members:** 17 nodes

## Members
- [[Attack Correlation Engine]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Caddy module http.handlers.corazium]] - concept - server/README.md
- [[ClickHouse (audit log analytics)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Coraza Edge Node  Enforcer Agent]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Frontend Coraza UI (Next.js 14, Shadcn)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Go Control Plane API]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Go FTW test sandbox (internalwafftw.go)]] - concept - server/README.md
- [[High-Level Architecture]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[NFR-2.3 Payload masking]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Node-side masking (internalagentmask.go)]] - concept - server/README.md
- [[Outcome Classification (BLOCKED, DETECTED, POSSIBLY_SUCCESSFUL)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Proxy integrations (Standalone, Envoy ext_proc, HAProxy SPOE, Caddy)]] - concept - server/README.md
- [[Server binaries (control-plane, edge-agent, corazium-ctl, devsim, caddy)]] - concept - server/README.md
- [[Tests (unit and integration)]] - concept - server/README.md
- [[cmdcontrol-plane (REST, WebSocket, gRPC mTLS, correlation)]] - concept - server/README.md
- [[cmddevsim (demo upstream and traffic generator)]] - concept - server/README.md
- [[cmdedge-agent (Coraza v3 + CRS v4 embedded)]] - concept - server/README.md

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/High-Level_Architecture
SORT file.name ASC
```

## Connections to other communities
- 8 edges to [[_COMMUNITY_Repo Layout and NFRs]]
- 3 edges to [[_COMMUNITY_PRD Core Modules and KPIs]]
- 3 edges to [[_COMMUNITY_Campaign Correlation Requirements]]
- 2 edges to [[_COMMUNITY_PRD Feature Modules]]
- 2 edges to [[_COMMUNITY_PRD Attack Correlation Module]]
- 1 edge to [[_COMMUNITY_mTLS and Node Enrollment]]
- 1 edge to [[_COMMUNITY_PRD Rules and CRS Module]]

## Top bridge nodes
- [[Attack Correlation Engine]] - degree 8, connects to 3 communities
- [[Go Control Plane API]] - degree 7, connects to 2 communities
- [[Coraza Edge Node  Enforcer Agent]] - degree 7, connects to 2 communities
- [[Server binaries (control-plane, edge-agent, corazium-ctl, devsim, caddy)]] - degree 6, connects to 2 communities
- [[ClickHouse (audit log analytics)]] - degree 5, connects to 2 communities