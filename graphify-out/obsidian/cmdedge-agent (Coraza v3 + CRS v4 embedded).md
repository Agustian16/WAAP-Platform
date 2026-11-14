---
source_file: "server/README.md"
type: "concept"
community: "High-Level Architecture"
tags:
  - graphify/concept
  - graphify/EXTRACTED
  - community/High-Level_Architecture
---

# cmd/edge-agent (Coraza v3 + CRS v4 embedded)

## Connections
- [[Coraza Edge Node  Enforcer Agent]] - `implements` [EXTRACTED]
- [[Node-side masking (internalagentmask.go)]] - `conceptually_related_to` [EXTRACTED]
- [[Proxy integrations (Standalone, Envoy ext_proc, HAProxy SPOE, Caddy)]] - `references` [EXTRACTED]
- [[Server binaries (control-plane, edge-agent, corazium-ctl, devsim, caddy)]] - `references` [EXTRACTED]
- [[cmdcontrol-plane (REST, WebSocket, gRPC mTLS, correlation)]] - `calls` [EXTRACTED]
- [[cmddevsim (demo upstream and traffic generator)]] - `calls` [EXTRACTED]

#graphify/concept #graphify/EXTRACTED #community/High-Level_Architecture