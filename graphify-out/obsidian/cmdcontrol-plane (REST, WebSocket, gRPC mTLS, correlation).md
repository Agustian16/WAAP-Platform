---
source_file: "server/README.md"
type: "concept"
community: "High-Level Architecture"
tags:
  - graphify/concept
  - graphify/EXTRACTED
  - community/High-Level_Architecture
---

# cmd/control-plane (REST, WebSocket, gRPC mTLS, correlation)

## Connections
- [[Attack Correlation Engine]] - `implements` [EXTRACTED]
- [[Backend switch via NEXT_PUBLIC_API_URL]] - `calls` [EXTRACTED]
- [[Go Control Plane API]] - `implements` [EXTRACTED]
- [[Server binaries (control-plane, edge-agent, corazium-ctl, devsim, caddy)]] - `references` [EXTRACTED]
- [[cmdedge-agent (Coraza v3 + CRS v4 embedded)]] - `calls` [EXTRACTED]

#graphify/concept #graphify/EXTRACTED #community/High-Level_Architecture