---
source_file: "server/README.md"
type: "concept"
community: "Repo Layout and NFRs"
tags:
  - graphify/concept
  - graphify/EXTRACTED
  - community/Repo_Layout_and_NFRs
---

# How it maps to the PRD

## Connections
- [[ClickHouse schema (coraza_audit_logs)]] - `implements` [EXTRACTED]
- [[Corazium control plane (server)]] - `references` [EXTRACTED]
- [[NFR-3.1 Fail-safe node operation (cached config)]] - `implements` [EXTRACTED]
- [[PostgreSQL schema (sites, nodes, custom_rules, rule_exceptions)]] - `implements` [EXTRACTED]
- [[Progression Detection and Campaign Risk Score]] - `implements` [EXTRACTED]
- [[gRPC Config Stream (zero-downtime hot-reload)]] - `implements` [EXTRACTED]

#graphify/concept #graphify/EXTRACTED #community/Repo_Layout_and_NFRs