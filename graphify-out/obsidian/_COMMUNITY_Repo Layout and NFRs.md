---
type: community
members: 16
---

# Repo Layout and NFRs

**Members:** 16 nodes

## Members
- [[Backend switch via NEXT_PUBLIC_API_URL]] - concept - web/README.md
- [[Configuration (environment variables)]] - concept - server/README.md
- [[Corazium Console (web)]] - document - web/README.md
- [[Corazium WAAP Platform (repo overview)]] - document - README.md
- [[Corazium control plane (server)]] - document - server/README.md
- [[Escalation alerts (webhook and SMTP email)]] - concept - server/README.md
- [[Event Enrichment (GeoIP, ASN, category, stage)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Frontend unit tests (linter, sandbox, kill chain, risk score, CIDR)]] - concept - web/README.md
- [[GeoIP enrichment (MaxMind GeoLite2)]] - concept - server/README.md
- [[How it maps to the PRD]] - concept - server/README.md
- [[Mock role switcher and outage simulation]] - concept - web/README.md
- [[NFR-3.1 Fail-safe node operation (cached config)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Progression Detection and Campaign Risk Score]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Repository layout (PRD, web, server, brand)]] - concept - README.md
- [[Run it locally (Docker Compose stack, Keycloak, GeoIP)]] - concept - server/README.md
- [[brand Corazium logo source]] - concept - README.md

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Repo_Layout_and_NFRs
SORT file.name ASC
```

## Connections to other communities
- 8 edges to [[_COMMUNITY_High-Level Architecture]]
- 4 edges to [[_COMMUNITY_PRD Core Modules and KPIs]]
- 3 edges to [[_COMMUNITY_PRD Feature Modules]]
- 3 edges to [[_COMMUNITY_Campaign Correlation Requirements]]
- 3 edges to [[_COMMUNITY_mTLS and Node Enrollment]]
- 2 edges to [[_COMMUNITY_PRD Attack Correlation Module]]

## Top bridge nodes
- [[Corazium Console (web)]] - degree 9, connects to 4 communities
- [[Corazium control plane (server)]] - degree 9, connects to 3 communities
- [[How it maps to the PRD]] - degree 6, connects to 3 communities
- [[Run it locally (Docker Compose stack, Keycloak, GeoIP)]] - degree 6, connects to 2 communities
- [[Backend switch via NEXT_PUBLIC_API_URL]] - degree 5, connects to 2 communities