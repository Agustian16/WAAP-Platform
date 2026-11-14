---
type: community
members: 6
---

# mTLS and Node Enrollment

**Members:** 6 nodes

## Members
- [[Built-in CA in PostgreSQL for mTLS]] - concept - server/README.md
- [[Known gaps and next phase]] - concept - server/README.md
- [[NFR-2.1 mTLS for gRPC]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Node enrollment (one-time token, CA pin, client cert)]] - concept - server/README.md
- [[Performance NFRs (latency 2ms, push 1s, 10k logss)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[gRPC Config Stream (zero-downtime hot-reload)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/mTLS_and_Node_Enrollment
SORT file.name ASC
```

## Connections to other communities
- 3 edges to [[_COMMUNITY_Repo Layout and NFRs]]
- 2 edges to [[_COMMUNITY_PRD Core Modules and KPIs]]
- 1 edge to [[_COMMUNITY_High-Level Architecture]]

## Top bridge nodes
- [[gRPC Config Stream (zero-downtime hot-reload)]] - degree 4, connects to 2 communities
- [[Node enrollment (one-time token, CA pin, client cert)]] - degree 3, connects to 2 communities
- [[Performance NFRs (latency 2ms, push 1s, 10k logss)]] - degree 3, connects to 1 community
- [[Known gaps and next phase]] - degree 2, connects to 1 community