---
type: community
members: 8
---

# HAProxy SPOA Integration

**Members:** 8 nodes

## Members
- [[dot-Run()_3]] - code - server/internal/agent/spoa.go
- [[dot-janitor()]] - code - server/internal/agent/spoa.go
- [[NewSPOA()]] - code - server/internal/agent/spoa.go
- [[SPOA]] - code - server/internal/agent/spoa.go
- [[Tx_4]] - code
- [[fail()_1]] - code - server/cmd/edge-agent/main.go
- [[main()_4]] - code - server/cmd/edge-agent/main.go
- [[pendingTx]] - code - server/internal/agent/spoa.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/HAProxy_SPOA_Integration
SORT file.name ASC
```

## Connections to other communities
- 5 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 3 edges to [[_COMMUNITY_Edge Agent Core]]
- 2 edges to [[_COMMUNITY_Edge Reverse Proxy]]
- 2 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_SPOE Handler]]
- 1 edge to [[_COMMUNITY_Envoy ExtProc Integration]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]

## Top bridge nodes
- [[main()_4]] - degree 7, connects to 5 communities
- [[SPOA]] - degree 8, connects to 4 communities
- [[pendingTx]] - degree 4, connects to 2 communities
- [[dot-Run()_3]] - degree 4, connects to 2 communities
- [[NewSPOA()]] - degree 4, connects to 2 communities