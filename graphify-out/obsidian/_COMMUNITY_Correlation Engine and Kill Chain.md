---
type: community
members: 20
---

# Correlation Engine and Kill Chain

**Members:** 20 nodes

## Members
- [[dot-Configure()]] - code - server/internal/correlate/engine.go
- [[dot-Lookup()]] - code - server/internal/correlate/killchain.go
- [[dot-Restore()]] - code - server/internal/correlate/engine.go
- [[dot-Run()]] - code - server/internal/correlate/engine.go
- [[dot-SetGeo()]] - code - server/internal/correlate/engine.go
- [[dot-Sync()]] - code - server/internal/correlate/engine.go
- [[dot-UseLive()]] - code - server/internal/correlate/engine.go
- [[dot-actorKey()]] - code - server/internal/correlate/engine.go
- [[dot-flush()_1]] - code - server/internal/correlate/engine.go
- [[CorrelationSettings]] - code - server/internal/model/model.go
- [[Engine]] - code - server/internal/correlate/engine.go
- [[Geo]] - code - server/internal/correlate/killchain.go
- [[KillchainMapping]] - code - server/internal/model/model.go
- [[LiveStore]] - code - server/internal/correlate/live.go
- [[Loc]] - code - server/internal/correlate/killchain.go
- [[maxminddb.Reader]] - code
- [[openMMDB()]] - code - server/internal/correlate/killchain.go
- [[override]] - code - server/internal/correlate/killchain.go
- [[sync.RWMutex]] - code
- [[syncatomic.Pointer]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Correlation_Engine_and_Kill_Chain
SORT file.name ASC
```

## Connections to other communities
- 9 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 5 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 5 edges to [[_COMMUNITY_Live Campaign Memory]]
- 5 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 4 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 4 edges to [[_COMMUNITY_Event Classification Pipeline]]
- 2 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 2 edges to [[_COMMUNITY_Postgres Store]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_Agent RPC Server]]
- 1 edge to [[_COMMUNITY_Control Plane API Handlers]]
- 1 edge to [[_COMMUNITY_Envoy ExtProc Integration]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]

## Top bridge nodes
- [[Engine]] - degree 28, connects to 9 communities
- [[KillchainMapping]] - degree 7, connects to 4 communities
- [[Geo]] - degree 8, connects to 3 communities
- [[CorrelationSettings]] - degree 5, connects to 3 communities
- [[LiveStore]] - degree 5, connects to 2 communities