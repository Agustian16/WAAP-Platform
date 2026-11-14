---
type: community
members: 10
---

# Live Event Hub

**Members:** 10 nodes

## Members
- [[dot-Close()_1]] - code - server/internal/waf/ftw.go
- [[dot-Publish()]] - code - server/internal/api/data.go
- [[dot-UseRedis()_1]] - code - server/internal/api/data.go
- [[dot-fanout()]] - code - server/internal/api/data.go
- [[dot-serve()_1]] - code - server/internal/api/data.go
- [[Hub]] - code - server/internal/api/data.go
- [[nethttphttptest.Server]] - code
- [[redis.Client_4]] - code
- [[sandboxWAF]] - code - server/internal/waf/ftw.go
- [[sync.Mutex]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Live_Event_Hub
SORT file.name ASC
```

## Connections to other communities
- 4 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 3 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 2 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 1 edge to [[_COMMUNITY_HAProxy SPOA Integration]]
- 1 edge to [[_COMMUNITY_Agent RPC Server]]
- 1 edge to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 1 edge to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 1 edge to [[_COMMUNITY_Live Campaign Memory]]
- 1 edge to [[_COMMUNITY_Campaign Store and Tests]]
- 1 edge to [[_COMMUNITY_FTW Sandbox Runner]]
- 1 edge to [[_COMMUNITY_Enrollment and Geo Feeds]]

## Top bridge nodes
- [[sync.Mutex]] - degree 9, connects to 7 communities
- [[Hub]] - degree 9, connects to 3 communities
- [[sandboxWAF]] - degree 7, connects to 2 communities
- [[dot-UseRedis()_1]] - degree 4, connects to 1 community
- [[dot-Publish()]] - degree 3, connects to 1 community