---
type: community
members: 16
---

# Live Campaign Memory

**Members:** 16 nodes

## Members
- [[dot-Seed()]] - code - server/internal/correlate/live.go
- [[dot-Seed()_1]] - code - server/internal/correlate/live.go
- [[dot-Seed()_2]] - code - server/internal/correlate/live.go
- [[dot-Update()]] - code - server/internal/correlate/live.go
- [[dot-Update()_1]] - code - server/internal/correlate/live.go
- [[dot-Update()_2]] - code - server/internal/correlate/live.go
- [[Campaign]] - code - server/internal/model/model.go
- [[MemoryLive]] - code - server/internal/correlate/live.go
- [[NewRedisLive()]] - code - server/internal/correlate/live.go
- [[Note]] - code - server/internal/model/model.go
- [[RedisLive]] - code - server/internal/correlate/live.go
- [[clone()]] - code - server/internal/correlate/live.go
- [[decode()]] - code - server/internal/correlate/live.go
- [[encode()]] - code - server/internal/correlate/live.go
- [[liveRec]] - code - server/internal/correlate/live.go
- [[redis.Client_2]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Live_Campaign_Memory
SORT file.name ASC
```

## Connections to other communities
- 9 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 6 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 6 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 5 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 5 edges to [[_COMMUNITY_Email Alerts and Redis]]
- 4 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 3 edges to [[_COMMUNITY_Postgres Store]]
- 2 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_Agent RPC Server]]
- 1 edge to [[_COMMUNITY_Event Classification Pipeline]]

## Top bridge nodes
- [[Campaign]] - degree 31, connects to 6 communities
- [[MemoryLive]] - degree 6, connects to 3 communities
- [[NewRedisLive()]] - degree 6, connects to 3 communities
- [[RedisLive]] - degree 6, connects to 2 communities
- [[clone()]] - degree 5, connects to 2 communities