---
type: community
members: 13
---

# Campaign Store and Tests

**Members:** 13 nodes

## Members
- [[dot-AddEvent()]] - code - server/internal/correlate/engine_test.go
- [[dot-AddEvent()_1]] - code - server/internal/store/ch.go
- [[dot-AddEvent()_2]] - code - server/internal/correlate/engine.go
- [[dot-Events()]] - code - server/internal/store/ch.go
- [[dot-SaveCampaign()_1]] - code - server/internal/correlate/engine_test.go
- [[dot-SaveCampaign()_2]] - code - server/internal/correlate/engine.go
- [[AttackEvent]] - code - server/internal/model/model.go
- [[CampaignStore]] - code - server/internal/correlate/engine.go
- [[NewEngine()_1]] - code - server/internal/correlate/engine.go
- [[NewMemoryLive()]] - code - server/internal/correlate/live.go
- [[Sink]] - code - server/internal/correlate/engine.go
- [[StreamMsg]] - code - server/internal/model/model.go
- [[fake]] - code - server/internal/correlate/engine_test.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Campaign_Store_and_Tests
SORT file.name ASC
```

## Connections to other communities
- 7 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 7 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 6 edges to [[_COMMUNITY_Live Campaign Memory]]
- 5 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 4 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 3 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 2 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_Postgres Store]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]

## Top bridge nodes
- [[NewEngine()_1]] - degree 12, connects to 5 communities
- [[fake]] - degree 10, connects to 5 communities
- [[StreamMsg]] - degree 8, connects to 5 communities
- [[CampaignStore]] - degree 5, connects to 3 communities
- [[Sink]] - degree 5, connects to 3 communities