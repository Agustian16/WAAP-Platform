---
type: community
members: 14
---

# Postgres Row Scanners

**Members:** 14 nodes

## Members
- [[dot-Campaign()_1]] - code - server/internal/store/pg.go
- [[dot-CreateSite()_1]] - code - server/internal/store/pg.go
- [[dot-PatchCampaign()_1]] - code - server/internal/store/pg.go
- [[dot-SaveCorrelation()_1]] - code - server/internal/store/pg.go
- [[dot-SaveMapping()_1]] - code - server/internal/store/pg.go
- [[dot-SaveSite()]] - code - server/internal/store/pg.go
- [[dot-Site()]] - code - server/internal/store/pg.go
- [[dot-Sites()_1]] - code - server/internal/store/pg.go
- [[Site]] - code - server/internal/model/model.go
- [[norm()]] - code - server/internal/store/pg.go
- [[pgx.Row]] - code
- [[scanCampaign()]] - code - server/internal/store/pg.go
- [[scanNode()]] - code - server/internal/store/pg.go
- [[scanSite()]] - code - server/internal/store/pg.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Postgres_Row_Scanners
SORT file.name ASC
```

## Connections to other communities
- 11 edges to [[_COMMUNITY_Postgres Store]]
- 9 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 5 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 4 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 4 edges to [[_COMMUNITY_Live Campaign Memory]]
- 3 edges to [[_COMMUNITY_Agent RPC Server]]
- 2 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 2 edges to [[_COMMUNITY_Threat Feed Store]]
- 2 edges to [[_COMMUNITY_IP List Store]]
- 2 edges to [[_COMMUNITY_Custom Rule Store]]
- 2 edges to [[_COMMUNITY_Users and Roles]]
- 1 edge to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 1 edge to [[_COMMUNITY_Edge Node Model]]

## Top bridge nodes
- [[norm()]] - degree 16, connects to 9 communities
- [[pgx.Row]] - degree 9, connects to 6 communities
- [[Site]] - degree 9, connects to 3 communities
- [[dot-PatchCampaign()_1]] - degree 5, connects to 3 communities
- [[dot-Campaign()_1]] - degree 4, connects to 3 communities