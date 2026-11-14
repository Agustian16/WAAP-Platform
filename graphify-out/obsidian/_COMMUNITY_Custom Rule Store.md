---
type: community
members: 7
---

# Custom Rule Store

**Members:** 7 nodes

## Members
- [[dot-DeleteRule()_1]] - code - server/internal/store/pg.go
- [[dot-InsertRule()]] - code - server/internal/store/pg.go
- [[dot-Rule()_1]] - code - server/internal/store/pg.go
- [[dot-SetRuleActive()_1]] - code - server/internal/store/pg.go
- [[dot-UpdateRule()]] - code - server/internal/store/pg.go
- [[CustomRule]] - code - server/internal/model/model.go
- [[scanRule()]] - code - server/internal/store/pg.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Custom_Rule_Store
SORT file.name ASC
```

## Connections to other communities
- 6 edges to [[_COMMUNITY_Postgres Store]]
- 5 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 3 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 2 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 2 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 1 edge to [[_COMMUNITY_Coraza and CRS Engine Deps]]

## Top bridge nodes
- [[CustomRule]] - degree 12, connects to 4 communities
- [[scanRule()]] - degree 9, connects to 2 communities
- [[dot-DeleteRule()_1]] - degree 4, connects to 2 communities
- [[dot-InsertRule()]] - degree 4, connects to 2 communities
- [[dot-Rule()_1]] - degree 4, connects to 2 communities