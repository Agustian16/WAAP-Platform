---
type: community
members: 4
---

# Edge Node Model

**Members:** 4 nodes

## Members
- [[dot-NodeHistory()]] - code - server/internal/store/ch.go
- [[dot-Nodes()_1]] - code - server/internal/store/pg.go
- [[EdgeNode]] - code - server/internal/model/model.go
- [[NodeHistory]] - code - server/internal/model/model.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Edge_Node_Model
SORT file.name ASC
```

## Connections to other communities
- 2 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 2 edges to [[_COMMUNITY_Postgres Store]]
- 2 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Postgres Row Scanners]]
- 1 edge to [[_COMMUNITY_ClickHouse Store and Test Harness]]

## Top bridge nodes
- [[EdgeNode]] - degree 5, connects to 3 communities
- [[dot-Nodes()_1]] - degree 4, connects to 2 communities
- [[dot-NodeHistory()]] - degree 3, connects to 2 communities
- [[NodeHistory]] - degree 3, connects to 1 community