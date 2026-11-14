---
type: community
members: 5
---

# IP List Store

**Members:** 5 nodes

## Members
- [[dot-DeleteIP()]] - code - server/internal/store/pg.go
- [[dot-IPList()]] - code - server/internal/store/pg.go
- [[dot-InsertIP()]] - code - server/internal/store/pg.go
- [[IPListEntry]] - code - server/internal/model/model.go
- [[scanIP()]] - code - server/internal/store/pg.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/IP_List_Store
SORT file.name ASC
```

## Connections to other communities
- 4 edges to [[_COMMUNITY_Postgres Store]]
- 3 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 2 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 2 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]

## Top bridge nodes
- [[IPListEntry]] - degree 6, connects to 2 communities
- [[scanIP()]] - degree 6, connects to 2 communities
- [[dot-DeleteIP()]] - degree 4, connects to 2 communities
- [[dot-InsertIP()]] - degree 4, connects to 2 communities
- [[dot-IPList()]] - degree 4, connects to 2 communities