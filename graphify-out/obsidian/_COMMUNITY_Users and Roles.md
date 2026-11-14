---
type: community
members: 7
---

# Users and Roles

**Members:** 7 nodes

## Members
- [[dot-SessionUser()]] - code - server/internal/store/pg.go
- [[dot-SetRole()_1]] - code - server/internal/store/pg.go
- [[dot-UserLogin()]] - code - server/internal/store/pg.go
- [[dot-Users()_1]] - code - server/internal/store/pg.go
- [[Role]] - code - server/internal/model/model.go
- [[User]] - code - server/internal/model/model.go
- [[scanUser()]] - code - server/internal/store/pg.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Users_and_Roles
SORT file.name ASC
```

## Connections to other communities
- 6 edges to [[_COMMUNITY_Postgres Store]]
- 4 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 4 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 3 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 2 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 2 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]

## Top bridge nodes
- [[Role]] - degree 8, connects to 4 communities
- [[User]] - degree 9, connects to 3 communities
- [[dot-UserLogin()]] - degree 6, connects to 3 communities
- [[dot-SessionUser()]] - degree 5, connects to 3 communities
- [[scanUser()]] - degree 7, connects to 2 communities