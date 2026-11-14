---
type: community
members: 24
---

# Postgres Store

**Members:** 24 nodes

## Members
- [[dot-ActiveCIDRs()]] - code - server/internal/store/pg.go
- [[dot-Audit()_1]] - code - server/internal/store/pg.go
- [[dot-AuditTrail()_1]] - code - server/internal/store/pg.go
- [[dot-Campaigns()_1]] - code - server/internal/store/pg.go
- [[dot-ConfigVersion()_1]] - code - server/internal/store/pg.go
- [[dot-Correlation()_1]] - code - server/internal/store/pg.go
- [[dot-DeleteExpiredIPs()]] - code - server/internal/store/pg.go
- [[dot-DeleteSession()]] - code - server/internal/store/pg.go
- [[dot-LiveCampaigns()]] - code - server/internal/store/pg.go
- [[dot-Mapping()_1]] - code - server/internal/store/pg.go
- [[dot-MarkDirty()_1]] - code - server/internal/store/pg.go
- [[dot-NodeNameTaken()]] - code - server/internal/store/pg.go
- [[dot-NodeVersions()]] - code - server/internal/store/pg.go
- [[dot-PKI()]] - code - server/internal/store/pg.go
- [[dot-ReplaceFeedEntries()]] - code - server/internal/store/pg.go
- [[dot-Rules()_1]] - code - server/internal/store/pg.go
- [[dot-SaveCampaign()]] - code - server/internal/store/pg.go
- [[AuditTrailEntry]] - code - server/internal/model/model.go
- [[NodeVersion]] - code - server/internal/store/pg.go
- [[OpenPG()]] - code - server/internal/store/pg.go
- [[PG]] - code - server/internal/store/pg.go
- [[collect()]] - code - server/internal/store/pg.go
- [[github.comjackcpgxv5pgxpool.Pool]] - code
- [[pgx.Rows]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Postgres_Store
SORT file.name ASC
```

## Connections to other communities
- 22 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 11 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 9 edges to [[_COMMUNITY_Agent RPC Server]]
- 6 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 6 edges to [[_COMMUNITY_Users and Roles]]
- 6 edges to [[_COMMUNITY_Custom Rule Store]]
- 6 edges to [[_COMMUNITY_Threat Feed Store]]
- 5 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 4 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 4 edges to [[_COMMUNITY_IP List Store]]
- 3 edges to [[_COMMUNITY_Live Campaign Memory]]
- 2 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 2 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 2 edges to [[_COMMUNITY_Edge Node Model]]
- 1 edge to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]
- 1 edge to [[_COMMUNITY_Campaign Store and Tests]]

## Top bridge nodes
- [[PG]] - degree 66, connects to 13 communities
- [[collect()]] - degree 19, connects to 8 communities
- [[OpenPG()]] - degree 5, connects to 4 communities
- [[AuditTrailEntry]] - degree 5, connects to 3 communities
- [[dot-SaveCampaign()]] - degree 4, connects to 3 communities