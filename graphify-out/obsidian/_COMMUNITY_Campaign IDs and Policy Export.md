---
type: community
members: 14
---

# Campaign IDs and Policy Export

**Members:** 14 nodes

## Members
- [[dot-DeleteException()_1]] - code - server/internal/store/pg.go
- [[dot-Exceptions()_1]] - code - server/internal/store/pg.go
- [[dot-InsertException()]] - code - server/internal/store/pg.go
- [[dot-NextCampaignID()]] - code - server/internal/correlate/engine_test.go
- [[dot-NextCampaignID()_1]] - code - server/internal/store/pg.go
- [[dot-NextCampaignID()_2]] - code - server/internal/correlate/engine.go
- [[dot-running()]] - code - server/internal/api/admin.go
- [[BuildException()]] - code - server/internal/waf/waf.go
- [[ExportPolicy()]] - code - server/internal/api/admin.go
- [[RuleException]] - code - server/internal/model/model.go
- [[Running]] - code - server/internal/api/admin.go
- [[scanExc()]] - code - server/internal/store/pg.go
- [[siteDirectives()]] - code - server/internal/waf/waf.go
- [[time.Time]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Campaign_IDs_and_Policy_Export
SORT file.name ASC
```

## Connections to other communities
- 7 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 6 edges to [[_COMMUNITY_Postgres Store]]
- 4 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 4 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 3 edges to [[_COMMUNITY_Custom Rule Store]]
- 3 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 2 edges to [[_COMMUNITY_Policy Documents]]
- 2 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 2 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 2 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_HAProxy SPOA Integration]]
- 1 edge to [[_COMMUNITY_Event Classification Pipeline]]
- 1 edge to [[_COMMUNITY_Threat Feed Store]]
- 1 edge to [[_COMMUNITY_Users and Roles]]
- 1 edge to [[_COMMUNITY_IP List Store]]
- 1 edge to [[_COMMUNITY_Edge Node Model]]
- 1 edge to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]

## Top bridge nodes
- [[time.Time]] - degree 19, connects to 13 communities
- [[Running]] - degree 7, connects to 4 communities
- [[RuleException]] - degree 10, connects to 2 communities
- [[scanExc()]] - degree 6, connects to 2 communities
- [[siteDirectives()]] - degree 5, connects to 2 communities