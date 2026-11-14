---
type: community
members: 28
---

# ClickHouse Store and Test Harness

**Members:** 28 nodes

## Members
- [[dot-AddLog()]] - code - server/internal/correlate/engine_test.go
- [[dot-AddLog()_1]] - code - server/internal/store/ch.go
- [[dot-AddLog()_2]] - code - server/internal/correlate/engine.go
- [[dot-AddMetric()]] - code - server/internal/store/ch.go
- [[dot-Close()]] - code - server/internal/store/ch.go
- [[dot-Flush()]] - code - server/internal/store/ch.go
- [[dot-Impact()]] - code - server/internal/store/ch.go
- [[dot-Log()]] - code - server/internal/store/ch.go
- [[dot-QueryLogs()_1]] - code - server/internal/store/ch.go
- [[dot-RuleMessages()]] - code - server/internal/store/ch.go
- [[dot-deploy()_1]] - code - server/internal/api/integration_test.go
- [[dot-do()]] - code - server/internal/api/integration_test.go
- [[dot-eventually()]] - code - server/internal/api/integration_test.go
- [[dot-hit()]] - code - server/internal/api/integration_test.go
- [[dot-insert()]] - code - server/internal/store/ch.go
- [[dot-logs()]] - code - server/internal/api/integration_test.go
- [[dot-loop()]] - code - server/internal/store/ch.go
- [[AuditLog]] - code - server/internal/model/model.go
- [[CH]] - code - server/internal/store/ch.go
- [[LogQuery]] - code - server/internal/store/ch.go
- [[NodeMetric]] - code - server/internal/store/ch.go
- [[OpenCH()]] - code - server/internal/store/ch.go
- [[github.comClickHouseclickhouse-gov2libdriver.Batch]] - code
- [[github.comClickHouseclickhouse-gov2libdriver.Conn]] - code
- [[github.comClickHouseclickhouse-gov2libdriver.Rows]] - code
- [[harness]] - code - server/internal/api/integration_test.go
- [[redis.Client]] - code
- [[scanLog()]] - code - server/internal/store/ch.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/ClickHouse_Store_and_Test_Harness
SORT file.name ASC
```

## Connections to other communities
- 8 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 7 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 7 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 6 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 2 edges to [[_COMMUNITY_Agent RPC Server]]
- 2 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 2 edges to [[_COMMUNITY_Live Event Hub]]
- 2 edges to [[_COMMUNITY_Users and Roles]]
- 2 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_Postgres Store]]
- 1 edge to [[_COMMUNITY_Edge Node Model]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]

## Top bridge nodes
- [[CH]] - degree 25, connects to 7 communities
- [[harness]] - degree 15, connects to 7 communities
- [[OpenCH()]] - degree 6, connects to 4 communities
- [[AuditLog]] - degree 12, connects to 3 communities
- [[dot-do()]] - degree 5, connects to 2 communities