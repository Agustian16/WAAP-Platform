---
type: community
members: 12
---

# Email Alerts and Redis

**Members:** 12 nodes

## Members
- [[dot-send()]] - code - server/internal/api/notify.go
- [[EmailConfig]] - code - server/internal/api/notify.go
- [[EmailNotifier()]] - code - server/internal/api/notify.go
- [[Notifier()]] - code - server/internal/api/data.go
- [[Notifiers()]] - code - server/internal/api/notify.go
- [[RedisLeader()]] - code - server/internal/api/admin.go
- [[env()]] - code - server/cmd/control-plane/main.go
- [[escalationMail()]] - code - server/internal/api/notify.go
- [[must()]] - code - server/cmd/control-plane/main.go
- [[oneLine()]] - code - server/internal/api/notify.go
- [[redis.Client_3]] - code
- [[run()]] - code - server/cmd/control-plane/main.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Email_Alerts_and_Redis
SORT file.name ASC
```

## Connections to other communities
- 9 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 5 edges to [[_COMMUNITY_Live Campaign Memory]]
- 5 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 4 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 3 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 1 edge to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 1 edge to [[_COMMUNITY_Postgres Store]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_Campaign Store and Tests]]
- 1 edge to [[_COMMUNITY_HAProxy SPOA Integration]]
- 1 edge to [[_COMMUNITY_Policy Documents]]
- 1 edge to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]

## Top bridge nodes
- [[run()]] - degree 24, connects to 10 communities
- [[EmailNotifier()]] - degree 7, connects to 3 communities
- [[escalationMail()]] - degree 6, connects to 3 communities
- [[RedisLeader()]] - degree 4, connects to 2 communities
- [[Notifier()]] - degree 3, connects to 2 communities