---
type: community
members: 25
---

# Agent RPC Server

**Members:** 25 nodes

## Members
- [[dot-Connect()_2]] - code - server/internal/agentrpc/server.go
- [[dot-CreateEnrollmentToken()]] - code - server/internal/store/pg.go
- [[dot-CreateSession()]] - code - server/internal/store/pg.go
- [[dot-EnrollHint()]] - code - server/internal/agentrpc/server.go
- [[dot-EnrollHint()_1]] - code - server/internal/api/api.go
- [[dot-InsertBundle()]] - code - server/internal/store/pg.go
- [[dot-LatestBundle()]] - code - server/internal/store/pg.go
- [[dot-NodeConfigVersion()]] - code - server/internal/store/pg.go
- [[dot-NodeHeartbeat()]] - code - server/internal/store/pg.go
- [[dot-NodeHello()]] - code - server/internal/store/pg.go
- [[dot-Push()]] - code - server/internal/agentrpc/server.go
- [[dot-Push()_1]] - code - server/internal/api/api.go
- [[dot-UseRedis()]] - code - server/internal/agentrpc/server.go
- [[dot-emit()]] - code - server/internal/agent/core.go
- [[dot-pushLocal()]] - code - server/internal/agentrpc/server.go
- [[dot-sendLocal()]] - code - server/internal/agentrpc/server.go
- [[Bundle]] - code - server/internal/model/model.go
- [[Fleet]] - code - server/internal/api/api.go
- [[Server]] - code - server/internal/agentrpc/server.go
- [[ack]] - code - server/internal/agentrpc/server.go
- [[actor]] - code - server/cmd/devsim/main.go
- [[redis.Client_1]] - code
- [[step]] - code - server/cmd/devsim/main.go
- [[time.Duration]] - code
- [[toProto()]] - code - server/internal/agentrpc/server.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Agent_RPC_Server
SORT file.name ASC
```

## Connections to other communities
- 11 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 9 edges to [[_COMMUNITY_Postgres Store]]
- 6 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 4 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 4 edges to [[_COMMUNITY_Edge Agent Core]]
- 3 edges to [[_COMMUNITY_Devsim Traffic Generator]]
- 3 edges to [[_COMMUNITY_Agent gRPC Bidi Streams]]
- 3 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 3 edges to [[_COMMUNITY_gRPC Server Auth Interceptors]]
- 3 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 2 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 2 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 1 edge to [[_COMMUNITY_gRPC Client Stubs]]
- 1 edge to [[_COMMUNITY_MatchedRule Messages]]
- 1 edge to [[_COMMUNITY_AgentService Server Stubs]]
- 1 edge to [[_COMMUNITY_Edge Transaction Handling]]
- 1 edge to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_Event Classification Pipeline]]
- 1 edge to [[_COMMUNITY_Live Campaign Memory]]

## Top bridge nodes
- [[Server]] - degree 22, connects to 11 communities
- [[time.Duration]] - degree 15, connects to 5 communities
- [[Bundle]] - degree 12, connects to 3 communities
- [[dot-Connect()_2]] - degree 9, connects to 3 communities
- [[dot-LatestBundle()]] - degree 6, connects to 3 communities