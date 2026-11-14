---
type: community
members: 21
---

# Edge Agent Core

**Members:** 21 nodes

## Members
- [[dot-Start()]] - code - server/internal/agent/core.go
- [[dot-advertiseIP()]] - code - server/internal/agent/core.go
- [[dot-apply()]] - code - server/internal/agent/core.go
- [[dot-auditStream()_2]] - code - server/internal/agent/core.go
- [[dot-cachePath()]] - code - server/internal/agent/core.go
- [[dot-configStream()]] - code - server/internal/agent/core.go
- [[dot-dial()]] - code - server/internal/agent/core.go
- [[dot-enroll()_4]] - code - server/internal/agent/core.go
- [[dot-file()]] - code - server/internal/agent/core.go
- [[dot-loadCache()]] - code - server/internal/agent/core.go
- [[AgentServiceClient_1]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[Config]] - code - server/internal/agent/core.go
- [[Core]] - code - server/internal/agent/core.go
- [[NewAgentServiceClient()]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[NewCore()]] - code - server/internal/agent/core.go
- [[build()]] - code - server/internal/agent/core.go
- [[coraza.WAF_1]] - code
- [[google.golang.orggrpc.ClientConn]] - code
- [[retry()]] - code - server/internal/agent/core.go
- [[runtime]] - code - server/internal/agent/core.go
- [[syncatomic.Uint64]] - code

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Edge_Agent_Core
SORT file.name ASC
```

## Connections to other communities
- 8 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 7 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 4 edges to [[_COMMUNITY_Agent RPC Server]]
- 3 edges to [[_COMMUNITY_gRPC Client Stubs]]
- 3 edges to [[_COMMUNITY_Agent gRPC Bidi Streams]]
- 3 edges to [[_COMMUNITY_Envoy ExtProc Integration]]
- 3 edges to [[_COMMUNITY_Edge Reverse Proxy]]
- 3 edges to [[_COMMUNITY_HAProxy SPOA Integration]]
- 3 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 2 edges to [[_COMMUNITY_Caddy Handler Module]]
- 2 edges to [[_COMMUNITY_FTW Sandbox Runner]]
- 1 edge to [[_COMMUNITY_ConfigBundle Messages]]
- 1 edge to [[_COMMUNITY_Minor corazium.go]]
- 1 edge to [[_COMMUNITY_Edge Transaction Handling]]
- 1 edge to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 1 edge to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Control Plane API Handlers]]
- 1 edge to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 1 edge to [[_COMMUNITY_Email Alerts and Redis]]

## Top bridge nodes
- [[Core]] - degree 30, connects to 12 communities
- [[NewCore()]] - degree 9, connects to 5 communities
- [[AgentServiceClient_1]] - degree 7, connects to 4 communities
- [[dot-configStream()]] - degree 9, connects to 3 communities
- [[NewAgentServiceClient()]] - degree 6, connects to 3 communities