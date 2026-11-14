---
type: community
members: 12
---

# gRPC Server Auth Interceptors

**Members:** 12 nodes

## Members
- [[dot-Serve()]] - code - server/internal/agentrpc/server.go
- [[dot-streamAuth()]] - code - server/internal/agentrpc/server.go
- [[dot-unaryAuth()]] - code - server/internal/agentrpc/server.go
- [[_AgentService_AuditStream_Handler()]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[_AgentService_Connect_Handler()]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[google.golang.orggrpc.ServerStream]] - code
- [[google.golang.orggrpc.StreamHandler]] - code
- [[google.golang.orggrpc.StreamServerInfo]] - code
- [[google.golang.orggrpc.UnaryHandler]] - code
- [[google.golang.orggrpc.UnaryServerInfo]] - code
- [[net.Listener]] - code
- [[nodeID()]] - code - server/internal/agentrpc/server.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/gRPC_Server_Auth_Interceptors
SORT file.name ASC
```

## Connections to other communities
- 4 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 3 edges to [[_COMMUNITY_Agent RPC Server]]
- 3 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 1 edge to [[_COMMUNITY_AgentService Server Stubs]]
- 1 edge to [[_COMMUNITY_Node Cert Signing]]

## Top bridge nodes
- [[dot-Serve()]] - degree 7, connects to 4 communities
- [[dot-unaryAuth()]] - degree 6, connects to 2 communities
- [[nodeID()]] - degree 4, connects to 2 communities
- [[dot-streamAuth()]] - degree 6, connects to 1 community
- [[google.golang.orggrpc.ServerStream]] - degree 4, connects to 1 community