---
type: community
members: 27
---

# Node TLS and Crypto

**Members:** 27 nodes

## Members
- [[AgentService_AuditStreamClient]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[AgentService_ConnectClient]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[AgentService_ConnectServer]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[agent_grpc.pb.go]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[core.go]] - code - server/internal/agent/core.go
- [[go_pkg_crypto_ecdsa]] - concept
- [[go_pkg_crypto_elliptic]] - concept
- [[go_pkg_crypto_rand]] - concept
- [[go_pkg_crypto_tls]] - concept
- [[go_pkg_crypto_x509]] - concept
- [[go_pkg_crypto_x509_pkix]] - concept
- [[go_pkg_encoding_pem]] - concept
- [[go_pkg_errors]] - concept
- [[go_pkg_github_com_shirou_gopsutil_v4_cpu]] - concept
- [[go_pkg_github_com_shirou_gopsutil_v4_mem]] - concept
- [[go_pkg_google_golang_org_grpc]] - concept
- [[go_pkg_google_golang_org_grpc_codes]] - concept
- [[go_pkg_google_golang_org_grpc_keepalive]] - concept
- [[go_pkg_google_golang_org_grpc_peer]] - concept
- [[go_pkg_google_golang_org_grpc_status]] - concept
- [[go_pkg_math_big]] - concept
- [[google.golang.orggrpc.MethodDesc]] - code
- [[google.golang.orggrpc.ServiceDesc]] - code
- [[google.golang.orggrpc.StreamDesc]] - code
- [[nodeKey]] - code - server/internal/agentrpc/server.go
- [[pki.go]] - code - server/internal/agentrpc/pki.go
- [[server.go]] - code - server/internal/agentrpc/server.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Node_TLS_and_Crypto
SORT file.name ASC
```

## Connections to other communities
- 39 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 13 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 8 edges to [[_COMMUNITY_Edge Agent Core]]
- 7 edges to [[_COMMUNITY_Caddy Module Deps]]
- 6 edges to [[_COMMUNITY_Policy Documents]]
- 5 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 4 edges to [[_COMMUNITY_Agent RPC Server]]
- 4 edges to [[_COMMUNITY_AgentService Server Stubs]]
- 4 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 4 edges to [[_COMMUNITY_Node Cert Signing]]
- 3 edges to [[_COMMUNITY_gRPC Server Auth Interceptors]]
- 2 edges to [[_COMMUNITY_Event Classification Pipeline]]
- 2 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 2 edges to [[_COMMUNITY_Protogen Tool Deps]]
- 2 edges to [[_COMMUNITY_Protobuf Runtime Deps]]
- 1 edge to [[_COMMUNITY_Agent gRPC Bidi Streams]]
- 1 edge to [[_COMMUNITY_Envoy ExtProc Integration]]

## Top bridge nodes
- [[server.go]] - degree 40, connects to 11 communities
- [[core.go]] - degree 43, connects to 8 communities
- [[agent_grpc.pb.go]] - degree 25, connects to 8 communities
- [[pki.go]] - degree 23, connects to 4 communities
- [[go_pkg_errors]] - degree 13, connects to 4 communities