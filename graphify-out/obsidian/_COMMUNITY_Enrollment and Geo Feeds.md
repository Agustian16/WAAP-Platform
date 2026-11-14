---
type: community
members: 24
---

# Enrollment and Geo Feeds

**Members:** 24 nodes

## Members
- [[dot-Context()]] - code - server/internal/agentrpc/server.go
- [[dot-Enroll()]] - code - server/internal/agentrpc/server.go
- [[dot-Enroll()_1]] - code - server/internal/store/pg.go
- [[dot-Enroll()_2]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[dot-Enroll()_3]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[dot-Enroll()_5]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[dot-Enroll()_6]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[dot-Ensure()]] - code - server/internal/correlate/geoupdate.go
- [[dot-GeoOverrides()]] - code - server/internal/store/pg.go
- [[dot-LoadCorrelation()]] - code - server/internal/api/admin.go
- [[dot-download()]] - code - server/internal/correlate/geoupdate.go
- [[dot-feedClient()]] - code - server/internal/api/admin.go
- [[dot-path()]] - code - server/internal/correlate/geoupdate.go
- [[dot-reloadCorrelation()]] - code - server/internal/api/admin.go
- [[GeoUpdater]] - code - server/internal/correlate/geoupdate.go
- [[_AgentService_Enroll_Handler()]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[authedStream]] - code - server/internal/agentrpc/server.go
- [[context.Context]] - code
- [[google.golang.orggrpc.UnaryServerInterceptor]] - code
- [[nethttp.Client]] - code
- [[refreshGeo()]] - code - server/cmd/control-plane/main.go
- [[send()]] - code - server/cmd/devsim/main.go
- [[sleep()]] - code - server/cmd/devsim/main.go
- [[traffic()]] - code - server/cmd/devsim/main.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Enrollment_and_Geo_Feeds
SORT file.name ASC
```

## Connections to other communities
- 22 edges to [[_COMMUNITY_Postgres Store]]
- 11 edges to [[_COMMUNITY_Agent RPC Server]]
- 10 edges to [[_COMMUNITY_Enroll Protobuf Messages]]
- 10 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 9 edges to [[_COMMUNITY_Postgres Row Scanners]]
- 7 edges to [[_COMMUNITY_Edge Agent Core]]
- 7 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 7 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 6 edges to [[_COMMUNITY_Live Campaign Memory]]
- 6 edges to [[_COMMUNITY_Threat Feed Store]]
- 5 edges to [[_COMMUNITY_Devsim Traffic Generator]]
- 5 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 5 edges to [[_COMMUNITY_Custom Rule Store]]
- 4 edges to [[_COMMUNITY_gRPC Server Auth Interceptors]]
- 4 edges to [[_COMMUNITY_Email Alerts and Redis]]
- 4 edges to [[_COMMUNITY_Users and Roles]]
- 3 edges to [[_COMMUNITY_Agent gRPC Bidi Streams]]
- 3 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 3 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 3 edges to [[_COMMUNITY_IP List Store]]
- 2 edges to [[_COMMUNITY_AgentService Server Stubs]]
- 2 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 2 edges to [[_COMMUNITY_gRPC Client Stubs]]
- 2 edges to [[_COMMUNITY_Edge Reverse Proxy]]
- 2 edges to [[_COMMUNITY_HAProxy SPOA Integration]]
- 2 edges to [[_COMMUNITY_Edge Node Model]]
- 1 edge to [[_COMMUNITY_Policy Documents]]
- 1 edge to [[_COMMUNITY_Node Cert Signing]]
- 1 edge to [[_COMMUNITY_Control Plane Main Deps]]
- 1 edge to [[_COMMUNITY_Event Classification Pipeline]]
- 1 edge to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_SPOE Handler]]

## Top bridge nodes
- [[context.Context]] - degree 129, connects to 25 communities
- [[refreshGeo()]] - degree 10, connects to 5 communities
- [[dot-Enroll()]] - degree 7, connects to 3 communities
- [[GeoUpdater]] - degree 7, connects to 2 communities
- [[dot-Enroll()_5]] - degree 7, connects to 2 communities