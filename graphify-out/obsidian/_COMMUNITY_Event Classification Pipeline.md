---
type: community
members: 16
---

# Event Classification Pipeline

**Members:** 16 nodes

## Members
- [[dot-AuditStream()_3]] - code - server/internal/agentrpc/server.go
- [[dot-Process()]] - code - server/internal/correlate/engine.go
- [[dot-classify()]] - code - server/internal/correlate/engine.go
- [[AgentService_AuditStreamServer]] - code - server/gen/agent/v1/agent_grpc.pb.go
- [[MapRule()]] - code - server/internal/correlate/killchain.go
- [[Outcome()]] - code - server/internal/correlate/killchain.go
- [[RiskScore()]] - code - server/internal/correlate/killchain.go
- [[Rule]] - code - server/internal/correlate/engine.go
- [[StageIndex()_1]] - code - server/internal/correlate/killchain.go
- [[TestMapRule()]] - code - server/internal/correlate/engine_test.go
- [[TestRiskAndOutcome()]] - code - server/internal/correlate/engine_test.go
- [[Tx_1]] - code - server/internal/correlate/engine.go
- [[clip()]] - code - server/internal/agentrpc/server.go
- [[contains()]] - code - server/internal/correlate/killchain.go
- [[pathOf()]] - code - server/internal/correlate/engine.go
- [[scoring()]] - code - server/internal/correlate/engine.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Event_Classification_Pipeline
SORT file.name ASC
```

## Connections to other communities
- 11 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 4 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 2 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 2 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 2 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Agent RPC Server]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_gRPC Client Stubs]]
- 1 edge to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 1 edge to [[_COMMUNITY_Live Campaign Memory]]

## Top bridge nodes
- [[dot-Process()]] - degree 12, connects to 3 communities
- [[MapRule()]] - degree 6, connects to 3 communities
- [[dot-AuditStream()_3]] - degree 5, connects to 2 communities
- [[StageIndex()_1]] - degree 5, connects to 2 communities
- [[Tx_1]] - degree 4, connects to 2 communities