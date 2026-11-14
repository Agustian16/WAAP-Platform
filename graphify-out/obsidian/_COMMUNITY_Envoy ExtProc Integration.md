---
type: community
members: 12
---

# Envoy ExtProc Integration

**Members:** 12 nodes

## Members
- [[dot-Process()_1]] - code - server/internal/agent/envoy.go
- [[dot-client()]] - code - server/internal/agent/envoy.go
- [[ClientAddr()]] - code - server/internal/agent/proxy.go
- [[Envoy]] - code - server/internal/agent/envoy.go
- [[NewEnvoy()]] - code - server/internal/agent/envoy.go
- [[github.comenvoyproxygo-control-planeenvoyserviceext_procv3.ExternalProcessor_ProcessServer]] - code
- [[github.comenvoyproxygo-control-planeenvoyserviceext_procv3.ProcessingRequest]] - code
- [[github.comenvoyproxygo-control-planeenvoyserviceext_procv3.UnimplementedExternalProcessorServer]] - code
- [[inAny()]] - code - server/internal/agent/core.go
- [[netnetip.Addr]] - code
- [[netnetip.Prefix]] - code
- [[protocol()]] - code - server/internal/agent/envoy.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Envoy_ExtProc_Integration
SORT file.name ASC
```

## Connections to other communities
- 4 edges to [[_COMMUNITY_Edge Transaction Handling]]
- 4 edges to [[_COMMUNITY_Caddy Module Deps]]
- 3 edges to [[_COMMUNITY_Edge Agent Core]]
- 3 edges to [[_COMMUNITY_Edge Reverse Proxy]]
- 1 edge to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 1 edge to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Node TLS and Crypto]]
- 1 edge to [[_COMMUNITY_HAProxy SPOA Integration]]
- 1 edge to [[_COMMUNITY_Proxy HTTP Handlers]]
- 1 edge to [[_COMMUNITY_Policy Documents]]

## Top bridge nodes
- [[NewEnvoy()]] - degree 6, connects to 4 communities
- [[Envoy]] - degree 8, connects to 3 communities
- [[netnetip.Prefix]] - degree 8, connects to 3 communities
- [[dot-Process()_1]] - degree 6, connects to 2 communities
- [[inAny()]] - degree 6, connects to 2 communities