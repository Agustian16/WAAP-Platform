---
type: community
members: 20
---

# Edge Transaction Handling

**Members:** 20 nodes

## Members
- [[dot-Begin()]] - code - server/internal/agent/tx.go
- [[dot-Blocked()]] - code - server/internal/agent/tx.go
- [[dot-Finish()]] - code - server/internal/agent/tx.go
- [[dot-ResponseBody()]] - code - server/internal/agent/tx.go
- [[dot-ResponseHeaders()]] - code - server/internal/agent/tx.go
- [[dot-WantsResponseBody()]] - code - server/internal/agent/tx.go
- [[dot-timed()]] - code - server/internal/agent/tx.go
- [[MaskBody()]] - code - server/internal/agent/mask.go
- [[MaskHeaders()]] - code - server/internal/agent/mask.go
- [[MaskMatch()]] - code - server/internal/agent/mask.go
- [[ProcessRequest()]] - code - server/internal/waf/waf.go
- [[Request_1]] - code - server/internal/agent/tx.go
- [[Tx]] - code - server/internal/agent/tx.go
- [[blockStatus()]] - code - server/internal/agent/tx.go
- [[github.comcorazawafcorazav3types.Interruption]] - code
- [[github.comcorazawafcorazav3types.Transaction]] - code
- [[github.comenvoyproxygo-control-planeenvoyconfigcorev3.HeaderMap]] - code
- [[headerMap()]] - code - server/internal/agent/envoy.go
- [[nethttp.Header]] - code
- [[parseHeaders()]] - code - server/internal/agent/spoa.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Edge_Transaction_Handling
SORT file.name ASC
```

## Connections to other communities
- 9 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 4 edges to [[_COMMUNITY_Envoy ExtProc Integration]]
- 4 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 1 edge to [[_COMMUNITY_gRPC Client Stubs]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_Agent RPC Server]]
- 1 edge to [[_COMMUNITY_Caddy Module Deps]]
- 1 edge to [[_COMMUNITY_SPOE Handler]]
- 1 edge to [[_COMMUNITY_Proxy HTTP Handlers]]

## Top bridge nodes
- [[Tx]] - degree 13, connects to 4 communities
- [[ProcessRequest()]] - degree 7, connects to 2 communities
- [[Request_1]] - degree 4, connects to 2 communities
- [[headerMap()]] - degree 4, connects to 2 communities
- [[parseHeaders()]] - degree 3, connects to 2 communities