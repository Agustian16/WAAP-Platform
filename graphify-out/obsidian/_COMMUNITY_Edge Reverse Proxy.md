---
type: community
members: 10
---

# Edge Reverse Proxy

**Members:** 10 nodes

## Members
- [[dot-ConfigVersion()_2]] - code - server/internal/agent/core.go
- [[dot-Run()_1]] - code - server/internal/agent/envoy.go
- [[dot-Run()_2]] - code - server/internal/agent/proxy.go
- [[dot-inspectResponse()]] - code - server/internal/agent/proxy.go
- [[NewProxy()]] - code - server/internal/agent/proxy.go
- [[Proxy]] - code - server/internal/agent/proxy.go
- [[Tx_3]] - code
- [[nethttp.Response]] - code
- [[nethttphttputil.ReverseProxy]] - code
- [[txOf()]] - code - server/internal/agent/proxy.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Edge_Reverse_Proxy
SORT file.name ASC
```

## Connections to other communities
- 3 edges to [[_COMMUNITY_Edge Agent Core]]
- 3 edges to [[_COMMUNITY_Envoy ExtProc Integration]]
- 3 edges to [[_COMMUNITY_Policy Documents]]
- 2 edges to [[_COMMUNITY_Proxy HTTP Handlers]]
- 2 edges to [[_COMMUNITY_HAProxy SPOA Integration]]
- 2 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 1 edge to [[_COMMUNITY_PKI Pinning and CA]]

## Top bridge nodes
- [[NewProxy()]] - degree 7, connects to 5 communities
- [[Proxy]] - degree 8, connects to 4 communities
- [[txOf()]] - degree 5, connects to 2 communities
- [[dot-ConfigVersion()_2]] - degree 4, connects to 2 communities
- [[dot-Run()_1]] - degree 3, connects to 2 communities