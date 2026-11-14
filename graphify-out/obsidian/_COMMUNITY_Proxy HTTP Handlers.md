---
type: community
members: 10
---

# Proxy HTTP Handlers

**Members:** 10 nodes

## Members
- [[dot-Flush()_2]] - code - server/internal/agent/proxy.go
- [[dot-ServeHTTP()]] - code - server/internal/agent/proxy.go
- [[dot-ServeHTTP()_1]] - code - server/integrations/caddy/corazium.go
- [[dot-WriteHeader()]] - code - server/internal/agent/proxy.go
- [[BufferBody()]] - code - server/internal/agent/proxy.go
- [[blockedResponse()]] - code - server/integrations/caddy/corazium.go
- [[github.comcaddyservercaddyv2modulescaddyhttp.Handler]] - code
- [[nethttp.Request]] - code
- [[nethttp.ResponseWriter]] - code
- [[statusRecorder]] - code - server/internal/agent/proxy.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Proxy_HTTP_Handlers
SORT file.name ASC
```

## Connections to other communities
- 2 edges to [[_COMMUNITY_Edge Reverse Proxy]]
- 2 edges to [[_COMMUNITY_Policy Documents]]
- 1 edge to [[_COMMUNITY_Caddy Handler Module]]
- 1 edge to [[_COMMUNITY_Edge Transaction Handling]]
- 1 edge to [[_COMMUNITY_Envoy ExtProc Integration]]
- 1 edge to [[_COMMUNITY_Caddy Module Deps]]

## Top bridge nodes
- [[dot-ServeHTTP()]] - degree 5, connects to 2 communities
- [[nethttp.Request]] - degree 5, connects to 2 communities
- [[dot-ServeHTTP()_1]] - degree 6, connects to 1 community
- [[statusRecorder]] - degree 4, connects to 1 community
- [[BufferBody()]] - degree 4, connects to 1 community