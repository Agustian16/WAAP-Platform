---
type: community
members: 6
---

# SPOE Handler

**Members:** 6 nodes

## Members
- [[dot-HandleSPOE()]] - code - server/internal/agent/spoa.go
- [[github.comdropmorepacketshaproxy-gopkgencoding.ActionWriter]] - code
- [[github.comdropmorepacketshaproxy-gopkgencoding.Message]] - code
- [[kv()]] - code - server/internal/agent/spoa.go
- [[num()]] - code - server/internal/agent/spoa.go
- [[verdict()]] - code - server/internal/agent/spoa.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/SPOE_Handler
SORT file.name ASC
```

## Connections to other communities
- 3 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 1 edge to [[_COMMUNITY_HAProxy SPOA Integration]]
- 1 edge to [[_COMMUNITY_Edge Transaction Handling]]
- 1 edge to [[_COMMUNITY_Enrollment and Geo Feeds]]

## Top bridge nodes
- [[dot-HandleSPOE()]] - degree 8, connects to 3 communities
- [[kv()]] - degree 3, connects to 1 community
- [[verdict()]] - degree 3, connects to 1 community
- [[num()]] - degree 2, connects to 1 community