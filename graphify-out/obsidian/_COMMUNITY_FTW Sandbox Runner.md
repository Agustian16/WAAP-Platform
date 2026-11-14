---
type: community
members: 4
---

# FTW Sandbox Runner

**Members:** 4 nodes

## Members
- [[CRSVersion()]] - code - server/internal/waf/waf.go
- [[EngineVersion()]] - code - server/internal/waf/waf.go
- [[ModuleVersion()]] - code - server/internal/waf/waf.go
- [[runFTW()]] - code - server/internal/waf/ftw.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/FTW_Sandbox_Runner
SORT file.name ASC
```

## Connections to other communities
- 8 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 2 edges to [[_COMMUNITY_Edge Agent Core]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]

## Top bridge nodes
- [[runFTW()]] - degree 8, connects to 2 communities
- [[EngineVersion()]] - degree 4, connects to 2 communities
- [[CRSVersion()]] - degree 3, connects to 2 communities
- [[ModuleVersion()]] - degree 4, connects to 1 community