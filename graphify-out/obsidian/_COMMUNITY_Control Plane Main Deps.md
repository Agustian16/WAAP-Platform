---
type: community
members: 24
---

# Control Plane Main Deps

**Members:** 24 nodes

## Members
- [[control-planemain.go]] - code - server/cmd/control-plane/main.go
- [[corazium-ctlmain.go]] - code - server/cmd/corazium-ctl/main.go
- [[edge-agentmain.go]] - code - server/cmd/edge-agent/main.go
- [[go_pkg_bufio]] - concept
- [[go_pkg_flag]] - concept
- [[go_pkg_fmt]] - concept
- [[go_pkg_github_com_dropmorepackets_haproxy_go_pkg_encoding]] - concept
- [[go_pkg_github_com_dropmorepackets_haproxy_go_spop]] - concept
- [[go_pkg_log_slog]] - concept
- [[go_pkg_net]] - concept
- [[go_pkg_net_smtp]] - concept
- [[go_pkg_net_textproto]] - concept
- [[go_pkg_os]] - concept
- [[go_pkg_os_signal]] - concept
- [[go_pkg_regexp]] - concept
- [[go_pkg_strings]] - concept
- [[go_pkg_syscall]] - concept
- [[loadEnvFile()]] - code - server/cmd/control-plane/main.go
- [[main()_1]] - code - server/cmd/control-plane/main.go
- [[mask.go]] - code - server/internal/agent/mask.go
- [[notify.go]] - code - server/internal/api/notify.go
- [[notify_test.go]] - code - server/internal/api/notify_test.go
- [[spoa.go]] - code - server/internal/agent/spoa.go
- [[str()]] - code - server/internal/agent/spoa.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Control_Plane_Main_Deps
SORT file.name ASC
```

## Connections to other communities
- 54 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 16 edges to [[_COMMUNITY_Policy Documents]]
- 13 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 12 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 9 edges to [[_COMMUNITY_Email Alerts and Redis]]
- 7 edges to [[_COMMUNITY_Caddy Module Deps]]
- 6 edges to [[_COMMUNITY_Devsim Traffic Generator]]
- 5 edges to [[_COMMUNITY_HAProxy SPOA Integration]]
- 5 edges to [[_COMMUNITY_Protogen Tool Deps]]
- 4 edges to [[_COMMUNITY_Edge Transaction Handling]]
- 3 edges to [[_COMMUNITY_SPOE Handler]]
- 2 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Control Plane API Handlers]]
- 1 edge to [[_COMMUNITY_Enrollment and Geo Feeds]]

## Top bridge nodes
- [[control-planemain.go]] - degree 37, connects to 7 communities
- [[go_pkg_fmt]] - degree 19, connects to 7 communities
- [[spoa.go]] - degree 23, connects to 6 communities
- [[go_pkg_strings]] - degree 22, connects to 6 communities
- [[edge-agentmain.go]] - degree 17, connects to 6 communities