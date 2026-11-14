---
type: community
members: 13
---

# Heartbeat Messages

**Members:** 13 nodes

## Members
- [[dot-GetBlocked()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetConfigVersion()_1]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetCpu()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetIntervalS()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetLatencyMs()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetMemory()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-GetRequests()]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-ProtoMessage()_9]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-Reset()_9]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-String()_9]] - code - server/gen/agent/v1/agent.pb.go
- [[dot-isNodeMessage_Msg()_2]] - code - server/gen/agent/v1/agent.pb.go
- [[Heartbeat]] - code - server/gen/agent/v1/agent.pb.go
- [[NodeMessage_Heartbeat]] - code - server/gen/agent/v1/agent.pb.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Heartbeat_Messages
SORT file.name ASC
```

## Connections to other communities
- 2 edges to [[_COMMUNITY_Enroll Protobuf Messages]]
- 2 edges to [[_COMMUNITY_Protobuf Runtime Deps]]
- 1 edge to [[_COMMUNITY_gRPC Client Stubs]]
- 1 edge to [[_COMMUNITY_Agent gRPC Bidi Streams]]
- 1 edge to [[_COMMUNITY_Protobuf Reflection]]
- 1 edge to [[_COMMUNITY_Proto File Descriptor]]
- 1 edge to [[_COMMUNITY_ConfigAck Messages]]

## Top bridge nodes
- [[Heartbeat]] - degree 18, connects to 6 communities
- [[NodeMessage_Heartbeat]] - degree 3, connects to 1 community
- [[dot-isNodeMessage_Msg()_2]] - degree 2, connects to 1 community