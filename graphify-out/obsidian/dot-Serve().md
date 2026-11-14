---
source_file: "server/internal/agentrpc/server.go"
type: "code"
community: "gRPC Server Auth Interceptors"
location: "L59"
tags:
  - graphify/code
  - graphify/EXTRACTED
  - community/gRPC_Server_Auth_Interceptors
---

# .Serve()

## Connections
- [[dot-ServerCert()]] - `calls` [INFERRED]
- [[dot-streamAuth()]] - `indirect_call` [INFERRED]
- [[dot-unaryAuth()]] - `indirect_call` [INFERRED]
- [[RegisterAgentServiceServer()]] - `calls` [EXTRACTED]
- [[Server]] - `method` [EXTRACTED]
- [[context.Context]] - `references` [EXTRACTED]
- [[net.Listener]] - `references` [EXTRACTED]

#graphify/code #graphify/EXTRACTED #community/gRPC_Server_Auth_Interceptors