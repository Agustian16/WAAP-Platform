---
type: community
members: 9
---

# Node Cert Signing

**Members:** 9 nodes

## Members
- [[dot-ServerCert()]] - code - server/internal/agentrpc/pki.go
- [[dot-SignNode()]] - code - server/internal/agentrpc/pki.go
- [[GenerateCA()]] - code - server/internal/agentrpc/pki.go
- [[cryptoecdsa.PrivateKey]] - code
- [[cryptotls.Certificate]] - code
- [[encodeCert()]] - code - server/internal/agentrpc/pki.go
- [[encodeKey()]] - code - server/internal/agentrpc/pki.go
- [[mathbig.Int]] - code
- [[serial()]] - code - server/internal/agentrpc/pki.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Node_Cert_Signing
SORT file.name ASC
```

## Connections to other communities
- 4 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 3 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 1 edge to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 1 edge to [[_COMMUNITY_gRPC Server Auth Interceptors]]

## Top bridge nodes
- [[dot-ServerCert()]] - degree 4, connects to 2 communities
- [[dot-SignNode()]] - degree 4, connects to 2 communities
- [[serial()]] - degree 5, connects to 1 community
- [[GenerateCA()]] - degree 4, connects to 1 community
- [[encodeCert()]] - degree 3, connects to 1 community