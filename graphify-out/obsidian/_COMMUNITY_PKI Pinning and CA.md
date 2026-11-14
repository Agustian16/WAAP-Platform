---
type: community
members: 22
---

# PKI Pinning and CA

**Members:** 22 nodes

## Members
- [[dot-Pin()]] - code - server/internal/agentrpc/pki.go
- [[CA]] - code - server/internal/agentrpc/pki.go
- [[GeoOverride]] - code - server/internal/store/pg.go
- [[NewGeo()]] - code - server/internal/correlate/killchain.go
- [[NewHub()]] - code - server/internal/api/data.go
- [[NewServer()]] - code - server/internal/agentrpc/server.go
- [[ParseCA()]] - code - server/internal/agentrpc/pki.go
- [[PinOf()]] - code - server/internal/agentrpc/pki.go
- [[TestActorKeyModes()]] - code - server/internal/correlate/engine_test.go
- [[TestCampaignLifecycle()]] - code - server/internal/correlate/engine_test.go
- [[TestControlPlaneEndToEnd()]] - code - server/internal/api/integration_test.go
- [[TestEmailNotifier()]] - code - server/internal/api/notify_test.go
- [[TestGeoLite2Lookup()]] - code - server/internal/correlate/geo_test.go
- [[Tx_2]] - code
- [[cryptox509.Certificate]] - code
- [[fakeSMTP()]] - code - server/internal/api/notify_test.go
- [[freeAddr()]] - code - server/internal/api/integration_test.go
- [[mustV()]] - code - server/internal/api/integration_test.go
- [[setup()]] - code - server/internal/api/integration_test.go
- [[setup()_1]] - code - server/internal/correlate/engine_test.go
- [[testing.T]] - code
- [[tx()]] - code - server/internal/correlate/engine_test.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/PKI_Pinning_and_CA
SORT file.name ASC
```

## Connections to other communities
- 11 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 6 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 5 edges to [[_COMMUNITY_Email Alerts and Redis]]
- 5 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 4 edges to [[_COMMUNITY_Node TLS and Crypto]]
- 4 edges to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 4 edges to [[_COMMUNITY_Campaign Store and Tests]]
- 3 edges to [[_COMMUNITY_Agent RPC Server]]
- 3 edges to [[_COMMUNITY_Node Cert Signing]]
- 3 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 3 edges to [[_COMMUNITY_Control Plane API Handlers]]
- 3 edges to [[_COMMUNITY_Edge Agent Core]]
- 2 edges to [[_COMMUNITY_Postgres Store]]
- 2 edges to [[_COMMUNITY_Live Campaign Memory]]
- 2 edges to [[_COMMUNITY_Control Plane Main Deps]]
- 2 edges to [[_COMMUNITY_Event Classification Pipeline]]
- 1 edge to [[_COMMUNITY_Live Event Hub]]
- 1 edge to [[_COMMUNITY_Edge Reverse Proxy]]
- 1 edge to [[_COMMUNITY_Envoy ExtProc Integration]]
- 1 edge to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 1 edge to [[_COMMUNITY_Protogen Tool Deps]]

## Top bridge nodes
- [[setup()]] - degree 19, connects to 8 communities
- [[TestControlPlaneEndToEnd()]] - degree 15, connects to 6 communities
- [[NewServer()]] - degree 9, connects to 6 communities
- [[NewGeo()]] - degree 11, connects to 4 communities
- [[testing.T]] - degree 17, connects to 3 communities