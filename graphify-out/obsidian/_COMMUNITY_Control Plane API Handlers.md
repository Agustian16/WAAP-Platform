---
type: community
members: 89
---

# Control Plane API Handlers

**Members:** 89 nodes

## Members
- [[dot-EnsureBundle()]] - code - server/internal/api/api.go
- [[dot-PushIPLists()]] - code - server/internal/api/api.go
- [[dot-Router()]] - code - server/internal/api/api.go
- [[dot-RunJobs()]] - code - server/internal/api/admin.go
- [[dot-addFeed()]] - code - server/internal/api/admin.go
- [[dot-addIP()]] - code - server/internal/api/admin.go
- [[dot-attackEvents()]] - code - server/internal/api/data.go
- [[dot-audit()]] - code - server/internal/api/api.go
- [[dot-auditTrail()]] - code - server/internal/api/admin.go
- [[dot-buildBundle()]] - code - server/internal/api/api.go
- [[dot-callback()]] - code - server/internal/api/auth.go
- [[dot-campaign()]] - code - server/internal/api/data.go
- [[dot-campaigns()]] - code - server/internal/api/data.go
- [[dot-configVersion()]] - code - server/internal/api/api.go
- [[dot-correlation()]] - code - server/internal/api/admin.go
- [[dot-cors()]] - code - server/internal/api/auth.go
- [[dot-createException()]] - code - server/internal/api/api.go
- [[dot-createSite()]] - code - server/internal/api/api.go
- [[dot-deleteException()]] - code - server/internal/api/api.go
- [[dot-deleteRule()]] - code - server/internal/api/api.go
- [[dot-deploy()]] - code - server/internal/api/api.go
- [[dot-enrollmentToken()]] - code - server/internal/api/api.go
- [[dot-exceptions()]] - code - server/internal/api/api.go
- [[dot-exportPolicy()]] - code - server/internal/api/admin.go
- [[dot-feeds()]] - code - server/internal/api/admin.go
- [[dot-fetchFeed()]] - code - server/internal/api/admin.go
- [[dot-fillIPLists()]] - code - server/internal/api/api.go
- [[dot-getLog()]] - code - server/internal/api/data.go
- [[dot-ipImpact()]] - code - server/internal/api/admin.go
- [[dot-ipLists()]] - code - server/internal/api/admin.go
- [[dot-login()]] - code - server/internal/api/auth.go
- [[dot-logout()]] - code - server/internal/api/auth.go
- [[dot-mapping()]] - code - server/internal/api/admin.go
- [[dot-markDirty()]] - code - server/internal/api/api.go
- [[dot-nodes()]] - code - server/internal/api/api.go
- [[dot-overview()]] - code - server/internal/api/data.go
- [[dot-patchCampaign()]] - code - server/internal/api/data.go
- [[dot-patchSite()]] - code - server/internal/api/api.go
- [[dot-provider()]] - code - server/internal/api/auth.go
- [[dot-providers()]] - code - server/internal/api/auth.go
- [[dot-pullFeed()]] - code - server/internal/api/admin.go
- [[dot-pushLists()]] - code - server/internal/api/admin.go
- [[dot-queryLogs()]] - code - server/internal/api/data.go
- [[dot-removeFeed()]] - code - server/internal/api/admin.go
- [[dot-removeIP()]] - code - server/internal/api/admin.go
- [[dot-roleFor()]] - code - server/internal/api/auth.go
- [[dot-rule()]] - code - server/internal/api/api.go
- [[dot-ruleIDs()]] - code - server/internal/api/api.go
- [[dot-rules()]] - code - server/internal/api/api.go
- [[dot-sandbox()]] - code - server/internal/api/api.go
- [[dot-saveCorrelation()]] - code - server/internal/api/admin.go
- [[dot-saveMapping()]] - code - server/internal/api/admin.go
- [[dot-saveRule()]] - code - server/internal/api/api.go
- [[dot-secure()]] - code - server/internal/api/auth.go
- [[dot-session()]] - code - server/internal/api/auth.go
- [[dot-setCookie()]] - code - server/internal/api/auth.go
- [[dot-setRole()]] - code - server/internal/api/admin.go
- [[dot-setRuleActive()]] - code - server/internal/api/api.go
- [[dot-sites()]] - code - server/internal/api/api.go
- [[dot-users()]] - code - server/internal/api/admin.go
- [[dot-validatePolicy()]] - code - server/internal/api/admin.go
- [[App]] - code - server/internal/api/api.go
- [[Auth]] - code - server/internal/api/auth.go
- [[AuthConfig]] - code - server/internal/api/auth.go
- [[LintRule()]] - code - server/internal/waf/waf.go
- [[NewAuth()]] - code - server/internal/api/auth.go
- [[NewEngine()]] - code - server/internal/waf/waf.go
- [[RuleID()]] - code - server/internal/waf/waf.go
- [[Validate()]] - code - server/internal/waf/waf.go
- [[ValidatePolicy()]] - code - server/internal/api/admin.go
- [[allow()]] - code - server/internal/api/auth.go
- [[bad()]] - code - server/internal/api/api.go
- [[bind()]] - code - server/internal/api/api.go
- [[claimPath()]] - code - server/internal/api/auth.go
- [[coraza.WAF]] - code
- [[fail()]] - code - server/internal/api/api.go
- [[github.comcoreosgo-oidcv3oidc.IDTokenVerifier]] - code
- [[github.comgin-gonicgin.Context]] - code
- [[github.comgin-gonicgin.Engine]] - code
- [[github.comgin-gonicgin.HandlerFunc]] - code
- [[golang.orgxoauth2.Config]] - code
- [[hashToken()]] - code - server/internal/api/auth.go
- [[idp]] - code - server/internal/api/auth.go
- [[main()]] - code - server/cmd/corazium-ctl/main.go
- [[parseCIDR()]] - code - server/internal/api/admin.go
- [[randToken()]] - code - server/internal/api/auth.go
- [[sameOrigin()]] - code - server/internal/api/auth.go
- [[stringsOf()]] - code - server/internal/api/auth.go
- [[userOf()]] - code - server/internal/api/auth.go

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Control_Plane_API_Handlers
SORT file.name ASC
```

## Connections to other communities
- 15 edges to [[_COMMUNITY_Go Stdlib and Store Deps]]
- 10 edges to [[_COMMUNITY_Enrollment and Geo Feeds]]
- 10 edges to [[_COMMUNITY_Coraza and CRS Engine Deps]]
- 6 edges to [[_COMMUNITY_Agent RPC Server]]
- 4 edges to [[_COMMUNITY_Postgres Store]]
- 4 edges to [[_COMMUNITY_Users and Roles]]
- 3 edges to [[_COMMUNITY_Live Event Hub]]
- 3 edges to [[_COMMUNITY_Campaign IDs and Policy Export]]
- 3 edges to [[_COMMUNITY_Email Alerts and Redis]]
- 3 edges to [[_COMMUNITY_PKI Pinning and CA]]
- 2 edges to [[_COMMUNITY_ClickHouse Store and Test Harness]]
- 2 edges to [[_COMMUNITY_Event Classification Pipeline]]
- 2 edges to [[_COMMUNITY_Policy Documents]]
- 1 edge to [[_COMMUNITY_Correlation Engine and Kill Chain]]
- 1 edge to [[_COMMUNITY_Threat Feed Store]]
- 1 edge to [[_COMMUNITY_Control Plane Main Deps]]
- 1 edge to [[_COMMUNITY_Edge Agent Core]]

## Top bridge nodes
- [[App]] - degree 35, connects to 7 communities
- [[NewAuth()]] - degree 9, connects to 5 communities
- [[Auth]] - degree 17, connects to 3 communities
- [[dot-buildBundle()]] - degree 8, connects to 3 communities
- [[dot-Router()]] - degree 23, connects to 2 communities