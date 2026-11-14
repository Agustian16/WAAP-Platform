---
type: community
members: 6
---

# Campaign Correlation Requirements

**Members:** 6 nodes

## Members
- [[Campaign Correlation (actor key, sliding window)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[In-browser mock API (libmockdata.ts)]] - concept - web/README.md
- [[Module 6 technical requirements (Redis state, WebSocket, safe degradation)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[NFR-3.2 Stateless Control Plane]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Several control plane instances via Redis]] - concept - server/README.md
- [[WebSocket wsattacks live stream]] - concept - web/README.md

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Campaign_Correlation_Requirements
SORT file.name ASC
```

## Connections to other communities
- 3 edges to [[_COMMUNITY_High-Level Architecture]]
- 3 edges to [[_COMMUNITY_Repo Layout and NFRs]]
- 1 edge to [[_COMMUNITY_PRD Attack Correlation Module]]

## Top bridge nodes
- [[Module 6 technical requirements (Redis state, WebSocket, safe degradation)]] - degree 4, connects to 2 communities
- [[In-browser mock API (libmockdata.ts)]] - degree 4, connects to 2 communities
- [[Several control plane instances via Redis]] - degree 4, connects to 1 community
- [[WebSocket wsattacks live stream]] - degree 3, connects to 1 community
- [[Campaign Correlation (actor key, sliding window)]] - degree 2, connects to 1 community