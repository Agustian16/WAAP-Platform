---
type: community
members: 6
---

# Compose Healthchecks

**Members:** 6 nodes

## Members
- [[healthcheck]] - code - server/deploy/docker-compose.yml
- [[healthcheck_1]] - code - server/deploy/docker-compose.yml
- [[healthcheck_2]] - code - server/deploy/docker-compose.yml
- [[interval]] - code - server/deploy/docker-compose.yml
- [[retries]] - code - server/deploy/docker-compose.yml
- [[test]] - code - server/deploy/docker-compose.yml

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/Compose_Healthchecks
SORT file.name ASC
```

## Connections to other communities
- 1 edge to [[_COMMUNITY_Compose Service Settings]]
- 1 edge to [[_COMMUNITY_Postgres Compose Config]]
- 1 edge to [[_COMMUNITY_Redis Compose Config]]

## Top bridge nodes
- [[healthcheck]] - degree 4, connects to 1 community
- [[healthcheck_1]] - degree 4, connects to 1 community
- [[healthcheck_2]] - degree 4, connects to 1 community