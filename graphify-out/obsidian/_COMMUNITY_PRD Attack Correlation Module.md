---
type: community
members: 11
---

# PRD Attack Correlation Module

**Members:** 11 nodes

## Members
- [[Attack Campaign]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Attack Event]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Attack Graph (interactive, WebGL)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[ClickHouse schema (coraza_audit_logs)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Geo Attack Map]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Kill Chain Mapping (WAF-observable, 7 stages)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Kill Chain Progress Bar, Timeline and Radar]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[MITRE ATT&CK technique references]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Module 6 schema (attack_events, attack_campaigns, killchain_rule_mapping, correlation_settings)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Module 6 Dynamic Attack Mapping and Cyber Kill Chain Visualization]] - concept - Coraza_WAF_Management_Dashboard_PRD.md
- [[Release Roadmap (3 phases)]] - concept - Coraza_WAF_Management_Dashboard_PRD.md

## Live Query (requires Dataview plugin)

```dataview
TABLE source_file, type FROM #community/PRD_Attack_Correlation_Module
SORT file.name ASC
```

## Connections to other communities
- 3 edges to [[_COMMUNITY_PRD Feature Modules]]
- 2 edges to [[_COMMUNITY_PRD Core Modules and KPIs]]
- 2 edges to [[_COMMUNITY_High-Level Architecture]]
- 2 edges to [[_COMMUNITY_Repo Layout and NFRs]]
- 1 edge to [[_COMMUNITY_PRD Rules and CRS Module]]
- 1 edge to [[_COMMUNITY_Campaign Correlation Requirements]]

## Top bridge nodes
- [[Module 6 Dynamic Attack Mapping and Cyber Kill Chain Visualization]] - degree 12, connects to 4 communities
- [[Kill Chain Mapping (WAF-observable, 7 stages)]] - degree 6, connects to 3 communities
- [[ClickHouse schema (coraza_audit_logs)]] - degree 3, connects to 2 communities
- [[Release Roadmap (3 phases)]] - degree 2, connects to 1 community