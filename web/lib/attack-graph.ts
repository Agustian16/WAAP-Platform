// Attack Graph model (FR-6.5, FR-6.9): turns enriched events into nodes/edges, aggregating attacker IPs into
// ASN clusters (then endpoints into per-site buckets) until the node budget holds. Pure; rendered by components/attack/graph.
import type { AttackEvent, RuleCategory, StageKey } from "./types";
import { stageIndex, CATEGORIES } from "./killchain";

export type GNodeType = "attacker" | "cluster" | "site" | "endpoint" | "category" | "edgenode";
export interface GNode { id: string; type: GNodeType; label: string; count: number; stage: StageKey | null; campaignIds: string[]; ips?: string[]; host?: string; path?: string; category?: RuleCategory; lastTs: number; ps: number }
export interface GEdge { id: string; source: string; target: string; kind: "attack" | "structure"; count: number; stage: StageKey | null; rules: number[]; lastTs: number; ps: number }
export interface GraphOptions { maxNodes: number; groupByAsn: boolean; showCategories: boolean; showEdgeNodes: boolean; expanded: Set<string> }

const higher = (a: StageKey | null, b: StageKey) => (a === null || stageIndex(b) > stageIndex(a) ? b : a);
const pathOf = (uri: string) => uri.split("?")[0];

export function buildGraph(events: AttackEvent[], o: GraphOptions) {
  const byIp = new Map<string, AttackEvent[]>();
  events.forEach((e) => byIp.set(e.client_ip, [...(byIp.get(e.client_ip) ?? []), e]));
  const endpoints = new Set(events.map((e) => `${e.host}${pathOf(e.uri)}`));
  const sites = new Set(events.map((e) => e.host));
  const cats = o.showCategories ? new Set(events.map((e) => e.rule_category)) : new Set<string>();
  const enodes = o.showEdgeNodes ? new Set(events.map((e) => e.node_id)) : new Set<string>();

  // Decide which IPs collapse into ASN clusters.
  const asnOf = new Map<string, number>();
  events.forEach((e) => asnOf.set(e.client_ip, e.asn));
  const asnGroups = new Map<number, string[]>();
  byIp.forEach((_, ip) => asnGroups.set(asnOf.get(ip)!, [...(asnGroups.get(asnOf.get(ip)!) ?? []), ip]));
  const collapsed = new Set<number>();
  const fixed = sites.size + cats.size + enodes.size;
  let endpointBudget = endpoints.size;
  const attackerCount = () => [...asnGroups].reduce((a, [asn, ips]) => a + (collapsed.has(asn) ? 1 : ips.length), 0);
  if (o.groupByAsn) asnGroups.forEach((ips, asn) => { if (ips.length > 1 && !o.expanded.has(`asn:${asn}`)) collapsed.add(asn); });
  // Auto-aggregate largest ASN groups first until within budget.
  const groups = [...asnGroups].filter(([, ips]) => ips.length > 1).sort((a, b) => b[1].length - a[1].length);
  for (const [asn] of groups) {
    if (fixed + endpointBudget + attackerCount() <= o.maxNodes) break;
    if (!o.expanded.has(`asn:${asn}`)) collapsed.add(asn);
  }
  // Still over: bucket endpoints per site, keeping the most-hit endpoints visible.
  const epCounts = new Map<string, number>();
  events.forEach((e) => { const k = `${e.host}${pathOf(e.uri)}`; epCounts.set(k, (epCounts.get(k) ?? 0) + 1); });
  const keepEp = new Set([...epCounts].sort((a, b) => b[1] - a[1]).map(([k]) => k));
  while (fixed + keepEp.size + attackerCount() > o.maxNodes && keepEp.size > sites.size) {
    const last = [...keepEp].pop()!;
    keepEp.delete(last);
  }
  endpointBudget = keepEp.size;

  const nodes = new Map<string, GNode>();
  const edges = new Map<string, GEdge>();
  const node = (id: string, init: () => Omit<GNode, "count" | "stage" | "campaignIds" | "lastTs" | "ps">, e: AttackEvent) => {
    let n = nodes.get(id);
    if (!n) { n = { ...init(), count: 0, stage: null, campaignIds: [], lastTs: 0, ps: 0 }; nodes.set(id, n); }
    n.count++;
    n.stage = higher(n.stage, e.killchain_stage);
    if (!n.campaignIds.includes(e.campaign_id)) n.campaignIds.push(e.campaign_id);
    n.lastTs = Math.max(n.lastTs, e.timestamp);
    if (e.outcome === "POSSIBLY_SUCCESSFUL") n.ps++;
    return n;
  };
  const edge = (source: string, target: string, kind: GEdge["kind"], e: AttackEvent) => {
    const id = `${source}->${target}`;
    let x = edges.get(id);
    if (!x) { x = { id, source, target, kind, count: 0, stage: null, rules: [], lastTs: 0, ps: 0 }; edges.set(id, x); }
    x.count++;
    x.stage = higher(x.stage, e.killchain_stage);
    if (!x.rules.includes(e.rule_id)) x.rules.push(e.rule_id);
    x.lastTs = Math.max(x.lastTs, e.timestamp);
    if (e.outcome === "POSSIBLY_SUCCESSFUL") x.ps++;
  };

  for (const e of events) {
    const asn = e.asn;
    const aId = collapsed.has(asn) ? `asn:${asn}` : `ip:${e.client_ip}`;
    node(aId, () => collapsed.has(asn)
      ? { id: aId, type: "cluster", label: `AS${asn} (${asnGroups.get(asn)!.length} IPs)`, ips: asnGroups.get(asn) }
      : { id: aId, type: "attacker", label: `${e.client_ip} (${e.country_code})`, ips: [e.client_ip] }, e);
    const epKey = `${e.host}${pathOf(e.uri)}`;
    const epId = keepEp.has(epKey) ? `ep:${epKey}` : `ep:${e.host}/*`;
    node(epId, () => keepEp.has(epKey)
      ? { id: epId, type: "endpoint", label: pathOf(e.uri).length > 34 ? pathOf(e.uri).slice(0, 33) + "…" : pathOf(e.uri), host: e.host, path: pathOf(e.uri) }
      : { id: epId, type: "endpoint", label: `${e.host} (other endpoints)`, host: e.host, path: "*" }, e);
    const sId = `site:${e.host}`;
    node(sId, () => ({ id: sId, type: "site", label: e.host, host: e.host }), e);
    edge(aId, epId, "attack", e);
    edge(epId, sId, "structure", e);
    if (o.showCategories) {
      const cId = `cat:${e.rule_category}`;
      node(cId, () => ({ id: cId, type: "category", label: CATEGORIES.find((c) => c.key === e.rule_category)!.name, category: e.rule_category }), e);
      edge(epId, cId, "structure", e);
    }
    if (o.showEdgeNodes) {
      const nId = `node:${e.node_id}`;
      node(nId, () => ({ id: nId, type: "edgenode", label: e.node_id.replace(/^n-/, "") }), e);
      edge(sId, nId, "structure", e);
    }
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], aggregated: collapsed.size > 0 || keepEp.size < endpoints.size, hiddenEndpoints: endpoints.size - keepEp.size };
}

/** Deterministic positions for the hierarchical (left->right per stage) and radial layouts. */
export function staticLayout(nodes: GNode[], mode: "hierarchical" | "radial") {
  const col = (n: GNode) => {
    if (n.type === "attacker" || n.type === "cluster") return 0;
    if (n.type === "endpoint") return 1 + Math.max(0, stageIndex(n.stage ?? "RECON") - 1); // RECON->1 ... OBJECTIVES->6
    if (n.type === "site") return 7.5;
    if (n.type === "edgenode") return 9;
    return 9; // category
  };
  const groups = new Map<number, GNode[]>();
  nodes.forEach((n) => groups.set(col(n), [...(groups.get(col(n)) ?? []), n]));
  const pos: Record<string, { x: number; y: number }> = {};
  if (mode === "hierarchical") {
    groups.forEach((list, c) => {
      list.sort((a, b) => (a.type === b.type ? b.count - a.count : a.type < b.type ? -1 : 1));
      list.forEach((n, i) => { pos[n.id] = { x: c * 120, y: (i - (list.length - 1) / 2) * 60 }; });
    });
  } else {
    const ring = (n: GNode) => (n.type === "attacker" || n.type === "cluster" ? 3 : n.type === "endpoint" ? 2 : n.type === "site" ? 1 : 0.45);
    const rings = new Map<number, GNode[]>();
    nodes.forEach((n) => rings.set(ring(n), [...(rings.get(ring(n)) ?? []), n]));
    rings.forEach((list, rr) => {
      list.sort((a, b) => a.id.localeCompare(b.id));
      list.forEach((n, i) => {
        const a = (i / list.length) * Math.PI * 2 + rr * 0.3;
        pos[n.id] = { x: Math.cos(a) * rr * 160, y: Math.sin(a) * rr * 160 };
      });
    });
  }
  return pos;
}
