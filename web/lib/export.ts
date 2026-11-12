// FR-6.16: campaign export as plain JSON or a STIX 2.1 bundle for SIEM/TIP ingestion.
import type { AttackEvent, Campaign } from "./types";
import { ATTACK_TECHNIQUES, STAGES, stageIndex, techKey, techniqueOf } from "./killchain";

const PHASE: Record<string, string> = {
  RECON: "reconnaissance", WEAPON: "weaponization", DELIVERY: "delivery", EXPLOIT: "exploitation",
  INSTALL: "installation", C2: "command-and-control", OBJECTIVES: "actions-on-objectives",
};

export function campaignJson(c: Campaign, events: AttackEvent[]) {
  return JSON.stringify({ campaign: c, events }, null, 2);
}

export function campaignStix(c: Campaign, events: AttackEvent[]) {
  const id = (t: string) => `${t}--${crypto.randomUUID()}`;
  const now = new Date().toISOString();
  const iso = (t: number) => new Date(t).toISOString();
  const identity = { type: "identity", spec_version: "2.1", id: id("identity"), created: now, modified: now, name: "Corazium", identity_class: "system" };
  const base = { spec_version: "2.1", created: now, modified: now, created_by_ref: identity.id };
  const campaign = { ...base, type: "campaign", id: id("campaign"), name: c.id, description: `WAF-correlated campaign from ${c.actor_key} (${c.country_code}, AS${c.asn}). Highest stage: ${STAGES[stageIndex(c.highest_stage)].name}. Risk ${c.risk_score}/100. Correlation confidence ${c.correlation_confidence}.`, first_seen: iso(c.first_seen), last_seen: iso(c.last_seen) };
  const ips = [...new Set(events.map((e) => e.client_ip))];
  const pattern = ips.length === 1 ? `[ipv4-addr:value = '${ips[0]}']` : ips.slice(0, 50).map((ip) => `[ipv4-addr:value = '${ip}']`).join(" OR ");
  const indicator = {
    ...base, type: "indicator", id: id("indicator"), name: `Attacker ${c.actor_key}`, pattern, pattern_type: "stix", valid_from: iso(c.first_seen), indicator_types: ["malicious-activity"],
    kill_chain_phases: c.stages.map((s) => ({ kill_chain_name: "lockheed-martin-cyber-kill-chain", phase_name: PHASE[s] })),
  };
  const techs = [...new Set(events.map((e) => techniqueOf(e)).filter(Boolean))] as string[];
  const patterns = techs.map((k) => {
    const t = ATTACK_TECHNIQUES.find((x) => techKey(x) === k)!;
    return { ...base, type: "attack-pattern", id: id("attack-pattern"), name: t.name, external_references: [{ source_name: "mitre-attack", external_id: t.id, url: `https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/` }] };
  });
  const rels = [
    { ...base, type: "relationship", id: id("relationship"), relationship_type: "indicates", source_ref: indicator.id, target_ref: campaign.id },
    ...patterns.map((p) => ({ ...base, type: "relationship", id: id("relationship"), relationship_type: "uses", source_ref: campaign.id, target_ref: p.id })),
  ];
  const sighting = { ...base, type: "sighting", id: id("sighting"), sighting_of_ref: indicator.id, count: events.length, first_seen: iso(c.first_seen), last_seen: iso(c.last_seen), where_sighted_refs: [identity.id] };
  return JSON.stringify({ type: "bundle", id: id("bundle"), objects: [identity, campaign, indicator, ...patterns, ...rels, sighting] }, null, 2);
}
