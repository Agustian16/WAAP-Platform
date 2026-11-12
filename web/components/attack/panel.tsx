"use client";
// Context panel (FR-6.14) + response actions (FR-6.15) + export (FR-6.16) for the selected campaign, node or edge.
import * as React from "react";
import Link from "next/link";
import { ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, Radar, Tooltip } from "recharts";
import { Copy, Prohibit, ListMagnifyingGlass, PushPin, PushPinSlash, Play, Stop, DownloadSimple, CaretDown, ArrowsOutSimple, FileText, ShieldSlash } from "@phosphor-icons/react";
import { attacks } from "@/lib/api";
import { CATEGORIES, stageIndex } from "@/lib/killchain";
import { campaignJson, campaignStix } from "@/lib/export";
import type { AttackEvent, Campaign, StageKey } from "@/lib/types";
import type { GEdge, GNode } from "@/lib/attack-graph";
import { cn, download, fmtNum, fmtTime, relTime } from "@/lib/utils";
import { Button, Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger, Select, Textarea } from "../ui";
import { CampaignStatusText, ConfidenceText, Mono, OutcomeText, Risk, SeverityText, StageLadder, StageTag } from "../atoms";
import { BlockDialog, ExceptionDialog, type ExceptionSeed } from "../response";
import { useSession, useToast } from "../providers";
import { TipBox } from "../charts";
import type { GraphApi } from "./picto";

const ANALYSTS = ["Ahmad", "Budi", "Deni"];

function Section({ title, children, aside }: { title: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="border-b border-border px-4 py-3">
      <div className="mb-2 flex items-center justify-between gap-2"><h3 className="text-[12px] font-semibold text-fg-2">{title}</h3>{aside}</div>
      {children}
    </section>
  );
}

const logsHref = (q: Record<string, string | undefined>) => `/logs?${new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]).toString()}`;

export function AttackRadar({ events }: { events: AttackEvent[] }) {
  const data = CATEGORIES.map((c) => ({ cat: c.key === "SQLI" ? "SQLi" : c.key === "SCANNER" ? "Scanner" : c.key === "PROTOCOL" ? "Protocol" : c.key === "LEAKAGE" ? "Leakage" : c.key, name: c.name, n: events.filter((e) => e.rule_category === c.key).length }));
  return (
    <div className="viz h-[190px]" role="img" aria-label={`Attack profile: ${data.filter((d) => d.n).map((d) => `${d.name} ${d.n}`).join(", ")}`}>
      <ResponsiveContainer>
        <RadarChart data={data} outerRadius="62%" margin={{ top: 8, bottom: 8, left: 36, right: 36 }}>
          <PolarGrid stroke="var(--grid)" />
          <PolarAngleAxis dataKey="cat" tick={{ fill: "rgb(var(--fg-2))", fontSize: 11 }} />
          {/* sqrt keeps a 120-event SQLi run from flattening a 3-event webshell upload */}
          <Radar dataKey={(d: { n: number }) => Math.sqrt(d.n)} stroke="var(--seq-4)" strokeWidth={2} fill="var(--seq-4)" fillOpacity={0.2} isAnimationActive={false} />
          {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
          <Tooltip content={({ active, payload }: any) => active && payload?.length ? <TipBox title={payload[0].payload.name} rows={[{ label: "Events", value: fmtNum(payload[0].payload.n) }]} /> : null} />
        </RadarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function CampaignPanel({ campaign, events, stageFilter, onStageFilter, onChanged, replaying, onReplay, graphApi }: {
  campaign: Campaign; events: AttackEvent[]; stageFilter: StageKey | null; onStageFilter: (s: StageKey | null) => void; onChanged: (c: Campaign) => void;
  replaying: boolean; onReplay: () => void; graphApi: React.MutableRefObject<GraphApi | null>;
}) {
  const s = useSession();
  const toast = useToast();
  const [block, setBlock] = React.useState(false);
  const [exc, setExc] = React.useState<ExceptionSeed | null>(null);
  const [note, setNote] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const c = campaign;
  const evs = events.filter((e) => e.campaign_id === c.id);
  const outcome = { BLOCKED: 0, DETECTED: 0, POSSIBLY_SUCCESSFUL: 0 };
  evs.forEach((e) => outcome[e.outcome]++);
  const rules = [...evs.reduce((m, e) => m.set(e.rule_id, (m.get(e.rule_id) ?? 0) + 1), new Map<number, number>())].sort((a, b) => b[1] - a[1]);
  const topRuleEv = evs.find((e) => e.rule_id === rules[0]?.[0]);
  const ps = evs.filter((e) => e.outcome === "POSSIBLY_SUCCESSFUL").slice(-3).reverse();

  const update = async (patch: Parameters<typeof attacks.update>[1], msg: string) => {
    setBusy(true);
    try { const n = await attacks.update(c.id, patch); onChanged(n); toast({ tone: "ok", title: msg }); }
    catch (x) { toast({ tone: "error", title: "Action failed", body: (x as Error).message }); }
    finally { setBusy(false); }
  };

  const link = typeof window !== "undefined" ? `${location.origin}/attacks?campaign=${c.id}` : "";

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b border-border px-4 py-3">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="text-[11px] text-muted">Campaign</p>
            <h2 className="truncate font-mono text-[13px] font-semibold">{c.id}</h2>
          </div>
          <Button size="icon" variant="ghost" aria-label="Copy deep link to this campaign" title="Copy link" onClick={() => { navigator.clipboard?.writeText(link); toast({ tone: "ok", title: "Link copied", body: link }); }}><Copy size={16} aria-hidden /></Button>
        </div>
        <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[12px]">
          <span className="text-muted">Risk</span><Risk value={c.risk_score} />
          <span className="text-muted">Status</span><CampaignStatusText s={c.status} />
          <span className="text-muted">Actor</span><span className="min-w-0 truncate font-mono" title={c.actor_key}>{c.actor_key}</span>
          <span className="text-muted">Origin</span><span>{c.country_code} · {c.as_name}</span>
          <span className="text-muted">Correlation</span><span><ConfidenceText c={c.correlation_confidence} /> <span className="text-muted">by {c.actor_mode === "CIDR24" ? "/24" : c.actor_mode.toLowerCase()}</span></span>
          <span className="text-muted">Window</span><span>{fmtTime(c.first_seen).slice(5, 16)} to {relTime(c.last_seen)}</span>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        <Section title="Kill chain" aside={stageFilter ? <button className="text-[11px] text-accent hover:underline" onClick={() => onStageFilter(null)}>Clear stage filter</button> : <span className="text-[11px] text-muted">click a stage to filter</span>}>
          <StageLadder size="lg" reached={c.stages} highest={c.highest_stage} onSelect={onStageFilter} selected={stageFilter} />
        </Section>
        <Section title="Outcome">
          <ul className="flex flex-col gap-1 text-[12px]">
            <li className="flex justify-between"><OutcomeText o="BLOCKED" /><span className="tnum">{fmtNum(outcome.BLOCKED)}</span></li>
            <li className="flex justify-between"><OutcomeText o="DETECTED" /><span className="tnum">{fmtNum(outcome.DETECTED)}</span></li>
            <li className="flex justify-between"><OutcomeText o="POSSIBLY_SUCCESSFUL" /><span className="tnum font-semibold text-crit">{fmtNum(outcome.POSSIBLY_SUCCESSFUL)}</span></li>
          </ul>
          {ps.length ? (
            <ul className="mt-2 flex flex-col gap-1">
              {ps.map((e) => (
                <li key={e.id}><Link href={logsHref({ ip: e.client_ip, uri: e.uri.split("?")[0], log: e.id })} className="block truncate rounded bg-crit/5 px-2 py-1 font-mono text-[11px] hover:bg-crit/10" title="Open in Log Explorer">{e.response_status} {e.method} {e.uri}</Link></li>
              ))}
            </ul>
          ) : null}
        </Section>
        <Section title="Attack profile"><AttackRadar events={evs} /></Section>
        <Section title={`Targets (${c.targets.length})`}>
          <ul className="flex flex-col gap-0.5">{c.targets.slice(0, 6).map((t) => <li key={t} className="truncate font-mono text-[11px] text-fg-2" title={t}>{t}</li>)}</ul>
        </Section>
        <Section title="Rules triggered">
          <ul className="flex flex-col gap-1">
            {rules.slice(0, 6).map(([id, n]) => {
              const e = evs.find((x) => x.rule_id === id)!;
              return (
                <li key={id} className="flex items-center justify-between gap-2 text-[12px]">
                  <Link href={logsHref({ rule: String(id), ip: c.actor_mode === "IP" ? c.actor_key : undefined })} className="font-mono hover:text-accent hover:underline">{id}</Link>
                  <span className="min-w-0 flex-1 truncate text-fg-2"><StageTag stage={e.killchain_stage} /></span>
                  <span className="tnum text-fg-2">{fmtNum(n)}</span>
                </li>
              );
            })}
          </ul>
        </Section>
        <Section title={`Notes (${c.notes.length})`}>
          <ul className="flex flex-col gap-2">
            {c.notes.map((n, i) => <li key={i} className="text-[12px]"><span className="font-medium">{n.author}</span> <span className="text-muted">{relTime(n.at)}</span><p className="text-fg-2">{n.text}</p></li>)}
          </ul>
          {s.can("respond") ? (
            <form className="mt-2 flex flex-col gap-2" onSubmit={(e) => { e.preventDefault(); if (note.trim()) update({ note }, "Note added").then(() => setNote("")); }}>
              <label htmlFor="note" className="sr-only">Add note</label>
              <Textarea id="note" rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note for the next analyst" />
              <Button size="sm" type="submit" disabled={!note.trim() || busy} className="self-end">Add note</Button>
            </form>
          ) : null}
        </Section>
      </div>
      <div className="no-print flex flex-wrap gap-1.5 border-t border-border bg-surface px-3 py-2.5">
        {s.can("respond") ? (
          <>
            <Button size="sm" variant="danger" onClick={() => setBlock(true)} disabled={c.actor_mode === "FINGERPRINT"} title={c.actor_mode === "FINGERPRINT" ? "Fingerprint actors span many IPs; block from an IP node instead" : undefined}><Prohibit size={14} aria-hidden />Block {c.actor_mode === "CIDR24" ? "CIDR" : "IP"}</Button>
            {topRuleEv ? <Button size="sm" onClick={() => setExc({ host: topRuleEv.host, ruleId: topRuleEv.rule_id, path: topRuleEv.uri.split("?")[0] })}><ShieldSlash size={14} aria-hidden />Exception</Button> : null}
          </>
        ) : null}
        <Button size="sm" onClick={() => (location.href = logsHref({ ip: c.actor_mode === "IP" ? c.actor_key : undefined, from: String(c.first_seen) }))}><ListMagnifyingGlass size={14} aria-hidden />Open logs</Button>
        <Button size="sm" onClick={onReplay} aria-pressed={replaying}>{replaying ? <Stop size={14} aria-hidden /> : <Play size={14} aria-hidden />}{replaying ? "Stop replay" : "Replay"}</Button>
        {s.can("respond") ? (
          <>
            <label htmlFor="assign" className="sr-only">Assignee</label>
            <Select id="assign" className="h-8 text-[12px]" value={c.assignee ?? ""} disabled={busy} onChange={(e) => update({ assignee: e.target.value || null }, e.target.value ? `Assigned to ${e.target.value}` : "Unassigned")}>
              <option value="">Unassigned</option>{ANALYSTS.map((a) => <option key={a}>{a}</option>)}
            </Select>
            <Menu>
              <MenuTrigger asChild><Button size="sm" disabled={busy}>Status<CaretDown size={12} aria-hidden /></Button></MenuTrigger>
              <MenuContent>
                <MenuItem disabled={c.status === "CONTAINED"} onSelect={() => update({ status: "CONTAINED" }, "Campaign marked contained")}>Mark contained</MenuItem>
                <MenuItem disabled={c.status === "FALSE_POSITIVE"} onSelect={() => update({ status: "FALSE_POSITIVE" }, "Marked as false positive")}>Mark as false positive</MenuItem>
                <MenuItem disabled={c.status === "CLOSED"} onSelect={() => update({ status: "CLOSED" }, "Campaign closed")}>Close campaign</MenuItem>
                <MenuSeparator />
                <MenuItem disabled={c.status === "ACTIVE"} onSelect={() => update({ status: "ACTIVE" }, "Campaign reopened")}>Reopen</MenuItem>
              </MenuContent>
            </Menu>
          </>
        ) : null}
        <Menu>
          <MenuTrigger asChild><Button size="sm"><DownloadSimple size={14} aria-hidden />Export<CaretDown size={12} aria-hidden /></Button></MenuTrigger>
          <MenuContent>
            <MenuLabel>Campaign data</MenuLabel>
            <MenuItem onSelect={() => download(`${c.id}.json`, campaignJson(c, evs))}>JSON</MenuItem>
            <MenuItem onSelect={() => download(`${c.id}.stix.json`, campaignStix(c, evs))}>STIX 2.1 bundle</MenuItem>
            <MenuItem asChild><Link href={`/attacks/report?campaign=${c.id}`} target="_blank"><FileText size={14} aria-hidden />Incident report (PDF)</Link></MenuItem>
            <MenuSeparator />
            <MenuLabel>Current graph view</MenuLabel>
            <MenuItem onSelect={() => graphApi.current?.png(c.id)} disabled={!graphApi.current}>PNG image</MenuItem>
            <MenuItem onSelect={() => graphApi.current?.svg(c.id)} disabled={!graphApi.current}>SVG image</MenuItem>
          </MenuContent>
        </Menu>
      </div>
      <BlockDialog open={block} onOpenChange={setBlock} initial={c.actor_key} context={`Campaign ${c.id}, highest stage ${c.highest_stage.toLowerCase()}`} />
      <ExceptionDialog open={!!exc} onOpenChange={(v) => !v && setExc(null)} seed={exc} />
    </div>
  );
}

export function NodePanel({ node, edge, events, campaigns, pinned, onTogglePin, onExpand, onSelectCampaign }: {
  node: GNode | null; edge: GEdge | null; events: AttackEvent[]; campaigns: Campaign[]; pinned: boolean;
  onTogglePin: () => void; onExpand: () => void; onSelectCampaign: (id: string) => void;
}) {
  const s = useSession();
  const [block, setBlock] = React.useState<string | null>(null);
  const [exc, setExc] = React.useState<ExceptionSeed | null>(null);

  // Events behind this node/edge, so counts and lists match what the graph shows.
  const match = (e: AttackEvent, id: string) => {
    if (id.startsWith("ip:")) return e.client_ip === id.slice(3);
    if (id.startsWith("asn:")) return e.asn === Number(id.slice(4));
    if (id.startsWith("site:")) return e.host === id.slice(5);
    if (id.startsWith("cat:")) return e.rule_category === id.slice(4);
    if (id.startsWith("node:")) return e.node_id === id.slice(5);
    if (id.startsWith("ep:")) { const k = id.slice(3); return k.endsWith("/*") ? e.host === k.slice(0, -2) : `${e.host}${e.uri.split("?")[0]}` === k; }
    return false;
  };
  const evs = edge ? events.filter((e) => match(e, edge.source) && match(e, edge.target)) : node ? events.filter((e) => match(e, node.id)) : [];
  const cmpIds = [...new Set(evs.map((e) => e.campaign_id))];
  const cmps = campaigns.filter((c) => cmpIds.includes(c.id)).sort((a, b) => b.risk_score - a.risk_score);
  const rules = [...evs.reduce((m, e) => m.set(e.rule_id, (m.get(e.rule_id) ?? 0) + 1), new Map<number, number>())].sort((a, b) => b[1] - a[1]);
  const first = evs[0];
  const ip = node?.type === "attacker" ? node.ips![0] : edge?.source.startsWith("ip:") ? edge.source.slice(3) : null;
  const ep = node?.type === "endpoint" ? node : edge ? { host: first?.host, path: first?.uri.split("?")[0] } : null;
  const title = edge ? "Attack path" : node!.type === "attacker" ? "Attacker IP" : node!.type === "cluster" ? "ASN cluster" : node!.type === "endpoint" ? "Endpoint" : node!.type === "site" ? "Target site" : node!.type === "category" ? "Rule category" : "Coraza edge node";
  const stage = evs.reduce<StageKey | null>((a, e) => (!a || stageIndex(e.killchain_stage) > stageIndex(a) ? e.killchain_stage : a), null);
  const ps = evs.filter((e) => e.outcome === "POSSIBLY_SUCCESSFUL").length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b border-border px-4 py-3">
        <p className="text-[11px] text-muted">{title}</p>
        <h2 className="break-all font-mono text-[13px] font-semibold">{edge ? `${edge.source.replace(/^\w+:/, "")} → ${edge.target.replace(/^\w+:/, "")}` : node!.type === "endpoint" ? `${node!.host}${node!.path === "*" ? " (other endpoints)" : node!.path}` : node!.label}</h2>
        <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5 text-[12px]">
          <span className="text-muted">Events</span><span className="tnum">{fmtNum(evs.length)}</span>
          {stage ? <><span className="text-muted">Highest stage</span><StageTag stage={stage} /></> : null}
          <span className="text-muted">2xx after payload</span><span className={cn("tnum", ps && "font-semibold text-crit")}>{ps || "none"}</span>
          {first && (node?.type === "attacker" || node?.type === "cluster") ? <><span className="text-muted">Origin</span><span>{first.country_code} · AS{first.asn}</span></> : null}
          {first ? <><span className="text-muted">Last seen</span><span>{relTime(Math.max(...evs.map((e) => e.timestamp)))}</span></> : null}
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {node?.type === "cluster" ? (
          <Section title={`IPs in cluster (${node.ips!.length})`}>
            <p className="font-mono text-[11px] leading-relaxed text-fg-2">{node.ips!.slice(0, 40).join(", ")}{node.ips!.length > 40 ? ` +${node.ips!.length - 40}` : ""}</p>
          </Section>
        ) : null}
        <Section title={`Campaigns (${cmps.length})`}>
          <ul className="flex flex-col gap-1">
            {cmps.slice(0, 8).map((c) => (
              <li key={c.id}>
                <button onClick={() => onSelectCampaign(c.id)} className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-surface-2">
                  <Risk value={c.risk_score} showBar={false} />
                  <StageLadder reached={c.stages} highest={c.highest_stage} />
                  <span className="min-w-0 flex-1 truncate font-mono text-[11px]">{c.actor_key}</span>
                </button>
              </li>
            ))}
          </ul>
        </Section>
        <Section title="Rules triggered">
          <ul className="flex flex-col gap-1.5">
            {rules.slice(0, 8).map(([id, n]) => {
              const e = evs.find((x) => x.rule_id === id)!;
              return (
                <li key={id} className="flex items-center gap-2 text-[12px]">
                  <span className="font-mono">{id}</span>
                  <SeverityText s={e.severity} />
                  <span className="tnum ml-auto text-fg-2">{fmtNum(n)}</span>
                  {s.can("respond") && ep?.host ? <Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => setExc({ host: ep.host!, ruleId: id, path: ep.path === "*" ? "" : ep.path ?? "" })} title="Create an exception for this rule on this endpoint">Exception</Button> : null}
                </li>
              );
            })}
          </ul>
        </Section>
        <Section title="Recent events">
          <ul className="flex flex-col gap-1">
            {evs.slice(-6).reverse().map((e) => (
              <li key={e.id} className="text-[11px]">
                <Link href={logsHref({ log: e.id, ip: e.client_ip })} className="flex gap-2 rounded px-1 py-0.5 hover:bg-surface-2">
                  <span className="text-muted">{fmtTime(e.timestamp).slice(11)}</span>
                  <Mono className="min-w-0 flex-1 truncate text-[11px]">{e.method} {e.uri}</Mono>
                  <span className={e.outcome === "POSSIBLY_SUCCESSFUL" ? "font-semibold text-crit" : "text-fg-2"}>{e.response_status}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Section>
      </div>
      <div className="flex flex-wrap gap-1.5 border-t border-border px-3 py-2.5">
        {s.can("respond") && (ip || node?.type === "cluster") ? (
          <Button size="sm" variant="danger" onClick={() => setBlock(ip ?? `${node!.ips![0].split(".").slice(0, 3).join(".")}.0/24`)}><Prohibit size={14} aria-hidden />Block {ip ? "IP" : "/24"}</Button>
        ) : null}
        <Button size="sm" onClick={() => (location.href = logsHref({ ip: ip ?? undefined, host: ep?.host ?? (node?.type === "site" ? node.host : undefined), uri: ep?.path && ep.path !== "*" ? ep.path : undefined }))}><ListMagnifyingGlass size={14} aria-hidden />Open in Log Explorer</Button>
        {node ? <Button size="sm" onClick={onTogglePin} aria-pressed={pinned}>{pinned ? <PushPinSlash size={14} aria-hidden /> : <PushPin size={14} aria-hidden />}{pinned ? "Unpin" : "Pin"}</Button> : null}
        {node?.type === "cluster" ? <Button size="sm" onClick={onExpand}><ArrowsOutSimple size={14} aria-hidden />Expand IPs</Button> : null}
        {node?.type === "attacker" ? <Button size="sm" onClick={onExpand} title="Fold this IP back into its ASN cluster"><ArrowsOutSimple size={14} aria-hidden />Group by ASN</Button> : null}
      </div>
      <BlockDialog open={!!block} onOpenChange={(v) => !v && setBlock(null)} initial={block ?? ""} context={cmps[0] ? `Campaign ${cmps[0].id}` : undefined} />
      <ExceptionDialog open={!!exc} onOpenChange={(v) => !v && setExc(null)} seed={exc} />
    </div>
  );
}
