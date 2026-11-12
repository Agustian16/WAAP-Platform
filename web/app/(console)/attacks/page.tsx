"use client";
import * as React from "react";
import dynamic from "next/dynamic";
import { useRouter, useSearchParams } from "next/navigation";
import { Pause, Play, MagnifyingGlassPlus, MagnifyingGlassMinus, CornersOut, FunnelSimple } from "@phosphor-icons/react";
import { attacks, fleet, policies, subscribeAttackStream } from "@/lib/api";
import { useAsync, useCssColors } from "@/lib/hooks";
import { buildGraph, type GNodeType } from "@/lib/attack-graph";
import { ATTACK_TECHNIQUES, CATEGORIES, STAGES, stageVar, techKey } from "@/lib/killchain";
import type { AttackEvent, Campaign, Outcome, RuleCategory, Severity, StageKey } from "@/lib/types";
import { Button, Empty, ErrorState, Field, Input, Loading, PageHeader, Select, Switch, Tabs, TabsContent, TabsList, TabsTrigger, TableWrap } from "@/components/ui";
import { CampaignStatusText, ConfidenceText, Risk, StageLadder, StageTag } from "@/components/atoms";
import { CampaignPanel, NodePanel } from "@/components/attack/panel";
import Timeline from "@/components/attack/timeline";
import KillChainMatrix from "@/components/attack/matrix";
import { PICTO, type GraphApi, type GraphColors } from "@/components/attack/picto";
import { cn, fmtNum, relTime } from "@/lib/utils";

const AttackGraph = dynamic(() => import("@/components/attack/graph"), { ssr: false, loading: () => <Loading label="Starting WebGL renderer" className="h-full" /> });
const GeoMap = dynamic(() => import("@/components/attack/geo-map"), { ssr: false, loading: () => <Loading label="Loading map" className="h-full" /> });

const RANGES = { "1h": 3600e3, "6h": 6 * 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3 } as const;
const ZOOMS = { "1m": 60e3, "6m": 6 * 60e3, "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3 } as const;
const COLOR_VARS = ["--stage-0", "--stage-1", "--stage-2", "--stage-3", "--stage-4", "--stage-5", "--stage-6", "--fg", "--fg-2", "--muted", "--surface", "--surface-3", "--border-strong", "--accent", "--c-crit"] as const;
type Sel = { kind: "campaign" | "node" | "edge"; id: string } | null;
type Tab = "graph" | "geo" | "campaigns" | "matrix";

export default function Page() {
  return <React.Suspense fallback={<Loading label="Loading attack map" />}><AttackMap /></React.Suspense>;
}

function AttackMap() {
  const params = useSearchParams();
  const router = useRouter();
  const [tab, setTab] = React.useState<Tab>((params.get("tab") as Tab) || "graph");
  const [range, setRange] = React.useState<keyof typeof RANGES>("24h");
  const [live, setLive] = React.useState(true);
  const [buffer, setBuffer] = React.useState<{ ev: AttackEvent; c: Campaign }[]>([]);
  const [f, setF] = React.useState({ site: "", stage: "" as StageKey | "", severity: "" as Severity | "", category: "" as RuleCategory | "", outcome: "" as Outcome | "", minRisk: 0, country: "" });
  const [layout, setLayout] = React.useState<"force" | "hierarchical" | "radial">("force");
  const [maxNodes, setMaxNodes] = React.useState(50);
  const [opts, setOpts] = React.useState({ groupByAsn: true, showCategories: true, showEdgeNodes: false });
  const [expanded, setExpanded] = React.useState<Set<string>>(new Set());
  const [pinned, setPinned] = React.useState<Set<string>>(new Set());
  const [sel, setSel] = React.useState<Sel>(params.get("campaign") ? { kind: "campaign", id: params.get("campaign")! } : null);
  const [selEvent, setSelEvent] = React.useState<string | null>(null);
  const [zoom, setZoom] = React.useState<keyof typeof ZOOMS | "custom">("24h");
  const [custom, setCustom] = React.useState<{ from: string; to: string }>({ from: "", to: "" });
  const [laneMode, setLaneMode] = React.useState<"actor" | "target">("actor");
  const [replay, setReplay] = React.useState<{ id: string; t: number } | null>(null);
  const [geoMode, setGeoMode] = React.useState<"live" | "heatmap">("live");
  const [recent, setRecent] = React.useState<AttackEvent[]>([]);
  const [search, setSearch] = React.useState("");
  const [now, setNow] = React.useState(() => Date.now());
  const graphApi = React.useRef<GraphApi | null>(null);
  const colors = useCssColors(COLOR_VARS) as GraphColors | null;

  const from = now - RANGES[range];
  const evQ = useAsync(() => attacks.events({ from }), [range]); // eslint-disable-line react-hooks/exhaustive-deps
  const cmpQ = useAsync(() => attacks.campaigns(), []);
  const sites = useAsync(() => policies.sites(), []);
  const nodes = useAsync(() => fleet.list(), []);

  // Deep link to a campaign older than the range: widen the range so its events load.
  React.useEffect(() => {
    if (sel?.kind !== "campaign" || !cmpQ.data) return;
    const c = cmpQ.data.find((x) => x.id === sel.id);
    if (c && c.first_seen < from) setRange(c.first_seen > Date.now() - RANGES["7d"] ? "7d" : "30d");
  }, [sel, cmpQ.data]); // eslint-disable-line react-hooks/exhaustive-deps

  // Keep the URL shareable (FR-6.16 deep-link) without adding history entries.
  React.useEffect(() => {
    const q = new URLSearchParams();
    if (tab !== "graph") q.set("tab", tab);
    if (sel?.kind === "campaign") q.set("campaign", sel.id);
    router.replace(`/attacks${q.size ? `?${q}` : ""}`, { scroll: false });
  }, [tab, sel, router]);

  // Live stream (FR-6.6): apply immediately when Live, buffer while paused.
  const liveRef = React.useRef(live);
  liveRef.current = live;
  const apply = React.useCallback((items: { ev: AttackEvent; c: Campaign }[]) => {
    evQ.setData((d) => (d ? [...d, ...items.map((i) => i.ev)] : d));
    cmpQ.setData((list) => {
      if (!list) return list;
      let out = list;
      items.forEach(({ c }) => { const i = out.findIndex((x) => x.id === c.id); out = i < 0 ? [c, ...out] : out.map((x, k) => (k === i ? c : x)); });
      return out;
    });
    setRecent((r) => [...r.filter((e) => Date.now() - e.timestamp < 3000), ...items.map((i) => i.ev)]);
    setNow(Date.now());
  }, [evQ.setData, cmpQ.setData]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => subscribeAttackStream((m) => {
    const item = { ev: m.event, c: m.campaign };
    if (liveRef.current) apply([item]); else setBuffer((b) => [...b, item]);
  }), [apply]);
  const toggleLive = () => {
    if (!live && buffer.length) { apply(buffer); setBuffer([]); }
    setLive(!live);
  };

  // Replay (FR-6.17): advance a playhead across the campaign's lifetime in ~15s.
  React.useEffect(() => {
    if (!replay) return;
    const c = cmpQ.data?.find((x) => x.id === replay.id);
    if (!c) return;
    const stepMs = Math.max(1000, (c.last_seen - c.first_seen) / 150);
    const t = setInterval(() => setReplay((r) => (r && r.t + stepMs <= c.last_seen + stepMs ? { ...r, t: r.t + stepMs } : null)), 100);
    return () => clearInterval(t);
  }, [replay?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const cmpById = React.useMemo(() => new Map((cmpQ.data ?? []).map((c) => [c.id, c])), [cmpQ.data]);
  const filtered = React.useMemo(() => (evQ.data ?? []).filter((e) => {
    const c = cmpById.get(e.campaign_id);
    return (!f.site || e.site_id === f.site) && (!f.stage || e.killchain_stage === f.stage) && (!f.severity || e.severity === f.severity) &&
      (!f.category || e.rule_category === f.category) && (!f.outcome || e.outcome === f.outcome) && (!f.country || e.country_code === f.country) &&
      (c?.risk_score ?? 0) >= f.minRisk;
  }), [evQ.data, cmpById, f]);
  const graphEvents = React.useMemo(() => (replay ? filtered.filter((e) => e.campaign_id === replay.id && e.timestamp <= replay.t) : filtered), [filtered, replay]);
  const model = React.useMemo(() => buildGraph(graphEvents, { maxNodes, ...opts, expanded }), [graphEvents, maxNodes, opts, expanded]);
  const visibleCampaigns = React.useMemo(() => {
    const ids = new Set(filtered.map((e) => e.campaign_id));
    return (cmpQ.data ?? []).filter((c) => ids.has(c.id));
  }, [filtered, cmpQ.data]);

  const selCampaign = sel?.kind === "campaign" ? cmpById.get(sel.id) ?? null : null;
  const selNode = sel?.kind === "node" ? model.nodes.find((n) => n.id === sel.id) ?? null : null;
  const selEdge = sel?.kind === "edge" ? model.edges.find((e) => e.id === sel.id) ?? null : null;

  const win = ZOOMS[zoom === "custom" ? "24h" : zoom];
  const anchor = selCampaign && selCampaign.last_seen < now - win / 2 ? selCampaign.last_seen + 60e3 : now;
  const rc = replay ? cmpById.get(replay.id) : undefined;
  const tlTo = rc ? rc.last_seen + 60e3 : zoom === "custom" && custom.to ? Date.parse(custom.to) : anchor;
  const tlFrom = rc ? rc.first_seen - 60e3 : zoom === "custom" && custom.from ? Date.parse(custom.from) : tlTo - win;

  const expand = (id: string) => {
    if (id.startsWith("asn:")) setExpanded((s) => new Set(s).add(id));
    else if (id.startsWith("ip:")) {
      const ev = filtered.find((e) => e.client_ip === id.slice(3));
      if (ev) { setExpanded((s) => { const n = new Set(s); n.delete(`asn:${ev.asn}`); return n; }); setOpts((o) => ({ ...o, groupByAsn: true })); }
    }
  };
  const selectNode = (id: string | null) => {
    setSelEvent(null);
    if (!id) return setSel(null);
    setSel({ kind: "node", id });
  };

  const loading = (evQ.loading && !evQ.data) || (cmpQ.loading && !cmpQ.data) || !colors;
  const error = (!evQ.data && evQ.error) || (!cmpQ.data && cmpQ.error);
  const setFilter = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((x) => ({ ...x, [k]: v }));
  const activeFilters = [f.site, f.stage, f.severity, f.category, f.outcome, f.country].filter(Boolean).length + (f.minRisk ? 1 : 0);

  return (
    <>
      <PageHeader
        title="Attack Map & Kill Chain"
        description="WAF events correlated into campaigns: who is attacking what, in which order, and how far they got."
        actions={
          <>
            <Button onClick={toggleLive} aria-pressed={live} variant={live ? "secondary" : "primary"}>
              {live ? <><span className="h-2 w-2 rounded-full bg-good" aria-hidden /><Pause size={14} aria-hidden />Live</> : <><Play size={14} aria-hidden />Resume{buffer.length ? ` (${buffer.length} new)` : ""}</>}
            </Button>
          </>
        }
      />

      {/* FR-6.8 filters */}
      <div className="panel mb-4 grid grid-cols-2 gap-3 p-3 sm:flex sm:flex-wrap sm:items-end [&_select]:w-full sm:[&_select]:w-auto" role="group" aria-label="Filters">
        <Field label="Time range" htmlFor="f-range"><Select id="f-range" value={range} onChange={(e) => { setRange(e.target.value as keyof typeof RANGES); setNow(Date.now()); }}>{Object.keys(RANGES).map((r) => <option key={r} value={r}>Last {r}</option>)}</Select></Field>
        <Field label="Site" htmlFor="f-site"><Select id="f-site" value={f.site} onChange={(e) => setFilter("site", e.target.value)}><option value="">All sites</option>{sites.data?.map((s) => <option key={s.id} value={s.id}>{s.domain_name}</option>)}</Select></Field>
        <Field label="Kill chain stage" htmlFor="f-stage"><Select id="f-stage" value={f.stage} onChange={(e) => setFilter("stage", e.target.value as StageKey)}><option value="">All stages</option>{STAGES.filter((s) => s.observable).map((s) => <option key={s.key} value={s.key}>{s.n}. {s.name}</option>)}</Select></Field>
        <Field label="Severity" htmlFor="f-sev"><Select id="f-sev" value={f.severity} onChange={(e) => setFilter("severity", e.target.value as Severity)}><option value="">Any</option>{["CRITICAL", "ERROR", "WARNING", "NOTICE"].map((s) => <option key={s} value={s}>{s[0] + s.slice(1).toLowerCase()}</option>)}</Select></Field>
        <Field label="Rule category" htmlFor="f-cat"><Select id="f-cat" value={f.category} onChange={(e) => setFilter("category", e.target.value as RuleCategory)}><option value="">Any</option>{CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}</Select></Field>
        <Field label="Outcome" htmlFor="f-out"><Select id="f-out" value={f.outcome} onChange={(e) => setFilter("outcome", e.target.value as Outcome)}><option value="">Any</option><option value="BLOCKED">Blocked</option><option value="DETECTED">Detected</option><option value="POSSIBLY_SUCCESSFUL">Possibly successful</option></Select></Field>
        <Field label="Min risk" htmlFor="f-risk"><Select id="f-risk" value={f.minRisk} onChange={(e) => setFilter("minRisk", Number(e.target.value))}>{[0, 25, 40, 50, 75].map((r) => <option key={r} value={r}>{r ? `>= ${r}` : "Any"}</option>)}</Select></Field>
        {activeFilters ? <Button variant="ghost" size="sm" className="mb-0.5" onClick={() => setF({ site: "", stage: "", severity: "", category: "", outcome: "", minRisk: 0, country: "" })}><FunnelSimple size={14} aria-hidden />Clear {activeFilters} filter{activeFilters > 1 ? "s" : ""}</Button> : null}
        <span className="col-span-2 self-center text-[12px] text-fg-2 sm:ml-auto"><span className="tnum font-medium text-fg">{fmtNum(filtered.length)}</span> events · <span className="tnum font-medium text-fg">{visibleCampaigns.length}</span> campaigns</span>
      </div>

      {error ? <div className="panel"><ErrorState title="Attack data could not be loaded" error={error} onRetry={() => { evQ.reload(); cmpQ.reload(); }} /></div> : (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div className="flex min-w-0 flex-col gap-4">
            <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="panel min-w-0 overflow-hidden">
              <TabsList className="px-2">
                <TabsTrigger value="graph">Attack Graph</TabsTrigger>
                <TabsTrigger value="geo">Geo Map</TabsTrigger>
                <TabsTrigger value="campaigns">Campaign List</TabsTrigger>
                <TabsTrigger value="matrix">Kill Chain Matrix</TabsTrigger>
              </TabsList>

              <TabsContent value="graph" className="outline-none">
                <div className="flex flex-wrap items-end gap-3 border-b border-border px-3 py-2.5">
                  <Field label="Layout" htmlFor="g-layout"><Select id="g-layout" value={layout} onChange={(e) => setLayout(e.target.value as typeof layout)}><option value="force">Force-directed</option><option value="hierarchical">Hierarchical (by stage)</option><option value="radial">Radial</option></Select></Field>
                  <Field label="Max nodes" htmlFor="g-max"><Select id="g-max" value={maxNodes} onChange={(e) => setMaxNodes(Number(e.target.value))}>{[50, 100, 250, 500, 1000, 5000].map((n) => <option key={n} value={n}>{fmtNum(n)}</option>)}</Select></Field>
                  <Field label="Find node" htmlFor="g-search" className="w-48">
                    <Input id="g-search" list="g-nodes" value={search} placeholder="IP, path, site" onChange={(e) => {
                      setSearch(e.target.value);
                      const n = model.nodes.find((x) => x.label === e.target.value);
                      if (n) { selectNode(n.id); graphApi.current?.focus(n.id); }
                    }} />
                    <datalist id="g-nodes">{model.nodes.map((n) => <option key={n.id} value={n.label} />)}</datalist>
                  </Field>
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-2 pb-2 text-[12px] text-fg-2">
                    {([["groupByAsn", "ASN clusters"], ["showCategories", "Rule categories"], ["showEdgeNodes", "Edge nodes"]] as const).map(([k, label]) => (
                      <label key={k} className="inline-flex items-center gap-2" htmlFor={`o-${k}`}>
                        <Switch id={`o-${k}`} label={label} checked={opts[k]} onCheckedChange={(v) => setOpts((o) => ({ ...o, [k]: v }))} />{label}
                      </label>
                    ))}
                  </div>
                </div>
                <div className="viz relative h-[520px] bg-surface">
                  {loading ? <Loading label="Correlating events" className="h-full" /> : graphEvents.length === 0 ? (
                    <Empty className="h-full" title={replay ? "Replay starting" : "No events match these filters"} body={replay ? "Events appear as the playhead reaches them." : "Widen the time range or clear filters. New events stream in while Live is on."} />
                  ) : (
                    <AttackGraph
                      nodes={model.nodes} edges={model.edges} layout={layout} colors={colors!} selectedId={sel?.kind === "node" || sel?.kind === "edge" ? sel.id : null}
                      highlightCampaign={selCampaign?.id ?? null} flash={live || !!replay} pinned={pinned} apiRef={graphApi}
                      onSelectNode={selectNode} onSelectEdge={(id) => setSel({ kind: "edge", id })} onExpand={expand}
                      onPinChange={(id, v) => setPinned((s) => { const n = new Set(s); if (v) n.add(id); else n.delete(id); return n; })}
                    />
                  )}
                  <div className="absolute right-3 top-3 flex flex-col gap-1">
                    <Button size="icon" aria-label="Zoom in" onClick={() => graphApi.current?.zoomIn()}><MagnifyingGlassPlus size={16} aria-hidden /></Button>
                    <Button size="icon" aria-label="Zoom out" onClick={() => graphApi.current?.zoomOut()}><MagnifyingGlassMinus size={16} aria-hidden /></Button>
                    <Button size="icon" aria-label="Fit graph to view" onClick={() => graphApi.current?.reset()}><CornersOut size={16} aria-hidden /></Button>
                  </div>
                  {model.aggregated ? (
                    <p className="absolute left-3 top-3 max-w-[60%] rounded border border-border bg-surface/95 px-2 py-1 text-[11px] text-fg-2">
                      Aggregated to stay within {fmtNum(maxNodes)} nodes{model.hiddenEndpoints ? `, ${model.hiddenEndpoints} endpoints grouped per site` : ""}. Double-click a cluster to expand it.
                    </p>
                  ) : null}
                  {replay ? <p className="absolute bottom-3 right-3 rounded bg-accent px-2 py-1 text-[12px] font-medium text-accent-fg">Replaying {replay.id}</p> : null}
                </div>
                <GraphLegend />
              </TabsContent>

              <TabsContent value="geo" className="outline-none">
                <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-2">
                  <div role="group" aria-label="Map mode" className="seg">
                    {(["live", "heatmap"] as const).map((m) => <button key={m} onClick={() => setGeoMode(m)} aria-pressed={geoMode === m} className="seg-btn">{m === "live" ? "Live feed" : "Heatmap"}</button>)}
                  </div>
                  {f.country ? <Button size="sm" variant="ghost" onClick={() => setFilter("country", "")}>Country: {f.country} (clear)</Button> : <span className="text-[12px] text-muted">Click a shaded country to filter by origin.</span>}
                </div>
                <div className="h-[520px]">
                  {loading || !nodes.data ? <Loading label="Loading map" className="h-full" /> : (
                    <GeoMap events={filtered} campaigns={cmpQ.data!} nodes={nodes.data} mode={geoMode} live={recent} selectedCampaign={selCampaign?.id ?? null}
                      onSelectCampaign={(id) => setSel({ kind: "campaign", id })} onSelectCountry={(cc) => setFilter("country", cc ?? "")} country={f.country || null} />
                  )}
                </div>
              </TabsContent>

              <TabsContent value="campaigns" className="outline-none">
                <CampaignTable campaigns={visibleCampaigns} loading={loading} selected={selCampaign?.id ?? null} onSelect={(id) => setSel({ kind: "campaign", id })} />
              </TabsContent>

              <TabsContent value="matrix" className="outline-none">
                {loading ? <Loading label="Building matrix" /> : (
                  <KillChainMatrix events={filtered} highlightCampaign={selCampaign?.id ?? null} onPick={(stage, key) => {
                    const t = ATTACK_TECHNIQUES.find((x) => techKey(x) === key)!;
                    setF((x) => ({ ...x, stage, category: t.categories[0] }));
                    setTab("graph");
                  }} />
                )}
              </TabsContent>
            </Tabs>

            <section className="panel min-w-0" aria-labelledby="tl-title">
              <div className="flex flex-wrap items-center justify-between gap-2 px-4 pb-1 pt-3">
                <h2 id="tl-title" className="text-[13px] font-semibold">Timeline</h2>
                <div className="flex flex-wrap items-center gap-2">
                  <div role="group" aria-label="Lanes" className="seg">
                    {(["actor", "target"] as const).map((m) => <button key={m} onClick={() => setLaneMode(m)} aria-pressed={laneMode === m} className="seg-btn">Per {m}</button>)}
                  </div>
                  <div role="group" aria-label="Timeline zoom" className="seg">
                    {([...Object.keys(ZOOMS), "custom"] as (keyof typeof ZOOMS | "custom")[]).map((z) => (
                      <button key={z} onClick={() => setZoom(z)} aria-pressed={zoom === z} className="seg-btn">{z === "custom" ? "Custom" : z}</button>
                    ))}
                  </div>
                </div>
              </div>
              {zoom === "custom" ? (
                <div className="flex flex-wrap gap-3 px-4 pb-2">
                  <Field label="From" htmlFor="tl-from"><Input id="tl-from" type="datetime-local" value={custom.from} onChange={(e) => setCustom((c) => ({ ...c, from: e.target.value }))} /></Field>
                  <Field label="To" htmlFor="tl-to"><Input id="tl-to" type="datetime-local" value={custom.to} onChange={(e) => setCustom((c) => ({ ...c, to: e.target.value }))} /></Field>
                </div>
              ) : null}
              <div className="px-3 pb-3">
                {loading ? <Loading label="Loading timeline" /> : (
                  <Timeline events={filtered} campaigns={cmpQ.data ?? []} from={tlFrom} to={tlTo} laneMode={laneMode} selectedEventId={selEvent}
                    highlightCampaign={selCampaign?.id ?? (selNode?.campaignIds.length === 1 ? selNode.campaignIds[0] : null)} playhead={replay?.t ?? null}
                    onSelectEvent={(e) => { setSelEvent(e.id); setSel({ kind: "edge", id: `${model.nodes.find((n) => n.ips?.includes(e.client_ip))?.id}->ep:${model.nodes.some((n) => n.id === `ep:${e.host}${e.uri.split("?")[0]}`) ? `${e.host}${e.uri.split("?")[0]}` : `${e.host}/*`}` }); }}
                    onSelectLane={(id) => setSel(id ? { kind: "campaign", id } : null)} />
                )}
              </div>
            </section>
          </div>

          <aside className="panel flex min-h-[560px] flex-col overflow-hidden xl:sticky xl:top-[72px] xl:h-[calc(100dvh-88px)]" aria-label="Details">
            {selCampaign ? (
              <CampaignPanel key={selCampaign.id} campaign={selCampaign} events={evQ.data ?? []} stageFilter={f.stage || null}
                onStageFilter={(s) => setFilter("stage", s ?? "")} onChanged={(c) => cmpQ.setData((l) => l?.map((x) => (x.id === c.id ? c : x)))}
                replaying={replay?.id === selCampaign.id} onReplay={() => setReplay(replay ? null : { id: selCampaign.id, t: selCampaign.first_seen })} graphApi={graphApi} />
            ) : selNode || selEdge ? (
              <NodePanel node={selNode} edge={selEdge} events={graphEvents} campaigns={cmpQ.data ?? []} pinned={!!selNode && pinned.has(selNode.id)}
                onTogglePin={() => selNode && setPinned((s) => { const n = new Set(s); if (n.has(selNode.id)) n.delete(selNode.id); else n.add(selNode.id); return n; })}
                onExpand={() => selNode && expand(selNode.id)}
                onSelectCampaign={(id) => setSel({ kind: "campaign", id })} />
            ) : (
              <CampaignPicker campaigns={visibleCampaigns} loading={loading} onSelect={(id) => setSel({ kind: "campaign", id })} />
            )}
          </aside>
        </div>
      )}
    </>
  );
}

function GraphLegend() {
  const types: [GNodeType, string][] = [["attacker", "Attacker IP"], ["cluster", "ASN cluster"], ["endpoint", "Endpoint"], ["site", "Site"], ["category", "Rule category"], ["edgenode", "Edge node"]];
  return (
    <div className="viz flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-border px-3 py-2 text-[11px] text-fg-2">
      {types.map(([t, l]) => (
        <span key={t} className="inline-flex items-center gap-1.5">
          <span className="flex h-4 w-4 items-center justify-center rounded-full bg-fg-2" aria-hidden><span className="h-2.5 w-2.5 bg-surface" style={{ mask: `url("${PICTO[t]}") center / contain no-repeat`, WebkitMask: `url("${PICTO[t]}") center / contain no-repeat` }} /></span>{l}
        </span>
      ))}
      <span className="inline-flex items-center gap-1">
        {STAGES.filter((s) => s.observable).map((s) => <span key={s.key} className="h-2.5 w-3" style={{ background: stageVar(s.key) }} title={s.name} aria-hidden />)}
        <span className="ml-1">Recon to Objectives (color = stage)</span>
      </span>
      <span>Edge width = volume · drag a node to pin it · Ctrl + scroll to zoom</span>
    </div>
  );
}

function CampaignPicker({ campaigns, loading, onSelect }: { campaigns: Campaign[]; loading: boolean; onSelect: (id: string) => void }) {
  const top = [...campaigns].filter((c) => c.status === "ACTIVE").sort((a, b) => b.risk_score - a.risk_score).slice(0, 8);
  return (
    <div className="flex flex-col">
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-[13px] font-semibold">Pick a campaign or node</h2>
        <p className="mt-1 text-[12px] text-fg-2">Click anything in the graph, map or timeline to see its kill chain, events and response actions.</p>
      </div>
      {loading ? <Loading label="Loading campaigns" /> : top.length === 0 ? <Empty title="No active campaigns in view" body="Clear filters or widen the time range." /> : (
        <ul className="flex flex-col p-2">
          {top.map((c) => (
            <li key={c.id}>
              <button onClick={() => onSelect(c.id)} className="flex w-full flex-col gap-1.5 rounded px-2 py-2 text-left hover:bg-surface-2">
                <span className="flex items-center gap-2"><Risk value={c.risk_score} /><span className="min-w-0 flex-1 truncate font-mono text-[12px]">{c.actor_key}</span><span className="text-[11px] text-muted">{relTime(c.last_seen)}</span></span>
                <span className="flex items-center gap-2"><StageLadder reached={c.stages} highest={c.highest_stage} /><StageTag stage={c.highest_stage} /></span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CampaignTable({ campaigns, loading, selected, onSelect }: { campaigns: Campaign[]; loading: boolean; selected: string | null; onSelect: (id: string) => void }) {
  const [sort, setSort] = React.useState<"risk" | "last" | "events">("risk");
  const [status, setStatus] = React.useState<string>("");
  const rows = campaigns.filter((c) => !status || c.status === status).sort((a, b) => (sort === "risk" ? b.risk_score - a.risk_score : sort === "last" ? b.last_seen - a.last_seen : b.event_count - a.event_count));
  if (loading) return <Loading label="Loading campaigns" />;
  return (
    <div>
      <div className="flex flex-wrap items-end gap-3 border-b border-border px-3 py-2.5">
        <Field label="Status" htmlFor="c-status"><Select id="c-status" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">Any</option><option value="ACTIVE">Active</option><option value="CONTAINED">Contained</option><option value="CLOSED">Closed</option><option value="FALSE_POSITIVE">False positive</option></Select></Field>
        <Field label="Sort by" htmlFor="c-sort"><Select id="c-sort" value={sort} onChange={(e) => setSort(e.target.value as typeof sort)}><option value="risk">Risk</option><option value="last">Last seen</option><option value="events">Events</option></Select></Field>
      </div>
      {rows.length === 0 ? <Empty title="No campaigns match" body="Campaigns open once an actor sends at least the minimum number of matching requests (Admin > Correlation)." /> : (
        <TableWrap label="Campaigns">
          <table className="data-table">
            <thead><tr><th>Risk</th><th>Campaign</th><th>Actor</th><th>Kill chain</th><th>Highest stage</th><th className="text-right">Events</th><th>2xx after payload</th><th>Status</th><th>Confidence</th><th>Assignee</th><th>Last seen</th></tr></thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} data-clickable data-selected={selected === c.id} onClick={() => onSelect(c.id)}>
                  <td><Risk value={c.risk_score} /></td>
                  <td><button className="font-mono text-[12px] hover:text-accent hover:underline" onClick={(e) => { e.stopPropagation(); onSelect(c.id); }}>{c.id}</button></td>
                  <td className="max-w-[200px] truncate font-mono text-[12px]" title={c.actor_key}>{c.actor_key} <span className="font-sans text-[11px] text-muted">{c.country_code}</span></td>
                  <td><StageLadder reached={c.stages} highest={c.highest_stage} /></td>
                  <td><StageTag stage={c.highest_stage} /></td>
                  <td className="tnum text-right">{fmtNum(c.event_count)}</td>
                  <td className={cn("tnum", c.possibly_successful ? "font-semibold text-crit" : "text-muted")}>{c.possibly_successful || "-"}</td>
                  <td><CampaignStatusText s={c.status} /></td>
                  <td><ConfidenceText c={c.correlation_confidence} /></td>
                  <td className="text-[12px]">{c.assignee ?? <span className="text-muted">-</span>}</td>
                  <td className="text-[12px] text-fg-2">{relTime(c.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <p className="border-t border-border px-4 py-2 text-[11px] text-muted">Kill chain stages are inferred from HTTP signals. Correlation by IP can merge different people behind shared NAT; confidence reflects that.</p>
    </div>
  );
}

