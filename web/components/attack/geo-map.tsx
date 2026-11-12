"use client";
// Geo Attack Map (FR-6.13): origin -> edge node arcs colored by stage; Live Feed animates new arcs, Heatmap shades
// origin countries on a single-hue sequential ramp. SVG keeps it crisp, themeable and keyboard reachable.
import * as React from "react";
import { geoNaturalEarth1, geoPath, geoInterpolate } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import type { AttackEvent, Campaign, EdgeNode } from "@/lib/types";
import { stageVar, stageIndex, STAGES } from "@/lib/killchain";
import { fmtNum } from "@/lib/utils";

const W = 960, H = 470;
const ISO_NUM: Record<string, string> = { RU: "643", CN: "156", BR: "076", NL: "528", US: "840", DE: "276", ID: "360", VN: "704", IN: "356", SG: "702", KR: "410", FR: "250", JP: "392" };
const NUM_ISO = Object.fromEntries(Object.entries(ISO_NUM).map(([k, v]) => [v, k]));

const topo = world as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
const countries = feature(topo, topo.objects.countries).features;
const projection = geoNaturalEarth1().fitExtent([[8, 8], [W - 8, H - 8]], { type: "Sphere" });
const path = geoPath(projection);

function arcPath(a: [number, number], b: [number, number]) {
  const p0 = projection(a)!, p1 = projection(b)!;
  const mid = projection(geoInterpolate(a, b)(0.5))!;
  const d = Math.hypot(p1[0] - p0[0], p1[1] - p0[1]);
  const lift = Math.min(90, d * 0.35);
  return { d: `M${p0[0]},${p0[1]} Q${mid[0]},${mid[1] - lift} ${p1[0]},${p1[1]}`, len: d * 1.25 };
}

interface Props {
  events: AttackEvent[];
  campaigns: Campaign[];
  nodes: EdgeNode[];
  mode: "live" | "heatmap";
  live: AttackEvent[]; // events received in the last few seconds (animated)
  selectedCampaign: string | null;
  onSelectCampaign: (id: string) => void;
  onSelectCountry: (cc: string | null) => void;
  country: string | null;
}

export default function GeoMap(p: Props) {
  const byCountry = React.useMemo(() => {
    const m = new Map<string, number>();
    p.events.forEach((e) => m.set(e.country_code, (m.get(e.country_code) ?? 0) + 1));
    return m;
  }, [p.events]);
  const max = Math.max(1, ...byCountry.values());
  const step = (n: number) => Math.min(6, 1 + Math.floor((Math.log(n) / Math.log(max + 1)) * 6));

  // One static arc per campaign -> edge node pair.
  const arcs = React.useMemo(() => {
    const m = new Map<string, { c: Campaign; node: EdgeNode; n: number; stage: AttackEvent["killchain_stage"] }>();
    p.events.forEach((e) => {
      const c = p.campaigns.find((x) => x.id === e.campaign_id);
      const node = p.nodes.find((x) => x.id === e.node_id);
      if (!c || !node) return;
      const k = `${c.id}|${node.id}`;
      const cur = m.get(k);
      if (cur) { cur.n++; if (stageIndex(e.killchain_stage) > stageIndex(cur.stage)) cur.stage = e.killchain_stage; }
      else m.set(k, { c, node, n: 1, stage: e.killchain_stage });
    });
    return [...m.values()];
  }, [p.events, p.campaigns, p.nodes]);

  const origins = React.useMemo(() => {
    const ids = new Set(p.events.map((e) => e.campaign_id));
    return p.campaigns.filter((c) => ids.has(c.id));
  }, [p.events, p.campaigns]);
  const maxN = Math.max(1, ...arcs.map((a) => a.n));

  return (
    <div className="viz flex h-full min-h-0 flex-col">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="group" aria-label="World map of attack origins and targeted edge nodes">
        <path d={path({ type: "Sphere" }) ?? ""} fill="none" stroke="var(--grid)" />
        {countries.map((f) => {
          const cc = NUM_ISO[String(f.id)];
          const n = cc ? byCountry.get(cc) ?? 0 : 0;
          const fill = p.mode === "heatmap" && n ? `var(--seq-${step(n)})` : "var(--map-land)";
          return (
            <path
              key={String(f.id) + f.properties.name}
              d={path(f) ?? ""}
              fill={fill}
              stroke={p.country && p.country === cc ? "rgb(var(--accent))" : "var(--map-stroke)"}
              strokeWidth={p.country && p.country === cc ? 1.5 : 0.5}
              onClick={() => n && p.onSelectCountry(p.country === cc ? null : cc!)}
              className={n ? "cursor-pointer hover:opacity-80" : undefined}
            >
              <title>{`${f.properties.name}${n ? `: ${fmtNum(n)} events` : ""}`}</title>
            </path>
          );
        })}
        {p.mode === "live" && arcs.map((a) => {
          const { d } = arcPath(a.c.geo, a.node.geo);
          const dim = p.selectedCampaign && p.selectedCampaign !== a.c.id;
          return (
            <path key={a.c.id + a.node.id} d={d} fill="none" stroke={stageVar(a.stage)} strokeWidth={1 + (a.n / maxN) * 3} strokeOpacity={dim ? 0.12 : 0.75} strokeLinecap="round" className="cursor-pointer" onClick={() => p.onSelectCampaign(a.c.id)}>
              <title>{`${a.c.actor_key} -> ${a.node.node_name}: ${a.n} events, ${STAGES[stageIndex(a.stage)].name}`}</title>
            </path>
          );
        })}
        {p.mode === "live" && p.live.map((e) => {
          const node = p.nodes.find((x) => x.id === e.node_id);
          if (!node) return null;
          const { d, len } = arcPath(e.geo, node.geo);
          return (
            <path key={e.id} d={d} fill="none" stroke="rgb(var(--accent))" strokeWidth={2.5} strokeLinecap="round"
              style={{ strokeDasharray: len, ["--len" as string]: len, animation: "arc-draw 0.9s ease-out forwards, fade-out 1.2s ease-in 1.4s forwards" }} aria-hidden />
          );
        })}
        {p.nodes.map((n) => {
          const [x, y] = projection(n.geo)!;
          return (
            <g key={n.id} aria-label={`Edge node ${n.node_name}`}>
              <rect x={x - 4} y={y - 4} width={8} height={8} fill={n.status === "OFFLINE" ? "var(--c-crit)" : "rgb(var(--fg))"} stroke="rgb(var(--surface))" strokeWidth={1.5} />
              <title>{`${n.node_name} (${n.region})${n.status === "OFFLINE" ? ", unreachable" : ""}`}</title>
            </g>
          );
        })}
        {origins.map((c) => {
          const [x, y] = projection(c.geo)!;
          const sel = p.selectedCampaign === c.id;
          return (
            <g
              key={c.id}
              role="button"
              tabIndex={0}
              aria-label={`Origin ${c.actor_key}, ${c.country_code}, risk ${c.risk_score}. Open campaign.`}
              onClick={() => p.onSelectCampaign(c.id)}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); p.onSelectCampaign(c.id); } }}
              className="cursor-pointer outline-none [&:focus-visible>circle:first-child]:stroke-[rgb(var(--accent))]"
            >
              <circle cx={x} cy={y} r={sel ? 9 : 6 + Math.min(c.event_count / 60, 4)} fill={stageVar(c.highest_stage)} stroke={sel ? "rgb(var(--accent))" : "rgb(var(--surface))"} strokeWidth={sel ? 3 : 1.5} />
              <title>{`${c.actor_key} (${c.country_code}), ${c.event_count} events`}</title>
            </g>
          );
        })}
      </svg>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border px-3 py-2 text-[11px] text-fg-2">
        {p.mode === "heatmap" ? (
          <span className="inline-flex items-center gap-1.5">Fewer events
            {[1, 2, 3, 4, 5, 6].map((i) => <span key={i} className="h-2.5 w-4" style={{ background: `var(--seq-${i})` }} aria-hidden />)}
            More events
          </span>
        ) : (
          <>
            <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full bg-[var(--stage-3)]" aria-hidden />Origin, colored by highest stage</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 bg-fg" aria-hidden />Coraza edge node</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-0.5 w-4 bg-accent" aria-hidden />Event in the last seconds</span>
          </>
        )}
        <span className="ml-auto text-muted">Locations come from GeoIP enrichment and can be wrong for VPNs and proxies.</span>
      </div>
    </div>
  );
}
