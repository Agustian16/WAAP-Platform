"use client";
// Attack Timeline (FR-6.11): severity histogram over swim-lanes (per actor or per target); marks colored by stage.
// Selecting an event highlights it in the graph (and vice versa via highlightLane).
import * as React from "react";
import type { AttackEvent, Campaign, Severity } from "@/lib/types";
import { stageVar, STAGES, stageIndex } from "@/lib/killchain";
import { fmtClock, fmtTime, cn } from "@/lib/utils";

const SEV_ORDER: Severity[] = ["NOTICE", "WARNING", "ERROR", "CRITICAL"];
const SEV_COLOR: Record<Severity, string> = { CRITICAL: "var(--c-crit)", ERROR: "var(--c-serious)", WARNING: "var(--c-warn)", NOTICE: "rgb(var(--muted))" };
const LANE_H = 22, HIST_H = 36, AXIS_H = 18, LABEL_W = 150, MAX_LANES = 10;

interface Props {
  events: AttackEvent[];
  campaigns: Campaign[];
  from: number;
  to: number;
  laneMode: "actor" | "target";
  selectedEventId: string | null;
  highlightCampaign: string | null;
  playhead: number | null;
  onSelectEvent: (e: AttackEvent) => void;
  onSelectLane: (campaignId: string | null) => void;
}

export default function Timeline(p: Props) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [width, setWidth] = React.useState(800);
  React.useEffect(() => {
    const ro = new ResizeObserver(([e]) => setWidth(Math.max(320, e.contentRect.width)));
    if (ref.current) ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  const inWin = React.useMemo(() => p.events.filter((e) => e.timestamp >= p.from && e.timestamp <= p.to), [p.events, p.from, p.to]);
  const lanes = React.useMemo(() => {
    const m = new Map<string, { key: string; label: string; campaignId: string | null; evs: AttackEvent[]; risk: number }>();
    inWin.forEach((e) => {
      const c = p.campaigns.find((x) => x.id === e.campaign_id);
      const key = p.laneMode === "actor" ? e.campaign_id : `${e.host}${e.uri.split("?")[0]}`;
      const label = p.laneMode === "actor" ? c?.actor_key ?? e.client_ip : key;
      const l = m.get(key) ?? { key, label, campaignId: p.laneMode === "actor" ? e.campaign_id : null, evs: [], risk: 0 };
      l.evs.push(e);
      l.risk = Math.max(l.risk, c?.risk_score ?? 0);
      m.set(key, l);
    });
    return [...m.values()].sort((a, b) => b.risk - a.risk || b.evs.length - a.evs.length);
  }, [inWin, p.campaigns, p.laneMode]);

  const shown = lanes.slice(0, MAX_LANES);
  const plotW = width - LABEL_W - 12;
  const x = (t: number) => LABEL_W + ((t - p.from) / Math.max(1, p.to - p.from)) * plotW;
  const bins = 60;
  const hist = React.useMemo(() => {
    const b = Array.from({ length: bins }, () => ({ NOTICE: 0, WARNING: 0, ERROR: 0, CRITICAL: 0 } as Record<Severity, number>));
    inWin.forEach((e) => { const i = Math.min(bins - 1, Math.floor(((e.timestamp - p.from) / (p.to - p.from)) * bins)); b[i][e.severity]++; });
    return b;
  }, [inWin, p.from, p.to]);
  const hMax = Math.max(1, ...hist.map((h) => SEV_ORDER.reduce((a, s) => a + h[s], 0)));
  const height = HIST_H + 6 + shown.length * LANE_H + AXIS_H;
  const ticks = 6;
  const span = p.to - p.from;
  const fmtTick = (t: number) => (span > 2 * 86400_000 ? new Date(t).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }) : fmtClock(t));

  if (!inWin.length) {
    return <div ref={ref} className="viz flex h-24 items-center justify-center text-[13px] text-fg-2">No events in this window. Widen the zoom or clear filters.</div>;
  }
  return (
    <div ref={ref} className="viz w-full">
      <svg width={width} height={height} role="group" aria-label={`Timeline of ${inWin.length} events from ${fmtTime(p.from)} to ${fmtTime(p.to)}`}>
        {/* severity histogram */}
        {hist.map((h, i) => {
          let y = HIST_H;
          const bw = plotW / bins;
          return SEV_ORDER.map((s) => {
            if (!h[s]) return null;
            const hh = (h[s] / hMax) * (HIST_H - 4);
            y -= hh;
            return <rect key={i + s} x={LABEL_W + i * bw + 0.5} y={y} width={Math.max(1, bw - 1)} height={hh} fill={SEV_COLOR[s]}><title>{`${h[s]} ${s.toLowerCase()}`}</title></rect>;
          });
        })}
        <text x={LABEL_W - 8} y={HIST_H - 2} textAnchor="end" className="fill-[rgb(var(--muted))] text-[10px]">severity</text>
        {/* lanes */}
        {shown.map((l, li) => {
          const y = HIST_H + 6 + li * LANE_H;
          const hl = p.highlightCampaign && l.campaignId === p.highlightCampaign;
          const dim = p.highlightCampaign && !hl;
          return (
            <g key={l.key} opacity={dim ? 0.35 : 1}>
              <rect x={0} y={y} width={width} height={LANE_H} fill={hl ? "rgb(var(--accent) / 0.08)" : li % 2 ? "rgb(var(--surface-2) / 0.5)" : "transparent"} />
              <text
                x={4} y={y + 15}
                className={cn("text-[11px] font-mono", l.campaignId && "cursor-pointer")}
                fill="rgb(var(--fg-2))"
                onClick={() => l.campaignId && p.onSelectLane(hl ? null : l.campaignId)}
              >
                {l.label.length > 20 ? l.label.slice(0, 19) + "…" : l.label}
                <title>{l.label}</title>
              </text>
              {l.evs.map((e) => {
                const sel = e.id === p.selectedEventId;
                return (
                  <rect
                    key={e.id}
                    x={x(e.timestamp) - (sel ? 2.5 : 1.5)} y={y + (sel ? 2 : 5)} width={sel ? 5 : 3} height={sel ? LANE_H - 4 : LANE_H - 10} rx={1}
                    fill={stageVar(e.killchain_stage)}
                    stroke={sel ? "rgb(var(--fg))" : e.outcome === "POSSIBLY_SUCCESSFUL" ? "var(--c-crit)" : "none"}
                    strokeWidth={sel ? 1.5 : 1}
                    className="cursor-pointer"
                    onClick={() => p.onSelectEvent(e)}
                  >
                    <title>{`${fmtTime(e.timestamp)}  ${e.method} ${e.host}${e.uri}\nrule ${e.rule_id} · ${STAGES[stageIndex(e.killchain_stage)].name} · ${e.outcome.toLowerCase().replace("_", " ")}`}</title>
                  </rect>
                );
              })}
            </g>
          );
        })}
        {/* axis */}
        {Array.from({ length: ticks + 1 }, (_, i) => {
          const t = p.from + (span * i) / ticks;
          const xx = x(t);
          return (
            <g key={i}>
              <line x1={xx} x2={xx} y1={HIST_H + 4} y2={height - AXIS_H} stroke="var(--grid)" />
              <text x={xx} y={height - 4} textAnchor={i === 0 ? "start" : i === ticks ? "end" : "middle"} className="text-[10px]" fill="rgb(var(--muted))">{fmtTick(t)}</text>
            </g>
          );
        })}
        {p.playhead ? <line x1={x(p.playhead)} x2={x(p.playhead)} y1={0} y2={height - AXIS_H} stroke="rgb(var(--accent))" strokeWidth={2} /> : null}
      </svg>
      {lanes.length > MAX_LANES ? <p className="px-1 pt-1 text-[11px] text-muted">Showing the {MAX_LANES} highest-risk lanes of {lanes.length}. Filter by site or stage to see others.</p> : null}
    </div>
  );
}
