"use client";
// Recharts wrappers with the dataviz mark spec: 2px lines, recessive grid, one y-axis per chart, hover tooltip.
import * as React from "react";
import { ResponsiveContainer, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from "recharts";
import { fmtClock, fmtNum } from "@/lib/utils";

const axis = { stroke: "var(--axis)", tick: { fill: "rgb(var(--muted))", fontSize: 11 }, tickLine: false } as const;

export function TipBox({ title, rows }: { title: string; rows: { label: string; value: string; color?: string }[] }) {
  return (
    <div className="viz rounded border border-border-strong bg-surface px-2.5 py-2 text-[12px] shadow-lg">
      <p className="mb-1 font-medium">{title}</p>
      {rows.map((r) => (
        <p key={r.label} className="flex items-center gap-2 text-fg-2">
          {r.color ? <span className="h-2 w-2 rounded-[2px]" style={{ background: r.color }} aria-hidden /> : null}
          <span>{r.label}</span>
          <span className="tnum ml-auto pl-3 font-medium text-fg">{r.value}</span>
        </p>
      ))}
    </div>
  );
}

/** Small-multiples pair for FR-4.1 Chart 1: traffic and attacks have different scales, so each gets its own axis. */
export function TrafficCharts({ data }: { data: { t: number; total: number; blocked: number; detected: number }[] }) {
  const [hover, setHover] = React.useState<number | null>(null);
  const sync = { syncId: "traffic", onMouseMove: (s: { activeTooltipIndex?: number | string | null }) => setHover(s?.activeTooltipIndex != null ? Number(s.activeTooltipIndex) : null), onMouseLeave: () => setHover(null) };
  const tip = (title: (p: (typeof data)[number]) => string, rows: (p: (typeof data)[number]) => { label: string; value: string; color?: string }[]) =>
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    function T({ active, payload }: any) {
      if (!active || !payload?.length) return null;
      const p = payload[0].payload;
      return <TipBox title={title(p)} rows={rows(p)} />;
    };
  return (
    <div className="viz flex flex-col gap-1" aria-label="Traffic and attack trend" role="group" data-hover={hover ?? undefined}>
      <p className="px-4 text-[12px] text-muted">Requests per second</p>
      <div className="h-[150px] px-1">
        <ResponsiveContainer>
          <AreaChart data={data} margin={{ top: 6, right: 16, left: 0, bottom: 0 }} {...sync}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="t" {...axis} tickFormatter={fmtClock} minTickGap={48} hide />
            <YAxis {...axis} width={44} tickFormatter={(v) => (v >= 1000 ? `${v / 1000}k` : v)} axisLine={false} />
            <Tooltip content={tip((p) => fmtClock(p.t), (p) => [{ label: "Requests/s", value: fmtNum(p.total), color: "var(--seq-4)" }])} cursor={{ stroke: "rgb(var(--muted))", strokeWidth: 1 }} />
            <Area type="monotone" dataKey="total" stroke="var(--seq-4)" strokeWidth={2} fill="var(--seq-4)" fillOpacity={0.12} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <p className="px-4 pt-2 text-[12px] text-muted">Attack events per 5 minutes</p>
      <div className="h-[110px] px-1">
        <ResponsiveContainer>
          <BarChart data={data} margin={{ top: 6, right: 16, left: 0, bottom: 0 }} barCategoryGap={1} {...sync}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="t" {...axis} tickFormatter={fmtClock} minTickGap={48} />
            <YAxis {...axis} width={44} axisLine={false} allowDecimals={false} />
            <Tooltip content={tip((p) => fmtClock(p.t), (p) => [{ label: "Blocked", value: fmtNum(p.blocked), color: "var(--c-crit)" }, { label: "Logged only", value: fmtNum(p.detected), color: "var(--c-warn)" }])} cursor={{ fill: "rgb(var(--fg) / 0.06)" }} />
            <Bar dataKey="blocked" stackId="a" fill="var(--c-crit)" isAnimationActive={false} />
            <Bar dataKey="detected" stackId="a" fill="var(--c-warn)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      <div className="flex gap-4 px-4 pb-1 text-[12px] text-fg-2">
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-[2px] bg-[var(--c-crit)]" aria-hidden />Blocked (DENY)</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-[2px] bg-[var(--c-warn)]" aria-hidden />Logged only (LOG)</span>
      </div>
    </div>
  );
}

/** FR-4.1 Chart 2: horizontal bars, one series; rule message lives in text, not color. */
export function TopRulesChart({ data, onSelect }: { data: { id: number; n: number; msg: string }[]; onSelect?: (id: number) => void }) {
  const max = Math.max(1, ...data.map((d) => d.n));
  return (
    <ol className="viz flex flex-col gap-1 px-4 pb-4">
      {data.map((d) => (
        <li key={d.id}>
          <button type="button" onClick={() => onSelect?.(d.id)} className="group grid w-full grid-cols-[64px_1fr_44px] items-center gap-3 rounded px-1 py-1 text-left hover:bg-surface-2" title={`${d.id}: ${d.msg}. Open in Log Explorer.`}>
            <span className="font-mono text-[12px]">{d.id}</span>
            <span className="min-w-0">
              <span className="block truncate text-[12px] text-fg-2 group-hover:text-fg">{d.msg}</span>
              <span className="mt-1 block h-1.5 rounded-sm bg-[var(--seq-4)]" style={{ width: `${(d.n / max) * 100}%` }} aria-hidden />
            </span>
            <span className="tnum text-right text-[12px] font-medium">{fmtNum(d.n)}</span>
          </button>
        </li>
      ))}
    </ol>
  );
}

export { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, axis };
