"use client";
// Domain atoms. The kill chain "stage ladder" is the console's identity motif: the same 7-segment glyph
// appears in tables, the campaign panel, the graph legend and reports, so stage progress reads the same everywhere.
import * as React from "react";
import { Prohibit, Eye, WarningDiamond, Warning, WarningOctagon, Info } from "@phosphor-icons/react";
import { STAGES, stageIndex, stageVar, riskBand } from "@/lib/killchain";
import type { Outcome, Severity, StageKey, NodeStatus, Action, CampaignStatus, Confidence } from "@/lib/types";
import { cn } from "@/lib/utils";

export function StageLadder({ reached, highest, size = "sm", onSelect, selected }: { reached: StageKey[]; highest?: StageKey; size?: "sm" | "lg"; onSelect?: (s: StageKey | null) => void; selected?: StageKey | null }) {
  const top = highest ?? [...reached].sort((a, b) => stageIndex(b) - stageIndex(a))[0];
  if (size === "sm") {
    return (
      <span className="viz inline-flex items-center gap-[2px]" role="img" aria-label={`Kill chain: highest stage ${top ? STAGES[stageIndex(top)].name : "none"}; reached ${reached.map((s) => STAGES[stageIndex(s)].short).join(", ") || "none"}`}>
        {STAGES.map((s) => {
          const on = reached.includes(s.key);
          return (
            <span
              key={s.key}
              className={cn("h-3 w-[7px] rounded-[1px]", !s.observable && "bg-[repeating-linear-gradient(135deg,var(--stage-0)_0_1px,transparent_1px_3px)]", s.key === top && "outline outline-1 outline-offset-1 outline-fg/70")}
              style={s.observable ? { background: on ? stageVar(s.key) : "rgb(var(--surface-3))" } : undefined}
            />
          );
        })}
      </span>
    );
  }
  // FR-6.10 progress bar: reached stages lit, highest marked, Weaponization grey "n/a", click to filter.
  return (
    <ol className="viz grid grid-cols-7 gap-1" aria-label="Kill chain progress">
      {STAGES.map((s) => {
        const on = reached.includes(s.key);
        const isTop = s.key === top;
        const sel = selected === s.key;
        const content = (
          <>
            <span
              className={cn("block h-2 w-full rounded-sm", !s.observable && "bg-[repeating-linear-gradient(135deg,var(--stage-0)_0_2px,transparent_2px_5px)]")}
              style={s.observable ? { background: on ? stageVar(s.key) : "rgb(var(--surface-3))" } : undefined}
            />
            <span className={cn("mt-1.5 block truncate text-[11px] font-medium", on ? "text-fg" : "text-muted")} title={`${s.n}. ${s.name}`}>{s.short}</span>
            <span className={cn("block text-[10px]", isTop ? "font-semibold text-fg" : "text-muted")}>{!s.observable ? "not observable" : isTop ? "current" : on ? "reached" : "-"}</span>
          </>
        );
        return (
          <li key={s.key} className="min-w-0">
            {onSelect && s.observable ? (
              <button
                type="button"
                onClick={() => onSelect(sel ? null : s.key)}
                aria-pressed={sel}
                title={`${s.name} (${s.attack}). Click to filter.`}
                className={cn("w-full rounded px-0.5 pb-1 pt-1 text-left hover:bg-surface-2", sel && "bg-accent/10 ring-1 ring-accent")}
              >
                {content}
              </button>
            ) : (
              <div className="px-0.5 pb-1 pt-1" title={s.observable ? `${s.name} (${s.attack})` : "Weaponization happens off-network; a WAF cannot observe it"}>{content}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function StageTag({ stage }: { stage: StageKey }) {
  const s = STAGES[stageIndex(stage)];
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[12px]">
      <span className="h-2.5 w-2.5 rounded-[2px]" style={{ background: stageVar(stage) }} aria-hidden />
      {s.name}
    </span>
  );
}

const SEV: Record<Severity, { cls: string; Icon: typeof Info; label: string }> = {
  CRITICAL: { cls: "text-crit", Icon: WarningOctagon, label: "Critical" },
  ERROR: { cls: "text-serious", Icon: WarningDiamond, label: "Error" },
  WARNING: { cls: "text-warn", Icon: Warning, label: "Warning" },
  NOTICE: { cls: "text-muted", Icon: Info, label: "Notice" },
};
export function SeverityText({ s }: { s: Severity }) {
  const { cls, Icon, label } = SEV[s];
  return <span className={cn("inline-flex items-center gap-1 whitespace-nowrap text-[12px] font-medium", cls)}><Icon size={14} weight="fill" aria-hidden />{label}</span>;
}

export function OutcomeText({ o }: { o: Outcome }) {
  if (o === "BLOCKED") return <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-fg-2"><Prohibit size={14} aria-hidden />Blocked</span>;
  if (o === "DETECTED") return <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] text-fg-2"><Eye size={14} aria-hidden />Detected</span>;
  return <span className="inline-flex items-center gap-1 whitespace-nowrap text-[12px] font-semibold text-crit"><WarningOctagon size={14} weight="fill" aria-hidden />Possibly successful</span>;
}

export function ActionText({ a, status }: { a: Action; status: number }) {
  return (
    <span className={cn("whitespace-nowrap font-mono text-[12px]", a === "DENY" ? "text-fg" : a === "LOG" && status < 300 ? "font-semibold text-crit" : "text-fg-2")}>
      {a}{` (${status})`}
    </span>
  );
}

export function Risk({ value, showBar = true }: { value: number; showBar?: boolean }) {
  const band = riskBand(value);
  return (
    <span className="inline-flex items-center gap-2" aria-label={`Risk ${value} of 100`}>
      <span className={cn("tnum w-6 text-right text-[13px] font-semibold", band === "crit" ? "text-crit" : band === "serious" ? "text-serious" : band === "warn" ? "text-warn" : "text-fg-2")}>{value}</span>
      {showBar ? (
        <span className="h-1.5 w-12 overflow-hidden rounded-sm bg-surface-3" aria-hidden>
          <span className="block h-full" style={{ width: `${value}%`, background: `var(--c-${band === "muted" ? "good" : band})` }} />
        </span>
      ) : null}
    </span>
  );
}

export function NodeStatusText({ s }: { s: NodeStatus }) {
  const map = { ONLINE: ["Online", "bg-good", "text-fg"], WARN: ["Degraded", "bg-warn", "text-warn"], OFFLINE: ["Unreachable", "bg-crit", "text-crit"] } as const;
  const [label, dot, txt] = map[s];
  return <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap text-[12px] font-medium", txt)}><span className={cn("h-2 w-2 rounded-full", dot)} aria-hidden />{label}</span>;
}

export function CampaignStatusText({ s }: { s: CampaignStatus }) {
  const map: Record<CampaignStatus, [string, string]> = {
    ACTIVE: ["Active", "text-fg font-semibold"],
    CONTAINED: ["Contained", "text-fg-2"],
    CLOSED: ["Closed", "text-muted"],
    FALSE_POSITIVE: ["False positive", "text-muted"],
  };
  return <span className={cn("whitespace-nowrap text-[12px]", map[s][1])}>{map[s][0]}</span>;
}

export function ConfidenceText({ c }: { c: Confidence }) {
  return <span className={cn("whitespace-nowrap text-[12px]", c === "LOW" ? "text-warn" : "text-fg-2")} title="Correlation confidence. Shared NAT or proxies lower it.">{c.toLowerCase()} confidence</span>;
}

export const Mono = ({ children, className }: { children: React.ReactNode; className?: string }) => <span className={cn("font-mono text-[12px]", className)}>{children}</span>;

export function Stat({ label, value, sub, emphasis }: { label: string; value: React.ReactNode; sub?: React.ReactNode; emphasis?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="text-[12px] text-muted">{label}</p>
      <p className={cn("tnum mt-0.5 truncate font-semibold leading-tight", emphasis ? "text-[26px]" : "text-[20px]")}>{value}</p>
      {sub ? <p className="mt-0.5 truncate text-[12px] text-fg-2">{sub}</p> : null}
    </div>
  );
}
