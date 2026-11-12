"use client";
// Kill Chain x MITRE ATT&CK matrix: one column per kill chain stage, one cell per HTTP-observable technique.
// Cell shade = event count (single-hue sequential ramp); outline = techniques used by the selected campaign.
import * as React from "react";
import type { AttackEvent, StageKey } from "@/lib/types";
import { ATTACK_TECHNIQUES, STAGES, techKey, techniqueOf, stageVar } from "@/lib/killchain";
import { cn, fmtNum } from "@/lib/utils";

export default function KillChainMatrix({ events, highlightCampaign, onPick }: { events: AttackEvent[]; highlightCampaign: string | null; onPick: (stage: StageKey, techniqueKey: string) => void }) {
  const counts = React.useMemo(() => {
    const m = new Map<string, { n: number; campaigns: Set<string> }>();
    events.forEach((e) => {
      const k = techniqueOf(e);
      if (!k) return;
      const c = m.get(k) ?? { n: 0, campaigns: new Set() };
      c.n++; c.campaigns.add(e.campaign_id);
      m.set(k, c);
    });
    return m;
  }, [events]);
  const max = Math.max(1, ...[...counts.values()].map((c) => c.n));
  const step = (n: number) => Math.min(6, 1 + Math.floor((Math.log(n) / Math.log(max + 1)) * 6));

  return (
    <div className="viz overflow-x-auto p-3" role="region" aria-label="Kill chain and ATT&CK matrix" tabIndex={0}>
      <div className="grid min-w-[980px] grid-cols-7 gap-2">
        {STAGES.map((s) => (
          <div key={s.key} className="flex min-w-0 flex-col gap-2">
            <div className="border-b-2 pb-1.5" style={{ borderColor: s.observable ? stageVar(s.key) : "var(--stage-0)" }}>
              <p className="text-[12px] font-semibold">{s.n}. {s.name}</p>
              <p className="text-[11px] text-muted">{s.observable ? s.attack : "not observable by a WAF"}</p>
            </div>
            {!s.observable ? (
              <p className="rounded border border-dashed border-border-strong p-2 text-[11px] text-muted">Payload building happens on the attacker side. Coraza only sees the HTTP requests that follow.</p>
            ) : ATTACK_TECHNIQUES.filter((t) => t.stage === s.key).map((t) => {
              const k = techKey(t);
              const c = counts.get(k);
              const st = c ? step(c.n) : 0;
              const used = highlightCampaign && c?.campaigns.has(highlightCampaign);
              return (
                <button
                  key={k}
                  type="button"
                  disabled={!c}
                  onClick={() => onPick(s.key, k)}
                  className={cn(
                    "flex min-h-[64px] flex-col rounded border p-2 text-left transition-colors",
                    c ? "border-transparent hover:ring-2 hover:ring-accent/50" : "border-border bg-surface text-muted",
                    used && "ring-2 ring-accent",
                  )}
                  style={c ? { background: `var(--seq-${st})`, color: `var(--seq-ink-${st})` } : undefined}
                  title={c ? `${t.id} ${t.name} (${t.tactic}): ${c.n} events in ${c.campaigns.size} campaigns. Click to filter the graph.` : `${t.id} ${t.name}: not seen in this range`}
                >
                  <span className="font-mono text-[11px] opacity-90">{t.id}</span>
                  <span className="text-[12px] font-medium leading-tight">{t.name}</span>
                  <span className="mt-auto pt-1 text-[11px]">{c ? `${fmtNum(c.n)} events · ${c.campaigns.size} campaign${c.campaigns.size > 1 ? "s" : ""}` : "not seen"}</span>
                </button>
              );
            })}
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-fg-2">
        <span className="inline-flex items-center gap-1.5">Fewer {[1, 2, 3, 4, 5, 6].map((i) => <span key={i} className="h-2.5 w-4" style={{ background: `var(--seq-${i})` }} aria-hidden />)} More events</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-3 w-4 rounded-sm ring-2 ring-accent" aria-hidden />Used by the selected campaign</span>
        <span className="text-muted">Stage and technique are inferred from Coraza rule IDs and tags (Admin &gt; Kill chain mapping).</span>
      </div>
    </div>
  );
}
