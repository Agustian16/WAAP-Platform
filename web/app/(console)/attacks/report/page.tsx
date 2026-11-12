"use client";
// FR-6.16 Incident Report: print-optimized page; the browser's "Save as PDF" produces the PDF.
import * as React from "react";
import { useSearchParams } from "next/navigation";
import { Printer } from "@phosphor-icons/react";
import { attacks } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Button, ErrorState, Loading, TableWrap } from "@/components/ui";
import { CampaignStatusText, OutcomeText, StageLadder, StageTag } from "@/components/atoms";
import Timeline from "@/components/attack/timeline";
import { AttackRadar } from "@/components/attack/panel";
import { STAGES, stageIndex, techniqueOf, ATTACK_TECHNIQUES, techKey } from "@/lib/killchain";
import { fmtNum, fmtTime } from "@/lib/utils";

export default function Page() {
  return <React.Suspense fallback={<Loading label="Loading report" />}><Report /></React.Suspense>;
}

function Report() {
  const id = useSearchParams().get("campaign") ?? "";
  const q = useAsync(() => attacks.campaign(id), [id]);
  if (q.error) return <ErrorState title="Report could not be built" error={q.error} onRetry={q.reload} />;
  if (!q.data) return <Loading label="Building incident report" />;
  const { campaign: c, events } = q.data;
  const outcome = { BLOCKED: 0, DETECTED: 0, POSSIBLY_SUCCESSFUL: 0 };
  events.forEach((e) => outcome[e.outcome]++);
  const techs = [...new Set(events.map((e) => techniqueOf(e)).filter(Boolean))].map((k) => ATTACK_TECHNIQUES.find((t) => techKey(t) === k)!);
  const evidence = [...events.filter((e) => e.outcome === "POSSIBLY_SUCCESSFUL"), ...events.filter((e) => e.outcome !== "POSSIBLY_SUCCESSFUL")].slice(0, 25);
  return (
    <article className="mx-auto max-w-4xl bg-surface p-6 print:max-w-none print:p-0">
      <div className="no-print mb-4 flex justify-end"><Button variant="primary" onClick={() => window.print()}><Printer size={16} aria-hidden />Print or save as PDF</Button></div>
      <header className="border-b border-border pb-4">
        <p className="text-[12px] text-muted">Corazium · Incident report · generated {fmtTime(Date.now())}</p>
        <h1 className="mt-1 font-mono text-[20px] font-semibold">{c.id}</h1>
        <p className="mt-2 text-[14px]">
          Actor <span className="font-mono">{c.actor_key}</span> ({c.country_code}, {c.as_name}) reached <strong>{STAGES[stageIndex(c.highest_stage)].name}</strong> against {c.targets.length} target{c.targets.length > 1 ? "s" : ""} between {fmtTime(c.first_seen)} and {fmtTime(c.last_seen)}.
          Risk {c.risk_score}/100, status <CampaignStatusText s={c.status} />, correlation confidence {c.correlation_confidence.toLowerCase()}.
        </p>
      </header>
      <section className="border-b border-border py-4">
        <h2 className="mb-2 text-[14px] font-semibold">Kill chain</h2>
        <StageLadder size="lg" reached={c.stages} highest={c.highest_stage} />
        <p className="mt-2 text-[12px] text-muted">Stages are inferred from HTTP-layer signals. Weaponization cannot be observed by a WAF.</p>
      </section>
      <section className="grid gap-4 border-b border-border py-4 sm:grid-cols-2">
        <div>
          <h2 className="mb-2 text-[14px] font-semibold">Outcome</h2>
          <ul className="flex flex-col gap-1 text-[13px]">
            <li className="flex justify-between"><OutcomeText o="BLOCKED" /><span className="tnum">{fmtNum(outcome.BLOCKED)}</span></li>
            <li className="flex justify-between"><OutcomeText o="DETECTED" /><span className="tnum">{fmtNum(outcome.DETECTED)}</span></li>
            <li className="flex justify-between"><OutcomeText o="POSSIBLY_SUCCESSFUL" /><span className="tnum font-semibold">{fmtNum(outcome.POSSIBLY_SUCCESSFUL)}</span></li>
          </ul>
          <h2 className="mb-1 mt-4 text-[14px] font-semibold">MITRE ATT&CK</h2>
          <ul className="text-[13px]">{techs.map((t) => <li key={techKey(t)}><span className="font-mono">{t.id}</span> {t.name} <span className="text-muted">({t.tactic})</span></li>)}</ul>
        </div>
        <div><h2 className="mb-2 text-[14px] font-semibold">Attack profile</h2><AttackRadar events={events} /></div>
      </section>
      <section className="border-b border-border py-4">
        <h2 className="mb-2 text-[14px] font-semibold">Timeline</h2>
        <Timeline events={events} campaigns={[c]} from={c.first_seen - 60e3} to={c.last_seen + 60e3} laneMode="target" selectedEventId={null} highlightCampaign={null} playhead={null} onSelectEvent={() => {}} onSelectLane={() => {}} />
      </section>
      <section className="py-4">
        <h2 className="mb-2 text-[14px] font-semibold">Evidence ({evidence.length} of {events.length} events, successful requests first)</h2>
        <TableWrap label="Evidence events">
          <table className="data-table">
            <thead><tr><th>Time</th><th>Request</th><th>Rule</th><th>Stage</th><th>Outcome</th></tr></thead>
            <tbody>
              {evidence.map((e) => (
                <tr key={e.id}>
                  <td className="tnum font-mono text-[11px]">{fmtTime(e.timestamp)}</td>
                  <td className="max-w-[300px] truncate font-mono text-[11px]">{e.method} {e.host}{e.uri}</td>
                  <td className="font-mono text-[12px]">{e.rule_id}</td>
                  <td><StageTag stage={e.killchain_stage} /></td>
                  <td><OutcomeText o={e.outcome} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </section>
      {c.notes.length ? (
        <section className="border-t border-border py-4">
          <h2 className="mb-2 text-[14px] font-semibold">Analyst notes</h2>
          {c.notes.map((n, i) => <p key={i} className="text-[13px]"><strong>{n.author}</strong> ({fmtTime(n.at)}): {n.text}</p>)}
        </section>
      ) : null}
    </article>
  );
}
