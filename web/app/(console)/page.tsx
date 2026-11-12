"use client";
import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { analytics, attacks, subscribeAttackStream } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Empty, ErrorState, Loading, PageHeader, SectionTitle, TableWrap } from "@/components/ui";
import { Mono, OutcomeText, Risk, StageLadder, StageTag, Stat } from "@/components/atoms";
import { TopRulesChart, TrafficCharts } from "@/components/charts";
import { fmtCompact, fmtNum, relTime, cn } from "@/lib/utils";
import type { Campaign } from "@/lib/types";

const RANGES = [1, 6, 24] as const;

export default function OverviewPage() {
  const [hours, setHours] = React.useState<(typeof RANGES)[number]>(6);
  const ov = useAsync(() => analytics.overview(hours), [hours]);
  const cmp = useAsync(() => attacks.campaigns(), []);
  const router = useRouter();

  // Live: campaigns update in place from the attack stream.
  React.useEffect(() => subscribeAttackStream((m) => cmp.setData((list) => {
    if (!list) return list;
    const i = list.findIndex((c) => c.id === m.campaign.id);
    return i < 0 ? [m.campaign, ...list] : list.map((c, k) => (k === i ? m.campaign : c));
  })), [cmp.setData]); // eslint-disable-line react-hooks/exhaustive-deps

  const attention = (cmp.data ?? []).filter((c) => c.status === "ACTIVE").sort((a, b) => b.risk_score - a.risk_score);
  const psTotal = attention.reduce((a, c) => a + c.possibly_successful, 0);

  return (
    <>
      <PageHeader
        title="Overview"
        description="Active attack campaigns ranked by risk, then traffic and rule activity across all sites."
        actions={
          <div role="group" aria-label="Time range" className="seg">
            {RANGES.map((h) => (
              <button key={h} onClick={() => setHours(h)} aria-pressed={hours === h} className="seg-btn">
                {h}h
              </button>
            ))}
          </div>
        }
      />

      <section aria-labelledby="attn" className="panel">
        <SectionTitle id="attn" aside={<Link href="/attacks?tab=campaigns" className="text-[12px] font-medium text-accent hover:underline">All campaigns</Link>}>
          Needs attention
        </SectionTitle>
        {cmp.loading && !cmp.data ? <Loading label="Loading campaigns" /> : cmp.error && !cmp.data ? <ErrorState title="Campaigns could not be loaded" error={cmp.error} onRetry={cmp.reload} /> : attention.length === 0 ? (
          <Empty title="No active campaigns" body="Correlated attack activity will appear here as soon as an actor crosses the minimum event count." />
        ) : (
          <>
            {psTotal > 0 ? (
              <p className="mx-4 mb-3 flex flex-wrap items-center gap-x-2 gap-y-1 rounded border border-crit/40 bg-crit/5 px-3 py-2 text-[13px]">
                <OutcomeText o="POSSIBLY_SUCCESSFUL" />
                <span className="text-fg-2"><span className="tnum font-semibold text-fg">{psTotal}</span> requests carried an attack payload and still returned 2xx. Triage these first.</span>
              </p>
            ) : null}
            <TableWrap label="Active campaigns">
              <table className="data-table">
                <thead><tr><th>Risk</th><th>Actor</th><th>Kill chain</th><th>Highest stage</th><th>Targets</th><th className="text-right">Events</th><th>2xx after payload</th><th>Assignee</th><th>Last seen</th></tr></thead>
                <tbody>
                  {attention.slice(0, 6).map((c: Campaign) => (
                    <tr key={c.id} data-clickable onClick={() => router.push(`/attacks?campaign=${c.id}`)}>
                      <td><Risk value={c.risk_score} /></td>
                      <td>
                        <Link href={`/attacks?campaign=${c.id}`} onClick={(e) => e.stopPropagation()} className="font-mono text-[12px] font-medium hover:text-accent hover:underline">{c.actor_key.length > 22 ? c.actor_key.slice(0, 22) + "…" : c.actor_key}</Link>
                        <span className="ml-2 text-[11px] text-muted">{c.country_code} · AS{c.asn}</span>
                      </td>
                      <td><StageLadder reached={c.stages} highest={c.highest_stage} /></td>
                      <td><StageTag stage={c.highest_stage} /></td>
                      <td className="max-w-[220px] truncate text-[12px] text-fg-2" title={c.targets.join("\n")}>{c.targets[0]}{c.targets.length > 1 ? ` +${c.targets.length - 1}` : ""}</td>
                      <td className="tnum text-right">{fmtNum(c.event_count)}</td>
                      <td className={cn("tnum", c.possibly_successful ? "font-semibold text-crit" : "text-muted")}>{c.possibly_successful || "-"}</td>
                      <td className="text-[12px]">{c.assignee ?? <span className="text-muted">Unassigned</span>}</td>
                      <td className="text-[12px] text-fg-2">{relTime(c.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </>
        )}
      </section>

      {ov.error && !ov.data ? (
        <div className="panel mt-4"><ErrorState title="Analytics could not be loaded" error={ov.error} onRetry={ov.reload} /></div>
      ) : !ov.data ? (
        <div className="panel mt-4"><Loading label="Loading traffic analytics" /></div>
      ) : (
        <>
          <section aria-label="Key indicators" className="panel mt-4 grid grid-cols-2 divide-border md:grid-cols-4 md:divide-x [&>*]:px-4 [&>*]:py-3.5">
            <Stat label="Traffic now" value={`${fmtNum(ov.data.rps)} req/s`} sub={`${fmtCompact(ov.data.totalRequests)} requests in ${hours}h`} />
            <Stat label="Blocked requests" value={fmtNum(ov.data.blocked)} sub={`last ${hours}h`} />
            <Stat label="Block ratio" value={`${ov.data.blockRatio < 0.01 ? "<0.01" : ov.data.blockRatio.toFixed(2)}%`} sub="blocked / total" />
            <Stat label="Avg WAF latency" value={`${ov.data.avgLatencyMs.toFixed(1)} ms`} sub={<span className={ov.data.avgLatencyMs > 2 ? "text-warn" : undefined}>{ov.data.avgLatencyMs > 2 ? "above the 2 ms target" : "within the 2 ms target"}</span>} />
          </section>

          <div className={cn("mt-4 grid gap-4 xl:grid-cols-[1.4fr_1fr]", ov.loading && "opacity-60 transition-opacity")}>
            <section aria-labelledby="trend" className="panel min-w-0">
              <SectionTitle id="trend">Traffic vs attack trend</SectionTitle>
              <TrafficCharts data={ov.data.series} />
            </section>
            <section aria-labelledby="toprules" className="panel min-w-0">
              <SectionTitle id="toprules" aside={<span className="text-[12px] text-muted">events, {hours}h</span>}>Top 10 triggered rules</SectionTitle>
              {ov.data.topRules.length ? <TopRulesChart data={ov.data.topRules} onSelect={(id) => router.push(`/logs?rule=${id}`)} /> : <Empty title="No rules triggered in this range" />}
            </section>
          </div>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <section aria-labelledby="endpoints" className="panel min-w-0">
              <SectionTitle id="endpoints">Top targeted endpoints</SectionTitle>
              <TableWrap label="Top targeted endpoints">
                <table className="data-table">
                  <thead><tr><th>Endpoint</th><th className="text-right">Events</th></tr></thead>
                  <tbody>
                    {ov.data.topEndpoints.map((e) => (
                      <tr key={e.endpoint} data-clickable onClick={() => router.push(`/logs?host=${e.endpoint.split("/")[0]}&uri=${encodeURIComponent("/" + e.endpoint.split("/").slice(1).join("/"))}`)}>
                        <td className="max-w-[360px] truncate"><Mono>{e.endpoint}</Mono></td>
                        <td className="tnum text-right">{fmtNum(e.n)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </section>
            <section aria-labelledby="ips" className="panel min-w-0">
              <SectionTitle id="ips" aside={<Link href="/attacks?tab=geo" className="text-[12px] font-medium text-accent hover:underline">Geo map</Link>}>Top attacking IPs</SectionTitle>
              <TableWrap label="Top attacking IPs">
                <table className="data-table">
                  <thead><tr><th>Client IP</th><th>Country</th><th>ASN</th><th className="text-right">Events</th></tr></thead>
                  <tbody>
                    {ov.data.topIps.map((e) => (
                      <tr key={e.ip} data-clickable onClick={() => router.push(`/logs?ip=${e.ip}`)}>
                        <td><Mono>{e.ip}</Mono></td>
                        <td className="text-[12px]">{e.cc}</td>
                        <td className="text-[12px] text-fg-2">AS{e.asn}</td>
                        <td className="tnum text-right">{fmtNum(e.n)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </section>
          </div>
        </>
      )}
    </>
  );
}
