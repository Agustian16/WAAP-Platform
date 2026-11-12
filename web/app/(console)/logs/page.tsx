"use client";
// Module 3: High-speed Log Explorer (FR-3.1), Transaction Inspector (FR-3.2), One-click exception (FR-3.3).
import * as React from "react";
import Link from "next/link";
import { useSearchParams, useRouter } from "next/navigation";
import { X, Prohibit, ShieldSlash, Graph, CaretLeft, CaretRight } from "@phosphor-icons/react";
import { logs, policies, subscribeAttackStream, type LogQuery } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import type { Action, AuditLog } from "@/lib/types";
import { Button, Empty, ErrorState, Field, Input, Loading, PageHeader, Select, Sheet, Switch, TableWrap } from "@/components/ui";
import { ActionText, Mono, SeverityText } from "@/components/atoms";
import { BlockDialog, ExceptionDialog, type ExceptionSeed } from "@/components/response";
import { useSession } from "@/components/providers";
import { cn, fmtNum, fmtTime } from "@/lib/utils";

const RANGES: Record<string, number> = { "15m": 15 * 60e3, "1h": 3600e3, "24h": 86400e3, "7d": 7 * 86400e3, "30d": 30 * 86400e3 };
const PAGE = 50;
type Filters = { ip: string; host: string; uri: string; ruleId: string; action: Action | ""; status: string; range: string };
const LABEL: Record<keyof Filters, string> = { ip: "Client IP", host: "Target", uri: "URI", ruleId: "Rule ID", action: "Action", status: "Status", range: "Range" };

export default function Page() {
  return <React.Suspense fallback={<Loading label="Loading log explorer" />}><LogExplorer /></React.Suspense>;
}

function LogExplorer() {
  const sp = useSearchParams();
  const router = useRouter();
  const init: Filters = { ip: sp.get("ip") ?? "", host: sp.get("host") ?? "", uri: sp.get("uri") ?? "", ruleId: sp.get("rule") ?? "", action: (sp.get("action") as Action) ?? "", status: sp.get("status") ?? "", range: "24h" };
  if (sp.get("from")) { const age = Date.now() - Number(sp.get("from")); init.range = Object.keys(RANGES).find((k) => RANGES[k] >= age) ?? "30d"; }
  const [draft, setDraft] = React.useState<Filters>(init);
  const [f, setF] = React.useState<Filters>(init);
  const [page, setPage] = React.useState(0);
  const [live, setLive] = React.useState(true);
  const [fresh, setFresh] = React.useState<Set<string>>(new Set());
  const [openId, setOpenId] = React.useState<string | null>(sp.get("log"));
  const sites = useAsync(() => policies.sites(), []);
  const q: LogQuery = React.useMemo(() => ({ from: Date.now() - RANGES[f.range], ip: f.ip, host: f.host, uri: f.uri, ruleId: f.ruleId, action: f.action, status: f.status, limit: PAGE, offset: page * PAGE }), [f, page]);
  const res = useAsync(() => logs.query(q), [q]);

  React.useEffect(() => {
    const p = new URLSearchParams();
    if (f.ip) p.set("ip", f.ip); if (f.host) p.set("host", f.host); if (f.uri) p.set("uri", f.uri); if (f.ruleId) p.set("rule", f.ruleId);
    if (f.action) p.set("action", f.action); if (f.status) p.set("status", f.status); if (openId) p.set("log", openId);
    router.replace(`/logs${p.size ? `?${p}` : ""}`, { scroll: false });
  }, [f, openId, router]);

  // Live stream: prepend matching rows on page 1.
  React.useEffect(() => {
    if (!live || page !== 0) return;
    return subscribeAttackStream(({ log: l }) => {
      const ok = (!f.ip || l.client_ip.startsWith(f.ip)) && (!f.host || l.host === f.host) && (!f.uri || l.uri.includes(f.uri)) &&
        (!f.ruleId || l.matched_rule_ids.some((id) => String(id).startsWith(f.ruleId))) && (!f.action || l.action_taken === f.action) && (!f.status || String(l.response_status) === f.status);
      if (!ok) return;
      res.setData((d) => d && { ...d, rows: [l, ...d.rows].slice(0, PAGE), total: d.total + 1 });
      setFresh((s) => new Set(s).add(l.id));
    });
  }, [live, page, f, res.setData]); // eslint-disable-line react-hooks/exhaustive-deps

  const apply = (e?: React.FormEvent) => { e?.preventDefault(); setPage(0); setF({ ...draft, ip: draft.ip.trim(), uri: draft.uri.trim(), ruleId: draft.ruleId.trim(), status: draft.status.trim() }); };
  const clear = (k: keyof Filters) => { const n = { ...f, [k]: k === "range" ? "24h" : "" }; setDraft(n); setF(n); setPage(0); };
  const chips = (Object.keys(f) as (keyof Filters)[]).filter((k) => k !== "range" && f[k]);
  const total = res.data?.total ?? 0;
  const set = (k: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setDraft((d) => ({ ...d, [k]: e.target.value }));

  return (
    <>
      <PageHeader
        title="Log Explorer"
        description="Coraza audit logs from ClickHouse. Filter, inspect a transaction, and suppress a false positive from the same screen."
        actions={<label className="inline-flex items-center gap-2 text-[13px]" htmlFor="live-logs"><Switch id="live-logs" label="Live stream" checked={live} onCheckedChange={setLive} />Live stream {live ? (page === 0 ? "on" : "paused on page 2+") : "off"}</label>}
      />
      <form onSubmit={apply} className="panel mb-3 grid grid-cols-2 gap-3 p-3 md:grid-cols-4 xl:grid-cols-[repeat(7,minmax(0,1fr))_auto]" aria-label="Log filters">
        <Field label="Time range" htmlFor="l-range"><Select id="l-range" value={draft.range} onChange={(e) => { setDraft((d) => ({ ...d, range: e.target.value })); setF((x) => ({ ...x, range: e.target.value })); setPage(0); }}>{Object.keys(RANGES).map((r) => <option key={r} value={r}>Last {r}</option>)}</Select></Field>
        <Field label="Client IP" htmlFor="l-ip"><Input id="l-ip" value={draft.ip} onChange={set("ip")} placeholder="185.220." className="font-mono" /></Field>
        <Field label="Target host" htmlFor="l-host"><Select id="l-host" value={draft.host} onChange={set("host")}><option value="">All</option>{sites.data?.map((s) => <option key={s.id} value={s.domain_name}>{s.domain_name}</option>)}</Select></Field>
        <Field label="URI contains" htmlFor="l-uri"><Input id="l-uri" value={draft.uri} onChange={set("uri")} placeholder="/api/v1/login" className="font-mono" /></Field>
        <Field label="Rule ID" htmlFor="l-rule"><Input id="l-rule" inputMode="numeric" value={draft.ruleId} onChange={set("ruleId")} placeholder="942100" className="font-mono" /></Field>
        <Field label="Action" htmlFor="l-action"><Select id="l-action" value={draft.action} onChange={set("action")}><option value="">Any</option><option value="DENY">DENY</option><option value="LOG">LOG</option><option value="ALLOW">ALLOW</option></Select></Field>
        <Field label="HTTP status" htmlFor="l-status"><Input id="l-status" inputMode="numeric" value={draft.status} onChange={set("status")} placeholder="403" className="font-mono" /></Field>
        <div className="flex items-end"><Button type="submit" variant="primary" className="w-full">Search logs</Button></div>
      </form>

      <div className="mb-3 flex min-h-8 flex-wrap items-center gap-2">
        {chips.map((k) => (
          <span key={k} className="inline-flex h-7 items-center gap-1 rounded border border-border-strong bg-surface pl-2 text-[12px]">
            <span className="text-muted">{LABEL[k]}:</span><span className="font-mono">{f[k]}</span>
            <button type="button" onClick={() => clear(k)} aria-label={`Remove ${LABEL[k]} filter`} className="flex h-7 w-7 items-center justify-center rounded-r text-muted hover:bg-surface-2 hover:text-fg"><X size={12} aria-hidden /></button>
          </span>
        ))}
        <span className="ml-auto text-[12px] text-fg-2" aria-live="polite">
          {res.data ? <><span className="tnum font-medium text-fg">{fmtNum(total)}</span> matches · query {res.data.tookMs} ms</> : null}
        </span>
      </div>

      <div className="panel">
        {res.error && !res.data ? <ErrorState title="Logs could not be queried" error={res.error} onRetry={res.reload} /> : !res.data ? <Loading label="Querying ClickHouse" /> : res.data.rows.length === 0 ? (
          <Empty title="No logs match these filters" body={chips.length ? "Remove a filter chip or widen the time range." : "Nothing was logged in this range."} action={chips.length ? <Button size="sm" onClick={() => { const n = { ...f, ip: "", host: "", uri: "", ruleId: "", action: "" as const, status: "" }; setDraft(n); setF(n); }}>Clear all filters</Button> : undefined} />
        ) : (
          <>
            <TableWrap label="Audit log results" className={cn(res.loading && "opacity-60")}>
              <table className="data-table">
                <thead><tr><th>Timestamp</th><th>Client IP</th><th>Method</th><th>Target</th><th>URI path</th><th>Rule ID</th><th>Severity</th><th>Action</th></tr></thead>
                <tbody>
                  {res.data.rows.map((l) => (
                    <tr key={l.id} data-clickable data-selected={openId === l.id} onClick={() => setOpenId(l.id)} className={fresh.has(l.id) ? "row-new" : undefined}>
                      <td className="tnum font-mono text-[12px] text-fg-2">{fmtTime(l.timestamp)}</td>
                      <td><Mono>{l.client_ip}</Mono> <span className="text-[11px] text-muted">{l.country_code}</span></td>
                      <td><Mono>{l.http_method}</Mono></td>
                      <td className="text-[12px] text-fg-2">{l.host}</td>
                      <td className="max-w-[280px] truncate"><button className="max-w-full truncate text-left font-mono text-[12px] hover:text-accent hover:underline" onClick={(e) => { e.stopPropagation(); setOpenId(l.id); }} title={l.uri}>{l.uri}</button></td>
                      <td><Mono>{l.matched_rule_ids[0]}</Mono>{l.matched_rule_ids.length > 1 ? <span className="text-[11px] text-muted"> +{l.matched_rule_ids.length - 1}</span> : null}</td>
                      <td><SeverityText s={l.severity} /></td>
                      <td><ActionText a={l.action_taken} status={l.response_status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
            <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2 text-[12px] text-fg-2">
              <span>Rows {fmtNum(page * PAGE + 1)}-{fmtNum(Math.min(total, (page + 1) * PAGE))} of {fmtNum(total)}</span>
              <div className="flex gap-1">
                <Button size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}><CaretLeft size={14} aria-hidden />Newer</Button>
                <Button size="sm" disabled={(page + 1) * PAGE >= total} onClick={() => setPage((p) => p + 1)}>Older<CaretRight size={14} aria-hidden /></Button>
              </div>
            </div>
          </>
        )}
      </div>
      <LogDetail id={openId} onClose={() => setOpenId(null)} />
    </>
  );
}

function LogDetail({ id, onClose }: { id: string | null; onClose: () => void }) {
  const s = useSession();
  const d = useAsync(() => (id ? logs.get(id) : Promise.resolve(null)), [id]);
  const [exc, setExc] = React.useState<ExceptionSeed | null>(null);
  const [block, setBlock] = React.useState(false);
  const l = d.data as AuditLog | null | undefined;
  const path = l?.uri.split("?")[0] ?? "";
  return (
    <Sheet open={!!id} onOpenChange={(v) => !v && onClose()} title={l ? `${l.http_method} ${path}` : "Transaction"} subtitle={l ? `Log ${l.id} · tx ${l.transaction_id} · ${fmtTime(l.timestamp)}` : undefined}
      footer={l && s.can("respond") ? (
        <>
          <Button variant="primary" onClick={() => setExc({ host: l.host, ruleId: l.matched_rule_ids[0], path, parameter: l.matched_vars[0]?.startsWith("ARGS") ? l.matched_vars[0] : null })}><ShieldSlash size={16} aria-hidden />Create exception for {path.length > 24 ? "this endpoint" : path}</Button>
          <Button variant="danger" onClick={() => setBlock(true)}><Prohibit size={16} aria-hidden />Add IP to blocklist</Button>
        </>
      ) : undefined}>
      {d.error ? <ErrorState title="Transaction could not be loaded" error={d.error} onRetry={d.reload} /> : !l ? <Loading label="Loading transaction" /> : (
        <div className="flex flex-col">
          <dl className="grid grid-cols-[120px_1fr] gap-x-4 gap-y-2 border-b border-border px-5 py-4 text-[13px]">
            <dt className="text-muted">Client IP</dt><dd><Mono className="text-[13px]">{l.client_ip}:{l.client_port}</Mono> <span className="text-fg-2">(Country: {l.country_code} / AS{l.asn})</span></dd>
            <dt className="text-muted">Target</dt><dd className="break-all font-mono text-[12px]">{l.host}{l.uri}</dd>
            <dt className="text-muted">Action taken</dt><dd><ActionText a={l.action_taken} status={l.response_status} /> {l.action_taken === "LOG" && l.response_status < 300 ? <span className="ml-1 text-[12px] font-semibold text-crit">payload detected and the request succeeded</span> : null}</dd>
            <dt className="text-muted">WAF latency</dt><dd className="tnum">{(l.latency_us / 1000).toFixed(2)} ms</dd>
            {l.campaign_id ? <><dt className="text-muted">Campaign</dt><dd><Link href={`/attacks?campaign=${l.campaign_id}`} className="inline-flex items-center gap-1 font-mono text-[12px] text-accent hover:underline"><Graph size={14} aria-hidden />{l.campaign_id}</Link></dd></> : null}
          </dl>
          <section className="border-b border-border px-5 py-4">
            <h3 className="mb-2 text-[12px] font-semibold text-fg-2">Matched rules</h3>
            <ul className="flex flex-col gap-3">
              {l.matched_rule_ids.map((rid, i) => (
                <li key={rid} className="rounded border border-border p-3">
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1"><Mono className="text-[13px] font-semibold">{rid}</Mono><SeverityText s={i === 0 ? l.severity : "NOTICE"} /></div>
                  <p className="mt-1 text-[13px]">{l.matched_messages[i]}</p>
                  {l.matched_vars[i] ? (
                    <p className="mt-2 break-all font-mono text-[12px]"><span className="text-muted">Matched var </span>{l.matched_vars[i]} <span className="text-muted">=</span> <span className="rounded bg-crit/10 px-1 text-crit">{l.matched_data[i]}</span></p>
                  ) : null}
                  {s.can("respond") && rid !== 949110 ? (
                    <Button size="sm" variant="ghost" className="-ml-2 mt-1" onClick={() => setExc({ host: l.host, ruleId: rid, path, parameter: l.matched_vars[i]?.startsWith("ARGS") ? l.matched_vars[i] : null })}>Disable rule {rid} for this endpoint</Button>
                  ) : null}
                </li>
              ))}
            </ul>
          </section>
          <section className="border-b border-border px-5 py-4">
            <h3 className="mb-2 text-[12px] font-semibold text-fg-2">Request headers</h3>
            <dl className="grid grid-cols-[minmax(0,140px)_1fr] gap-x-3 gap-y-1 font-mono text-[12px]">
              {Object.entries(l.request_headers).map(([k, v]) => <React.Fragment key={k}><dt className="truncate text-muted">{k}</dt><dd className={cn("break-all", v.includes("[masked]") && "text-muted")}>{v}</dd></React.Fragment>)}
            </dl>
            <p className="mt-2 text-[11px] text-muted">Authorization, session cookies and password fields are masked before storage (NFR-2.3).</p>
          </section>
          <section className="px-5 py-4">
            <h3 className="mb-2 text-[12px] font-semibold text-fg-2">Request body</h3>
            {l.request_body ? <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded border border-border bg-surface-2 p-3 font-mono text-[12px]">{l.request_body}</pre> : <p className="text-[13px] text-muted">No body ({l.http_method} request).</p>}
          </section>
        </div>
      )}
      {l ? <BlockDialog open={block} onOpenChange={setBlock} initial={l.client_ip} context={`Rule ${l.matched_rule_ids[0]} on ${l.host}${path}`} /> : null}
      <ExceptionDialog open={!!exc} onOpenChange={(v) => !v && setExc(null)} seed={exc} />
    </Sheet>
  );
}
