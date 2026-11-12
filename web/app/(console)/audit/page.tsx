"use client";
// FR-5.2: immutable audit trail of configuration changes (who, when, action, source IP, target nodes).
import * as React from "react";
import { DownloadSimple } from "@phosphor-icons/react";
import { admin } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Button, Empty, ErrorState, Field, Input, Loading, PageHeader, Select, TableWrap } from "@/components/ui";
import { Mono } from "@/components/atoms";
import { download, fmtTime, relTime } from "@/lib/utils";

export default function AuditPage() {
  const q = useAsync(() => admin.trail(), []);
  const [text, setText] = React.useState("");
  const [actor, setActor] = React.useState("");
  const rows = (q.data ?? []).filter((e) => (!actor || e.actor === actor) && (!text || `${e.action} ${e.target}`.toLowerCase().includes(text.toLowerCase())));
  const actors = [...new Set((q.data ?? []).map((e) => e.actor))];
  const csv = () => download(`coraza-audit-${new Date().toISOString().slice(0, 10)}.csv`, ["at,actor,role,action,target,source_ip,target_nodes", ...rows.map((e) => [e.at, e.actor, e.role, e.action, e.target, e.source_ip, e.target_nodes].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))].join("\n"), "text/csv");
  return (
    <>
      <PageHeader title="Audit Trail" description="Every configuration change, append-only in PostgreSQL. Entries cannot be edited or deleted from the console."
        actions={<Button onClick={csv} disabled={!rows.length}><DownloadSimple size={16} aria-hidden />Export CSV</Button>} />
      <div className="panel">
        <div className="flex flex-wrap items-end gap-3 border-b border-border p-3">
          <Field label="Search action or target" htmlFor="a-q" className="w-full sm:w-72"><Input id="a-q" value={text} onChange={(e) => setText(e.target.value)} placeholder="942100, Policy deployed" /></Field>
          <Field label="Actor" htmlFor="a-actor"><Select id="a-actor" value={actor} onChange={(e) => setActor(e.target.value)}><option value="">Everyone</option>{actors.map((a) => <option key={a}>{a}</option>)}</Select></Field>
          <span className="ml-auto text-[12px] text-fg-2">{rows.length} entries</span>
        </div>
        {q.error && !q.data ? <ErrorState title="Audit trail could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data ? <Loading label="Loading audit trail" /> : rows.length === 0 ? <Empty title="No entries match" body="Clear the search or actor filter." /> : (
          <TableWrap label="Audit trail">
            <table className="data-table">
              <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Source IP</th><th>Target nodes</th></tr></thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="text-[12px]" title={fmtTime(e.at)}><span className="tnum font-mono text-fg-2">{fmtTime(e.at)}</span> <span className="text-muted">({relTime(e.at)})</span></td>
                    <td className="text-[12px]"><span className="font-medium">{e.actor}</span> <span className="text-muted">{e.role}</span></td>
                    <td className="text-[13px] font-medium">{e.action}</td>
                    <td className="max-w-[360px] truncate font-mono text-[12px]" title={e.target}>{e.target}</td>
                    <td><Mono className="text-fg-2">{e.source_ip}</Mono></td>
                    <td className="text-[12px] text-fg-2">{e.target_nodes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </div>
    </>
  );
}
