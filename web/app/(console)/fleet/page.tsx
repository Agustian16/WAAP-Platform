"use client";
// Module 1: fleet registry (FR-1.1), health & performance (FR-1.2), config sync status (FR-1.3).
import * as React from "react";
import { Plus, Copy } from "@phosphor-icons/react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ReferenceLine } from "recharts";
import { fleet, policies } from "@/lib/api";
import { useAsync, useInterval } from "@/lib/hooks";
import type { EdgeNode } from "@/lib/types";
import { Button, Dialog, Empty, ErrorState, Field, Input, Loading, PageHeader, Sheet, TableWrap } from "@/components/ui";
import { Mono, NodeStatusText, Stat } from "@/components/atoms";
import { TipBox, axis } from "@/components/charts";
import { useSession, useToast } from "@/components/providers";
import { cn, fmtClock, fmtNum, fmtTime, relTime } from "@/lib/utils";

export default function FleetPage() {
  const s = useSession();
  const q = useAsync(() => fleet.list(), []);
  const ver = useAsync(() => fleet.configVersion(), []);
  const [open, setOpen] = React.useState<string | null>(null);
  const [reg, setReg] = React.useState(false);
  useInterval(() => { q.reload(); ver.reload(); }, 15000); // heartbeat refresh
  const nodes = q.data ?? [];
  const online = nodes.filter((n) => n.status !== "OFFLINE");
  const node = nodes.find((n) => n.id === open) ?? null;
  return (
    <>
      <PageHeader title="Fleet" description="Coraza edge nodes registered over gRPC (mTLS). Nodes keep enforcing their cached config if the control plane is unreachable."
        actions={s.can("admin") ? <Button variant="primary" onClick={() => setReg(true)}><Plus size={16} aria-hidden />Register node</Button> : undefined} />
      {q.error && !q.data ? <div className="panel"><ErrorState title="Fleet status could not be loaded" error={q.error} onRetry={q.reload} /></div> : !q.data ? <div className="panel"><Loading label="Loading fleet" /></div> : nodes.length === 0 ? (
        <div className="panel"><Empty title="No nodes registered" body="Install the Coraza agent next to Caddy, Envoy or HAProxy SPOA and enroll it with a token." action={s.can("admin") ? <Button variant="primary" onClick={() => setReg(true)}>Register the first node</Button> : undefined} /></div>
      ) : (
        <>
          <section aria-label="Fleet summary" className="panel mb-4 grid grid-cols-2 md:grid-cols-4 md:divide-x divide-border [&>*]:px-4 [&>*]:py-3.5">
            <Stat label="Nodes online" value={`${online.length} of ${nodes.length}`} sub={nodes.length - online.length ? <span className="text-crit">{nodes.length - online.length} unreachable</span> : "all reporting"} />
            <Stat label="Fleet throughput" value={`${fmtNum(online.reduce((a, n) => a + n.rps, 0))} req/s`} />
            <Stat label="Avg WAF latency" value={`${(online.reduce((a, n) => a + n.latency_ms, 0) / Math.max(online.length, 1)).toFixed(1)} ms`} sub={`target < 2 ms · worst ${Math.max(...online.map((n) => n.latency_ms)).toFixed(1)} ms`} />
            <Stat label="Config version" value={ver.data ? `v${ver.data}` : "..."} sub={`${nodes.filter((n) => n.sync_status === "IN_SYNC").length} in sync · ${nodes.filter((n) => n.sync_status === "PENDING_UPDATE").length} pending`} />
          </section>
          <div className="panel">
            <TableWrap label="Edge nodes">
              <table className="data-table">
                <thead><tr><th>Node name</th><th>Hostname</th><th>Proxy</th><th>Status</th><th className="text-right">Latency</th><th className="text-right">RPS</th><th className="text-right">CPU</th><th className="text-right">Memory</th><th>CRS version</th><th>Sync status</th><th>Heartbeat</th></tr></thead>
                <tbody>
                  {nodes.map((n) => (
                    <tr key={n.id} data-clickable data-selected={open === n.id} onClick={() => setOpen(n.id)}>
                      <td><button className="font-mono text-[12px] font-medium hover:text-accent hover:underline" onClick={(e) => { e.stopPropagation(); setOpen(n.id); }}>{n.node_name}</button></td>
                      <td><Mono className="text-fg-2">{n.hostname}</Mono></td>
                      <td className="text-[12px]">{n.proxy}</td>
                      <td><NodeStatusText s={n.status} /></td>
                      <td className={cn("tnum text-right", n.latency_ms > 2 && "font-medium text-warn")}>{n.status === "OFFLINE" ? "-" : `${n.latency_ms.toFixed(1)} ms`}</td>
                      <td className="tnum text-right">{n.status === "OFFLINE" ? "-" : fmtNum(n.rps)}</td>
                      <td className={cn("tnum text-right", n.cpu > 80 && "font-medium text-warn")}>{n.status === "OFFLINE" ? "-" : `${n.cpu}%`}</td>
                      <td className="tnum text-right">{n.status === "OFFLINE" ? "-" : `${n.memory}%`}</td>
                      <td className={cn("text-[12px]", n.crs_version !== "CRS v4.0.0" && "text-warn")}>{n.crs_version}</td>
                      <td className={cn("font-mono text-[12px]", n.sync_status === "PENDING_UPDATE" ? "text-warn" : "text-fg-2")}>{n.sync_status === "IN_SYNC" ? `IN_SYNC (v${n.current_config_version})` : `PENDING_UPDATE (v${n.current_config_version})`}</td>
                      <td className={cn("text-[12px]", n.status === "OFFLINE" ? "text-crit" : "text-fg-2")} title={fmtTime(n.last_heartbeat)}>{relTime(n.last_heartbeat)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </div>
        </>
      )}
      <NodeSheet node={node} onClose={() => setOpen(null)} />
      <RegisterDialog open={reg} onOpenChange={setReg} onDone={q.reload} />
    </>
  );
}

function MiniChart({ data, k, unit, target, label }: { data: EdgeNode["history"]; k: "rps" | "latency" | "cpu"; unit: string; target?: number; label: string }) {
  return (
    <div className="viz">
      <p className="mb-1 text-[12px] text-muted">{label}</p>
      <div className="h-[110px]">
        <ResponsiveContainer>
          <LineChart data={data} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis dataKey="t" {...axis} tickFormatter={fmtClock} minTickGap={50} />
            <YAxis {...axis} width={40} axisLine={false} />
            {target ? <ReferenceLine y={target} stroke="var(--c-warn)" strokeDasharray="4 3" /> : null}
            {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
            <Tooltip content={({ active, payload }: any) => active && payload?.length ? <TipBox title={fmtClock(payload[0].payload.t)} rows={[{ label, value: `${payload[0].value}${unit}` }]} /> : null} />
            <Line type="monotone" dataKey={k} stroke="var(--seq-4)" strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function NodeSheet({ node, onClose }: { node: EdgeNode | null; onClose: () => void }) {
  const sites = useAsync(() => policies.sites(), []);
  return (
    <Sheet open={!!node} onOpenChange={(v) => !v && onClose()} title={node?.node_name ?? ""} subtitle={node ? `${node.proxy} · ${node.version} · ${node.region}` : undefined}>
      {node ? (
        <div className="flex flex-col gap-5 px-5 py-4">
          <dl className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2 text-[13px]">
            <dt className="text-muted">Status</dt><dd><NodeStatusText s={node.status} /></dd>
            <dt className="text-muted">IP address</dt><dd><Mono className="text-[13px]">{node.ip_address}</Mono></dd>
            <dt className="text-muted">Node ID</dt><dd><Mono>{node.id}</Mono></dd>
            <dt className="text-muted">Config</dt><dd className={node.sync_status === "PENDING_UPDATE" ? "text-warn" : undefined}>v{node.current_config_version} · {node.sync_status === "IN_SYNC" ? "in sync" : "pending update"}</dd>
            <dt className="text-muted">Last heartbeat</dt><dd>{fmtTime(node.last_heartbeat)} ({relTime(node.last_heartbeat)})</dd>
            <dt className="text-muted">Transport</dt><dd>gRPC stream, mTLS (x509)</dd>
            <dt className="text-muted">Serves</dt><dd>{sites.data?.map((x) => x.domain_name).join(", ") ?? "..."}</dd>
          </dl>
          {node.status === "OFFLINE" ? <p className="rounded border border-crit/40 bg-crit/5 px-3 py-2 text-[13px]">No heartbeat for {relTime(node.last_heartbeat).replace(" ago", "")}. The node keeps inspecting traffic with config v{node.current_config_version} until it reconnects (NFR-3.1).</p> : null}
          <MiniChart data={node.history} k="rps" unit=" req/s" label="Requests per second, last hour" />
          <MiniChart data={node.history} k="latency" unit=" ms" target={2} label="WAF latency (ms), 2 ms target dashed" />
          <MiniChart data={node.history} k="cpu" unit="%" label="CPU usage (%)" />
        </div>
      ) : null}
    </Sheet>
  );
}

function RegisterDialog({ open, onOpenChange, onDone }: { open: boolean; onOpenChange: (v: boolean) => void; onDone: () => void }) {
  const toast = useToast();
  const [name, setName] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);
  const [res, setRes] = React.useState<{ token: string; command: string } | null>(null);
  React.useEffect(() => { if (!open) { setName(""); setErr(null); setRes(null); } }, [open]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    try { setRes(await fleet.register(name.trim())); onDone(); } catch (x) { setErr((x as Error).message); }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Register node" description="Issue a one-time enrollment token. The agent exchanges it for an mTLS client certificate and then appears in this list."
      footer={res ? <Button variant="primary" onClick={() => onOpenChange(false)}>Done</Button> : <><Button onClick={() => onOpenChange(false)}>Cancel</Button><Button type="submit" form="reg-form" variant="primary">Create token</Button></>}>
      {res ? (
        <div className="flex flex-col gap-2">
          <p className="text-[13px]">Run this on the node within 24 hours. The token works once.</p>
          <pre className="overflow-x-auto rounded border border-border bg-surface-2 p-3 font-mono text-[12px]">{res.command}</pre>
          <Button size="sm" className="self-start" onClick={() => { navigator.clipboard?.writeText(res.command.replace(/\\\n\s*/g, "")); toast({ tone: "ok", title: "Command copied" }); }}><Copy size={14} aria-hidden />Copy command</Button>
        </div>
      ) : (
        <form id="reg-form" onSubmit={submit}>
          <Field label="Node name" htmlFor="reg-name" error={err} hint="Lowercase letters, digits and dashes, e.g. edge-sg-caddy-03">
            <Input id="reg-name" value={name} onChange={(e) => setName(e.target.value)} className="font-mono" autoComplete="off" required />
          </Field>
        </form>
      )}
    </Dialog>
  );
}
