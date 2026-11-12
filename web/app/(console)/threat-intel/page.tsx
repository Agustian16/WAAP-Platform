"use client";
// FR-4.2: central IP allowlist/blocklist with CIDR support and URL-based threat feed import.
import * as React from "react";
import { Plus, Trash, ArrowsClockwise } from "@phosphor-icons/react";
import { ipLists } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import type { IpListEntry } from "@/lib/types";
import { Button, Dialog, Empty, ErrorState, Field, Input, Loading, PageHeader, Select, Tabs, TabsContent, TabsList, TabsTrigger, TableWrap } from "@/components/ui";
import { Mono } from "@/components/atoms";
import { useSession, useToast } from "@/components/providers";
import { cn, fmtNum, fmtTime, parseCidr, relTime } from "@/lib/utils";

export default function ThreatIntelPage() {
  const list = useAsync(() => ipLists.list(), []);
  const feeds = useAsync(() => ipLists.feeds(), []);
  return (
    <>
      <PageHeader title="IP Reputation" description="Blocklist and allowlist entries apply to every site and node. Allowlist wins when both match." />
      <Tabs defaultValue="block" className="panel">
        <TabsList className="px-2">
          <TabsTrigger value="block">Blocklist{list.data ? ` (${list.data.filter((e) => e.list === "block").length})` : ""}</TabsTrigger>
          <TabsTrigger value="allow">Allowlist{list.data ? ` (${list.data.filter((e) => e.list === "allow").length})` : ""}</TabsTrigger>
          <TabsTrigger value="feeds">Threat feeds{feeds.data ? ` (${feeds.data.length})` : ""}</TabsTrigger>
        </TabsList>
        <TabsContent value="block" className="outline-none"><ListTab kind="block" q={list} /></TabsContent>
        <TabsContent value="allow" className="outline-none"><ListTab kind="allow" q={list} /></TabsContent>
        <TabsContent value="feeds" className="outline-none"><FeedsTab q={feeds} onPulled={list.reload} /></TabsContent>
      </Tabs>
    </>
  );
}

function ListTab({ kind, q }: { kind: "block" | "allow"; q: ReturnType<typeof useAsync<IpListEntry[]>> }) {
  const s = useSession();
  const toast = useToast();
  const [cidr, setCidr] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [ttl, setTtl] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);
  const [filter, setFilter] = React.useState("");
  const parsed = parseCidr(cidr);
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!parsed) { setErr("Enter an IPv4 address or CIDR, for example 192.168.1.0/24"); return; }
    try {
      await ipLists.add({ cidr, list: kind, reason, ttlHours: ttl ? Number(ttl) : null });
      toast({ tone: "ok", title: `${parsed.normalized} added to the ${kind}list` });
      setCidr(""); setReason(""); setErr(null); q.reload();
    } catch (x) { setErr((x as Error).message); }
  };
  const rows = (q.data ?? []).filter((e) => e.list === kind && (!filter || e.cidr.includes(filter) || e.reason.toLowerCase().includes(filter.toLowerCase())));
  return (
    <div>
      {s.can("respond") ? (
        <form onSubmit={add} className="grid gap-3 border-b border-border p-3 sm:grid-cols-[minmax(0,200px)_minmax(0,1fr)_160px_auto]" aria-label={`Add to ${kind}list`}>
          <Field label="IP or CIDR" htmlFor={`${kind}-cidr`} error={cidr && !parsed ? "Not a valid IPv4 address or CIDR" : err} hint={parsed && parsed.normalized !== cidr.trim() ? `Stored as ${parsed.normalized}` : undefined}>
            <Input id={`${kind}-cidr`} value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" className="font-mono" />
          </Field>
          <Field label="Reason" htmlFor={`${kind}-reason`}><Input id={`${kind}-reason`} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={kind === "block" ? "Credential stuffing source" : "Partner health checks"} /></Field>
          <Field label="Expires" htmlFor={`${kind}-ttl`}><Select id={`${kind}-ttl`} value={ttl} onChange={(e) => setTtl(e.target.value)}><option value="">Never</option><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></Select></Field>
          <div className="flex items-start sm:pt-[22px]"><Button type="submit" variant={kind === "block" ? "danger" : "primary"} disabled={!parsed}><Plus size={16} aria-hidden />Add to {kind}list</Button></div>
        </form>
      ) : null}
      <div className="flex items-center gap-2 px-3 py-2">
        <label htmlFor={`${kind}-filter`} className="sr-only">Filter entries</label>
        <Input id={`${kind}-filter`} value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by CIDR or reason" className="max-w-xs" />
      </div>
      {q.error && !q.data ? <ErrorState title="Lists could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data ? <Loading label="Loading entries" /> : rows.length === 0 ? (
        <Empty title={filter ? "No entries match" : `The ${kind}list is empty`} body={filter ? "Clear the filter to see all entries." : kind === "block" ? "Block sources from here, from a log entry or from the attack graph." : "Add trusted scanners or partners so their traffic is never blocked."} />
      ) : (
        <TableWrap label={`${kind}list entries`}>
          <table className="data-table">
            <thead><tr><th>CIDR</th><th>Source</th><th>Reason</th><th>Expires</th><th>Added</th>{s.can("respond") ? <th><span className="sr-only">Actions</span></th> : null}</tr></thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.id}>
                  <td><Mono>{e.cidr}</Mono></td>
                  <td className="text-[12px] text-fg-2">{e.source}</td>
                  <td className="max-w-[320px] truncate text-[12px]" title={e.reason}>{e.reason}</td>
                  <td className={cn("text-[12px]", e.expires_at ? "text-fg" : "text-muted")} title={e.expires_at ? fmtTime(e.expires_at) : undefined}>{e.expires_at ? relTime(e.expires_at) : "never"}</td>
                  <td className="text-[12px] text-fg-2">{e.created_by}, {relTime(e.created_at)}</td>
                  {s.can("respond") ? <td className="text-right"><Button size="icon" variant="ghost" aria-label={`Remove ${e.cidr}`} onClick={async () => {
                    try { await ipLists.remove(e.id); q.reload(); toast({ tone: "ok", title: `${e.cidr} removed` }); } catch (x) { toast({ tone: "error", title: "Remove failed", body: (x as Error).message }); }
                  }}><Trash size={16} aria-hidden /></Button></td> : null}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </div>
  );
}

function FeedsTab({ q, onPulled }: { q: ReturnType<typeof useAsync<Awaited<ReturnType<typeof ipLists.feeds>>>>; onPulled: () => void }) {
  const s = useSession();
  const toast = useToast();
  const [open, setOpen] = React.useState(false);
  const [f, setF] = React.useState({ name: "", url: "", format: "text" as "text" | "csv", interval_minutes: 60 });
  const [err, setErr] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await ipLists.addFeed(f); toast({ tone: "ok", title: `Feed ${f.name} added`, body: "Pull it now or wait for the schedule." }); setOpen(false); setF({ name: "", url: "", format: "text", interval_minutes: 60 }); q.reload(); }
    catch (x) { setErr((x as Error).message); }
  };
  return (
    <div>
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
        <p className="text-[12px] text-fg-2">Feeds are fetched by the control plane on their interval. Plain text (one IP or CIDR per line) and CSV (first column) are supported.</p>
        {s.can("admin") ? <Button size="sm" onClick={() => { setErr(null); setOpen(true); }}><Plus size={14} aria-hidden />Add feed</Button> : null}
      </div>
      {q.error && !q.data ? <ErrorState title="Feeds could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data ? <Loading label="Loading feeds" /> : q.data.length === 0 ? <Empty title="No threat feeds" body="Add a feed URL to import blocklist entries automatically." /> : (
        <TableWrap label="Threat feeds">
          <table className="data-table">
            <thead><tr><th>Name</th><th>URL</th><th>Format</th><th>Every</th><th>Last pull</th><th className="text-right">Entries</th><th>Status</th>{s.can("admin") ? <th><span className="sr-only">Actions</span></th> : null}</tr></thead>
            <tbody>
              {q.data.map((x) => (
                <tr key={x.id}>
                  <td className="font-medium">{x.name}</td>
                  <td className="max-w-[260px] truncate font-mono text-[12px] text-fg-2" title={x.url}>{x.url}</td>
                  <td className="text-[12px] uppercase">{x.format}</td>
                  <td className="text-[12px]">{x.interval_minutes >= 60 ? `${x.interval_minutes / 60}h` : `${x.interval_minutes}m`}</td>
                  <td className="text-[12px] text-fg-2">{x.last_pulled ? relTime(x.last_pulled) : "never"}</td>
                  <td className="tnum text-right">{fmtNum(x.entries)}</td>
                  <td className={cn("text-[12px]", x.status === "ERROR" ? "font-medium text-crit" : x.status === "OK" ? "text-fg" : "text-muted")} title={x.error}>{x.status === "ERROR" ? `Error: ${x.error}` : x.status === "OK" ? "OK" : "Not pulled yet"}</td>
                  {s.can("admin") ? (
                    <td className="whitespace-nowrap text-right">
                      <Button size="sm" variant="ghost" disabled={busy === x.id} onClick={async () => {
                        setBusy(x.id);
                        try { const r = await ipLists.pullFeed(x.id); q.setData((l) => l?.map((y) => (y.id === r.id ? r : y))); onPulled(); toast(r.status === "OK" ? { tone: "ok", title: `${r.name}: ${fmtNum(r.entries)} entries` } : { tone: "error", title: `${r.name} failed`, body: r.error }); }
                        catch (e) { toast({ tone: "error", title: "Pull failed", body: (e as Error).message }); } finally { setBusy(null); }
                      }}><ArrowsClockwise size={14} aria-hidden className={busy === x.id ? "animate-spin" : undefined} />Pull now</Button>
                      <Button size="icon" variant="ghost" aria-label={`Remove feed ${x.name}`} onClick={async () => { try { await ipLists.removeFeed(x.id); q.reload(); } catch (e) { toast({ tone: "error", title: "Remove failed", body: (e as Error).message }); } }}><Trash size={16} aria-hidden /></Button>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <Dialog open={open} onOpenChange={setOpen} title="Add threat feed" description="The control plane fetches the URL on schedule and merges entries into the blocklist with the feed as source."
        footer={<><Button onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="feed-form" variant="primary">Add feed</Button></>}>
        <form id="feed-form" onSubmit={add} className="flex flex-col gap-4">
          <Field label="Name" htmlFor="fd-name"><Input id="fd-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required /></Field>
          <Field label="Feed URL" htmlFor="fd-url" error={err}><Input id="fd-url" type="url" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://feeds.example.net/list.txt" className="font-mono" required /></Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Format" htmlFor="fd-fmt"><Select id="fd-fmt" value={f.format} onChange={(e) => setF({ ...f, format: e.target.value as "text" | "csv" })}><option value="text">Plain text</option><option value="csv">CSV</option></Select></Field>
            <Field label="Pull every" htmlFor="fd-int"><Select id="fd-int" value={f.interval_minutes} onChange={(e) => setF({ ...f, interval_minutes: Number(e.target.value) })}><option value={15}>15 minutes</option><option value={60}>1 hour</option><option value={360}>6 hours</option><option value={1440}>24 hours</option></Select></Field>
          </div>
        </form>
      </Dialog>
    </div>
  );
}
