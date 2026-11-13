"use client";
// Module 2: OWASP CRS v4 switches (FR-2.1), Paranoia Level & anomaly thresholds (FR-2.2), exceptions (FR-3.3 output).
import * as React from "react";
import { CloudArrowUp, Plus, Trash } from "@phosphor-icons/react";
import { exceptionsApi, fleet, policies } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import type { Site } from "@/lib/types";
import { Button, Dialog, Empty, ErrorState, Field, Input, Loading, PageHeader, SectionTitle, Switch, TableWrap } from "@/components/ui";
import { Mono } from "@/components/atoms";
import { ExceptionDialog, type ExceptionSeed } from "@/components/response";
import { useSession, useToast } from "@/components/providers";
import { cn, fmtTime, relTime } from "@/lib/utils";

const CRS: { id: string; name: string; desc: string }[] = [
  { id: "913", name: "Scanner detection", desc: "Security scanner user agents and probes" },
  { id: "920", name: "Protocol enforcement", desc: "Malformed requests, invalid encodings, missing headers" },
  { id: "921", name: "Protocol attack", desc: "Request smuggling, response splitting, header injection" },
  { id: "930", name: "Local file inclusion", desc: "Path traversal and OS file access" },
  { id: "931", name: "Remote file inclusion", desc: "URL parameters pointing to remote payloads" },
  { id: "932", name: "Remote code execution", desc: "Unix and Windows shell command injection" },
  { id: "933", name: "PHP injection", desc: "PHP functions, wrappers and object injection" },
  { id: "941", name: "Cross-site scripting", desc: "Script injection via libinjection and patterns" },
  { id: "942", name: "SQL injection", desc: "SQLi via libinjection and database-specific patterns" },
  { id: "944", name: "Java injection", desc: "Deserialization, Log4Shell, Java process spawn" },
  { id: "950", name: "Data leakage", desc: "Outbound SQL errors, stack traces, directory listings" },
  { id: "955", name: "Web shells", desc: "Known web shell signatures in responses" },
];
const PL = [
  "Baseline. Lowest false-positive rate; right for most sites.",
  "Adds rules for less common attacks. Expect some tuning on rich forms.",
  "Specialized rules for high-value apps. Plan a tuning window.",
  "Maximum coverage. Many false positives; use behind strict review.",
];

export default function PoliciesPage() {
  const s = useSession();
  const toast = useToast();
  const sites = useAsync(() => policies.sites(), []);
  const nodes = useAsync(() => fleet.list(), []);
  const exc = useAsync(() => exceptionsApi.list(), []);
  const [siteId, setSiteId] = React.useState<string | null>(null);
  const [draft, setDraft] = React.useState<Site | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [deploying, setDeploying] = React.useState(false);
  const [confirmDeploy, setConfirmDeploy] = React.useState(false);
  const [newExc, setNewExc] = React.useState<ExceptionSeed | null>(null);
  const [addSite, setAddSite] = React.useState(false);
  const site = sites.data?.find((x) => x.id === (siteId ?? sites.data?.[0]?.id));
  React.useEffect(() => { if (site) setDraft(structuredClone(site)); }, [site]);
  const dirty = !!draft && !!site && JSON.stringify(draft) !== JSON.stringify(site);
  const editable = s.can("editPolicy");
  const pending = nodes.data?.filter((n) => n.sync_status === "PENDING_UPDATE" && n.status !== "OFFLINE").length ?? 0;
  const thErr = (v: number) => (!Number.isInteger(v) || v < 1 || v > 100 ? "Whole number, 1 to 100" : null);

  const save = async () => {
    if (!draft || thErr(draft.inbound_threshold) || thErr(draft.outbound_threshold)) return;
    setSaving(true);
    try {
      const n = await policies.updateSite(draft.id, { paranoia_level: draft.paranoia_level, inbound_threshold: draft.inbound_threshold, outbound_threshold: draft.outbound_threshold, crs_categories: draft.crs_categories });
      sites.setData((l) => l?.map((x) => (x.id === n.id ? n : x)));
      nodes.reload();
      toast({ tone: "ok", title: `${n.domain_name} saved`, body: "Deploy the policy to push it to the fleet." });
    } catch (e) { toast({ tone: "error", title: "Save failed", body: (e as Error).message }); } finally { setSaving(false); }
  };
  const deploy = async () => {
    setDeploying(true);
    const t0 = performance.now();
    try {
      const r = await fleet.deploy();
      toast({ tone: r.unreachable.length ? "info" : "ok", title: `Config v${r.version} pushed to ${r.synced} nodes in ${((performance.now() - t0) / 1000).toFixed(2)} s`, body: r.unreachable.length ? `Unreachable: ${r.unreachable.join(", ")}. They keep their cached config and sync when back.` : undefined });
      nodes.reload(); setConfirmDeploy(false);
    } catch (e) { toast({ tone: "error", title: "Deploy failed", body: (e as Error).message }); } finally { setDeploying(false); }
  };

  return (
    <>
      <PageHeader
        title="Policies & CRS"
        description="Per-site OWASP Core Rule Set v4 configuration. Changes are versioned and reach the fleet only when you deploy."
        actions={s.can("deploy") ? <Button variant="primary" disabled={!pending || deploying} onClick={() => setConfirmDeploy(true)}><CloudArrowUp size={16} aria-hidden />{pending ? `Deploy to ${pending} pending node${pending > 1 ? "s" : ""}` : "Fleet in sync"}</Button> : undefined}
      />
      {!editable ? <p className="mb-4 rounded border border-border bg-surface px-3 py-2 text-[13px] text-fg-2">You are signed in as {s.role}. Policy changes need the Admin role, so controls are read-only.</p> : null}

      {sites.error && !sites.data ? <div className="panel"><ErrorState title="Sites could not be loaded" error={sites.error} onRetry={sites.reload} /></div> : sites.data?.length === 0 ? (
        <div className="panel">
          <Empty title="No sites yet" body={editable ? "Add the first domain the fleet protects. It starts at paranoia level 1 with every CRS category on." : "An Admin has not added any sites yet."}
            action={editable ? <Button variant="primary" onClick={() => setAddSite(true)}><Plus size={16} aria-hidden />Add site</Button> : undefined} />
        </div>
      ) : !sites.data || !draft ? <div className="panel"><Loading label="Loading sites" /></div> : (
        <div className="grid gap-4 lg:grid-cols-[240px_minmax(0,1fr)]">
          <nav aria-label="Sites" className="panel h-fit p-1.5">
            <ul className="flex gap-1 overflow-x-auto lg:flex-col">
              {sites.data.map((x) => (
                <li key={x.id} className="shrink-0">
                  <button onClick={() => setSiteId(x.id)} aria-current={x.id === draft.id ? "true" : undefined} className={cn("w-full rounded px-2.5 py-2 text-left hover:bg-surface-2", x.id === draft.id && "bg-surface-2")}>
                    <span className="block text-[13px] font-medium">{x.domain_name}</span>
                    <span className="block text-[11px] text-muted">{x.name} · PL{x.paranoia_level}</span>
                  </button>
                </li>
              ))}
            </ul>
            {editable ? (
              <button onClick={() => setAddSite(true)} className="mt-1 hidden w-full items-center gap-1.5 rounded px-2.5 py-2 text-left text-[13px] font-medium text-accent hover:bg-surface-2 lg:flex">
                <Plus size={14} aria-hidden />Add site
              </button>
            ) : null}
          </nav>
          {editable ? <Button className="lg:hidden" onClick={() => setAddSite(true)}><Plus size={16} aria-hidden />Add site</Button> : null}

          <div className="flex min-w-0 flex-col gap-4">
            <section className="panel" aria-labelledby="pl-h">
              <SectionTitle id="pl-h" aside={<span className="text-[12px] text-muted">updated {relTime(site!.updated_at)}</span>}>Paranoia level & anomaly scoring · {draft.domain_name}</SectionTitle>
              <div className="grid gap-6 px-4 pb-4 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)]">
                <div>
                  <label htmlFor="pl" className="text-[12px] font-medium text-fg-2">Paranoia level</label>
                  <input id="pl" type="range" min={1} max={4} step={1} value={draft.paranoia_level} disabled={!editable}
                    onChange={(e) => setDraft({ ...draft, paranoia_level: Number(e.target.value) as Site["paranoia_level"] })}
                    className="mt-3 w-full accent-[rgb(var(--accent))] disabled:opacity-60" aria-valuetext={`PL${draft.paranoia_level}`} />
                  <div className="mt-1 grid grid-cols-4 text-[12px]" aria-hidden>
                    {[1, 2, 3, 4].map((n) => <span key={n} className={cn(n === 1 ? "text-left" : n === 4 ? "text-right" : "text-center", n === draft.paranoia_level ? "font-semibold text-fg" : "text-muted")}>PL{n}</span>)}
                  </div>
                  <p className="mt-2 text-[13px] text-fg-2">{PL[draft.paranoia_level - 1]}</p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Inbound threshold" htmlFor="th-in" hint="CRS default 5" error={thErr(draft.inbound_threshold)}>
                    <Input id="th-in" type="number" min={1} max={100} value={draft.inbound_threshold} disabled={!editable} onChange={(e) => setDraft({ ...draft, inbound_threshold: Number(e.target.value) })} />
                  </Field>
                  <Field label="Outbound threshold" htmlFor="th-out" hint="CRS default 4" error={thErr(draft.outbound_threshold)}>
                    <Input id="th-out" type="number" min={1} max={100} value={draft.outbound_threshold} disabled={!editable} onChange={(e) => setDraft({ ...draft, outbound_threshold: Number(e.target.value) })} />
                  </Field>
                </div>
              </div>
            </section>

            <section className="panel" aria-labelledby="crs-h">
              <SectionTitle id="crs-h" aside={<span className="text-[12px] text-muted">{Object.values(draft.crs_categories).filter(Boolean).length} of {CRS.length} enabled</span>}>CRS rule categories</SectionTitle>
              <ul className="grid border-t border-border sm:grid-cols-2">
                {CRS.map((c, i) => {
                  const on = draft.crs_categories[c.id] ?? true;
                  return (
                    <li key={c.id} className={cn("flex items-center gap-3 border-b border-border px-4 py-3", i % 2 === 0 && "sm:border-r")}>
                      <div className="min-w-0 flex-1">
                        <label htmlFor={`crs-${c.id}`} className="block text-[13px] font-medium"><Mono className="mr-2 text-[12px] text-fg-2">{c.id}xxx</Mono>{c.name}</label>
                        <p className="truncate text-[12px] text-muted" title={c.desc}>{c.desc}</p>
                      </div>
                      <Switch id={`crs-${c.id}`} label={`${c.name} (${c.id}xxx)`} checked={on} disabled={!editable} onCheckedChange={(v) => setDraft({ ...draft, crs_categories: { ...draft.crs_categories, [c.id]: v } })} />
                    </li>
                  );
                })}
              </ul>
              {editable ? (
                <div className="flex flex-wrap items-center justify-end gap-2 px-4 py-3">
                  {dirty ? <span className="mr-auto text-[12px] text-warn">Unsaved changes</span> : null}
                  <Button disabled={!dirty || saving} onClick={() => setDraft(structuredClone(site!))}>Discard</Button>
                  <Button variant="primary" disabled={!dirty || saving} onClick={save}>{saving ? "Saving..." : "Save site policy"}</Button>
                </div>
              ) : null}
            </section>

            <section id="exceptions" className="panel scroll-mt-20" aria-labelledby="exc-h">
              <SectionTitle id="exc-h" aside={s.can("respond") ? <Button size="sm" onClick={() => setNewExc({ host: draft.domain_name, ruleId: 942100, path: "/" })}><Plus size={14} aria-hidden />New exception</Button> : undefined}>Rule exceptions</SectionTitle>
              {exc.error && !exc.data ? <ErrorState title="Exceptions could not be loaded" error={exc.error} onRetry={exc.reload} /> : !exc.data ? <Loading label="Loading exceptions" /> : (() => {
                const rows = exc.data.filter((e) => e.site_id === draft.id);
                return rows.length === 0 ? <Empty title={`No exceptions on ${draft.domain_name}`} body="Create one from a log entry in Log Explorer, or here if you already know the rule and path." /> : (
                  <TableWrap label="Rule exceptions">
                    <table className="data-table">
                      <thead><tr><th>Rule</th><th>Path</th><th>Parameter</th><th>Reason</th><th>Created</th>{s.can("editPolicy") ? <th><span className="sr-only">Actions</span></th> : null}</tr></thead>
                      <tbody>
                        {rows.map((e) => (
                          <tr key={e.id}>
                            <td><Mono>{e.rule_id}</Mono></td>
                            <td><Mono>{e.path_pattern}</Mono></td>
                            <td>{e.parameter_name ? <Mono>{e.parameter_name}</Mono> : <span className="text-[12px] text-muted">whole rule</span>}</td>
                            <td className="max-w-[320px] truncate text-[12px] text-fg-2" title={e.reason}>{e.reason}</td>
                            <td className="text-[12px] text-fg-2" title={fmtTime(e.created_at)}>{e.created_by}, {relTime(e.created_at)}</td>
                            {s.can("editPolicy") ? (
                              <td className="text-right"><Button size="icon" variant="ghost" aria-label={`Remove exception for rule ${e.rule_id} on ${e.path_pattern}`} onClick={async () => {
                                try { await exceptionsApi.remove(e.id); exc.reload(); nodes.reload(); toast({ tone: "ok", title: `Exception for ${e.rule_id} removed` }); }
                                catch (x) { toast({ tone: "error", title: "Remove failed", body: (x as Error).message }); }
                              }}><Trash size={16} aria-hidden /></Button></td>
                            ) : null}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </TableWrap>
                );
              })()}
            </section>
          </div>
        </div>
      )}
      <ExceptionDialog open={!!newExc} onOpenChange={(v) => !v && setNewExc(null)} seed={newExc} onDone={() => { exc.reload(); nodes.reload(); }} />
      <AddSiteDialog open={addSite} onOpenChange={setAddSite} onCreated={(n) => {
        sites.setData((l) => [...(l ?? []), n]);
        setSiteId(n.id);
        nodes.reload();
        toast({ tone: "ok", title: `${n.domain_name} added`, body: "Deploy the policy so the fleet starts protecting it." });
      }} />
      <Dialog open={confirmDeploy} onOpenChange={setConfirmDeploy} title="Deploy policy to the fleet" description="Pushes the current policy over the gRPC config stream. Nodes hot-reload without dropping traffic."
        footer={<><Button onClick={() => setConfirmDeploy(false)}>Cancel</Button><Button variant="primary" disabled={deploying} onClick={deploy}>{deploying ? "Deploying..." : "Deploy now"}</Button></>}>
        <ul className="flex flex-col gap-1 text-[13px]">
          {nodes.data?.map((n) => (
            <li key={n.id} className="flex justify-between gap-2"><Mono>{n.node_name}</Mono><span className={n.status === "OFFLINE" ? "text-crit" : n.sync_status === "PENDING_UPDATE" ? "text-warn" : "text-fg-2"}>{n.status === "OFFLINE" ? "unreachable, keeps cached config" : n.sync_status === "PENDING_UPDATE" ? `v${n.current_config_version} -> update` : "in sync"}</span></li>
          ))}
        </ul>
      </Dialog>
    </>
  );
}

function AddSiteDialog({ open, onOpenChange, onCreated }: { open: boolean; onOpenChange: (v: boolean) => void; onCreated: (s: Site) => void }) {
  const [f, setF] = React.useState({ name: "", domain: "" });
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  React.useEffect(() => { if (open) { setF({ name: "", domain: "" }); setErr(null); } }, [open]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    try { onCreated(await policies.createSite({ name: f.name, domain_name: f.domain })); onOpenChange(false); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Add site" description="A site is one host name the fleet protects, with its own CRS settings and exceptions.">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <Field label="Name" htmlFor="site-name"><Input id="site-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="Partner API" required /></Field>
        <Field label="Domain" htmlFor="site-domain" hint="Exactly as clients send it in the Host header" error={err}>
          <Input id="site-domain" value={f.domain} onChange={(e) => setF({ ...f, domain: e.target.value })} placeholder="partners.example.com" className="font-mono" required />
        </Field>
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={busy || !f.name.trim() || !f.domain.trim()}>{busy ? "Adding..." : "Add site"}</Button>
        </div>
      </form>
    </Dialog>
  );
}
