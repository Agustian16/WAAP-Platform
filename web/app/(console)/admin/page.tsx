"use client";
// Module 5: RBAC (FR-5.1), GitOps export/validate (FR-5.3); Module 6 config: kill chain mapping & correlation settings.
import * as React from "react";
import { DownloadSimple, UploadSimple, CheckCircle, WarningOctagon, PencilSimple } from "@phosphor-icons/react";
import { admin, policies } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import type { CorrelationSettings, KillchainMapping, Role } from "@/lib/types";
import { CATEGORIES, STAGES } from "@/lib/killchain";
import { Button, Dialog, Empty, ErrorState, Field, Input, Loading, PageHeader, Select, Tabs, TabsContent, TabsList, TabsTrigger, Textarea, TableWrap } from "@/components/ui";
import { Mono, StageTag } from "@/components/atoms";
import { useSession, useToast } from "@/components/providers";
import { download, relTime } from "@/lib/utils";

export default function AdminPage() {
  const s = useSession();
  if (!s.can("admin")) {
    return (
      <>
        <PageHeader title="Administration" />
        <div className="panel"><Empty title="Admin role required" body={`You are signed in as ${s.role}. Ask an Admin to change users, GitOps or correlation settings.`} /></div>
      </>
    );
  }
  return (
    <>
      <PageHeader title="Administration" description="Users and roles, policy-as-code, and how WAF events become attack campaigns." />
      <Tabs defaultValue="users" className="panel">
        <TabsList className="px-2">
          <TabsTrigger value="users">Users & roles</TabsTrigger>
          <TabsTrigger value="gitops">GitOps</TabsTrigger>
          <TabsTrigger value="mapping">Kill chain mapping</TabsTrigger>
          <TabsTrigger value="correlation">Correlation</TabsTrigger>
        </TabsList>
        <TabsContent value="users" className="outline-none"><Users /></TabsContent>
        <TabsContent value="gitops" className="outline-none"><GitOps /></TabsContent>
        <TabsContent value="mapping" className="outline-none"><Mapping /></TabsContent>
        <TabsContent value="correlation" className="outline-none"><Correlation /></TabsContent>
      </Tabs>
    </>
  );
}

const ROLE_DESC: Record<Role, string> = {
  Admin: "Everything, including users, policy deploys and settings",
  "SecOps Analyst": "Logs, triage, exceptions, blocks and draft rules",
  Auditor: "Read-only dashboards, analytics and audit trail",
};

function Users() {
  const toast = useToast();
  const q = useAsync(() => admin.users(), []);
  return (
    <div>
      <p className="border-b border-border px-4 py-3 text-[12px] text-fg-2">Sign-in is through your OIDC provider with MFA enforced. Users appear here after their first login; roles are assigned here.</p>
      {q.error && !q.data ? <ErrorState title="Users could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data ? <Loading label="Loading users" /> : (
        <TableWrap label="Users">
          <table className="data-table">
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>What the role allows</th><th>MFA</th><th>Last login</th></tr></thead>
            <tbody>
              {q.data.map((u) => (
                <tr key={u.id}>
                  <td className="font-medium">{u.name}</td>
                  <td className="text-[12px] text-fg-2">{u.email}</td>
                  <td>
                    <label htmlFor={`role-${u.id}`} className="sr-only">Role for {u.name}</label>
                    <Select id={`role-${u.id}`} className="h-8 text-[12px]" value={u.role} onChange={async (e) => {
                      try { const n = await admin.setRole(u.id, e.target.value as Role); q.setData((l) => l?.map((x) => (x.id === n.id ? n : x))); toast({ tone: "ok", title: `${u.name} is now ${n.role}` }); }
                      catch (x) { toast({ tone: "error", title: "Role not changed", body: (x as Error).message }); }
                    }}>{(Object.keys(ROLE_DESC) as Role[]).map((r) => <option key={r}>{r}</option>)}</Select>
                  </td>
                  <td className="text-[12px] text-fg-2">{ROLE_DESC[u.role]}</td>
                  <td className="text-[12px]">{u.mfa ? "Enforced" : <span className="text-crit">Missing</span>}</td>
                  <td className="text-[12px] text-fg-2">{u.last_login ? relTime(u.last_login) : "never"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </div>
  );
}

function GitOps() {
  const toast = useToast();
  const exp = useAsync(() => admin.exportPolicy(), []);
  const [text, setText] = React.useState("");
  const [res, setRes] = React.useState<{ ok: boolean; errors: string[]; summary: string[] } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const validate = async () => {
    setBusy(true);
    try { setRes(await admin.validatePolicy(text)); } catch (e) { toast({ tone: "error", title: "Validation failed", body: (e as Error).message }); } finally { setBusy(false); }
  };
  return (
    <div className="grid gap-4 p-4 lg:grid-cols-2">
      <section className="min-w-0" aria-labelledby="exp-h">
        <div className="mb-2 flex items-center justify-between gap-2">
          <h2 id="exp-h" className="text-[13px] font-semibold">Export coraza-policy.yaml</h2>
          <Button size="sm" disabled={!exp.data} onClick={() => download("coraza-policy.yaml", exp.data!, "application/yaml")}><DownloadSimple size={14} aria-hidden />Download</Button>
        </div>
        {exp.error ? <ErrorState title="Export failed" error={exp.error} onRetry={exp.reload} /> : !exp.data ? <Loading label="Rendering policy" /> : (
          <pre className="max-h-[420px] overflow-auto rounded border border-border bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">{exp.data}</pre>
        )}
        <p className="mt-3 text-[12px] font-medium text-fg-2">Validate in CI (GitHub Actions / GitLab CI)</p>
        <pre className="mt-1 overflow-x-auto rounded border border-border bg-surface-2 p-3 font-mono text-[12px]">{`coraza-console policy validate coraza-policy.yaml \\\n  --server https://console.domain.com --token $CORAZA_CI_TOKEN`}</pre>
      </section>
      <section className="min-w-0" aria-labelledby="imp-h">
        <div className="mb-2 flex items-center justify-between gap-2">
          <h2 id="imp-h" className="text-[13px] font-semibold">Validate an import</h2>
          <label className="inline-flex h-8 cursor-pointer items-center gap-1.5 rounded border border-border-strong px-2.5 text-[12px] font-medium hover:bg-surface-2">
            <UploadSimple size={14} aria-hidden />Load file
            <input type="file" accept=".yaml,.yml" className="sr-only" onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setText(await f.text()); setRes(null); } }} />
          </label>
        </div>
        <label htmlFor="imp" className="sr-only">Policy YAML</label>
        <Textarea id="imp" rows={14} value={text} onChange={(e) => { setText(e.target.value); setRes(null); }} placeholder="Paste coraza-policy.yaml, or load the export on the left and edit it" className="font-mono text-[12px]" spellCheck={false} />
        <div className="mt-2 flex flex-wrap gap-2">
          <Button variant="primary" disabled={!text.trim() || busy} onClick={validate}>{busy ? "Validating..." : "Validate"}</Button>
          <Button disabled={!exp.data} onClick={() => { setText(exp.data!); setRes(null); }}>Load current export</Button>
        </div>
        {res ? (
          <div className="mt-3 rounded border border-border p-3 text-[13px]" aria-live="polite">
            <p className={res.ok ? "flex items-center gap-1.5 font-medium" : "flex items-center gap-1.5 font-medium text-crit"}>
              {res.ok ? <CheckCircle size={16} weight="fill" className="text-good" aria-hidden /> : <WarningOctagon size={16} weight="fill" aria-hidden />}
              {res.ok ? "Valid. Applying happens through your Git pipeline, not this page." : `${res.errors.length} problem${res.errors.length > 1 ? "s" : ""} found`}
            </p>
            {res.errors.map((e) => <p key={e} className="mt-1 font-mono text-[12px] text-crit">{e}</p>)}
            {res.summary.length ? <ul className="mt-2 font-mono text-[12px] text-fg-2">{res.summary.map((x) => <li key={x}>{x}</li>)}</ul> : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}

function Mapping() {
  const toast = useToast();
  const q = useAsync(() => admin.killchainMapping(), []);
  const [edit, setEdit] = React.useState<KillchainMapping | null>(null);
  const [err, setErr] = React.useState<string | null>(null);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    try { const m = await admin.saveMapping(edit!); q.setData((l) => (l?.some((x) => x.id === m.id) ? l.map((x) => (x.id === m.id ? m : x)) : [...(l ?? []), m])); toast({ tone: "ok", title: "Mapping saved", body: "Applies to new events; past events keep their stage." }); setEdit(null); }
    catch (x) { setErr((x as Error).message); }
  };
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
        <p className="text-[12px] text-fg-2">The narrowest matching range wins, so a single custom rule can override its CRS family.</p>
        <Button size="sm" onClick={() => { setErr(null); setEdit({ id: `km-${Date.now()}`, rule_id_from: 900000, rule_id_to: 900000, tag: null, rule_category: "SQLI", killchain_stage: "EXPLOIT", mitre_technique: "T1190" }); }}>Add override</Button>
      </div>
      {q.error && !q.data ? <ErrorState title="Mapping could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data ? <Loading label="Loading mapping" /> : (
        <TableWrap label="Kill chain mapping">
          <table className="data-table">
            <thead><tr><th>Rule IDs</th><th>Tag</th><th>Category</th><th>Kill chain stage</th><th>ATT&CK</th><th><span className="sr-only">Edit</span></th></tr></thead>
            <tbody>
              {q.data.map((m) => (
                <tr key={m.id}>
                  <td><Mono>{m.rule_id_from === m.rule_id_to ? m.rule_id_from : `${m.rule_id_from}-${m.rule_id_to}`}</Mono></td>
                  <td>{m.tag ? <Mono className="text-fg-2">{m.tag}</Mono> : <span className="text-muted">-</span>}</td>
                  <td className="text-[12px]">{CATEGORIES.find((c) => c.key === m.rule_category)?.name}</td>
                  <td><StageTag stage={m.killchain_stage} /></td>
                  <td><Mono>{m.mitre_technique ?? "-"}</Mono></td>
                  <td className="text-right"><Button size="icon" variant="ghost" aria-label={`Edit mapping ${m.rule_id_from}-${m.rule_id_to}`} onClick={() => { setErr(null); setEdit({ ...m }); }}><PencilSimple size={16} aria-hidden /></Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      <Dialog open={!!edit} onOpenChange={(v) => !v && setEdit(null)} title="Kill chain mapping" footer={<><Button onClick={() => setEdit(null)}>Cancel</Button><Button type="submit" form="map-form" variant="primary">Save mapping</Button></>}>
        {edit ? (
          <form id="map-form" onSubmit={save} className="grid grid-cols-2 gap-3">
            <Field label="Rule ID from" htmlFor="m-from"><Input id="m-from" type="number" value={edit.rule_id_from} onChange={(e) => setEdit({ ...edit, rule_id_from: Number(e.target.value) })} /></Field>
            <Field label="Rule ID to" htmlFor="m-to"><Input id="m-to" type="number" value={edit.rule_id_to} onChange={(e) => setEdit({ ...edit, rule_id_to: Number(e.target.value) })} /></Field>
            <Field label="Tag (optional)" htmlFor="m-tag" className="col-span-2"><Input id="m-tag" value={edit.tag ?? ""} onChange={(e) => setEdit({ ...edit, tag: e.target.value || null })} className="font-mono" /></Field>
            <Field label="Category" htmlFor="m-cat"><Select id="m-cat" value={edit.rule_category} onChange={(e) => setEdit({ ...edit, rule_category: e.target.value as KillchainMapping["rule_category"] })}>{CATEGORIES.map((c) => <option key={c.key} value={c.key}>{c.name}</option>)}</Select></Field>
            <Field label="Stage" htmlFor="m-stage"><Select id="m-stage" value={edit.killchain_stage} onChange={(e) => setEdit({ ...edit, killchain_stage: e.target.value as KillchainMapping["killchain_stage"] })}>{STAGES.filter((x) => x.observable).map((x) => <option key={x.key} value={x.key}>{x.n}. {x.name}</option>)}</Select></Field>
            <Field label="MITRE ATT&CK technique" htmlFor="m-mitre" className="col-span-2" error={err}><Input id="m-mitre" value={edit.mitre_technique ?? ""} onChange={(e) => setEdit({ ...edit, mitre_technique: e.target.value || null })} className="font-mono" placeholder="T1190" /></Field>
          </form>
        ) : null}
      </Dialog>
    </div>
  );
}

function Correlation() {
  const toast = useToast();
  const q = useAsync(() => admin.correlation(), []);
  const sites = useAsync(() => policies.sites(), []);
  const [draft, setDraft] = React.useState<Record<string, CorrelationSettings>>({});
  React.useEffect(() => { if (q.data) setDraft(Object.fromEntries(q.data.map((c) => [c.site_id, { ...c }]))); }, [q.data]);
  return (
    <div>
      <p className="border-b border-border px-4 py-3 text-[12px] text-fg-2">Events from the same actor within the idle timeout join one campaign. Grouping by /24 or ASN catches distributed scans but lowers confidence on shared NAT.</p>
      {q.error && !q.data ? <ErrorState title="Settings could not be loaded" error={q.error} onRetry={q.reload} /> : !q.data || !sites.data ? <Loading label="Loading settings" /> : (
        <TableWrap label="Correlation settings">
          <table className="data-table">
            <thead><tr><th>Site</th><th>Actor key</th><th>Idle timeout (min)</th><th>Min events to open</th><th><span className="sr-only">Save</span></th></tr></thead>
            <tbody>
              {q.data.map((c) => {
                const d = draft[c.site_id] ?? c;
                const dirty = JSON.stringify(d) !== JSON.stringify(c);
                const site = sites.data!.find((x) => x.id === c.site_id)!;
                return (
                  <tr key={c.site_id}>
                    <td className="font-medium">{site.domain_name}</td>
                    <td><label htmlFor={`ak-${c.site_id}`} className="sr-only">Actor key for {site.domain_name}</label><Select id={`ak-${c.site_id}`} className="h-8 text-[12px]" value={d.actor_key_mode} onChange={(e) => setDraft({ ...draft, [c.site_id]: { ...d, actor_key_mode: e.target.value as CorrelationSettings["actor_key_mode"] } })}><option value="IP">Client IP</option><option value="CIDR24">/24 network</option><option value="ASN">ASN</option><option value="FINGERPRINT">UA + JA3 fingerprint</option></Select></td>
                    <td><label htmlFor={`it-${c.site_id}`} className="sr-only">Idle timeout for {site.domain_name}</label><Input id={`it-${c.site_id}`} type="number" min={1} max={1440} className="h-8 w-24" value={d.idle_timeout_minutes} onChange={(e) => setDraft({ ...draft, [c.site_id]: { ...d, idle_timeout_minutes: Number(e.target.value) } })} /></td>
                    <td><label htmlFor={`me-${c.site_id}`} className="sr-only">Minimum events for {site.domain_name}</label><Input id={`me-${c.site_id}`} type="number" min={1} className="h-8 w-24" value={d.min_events_to_open} onChange={(e) => setDraft({ ...draft, [c.site_id]: { ...d, min_events_to_open: Number(e.target.value) } })} /></td>
                    <td className="text-right"><Button size="sm" variant={dirty ? "primary" : "secondary"} disabled={!dirty} onClick={async () => {
                      try { const n = await admin.saveCorrelation(d); q.setData((l) => l?.map((x) => (x.site_id === n.site_id ? n : x))); toast({ tone: "ok", title: `Correlation for ${site.domain_name} saved` }); }
                      catch (x) { toast({ tone: "error", title: "Not saved", body: (x as Error).message }); }
                    }}>Save</Button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
    </div>
  );
}
