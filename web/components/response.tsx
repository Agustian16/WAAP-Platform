"use client";
// Response actions shared by Log Explorer (FR-3.3) and the Attack Graph (FR-6.15).
import * as React from "react";
import { ipLists, exceptionsApi, policies } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { Button, Dialog, Field, Input, Select, Textarea } from "./ui";
import { useToast } from "./providers";
import { fmtNum, parseCidr } from "@/lib/utils";

const TTL = [
  { v: "1", label: "1 hour" }, { v: "24", label: "24 hours" }, { v: "168", label: "7 days" }, { v: "720", label: "30 days" }, { v: "", label: "No expiry" },
];

export function BlockDialog({ open, onOpenChange, initial, context, onDone }: { open: boolean; onOpenChange: (v: boolean) => void; initial: string; context?: string; onDone?: () => void }) {
  const toast = useToast();
  const [cidr, setCidr] = React.useState(initial);
  const [ttl, setTtl] = React.useState("24");
  const [reason, setReason] = React.useState(context ?? "");
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  React.useEffect(() => { if (open) { setCidr(initial); setReason(context ?? ""); setErr(null); } }, [open, initial, context]);
  const valid = parseCidr(cidr);
  const impact = useAsync(() => (valid ? ipLists.impact(valid.normalized) : Promise.resolve(null)), [valid?.normalized, open]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!valid) { setErr("Enter an IPv4 address or CIDR, for example 203.0.113.0/24"); return; }
    setBusy(true); setErr(null);
    try {
      const r = await ipLists.add({ cidr: valid.normalized, list: "block", reason, ttlHours: ttl ? Number(ttl) : null });
      toast({ tone: "ok", title: `Blocked ${r.cidr}`, body: `${ttl ? `Expires in ${TTL.find((t) => t.v === ttl)!.label}. ` : ""}Pushed to the blocklist; nodes pick it up on the next config sync.`, action: { label: "View blocklist", href: "/threat-intel" } });
      onOpenChange(false);
      onDone?.();
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="Block IP or CIDR" description="Adds the source to the central blocklist (FR-4.2). Every Coraza node enforces it after the next config push."
      footer={<><Button type="button" onClick={() => onOpenChange(false)}>Cancel</Button><Button type="submit" form="block-form" variant="danger" disabled={busy}>{busy ? "Blocking..." : `Block ${valid?.normalized ?? ""}`}</Button></>}>
      <form id="block-form" onSubmit={submit} className="flex flex-col gap-4">
        <Field label="IP or CIDR" htmlFor="b-cidr" error={cidr && !valid ? "Not a valid IPv4 address or CIDR" : err} hint={valid && valid.normalized !== cidr.trim() && cidr.includes("/") ? `Will be stored as ${valid.normalized}` : undefined}>
          <Input id="b-cidr" value={cidr} onChange={(e) => setCidr(e.target.value)} className="font-mono" autoComplete="off" spellCheck={false} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Expires after" htmlFor="b-ttl"><Select id="b-ttl" value={ttl} onChange={(e) => setTtl(e.target.value)}>{TTL.map((t) => <option key={t.v} value={t.v}>{t.label}</option>)}</Select></Field>
        </div>
        <Field label="Reason (shown in audit trail)" htmlFor="b-reason"><Textarea id="b-reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
        <div className="rounded border border-border bg-surface-2 p-3 text-[13px]" aria-live="polite">
          <p className="mb-1 text-[12px] font-medium text-fg-2">Impact, last 30 days</p>
          {!valid ? <p className="text-muted">Enter a valid address to see impact.</p> : impact.loading ? <p className="text-muted">Checking traffic from {valid.normalized}...</p> : impact.error ? <p className="text-crit">Impact check failed: {(impact.error as Error).message}</p> : impact.data ? (
            <ul className="space-y-0.5">
              <li><span className="tnum font-semibold">{fmtNum(impact.data.attackEvents)}</span> attack events in <span className="tnum font-semibold">{impact.data.campaigns}</span> campaigns</li>
              <li className={impact.data.legitRequests ? "text-warn" : undefined}><span className="tnum font-semibold">{fmtNum(impact.data.legitRequests)}</span> requests that matched no rule{impact.data.legitRequests ? " will also be blocked (shared NAT or proxy?)" : ""}</li>
            </ul>
          ) : null}
        </div>
      </form>
    </Dialog>
  );
}

export interface ExceptionSeed { siteId?: string; host?: string; ruleId: number; path: string; parameter?: string | null }

export function ExceptionDialog({ open, onOpenChange, seed, onDone }: { open: boolean; onOpenChange: (v: boolean) => void; seed: ExceptionSeed | null; onDone?: () => void }) {
  const toast = useToast();
  const sites = useAsync(() => policies.sites(), []);
  const [f, setF] = React.useState({ siteId: "", ruleId: "", path: "", parameter: "", scope: "endpoint" as "endpoint" | "global", reason: "" });
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!open || !seed) return;
    const siteId = seed.siteId ?? sites.data?.find((s) => s.domain_name === seed.host)?.id ?? sites.data?.[0]?.id ?? "";
    setF({ siteId, ruleId: String(seed.ruleId), path: seed.path, parameter: seed.parameter ?? "", scope: "endpoint", reason: "" });
    setErr(null);
  }, [open, seed, sites.data]);
  const ruleOk = /^\d{1,7}$/.test(f.ruleId);
  const preview = ruleOk ? exceptionsApi.preview({ ruleId: +f.ruleId, path: f.path, parameter: f.parameter.trim() || null, scope: f.scope }) : "# Enter a numeric rule ID";
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setF((x) => ({ ...x, [k]: e.target.value }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleOk) { setErr("Rule ID must be a number"); return; }
    setBusy(true); setErr(null);
    try {
      await exceptionsApi.create({ siteId: f.siteId, ruleId: +f.ruleId, path: f.path, parameter: f.parameter.trim() || null, scope: f.scope, reason: f.reason });
      toast({ tone: "ok", title: `Exception for rule ${f.ruleId} saved`, body: "Nodes show Pending update until the policy is deployed.", action: { label: "Review exceptions", href: "/policies#exceptions" } });
      onOpenChange(false);
      onDone?.();
    } catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };

  return (
    <Dialog wide open={open} onOpenChange={onOpenChange} title="Create rule exception" description="Suppress a false positive without editing files. The SecLang below is generated for you and versioned with the policy."
      footer={<><Button type="button" onClick={() => onOpenChange(false)}>Cancel</Button><Button type="submit" form="exc-form" variant="primary" disabled={busy}>{busy ? "Saving..." : "Save exception"}</Button></>}>
      <form id="exc-form" onSubmit={submit} className="grid gap-4 md:grid-cols-2">
        <div className="flex flex-col gap-4">
          <Field label="Site" htmlFor="x-site">
            <Select id="x-site" value={f.siteId} onChange={set("siteId")}>{sites.data?.map((s) => <option key={s.id} value={s.id}>{s.domain_name}</option>)}</Select>
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Rule ID" htmlFor="x-rule" error={f.ruleId && !ruleOk ? "Numbers only" : null}><Input id="x-rule" inputMode="numeric" value={f.ruleId} onChange={set("ruleId")} className="font-mono" /></Field>
            <Field label="Scope" htmlFor="x-scope">
              <Select id="x-scope" value={f.scope} onChange={set("scope")}><option value="endpoint">This endpoint</option><option value="global">All paths</option></Select>
            </Field>
          </div>
          {f.scope === "endpoint" ? (
            <Field label="Path" htmlFor="x-path" hint="End with * to match a prefix, e.g. /api/v1/*"><Input id="x-path" value={f.path} onChange={set("path")} className="font-mono" /></Field>
          ) : null}
          <Field label="Parameter (optional)" htmlFor="x-param" hint="Leave empty to disable the whole rule; set e.g. ARGS:username to exclude only that field.">
            <Input id="x-param" value={f.parameter} onChange={set("parameter")} className="font-mono" placeholder="ARGS:username" />
          </Field>
          <Field label="Reason" htmlFor="x-reason" error={err}><Textarea id="x-reason" rows={2} value={f.reason} onChange={set("reason")} placeholder="Why is this traffic legitimate?" required /></Field>
        </div>
        <div className="flex min-w-0 flex-col gap-1.5">
          <p className="text-[12px] font-medium text-fg-2">Generated SecLang</p>
          <pre className="min-h-[160px] flex-1 whitespace-pre-wrap break-all rounded border border-border bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">{preview}</pre>
          <p className="text-[12px] text-muted">{f.scope === "endpoint" ? (f.parameter ? "ctl:ruleRemoveTargetById keeps the rule active for every other field." : "ctl:ruleRemoveById turns the rule off for this path only.") : f.parameter ? "SecRuleUpdateTargetById excludes the field on every path." : "SecRuleRemoveById removes the rule site-wide. Prefer a narrower scope."}</p>
        </div>
      </form>
    </Dialog>
  );
}
