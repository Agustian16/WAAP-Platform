"use client";
// FR-2.3 Visual builder + Monaco code mode with live linter; FR-2.4 test sandbox (Go FTW on the control plane).
import * as React from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, CheckCircle, WarningOctagon, Warning, Flask } from "@phosphor-icons/react";
import { policies, rules } from "@/lib/api";
import { useAsync } from "@/lib/hooks";
import { buildRule, lint, nextFreeId, parseToBuilder, type BuilderRule, type SandboxResult } from "@/lib/seclang";
import { Button, ErrorState, Field, Input, Loading, Select, Switch, Textarea } from "@/components/ui";
import { SecLangEditor, type EditorHandle } from "@/components/seclang-editor";
import { useSession, useToast } from "@/components/providers";
import { cn } from "@/lib/utils";

const OPS = ["rx", "pm", "contains", "streq", "beginsWith", "endsWith", "within", "detectSQLi", "detectXSS", "ipMatch", "eq", "gt", "lt"];
const NO_ARG = ["detectSQLi", "detectXSS"];
const COMMON_T = ["lowercase", "urlDecodeUni", "htmlEntityDecode", "compressWhitespace", "removeNulls", "trim"];
const PHASES = ["1 · Request headers", "2 · Request body", "3 · Response headers", "4 · Response body", "5 · Logging"];
const VAR_HINTS = ["ARGS", "ARGS_NAMES", "REQUEST_URI", "REQUEST_FILENAME", "REQUEST_HEADERS:User-Agent", "REQUEST_COOKIES", "REQUEST_BODY", "RESPONSE_BODY"];
const PRESETS = [
  { name: "PRD sample: UNION SELECT", method: "GET", url: "/api/v1/users?user_id=1 UNION SELECT password FROM users", headers: "User-Agent: Mozilla/5.0", body: "" },
  { name: "Login bypass", method: "POST", url: "/api/v1/login", headers: "Content-Type: application/x-www-form-urlencoded", body: "username=' OR '1'='1&password=x" },
  { name: "Scanner user agent", method: "GET", url: "/", headers: "User-Agent: sqlmap/1.8.2#stable", body: "" },
  { name: "Clean request", method: "GET", url: "/api/v1/users?user_id=42", headers: "User-Agent: Mozilla/5.0", body: "" },
];

export default function RuleEditorPage() {
  const { id } = useParams<{ id: string }>();
  const isNew = id === "new";
  const s = useSession();
  const toast = useToast();
  const router = useRouter();
  const existing = useAsync(() => (isNew ? Promise.resolve(null) : rules.get(id)), [id]);
  const used = useAsync(() => rules.usedIds(), []);
  const sites = useAsync(() => policies.sites(), []);
  const [name, setName] = React.useState("");
  const [siteId, setSiteId] = React.useState<string>("");
  const [active, setActive] = React.useState(false);
  const [code, setCode] = React.useState("");
  const [mode, setMode] = React.useState<"visual" | "code">("code");
  const [builder, setBuilder] = React.useState<BuilderRule | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  const editor = React.useRef<EditorHandle>(null);
  const ready = (isNew ? !!used.data : !!existing.data);

  React.useEffect(() => {
    if (isNew && used.data && !code) {
      const b: BuilderRule = { id: nextFreeId(used.data, 900100, 999999), variables: ["ARGS"], operator: "rx", value: "(?i)<pattern>", negate: false, transforms: ["urlDecodeUni"], phase: 2, action: "deny", status: 403, severity: "CRITICAL", msg: "Describe what this rule detects", tags: ["application-multi"] };
      setBuilder(b); setCode(buildRule(b)); setMode("visual"); setName("NEW_CUSTOM_RULE");
    }
    if (!isNew && existing.data) {
      const r = existing.data;
      setName(r.name); setSiteId(r.site_id ?? ""); setActive(r.is_active); setCode(r.seclang_raw); setBuilder(parseToBuilder(r.seclang_raw));
    }
  }, [isNew, used.data, existing.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const otherIds = (used.data ?? []).filter((x) => x !== existing.data?.rule_id);
  const diags = React.useMemo(() => lint(code, { existingIds: otherIds }), [code, otherIds.join(",")]); // eslint-disable-line react-hooks/exhaustive-deps
  const errors = diags.filter((d) => d.severity === "error").length;
  const warnings = diags.length - errors;
  const canEdit = s.can("writeRule");

  const updateBuilder = (patch: Partial<BuilderRule>) => {
    if (!builder) return;
    const b = { ...builder, ...patch };
    setBuilder(b); setCode(buildRule(b));
  };
  const switchMode = (m: "visual" | "code") => {
    if (m === "visual") {
      const b = parseToBuilder(code);
      if (!b) { toast({ tone: "info", title: "Stay in code mode for this rule", body: "It uses chains or several statements, which the visual builder cannot show without losing detail." }); return; }
      setBuilder(b);
    }
    setMode(m);
  };
  const save = async () => {
    setErr(null);
    if (errors) { setErr("Fix the syntax errors before saving."); return; }
    setSaving(true);
    try {
      const r = await rules.save({ id: isNew ? undefined : id, name, site_id: siteId || null, seclang_raw: code, is_active: active });
      toast({ tone: "ok", title: `Rule ${r.rule_id} saved${r.is_active ? "" : " as draft"}`, body: s.role === "Admin" ? "Deploy from Policies & CRS to push it to the fleet." : "An Admin reviews and activates drafts." });
      if (isNew) router.replace(`/rules/${r.id}`);
    } catch (e) { setErr((e as Error).message); } finally { setSaving(false); }
  };

  if (existing.error) return <div className="panel"><ErrorState title="Rule could not be loaded" error={existing.error} onRetry={existing.reload} /></div>;
  if (!ready) return <Loading label="Loading rule" />;

  return (
    <>
      <Link href="/rules" className="mb-3 inline-flex items-center gap-1 text-[13px] text-fg-2 hover:text-fg"><ArrowLeft size={14} aria-hidden />Custom Rules</Link>
      <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-end">
        <div className="min-w-0 flex-1">
          <p className="text-[12px] text-muted">Rule editor</p>
          <h1 className="truncate font-mono text-[18px] font-semibold">{name || "Untitled rule"}{builder?.id || code.match(/id:(\d+)/) ? ` · ${builder?.id ?? code.match(/id:(\d+)/)?.[1]}` : ""}</h1>
        </div>
        <div className="grid grid-cols-2 gap-3 sm:flex sm:items-end">
          <Field label="Name" htmlFor="r-name"><Input id="r-name" value={name} onChange={(e) => setName(e.target.value)} disabled={!canEdit} className="font-mono sm:w-64" /></Field>
          <Field label="Scope" htmlFor="r-site"><Select id="r-site" value={siteId} onChange={(e) => setSiteId(e.target.value)} disabled={!canEdit}><option value="">All sites</option>{sites.data?.map((x) => <option key={x.id} value={x.id}>{x.domain_name}</option>)}</Select></Field>
          {s.can("editPolicy") ? <label htmlFor="r-active" className="flex h-9 items-center gap-2 text-[13px]"><Switch id="r-active" label="Active" checked={active} onCheckedChange={setActive} />Active</label> : null}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(340px,1fr)]">
        <section className="panel min-w-0 overflow-hidden" aria-label="Rule definition">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
            <div role="group" aria-label="Editor mode" className="seg">
              {(["visual", "code"] as const).map((m) => (
                <button key={m} onClick={() => switchMode(m)} aria-pressed={mode === m} className="seg-btn">{m === "visual" ? "Visual builder" : "SecLang code"}</button>
              ))}
            </div>
            <span className="text-[12px] text-muted">Ctrl+Space for completions</span>
          </div>

          {mode === "visual" && builder ? (
            <div className="grid gap-4 p-4 md:grid-cols-2">
              <Field label="Rule ID" htmlFor="b-id" hint="900000-999999 is reserved for custom rules"><Input id="b-id" type="number" value={builder.id} disabled={!canEdit} onChange={(e) => updateBuilder({ id: Number(e.target.value) })} className="font-mono" /></Field>
              <Field label="Phase" htmlFor="b-phase"><Select id="b-phase" value={builder.phase} disabled={!canEdit} onChange={(e) => updateBuilder({ phase: Number(e.target.value) })}>{PHASES.map((p, i) => <option key={p} value={i + 1}>{p}</option>)}</Select></Field>
              <Field label="Match target (variables, | separated)" htmlFor="b-vars" className="md:col-span-2" hint={<span className="flex flex-wrap gap-1">{VAR_HINTS.map((v) => <button key={v} type="button" disabled={!canEdit} onClick={() => updateBuilder({ variables: [...new Set([...builder.variables, v])] })} className="rounded border border-border px-1.5 font-mono text-[11px] hover:bg-surface-2">+ {v}</button>)}</span>}>
                <Input id="b-vars" value={builder.variables.join("|")} disabled={!canEdit} onChange={(e) => updateBuilder({ variables: e.target.value.split("|").map((x) => x.trim()).filter(Boolean) })} className="font-mono" />
              </Field>
              <Field label="Operator" htmlFor="b-op">
                <div className="flex gap-2">
                  <Select id="b-op" value={builder.operator} disabled={!canEdit} onChange={(e) => updateBuilder({ operator: e.target.value, value: NO_ARG.includes(e.target.value) ? "" : builder.value })} className="flex-1 font-mono">{OPS.map((o) => <option key={o} value={o}>@{o}</option>)}</Select>
                  <label className="flex items-center gap-1.5 text-[12px]" htmlFor="b-neg"><input id="b-neg" type="checkbox" checked={builder.negate} disabled={!canEdit} onChange={(e) => updateBuilder({ negate: e.target.checked })} className="h-4 w-4 accent-[rgb(var(--accent))]" />Negate</label>
                </div>
              </Field>
              <Field label="Value" htmlFor="b-val" hint={builder.operator === "rx" ? "RE2 syntax; (?i) makes it case-insensitive" : builder.operator === "pm" ? "Space-separated phrases" : undefined}>
                <Input id="b-val" value={builder.value} disabled={!canEdit || NO_ARG.includes(builder.operator)} onChange={(e) => updateBuilder({ value: e.target.value })} className="font-mono" placeholder={NO_ARG.includes(builder.operator) ? "no argument (libinjection)" : undefined} />
              </Field>
              <fieldset className="md:col-span-2">
                <legend className="mb-1.5 text-[12px] font-medium text-fg-2">Transformations</legend>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {COMMON_T.map((t) => (
                    <label key={t} htmlFor={`t-${t}`} className="inline-flex items-center gap-1.5 font-mono text-[12px]">
                      <input id={`t-${t}`} type="checkbox" checked={builder.transforms.includes(t)} disabled={!canEdit} className="h-4 w-4 accent-[rgb(var(--accent))]" onChange={(e) => updateBuilder({ transforms: e.target.checked ? [...builder.transforms, t] : builder.transforms.filter((x) => x !== t) })} />t:{t}
                    </label>
                  ))}
                </div>
              </fieldset>
              <Field label="Action" htmlFor="b-act"><Select id="b-act" value={builder.action} disabled={!canEdit} onChange={(e) => updateBuilder({ action: e.target.value as BuilderRule["action"] })}><option value="deny">deny (block now)</option><option value="block">block (anomaly scoring)</option><option value="log">log only</option></Select></Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Status" htmlFor="b-status"><Input id="b-status" type="number" value={builder.status} disabled={!canEdit || builder.action !== "deny"} onChange={(e) => updateBuilder({ status: Number(e.target.value) })} /></Field>
                <Field label="Severity" htmlFor="b-sev"><Select id="b-sev" value={builder.severity} disabled={!canEdit} onChange={(e) => updateBuilder({ severity: e.target.value })}>{["CRITICAL", "ERROR", "WARNING", "NOTICE"].map((x) => <option key={x}>{x}</option>)}</Select></Field>
              </div>
              <Field label="Message" htmlFor="b-msg" className="md:col-span-2"><Input id="b-msg" value={builder.msg} disabled={!canEdit} onChange={(e) => updateBuilder({ msg: e.target.value })} /></Field>
              <Field label="Tags (comma separated)" htmlFor="b-tags" className="md:col-span-2" hint="Tags like attack-sqli also drive kill chain mapping"><Input id="b-tags" value={builder.tags.join(", ")} disabled={!canEdit} onChange={(e) => updateBuilder({ tags: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })} className="font-mono" /></Field>
              <div className="md:col-span-2">
                <p className="mb-1.5 text-[12px] font-medium text-fg-2">Generated SecLang</p>
                <pre className="overflow-x-auto rounded border border-border bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">{code}</pre>
              </div>
            </div>
          ) : (
            <SecLangEditor ref={editor} value={code} onChange={setCode} diagnostics={diags} readOnly={!canEdit} height={420} />
          )}

          <div className={cn("border-t border-border px-3 py-2 text-[12px]", errors ? "bg-crit/5" : "")} aria-live="polite">
            {diags.length === 0 ? (
              <p className="flex items-center gap-1.5 text-fg-2"><CheckCircle size={16} weight="fill" className="text-good" aria-hidden />Syntax validated (0 errors, 0 warnings)</p>
            ) : (
              <>
                <p className="mb-1 font-medium">{errors} error{errors === 1 ? "" : "s"}, {warnings} warning{warnings === 1 ? "" : "s"}</p>
                <ul className="flex flex-col gap-0.5">
                  {diags.map((d, i) => (
                    <li key={i}>
                      <button type="button" onClick={() => { if (mode !== "code") setMode("code"); setTimeout(() => editor.current?.revealLine(d.line), 50); }} className="flex items-center gap-1.5 text-left hover:underline">
                        {d.severity === "error" ? <WarningOctagon size={14} weight="fill" className="text-crit" aria-hidden /> : <Warning size={14} weight="fill" className="text-warn" aria-hidden />}
                        <span className="font-mono text-muted">L{d.line}</span>{d.message}
                      </button>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
          {canEdit ? (
            <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-3 py-2.5">
              {err ? <p className="mr-auto text-[12px] text-crit" role="alert">{err}</p> : !s.can("editPolicy") ? <p className="mr-auto text-[12px] text-muted">Saved as a draft for Admin review.</p> : null}
              <Button onClick={() => router.push("/rules")}>Cancel</Button>
              <Button variant="primary" onClick={save} disabled={saving || errors > 0}>{saving ? "Saving..." : "Save rule"}</Button>
            </div>
          ) : <p className="border-t border-border px-3 py-2 text-[12px] text-muted">Read-only for {s.role}.</p>}
        </section>

        <Sandbox code={code} disabled={errors > 0} />
      </div>
    </>
  );
}

function Sandbox({ code, disabled }: { code: string; disabled: boolean }) {
  const [req, setReq] = React.useState({ method: PRESETS[0].method, url: PRESETS[0].url, headers: PRESETS[0].headers, body: PRESETS[0].body });
  const [res, setRes] = React.useState<(SandboxResult & { engine: string }) | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState<string | null>(null);
  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr(null);
    const headers = Object.fromEntries(req.headers.split("\n").map((l) => l.split(/:(.*)/s).map((x) => x.trim())).filter(([k, v]) => k && v !== undefined));
    try { setRes((await rules.sandbox(code, { method: req.method, url: req.url, headers, body: req.body })) as SandboxResult & { engine: string }); }
    catch (x) { setErr((x as Error).message); } finally { setBusy(false); }
  };
  return (
    <section className="panel h-fit" aria-labelledby="sb-h">
      <div className="flex items-center justify-between gap-2 border-b border-border px-4 py-3">
        <h2 id="sb-h" className="flex items-center gap-2 text-[13px] font-semibold"><Flask size={16} aria-hidden />Test sandbox</h2>
        <label htmlFor="sb-preset" className="sr-only">Load sample request</label>
        <Select id="sb-preset" className="h-8 text-[12px]" defaultValue="" onChange={(e) => { const p = PRESETS[Number(e.target.value)]; if (p) setReq({ method: p.method, url: p.url, headers: p.headers, body: p.body }); setRes(null); }}>
          <option value="" disabled>Load sample request</option>{PRESETS.map((p, i) => <option key={p.name} value={i}>{p.name}</option>)}
        </Select>
      </div>
      <form onSubmit={run} className="flex flex-col gap-3 p-4">
        <div className="grid grid-cols-[96px_1fr] gap-2">
          <Field label="Method" htmlFor="sb-m"><Select id="sb-m" value={req.method} onChange={(e) => setReq({ ...req, method: e.target.value })}>{["GET", "POST", "PUT", "DELETE"].map((m) => <option key={m}>{m}</option>)}</Select></Field>
          <Field label="Path and query" htmlFor="sb-url"><Input id="sb-url" value={req.url} onChange={(e) => setReq({ ...req, url: e.target.value })} className="font-mono" /></Field>
        </div>
        <Field label="Headers (one per line)" htmlFor="sb-h2"><Textarea id="sb-h2" rows={2} value={req.headers} onChange={(e) => setReq({ ...req, headers: e.target.value })} className="font-mono text-[12px]" /></Field>
        <Field label="Body" htmlFor="sb-body"><Textarea id="sb-body" rows={3} value={req.body} onChange={(e) => setReq({ ...req, body: e.target.value })} className="font-mono text-[12px]" placeholder="key=value&... or JSON" /></Field>
        <Button type="submit" variant="primary" disabled={busy || disabled} title={disabled ? "Fix syntax errors first" : undefined}>{busy ? "Running..." : "Run test"}</Button>
      </form>
      <div className="border-t border-border px-4 py-3" aria-live="polite">
        {err ? <p className="text-[13px] text-crit">{err}</p> : !res ? <p className="text-[12px] text-muted">Send a sample request through this rule before saving. Results show MATCHED or PASSED with the rule IDs that fired.</p> : (
          <div className="flex flex-col gap-2">
            <p className={cn("font-mono text-[16px] font-semibold", res.status === "MATCHED" ? "text-crit" : "text-good")}>{res.status}</p>
            {res.matched.map((m) => (
              <div key={m.ruleId} className="rounded border border-border p-2 text-[12px]">
                <p><span className="font-mono font-semibold">{m.ruleId}</span> {m.msg}</p>
                <p className="mt-1 break-all font-mono text-fg-2">{m.variable} <span className="text-muted">matched</span> <span className="rounded bg-crit/10 px-1 text-crit">{m.data}</span></p>
              </div>
            ))}
            {res.skipped.map((x) => <p key={x} className="text-[12px] text-warn">Not evaluated: {x}</p>)}
            <p className="text-[11px] text-muted">Engine: {res.engine}</p>
          </div>
        )}
      </div>
    </section>
  );
}
