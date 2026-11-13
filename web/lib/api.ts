// API client for the Go Control Plane (PRD 2.1). Every call names its REST path; when NEXT_PUBLIC_API_URL is unset
// the in-browser mock below answers instead, with the same shapes, so swapping in the real backend is config only.
import { stringify, parse } from "yaml";
import * as db from "./mock/data";
import { buildException, evaluate, lint, nextFreeId, type SandboxRequest } from "./seclang";
import { escalation, mapRule, riskScore, stageIndex, classifyOutcome } from "./killchain";
import { parseCidr } from "./utils";
import type {
  AttackEvent, AuditLog, AuditTrailEntry, Campaign, CorrelationSettings, CustomRule, EdgeNode, IpListEntry,
  KillchainMapping, Role, RuleException, Site, StageKey, ThreatFeed, User, Action,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL;
export const usingMock = !BASE;

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

let session: { name: string; role: Role } = { name: "Ahmad", role: "SecOps Analyst" };
export const setSession = (s: typeof session) => { session = s; };

const FAIL_KEY = "coraza.mock.fail";
export const mockFailing = () => { try { return localStorage.getItem(FAIL_KEY) === "1"; } catch { return false; } };
export const setMockFailing = (v: boolean) => { try { if (v) localStorage.setItem(FAIL_KEY, "1"); else localStorage.removeItem(FAIL_KEY); } catch { /* storage blocked */ } };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function call<T>(method: string, path: string, body: unknown, mock: () => T): Promise<T> {
  if (BASE) {
    const res = await fetch(BASE + path, {
      method, credentials: "include",
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 401 && typeof location !== "undefined" && !location.pathname.startsWith("/login")) location.assign("/login");
    if (!res.ok) throw new ApiError(res.status, (await res.text()) || res.statusText);
    return res.json();
  }
  await sleep(150 + Math.random() * 250);
  if (mockFailing()) throw new ApiError(503, "Control plane unreachable (simulated from the user menu)");
  return structuredClone(mock());
}

function requireRole(...roles: Role[]) {
  if (!roles.includes(session.role)) throw new ApiError(403, `${session.role} cannot perform this action`);
}

function audit(action: string, target: string, target_nodes = "-") {
  const e: AuditTrailEntry = { id: db.uuid(), at: new Date().toISOString(), actor: session.name, role: session.role, action, target, source_ip: "10.8.0.14", target_nodes };
  db.auditTrail.unshift(e);
}

const markPending = () => db.nodes.forEach((n) => { if (n.status !== "OFFLINE") n.sync_status = "PENDING_UPDATE"; });
let configVersion = db.CONFIG_VERSION;

// ---------------- Session (NFR-2.2). Real mode only: the mock has no sign-in. ----------------
export const auth = {
  me: () => call<User>("GET", "/api/v1/me", undefined, () => { throw new ApiError(401, "mock session"); }),
  providers: () => call<{ id: string; name: string }[]>("GET", "/auth/providers", undefined, () => []),
  loginUrl: (providerId: string) => `${BASE}/auth/oidc/login?provider=${encodeURIComponent(providerId)}`,
  logout: () => call<{ ok: true; logoutUrl?: string }>("POST", "/auth/logout", {}, () => ({ ok: true })),
};

// ---------------- Fleet (Module 1) ----------------
export const fleet = {
  list: () => call<EdgeNode[]>("GET", "/api/v1/nodes", undefined, () => db.nodes),
  configVersion: () => call<number>("GET", "/api/v1/config/version", undefined, () => configVersion),
  register: (name: string) => call<{ token: string; command: string }>("POST", "/api/v1/nodes/enrollment-tokens", { name }, () => {
    requireRole("Admin");
    if (!/^[a-z0-9-]{3,63}$/.test(name)) throw new ApiError(422, "Use 3-63 lowercase letters, digits or dashes");
    if (db.nodes.some((n) => n.node_name === name)) throw new ApiError(409, `Node ${name} already exists`);
    const token = `cze_${db.hex(32)}`;
    audit("Enrollment token issued", name);
    return { token, command: `coraza-agent enroll \\\n  --control-plane grpcs://control.domain.com:8443 \\\n  --node-name ${name} \\\n  --token ${token}` };
  }),
  /** FR push: bumps the config version; nodes report IN_SYNC on their next heartbeat (mock: immediately). */
  deploy: () => call<{ version: number; synced: number; unreachable: string[] }>("POST", "/api/v1/config/deploy", {}, () => {
    requireRole("Admin");
    configVersion++;
    const unreachable: string[] = [];
    db.nodes.forEach((n) => {
      if (n.status === "OFFLINE") { unreachable.push(n.node_name); return; }
      n.current_config_version = configVersion; n.sync_status = "IN_SYNC";
    });
    audit("Policy deployed", `config v${configVersion}`, `${db.nodes.length - unreachable.length} of ${db.nodes.length}`);
    return { version: configVersion, synced: db.nodes.length - unreachable.length, unreachable };
  }),
};

// ---------------- Policies & rules (Module 2) ----------------
export const policies = {
  sites: () => call<Site[]>("GET", "/api/v1/sites", undefined, () => db.sites),
  updateSite: (id: string, patch: Partial<Pick<Site, "paranoia_level" | "inbound_threshold" | "outbound_threshold" | "crs_categories">>) =>
    call<Site>("PATCH", `/api/v1/sites/${id}`, patch, () => {
      requireRole("Admin");
      const s = db.sites.find((x) => x.id === id);
      if (!s) throw new ApiError(404, "Site not found");
      const th = [patch.inbound_threshold, patch.outbound_threshold].filter((v) => v !== undefined) as number[];
      if (th.some((v) => !Number.isInteger(v) || v < 1 || v > 100)) throw new ApiError(422, "Thresholds must be whole numbers between 1 and 100");
      const changes: string[] = [];
      if (patch.paranoia_level && patch.paranoia_level !== s.paranoia_level) changes.push(`PL${s.paranoia_level} -> PL${patch.paranoia_level}`);
      if (patch.inbound_threshold !== undefined && patch.inbound_threshold !== s.inbound_threshold) changes.push(`inbound ${s.inbound_threshold} -> ${patch.inbound_threshold}`);
      if (patch.outbound_threshold !== undefined && patch.outbound_threshold !== s.outbound_threshold) changes.push(`outbound ${s.outbound_threshold} -> ${patch.outbound_threshold}`);
      if (patch.crs_categories) Object.entries(patch.crs_categories).forEach(([k, v]) => { if (s.crs_categories[k] !== v) changes.push(`${k}xxx ${v ? "on" : "off"}`); });
      Object.assign(s, patch, { updated_at: new Date().toISOString() });
      if (changes.length) { audit("Policy changed", `${s.domain_name}: ${changes.join(", ")}`); markPending(); }
      return s;
    }),
};

export const rules = {
  list: () => call<CustomRule[]>("GET", "/api/v1/rules", undefined, () => db.customRules),
  get: (id: string) => call<CustomRule>("GET", `/api/v1/rules/${id}`, undefined, () => {
    const x = db.customRules.find((r) => r.id === id);
    if (!x) throw new ApiError(404, "Rule not found");
    return x;
  }),
  usedIds: () => call<number[]>("GET", "/api/v1/rules/ids", undefined, () => db.customRules.map((r) => r.rule_id)),
  save: (input: Pick<CustomRule, "name" | "site_id" | "seclang_raw" | "is_active"> & { id?: string }) =>
    call<CustomRule>(input.id ? "PUT" : "POST", input.id ? `/api/v1/rules/${input.id}` : "/api/v1/rules", input, () => {
      requireRole("Admin", "SecOps Analyst");
      const other = db.customRules.filter((r) => r.id !== input.id).map((r) => r.rule_id);
      const errs = lint(input.seclang_raw, { existingIds: other }).filter((d) => d.severity === "error");
      if (errs.length) throw new ApiError(422, `Line ${errs[0].line}: ${errs[0].message}`);
      const idm = input.seclang_raw.match(/id:(\d+)/);
      if (!idm) throw new ApiError(422, "Rule needs an id");
      if (!input.name.trim()) throw new ApiError(422, "Name is required");
      // Analysts write drafts (FR-5.1): their saves are stored inactive until an Admin activates them.
      const active = session.role === "Admin" ? input.is_active : false;
      const now = new Date().toISOString();
      let rule = db.customRules.find((r) => r.id === input.id);
      if (rule) Object.assign(rule, { ...input, is_active: active, rule_id: +idm[1], updated_at: now });
      else {
        rule = { id: db.uuid(), rule_id: +idm[1], created_by: session.name, updated_at: now, ...input, is_active: active };
        db.customRules.unshift(rule);
      }
      audit(input.id ? "Rule updated" : session.role === "Admin" ? "Rule added" : "Rule drafted", `${rule.rule_id} ${rule.name}`);
      markPending();
      return rule;
    }),
  setActive: (id: string, active: boolean) => call<CustomRule>("PATCH", `/api/v1/rules/${id}`, { is_active: active }, () => {
    requireRole("Admin");
    const x = db.customRules.find((r) => r.id === id)!;
    x.is_active = active; x.updated_at = new Date().toISOString();
    audit(active ? "Rule enabled" : "Rule disabled", `${x.rule_id} ${x.name}`); markPending();
    return x;
  }),
  remove: (id: string) => call<{ ok: true }>("DELETE", `/api/v1/rules/${id}`, undefined, () => {
    requireRole("Admin");
    const i = db.customRules.findIndex((r) => r.id === id);
    const [x] = db.customRules.splice(i, 1);
    audit("Rule deleted", `${x.rule_id} ${x.name}`); markPending();
    return { ok: true };
  }),
  /** FR-2.4: the control plane runs Go FTW; the mock uses the in-browser preview evaluator. */
  sandbox: (seclang: string, request: SandboxRequest) => call("POST", "/api/v1/sandbox/ftw", { seclang, request }, () => ({ ...evaluate(seclang, request), engine: "browser preview (mock of Go FTW)" })),
};

export const exceptionsApi = {
  list: () => call<RuleException[]>("GET", "/api/v1/exceptions", undefined, () => db.exceptions),
  preview: (x: { ruleId: number; path: string; parameter: string | null; scope: "endpoint" | "global" }) =>
    buildException({ ...x, exceptionId: nextFreeId(db.exceptions.map((_, i) => 10000 + i), 10000, 19999), comment: `Exception: rule ${x.ruleId} on ${x.path || "all paths"}${x.parameter ? ` for ${x.parameter}` : ""}` }),
  create: (x: { siteId: string; ruleId: number; path: string; parameter: string | null; scope: "endpoint" | "global"; reason: string }) =>
    call<{ exception: RuleException; seclang: string }>("POST", "/api/v1/exceptions", x, () => {
      requireRole("Admin", "SecOps Analyst");
      if (!x.reason.trim()) throw new ApiError(422, "Give a reason so reviewers know why this rule is suppressed");
      if (x.scope === "endpoint" && !x.path.startsWith("/")) throw new ApiError(422, "Path must start with /");
      const site = db.sites.find((s) => s.id === x.siteId)!;
      const e: RuleException = { id: db.uuid(), site_id: x.siteId, rule_id: x.ruleId, path_pattern: x.scope === "global" ? "*" : x.path, parameter_name: x.parameter, reason: x.reason, created_by: session.name, created_at: new Date().toISOString() };
      const seclang = exceptionsApi.preview(x);
      db.exceptions.unshift(e);
      audit("Exception created", `${x.ruleId} @ ${site.domain_name}${x.scope === "global" ? " (global)" : x.path}${x.parameter ? ` ${x.parameter}` : ""}`, "all");
      markPending();
      return { exception: e, seclang };
    }),
  remove: (id: string) => call<{ ok: true }>("DELETE", `/api/v1/exceptions/${id}`, undefined, () => {
    requireRole("Admin");
    const i = db.exceptions.findIndex((e) => e.id === id);
    const [x] = db.exceptions.splice(i, 1);
    audit("Exception removed", `${x.rule_id} ${x.path_pattern}`); markPending();
    return { ok: true };
  }),
};

// ---------------- Logs (Module 3) ----------------
export interface LogQuery { from?: number; to?: number; ip?: string; host?: string; uri?: string; ruleId?: string; action?: Action | ""; status?: string; limit?: number; offset?: number }
export const logs = {
  query: (q: LogQuery) => call<{ rows: AuditLog[]; total: number; tookMs: number }>("POST", "/api/v1/logs/query", q, () => {
    const t0 = performance.now();
    const rows = db.auditLogs.filter((l) => {
      const t = Date.parse(l.timestamp);
      return (!q.from || t >= q.from) && (!q.to || t <= q.to) && (!q.ip || l.client_ip.startsWith(q.ip.trim())) && (!q.host || l.host === q.host) &&
        (!q.uri || l.uri.includes(q.uri)) && (!q.ruleId || l.matched_rule_ids.some((id) => String(id).startsWith(q.ruleId!.trim()))) &&
        (!q.action || l.action_taken === q.action) && (!q.status || String(l.response_status) === q.status.trim());
    });
    const off = q.offset ?? 0;
    return { rows: rows.slice(off, off + (q.limit ?? 50)), total: rows.length, tookMs: +(performance.now() - t0).toFixed(1) };
  }),
  get: (id: string) => call<AuditLog>("GET", `/api/v1/logs/${id}`, undefined, () => {
    const l = db.auditLogs.find((x) => x.id === id);
    if (!l) throw new ApiError(404, "Log not found or past retention");
    return { ...l, campaign_id: db.events.find((e) => e.id === id)?.campaign_id };
  }),
};

// ---------------- Analytics (Module 4) ----------------
export const analytics = {
  overview: (hours: number) => call("GET", `/api/v1/analytics/overview?hours=${hours}`, undefined, () => {
    const from = Date.now() - hours * 3600_000;
    const series = db.traffic.filter((p) => p.t >= from);
    const evs = db.events.filter((e) => e.timestamp >= from);
    const total = series.reduce((a, p) => a + p.total, 0) * 300;
    const blocked = evs.filter((e) => e.outcome === "BLOCKED").length + series.reduce((a, p) => a + p.blocked, 0);
    const count = <K extends string | number>(f: (e: AttackEvent) => K) => {
      const m = new Map<K, number>();
      evs.forEach((e) => m.set(f(e), (m.get(f(e)) ?? 0) + 1));
      return [...m.entries()].sort((a, b) => b[1] - a[1]);
    };
    const live = db.nodes.filter((n) => n.status !== "OFFLINE");
    return {
      rps: Math.round(series.at(-1)?.total ?? 0),
      totalRequests: total,
      blocked,
      blockRatio: total ? (blocked / total) * 100 : 0,
      avgLatencyMs: live.reduce((a, n) => a + n.latency_ms, 0) / Math.max(live.length, 1),
      series,
      topRules: count((e) => e.rule_id).slice(0, 10).map(([id, n]) => ({ id: id as number, n, msg: db.ruleMeta(id as number).msg, category: mapRule(id as number)?.rule_category })),
      topEndpoints: count((e) => `${e.host}${e.uri.split("?")[0]}`).slice(0, 8).map(([k, n]) => ({ endpoint: k as string, n })),
      topIps: count((e) => e.client_ip).slice(0, 8).map(([ip, n]) => {
        const e = evs.find((x) => x.client_ip === ip)!;
        return { ip: ip as string, n, cc: e.country_code, asn: e.asn };
      }),
      possiblySuccessful: evs.filter((e) => e.outcome === "POSSIBLY_SUCCESSFUL").length,
    };
  }),
};

// ---------------- IP reputation (FR-4.2) ----------------
export const ipLists = {
  list: () => call<IpListEntry[]>("GET", "/api/v1/ip-lists", undefined, () => db.ipList),
  add: (x: { cidr: string; list: "block" | "allow"; reason: string; ttlHours: number | null }) => call<IpListEntry>("POST", "/api/v1/ip-lists", x, () => {
    requireRole("Admin", "SecOps Analyst");
    const c = parseCidr(x.cidr);
    if (!c) throw new ApiError(422, `"${x.cidr}" is not a valid IPv4 address or CIDR`);
    const norm = c.normalized;
    const dup = db.ipList.find((e) => e.cidr === norm && e.list === x.list);
    if (dup) throw new ApiError(409, `${norm} is already on the ${x.list}list`);
    const e: IpListEntry = { id: db.uuid(), cidr: norm, list: x.list, source: "manual", reason: x.reason || "-", expires_at: x.ttlHours ? new Date(Date.now() + x.ttlHours * 3600_000).toISOString() : null, created_by: session.name, created_at: new Date().toISOString() };
    db.ipList.unshift(e);
    audit(x.list === "block" ? "IP blocked" : "IP allowed", `${norm}${x.ttlHours ? ` (TTL ${x.ttlHours}h)` : ""}`, "all");
    markPending();
    return e;
  }),
  remove: (id: string) => call<{ ok: true }>("DELETE", `/api/v1/ip-lists/${id}`, undefined, () => {
    requireRole("Admin", "SecOps Analyst");
    const i = db.ipList.findIndex((e) => e.id === id);
    const [x] = db.ipList.splice(i, 1);
    audit(x.list === "block" ? "IP unblocked" : "Allowlist entry removed", x.cidr, "all"); markPending();
    return { ok: true };
  }),
  /** Impact preview for Block actions (FR-6.15): legitimate (no rule matched) requests seen from this source, 30 days. */
  impact: (cidr: string) => call<{ legitRequests: number; attackEvents: number; campaigns: number }>("GET", `/api/v1/ip-lists/impact?cidr=${encodeURIComponent(cidr)}`, undefined, () => {
    const c = parseCidr(cidr);
    const evs = c ? db.events.filter((e) => c.contains(e.client_ip)) : [];
    const seed = [...cidr].reduce((a, ch) => a + ch.charCodeAt(0), 0);
    return { legitRequests: c && c.bits < 32 ? 1200 + (seed % 900) : seed % 7 === 0 ? 14 : 0, attackEvents: evs.length, campaigns: new Set(evs.map((e) => e.campaign_id)).size };
  }),
  feeds: () => call<ThreatFeed[]>("GET", "/api/v1/threat-feeds", undefined, () => db.feeds),
  addFeed: (x: { name: string; url: string; format: "text" | "csv"; interval_minutes: number }) => call<ThreatFeed>("POST", "/api/v1/threat-feeds", x, () => {
    requireRole("Admin");
    let u: URL;
    try { u = new URL(x.url); } catch { throw new ApiError(422, "Enter a full URL, including https://"); }
    if (u.protocol !== "https:") throw new ApiError(422, "Feeds must be served over HTTPS");
    if (!x.name.trim()) throw new ApiError(422, "Name is required");
    const f: ThreatFeed = { id: db.uuid(), ...x, last_pulled: null, entries: 0, status: "NEVER" };
    db.feeds.push(f);
    audit("Threat feed added", `${x.name} (${u.host})`);
    return f;
  }),
  pullFeed: (id: string) => call<ThreatFeed>("POST", `/api/v1/threat-feeds/${id}/pull`, {}, () => {
    requireRole("Admin");
    const f = db.feeds.find((x) => x.id === id)!;
    f.last_pulled = new Date().toISOString();
    if (f.url.includes("abuse.csv")) { f.status = "ERROR"; f.error = "HTTP 404 from feed URL"; }
    else { f.status = "OK"; f.error = undefined; f.entries = f.entries || 312; }
    audit("Threat feed pulled", f.name);
    return f;
  }),
  removeFeed: (id: string) => call<{ ok: true }>("DELETE", `/api/v1/threat-feeds/${id}`, undefined, () => {
    requireRole("Admin");
    const i = db.feeds.findIndex((x) => x.id === id);
    const [f] = db.feeds.splice(i, 1);
    audit("Threat feed removed", f.name);
    return { ok: true };
  }),
};

// ---------------- Admin (Module 5) ----------------
export const admin = {
  trail: () => call<AuditTrailEntry[]>("GET", "/api/v1/audit-trail", undefined, () => db.auditTrail),
  users: () => call<User[]>("GET", "/api/v1/users", undefined, () => db.users),
  setRole: (id: string, role: Role) => call<User>("PATCH", `/api/v1/users/${id}`, { role }, () => {
    requireRole("Admin");
    const u = db.users.find((x) => x.id === id)!;
    if (u.role === "Admin" && role !== "Admin" && db.users.filter((x) => x.role === "Admin").length === 1) throw new ApiError(409, "At least one Admin must remain");
    audit("Role changed", `${u.email}: ${u.role} -> ${role}`);
    u.role = role;
    return u;
  }),
  exportPolicy: () => call<string>("GET", "/api/v1/gitops/export", undefined, () => stringify({
    apiVersion: "coraza.console/v1",
    kind: "CorazaPolicy",
    metadata: { configVersion, exportedAt: new Date().toISOString() },
    sites: db.sites.map((s) => ({
      domain: s.domain_name, name: s.name, paranoiaLevel: s.paranoia_level,
      anomalyThreshold: { inbound: s.inbound_threshold, outbound: s.outbound_threshold },
      crs: { disabledCategories: Object.entries(s.crs_categories).filter(([, v]) => !v).map(([k]) => `${k}xxx`) },
      exceptions: db.exceptions.filter((e) => e.site_id === s.id).map((e) => ({ ruleId: e.rule_id, path: e.path_pattern, parameter: e.parameter_name ?? undefined, reason: e.reason })),
    })),
    customRules: db.customRules.map((r) => ({ id: r.rule_id, name: r.name, site: db.sites.find((s) => s.id === r.site_id)?.domain_name ?? "*", active: r.is_active, seclang: r.seclang_raw })),
    ipLists: { block: db.ipList.filter((e) => e.list === "block").map((e) => e.cidr), allow: db.ipList.filter((e) => e.list === "allow").map((e) => e.cidr) },
  }, { lineWidth: 0 })),
  /** Validates a coraza-policy.yaml (same checks the CI CLI runs) and returns a change summary without applying it. */
  validatePolicy: (text: string) => call<{ ok: boolean; errors: string[]; summary: string[] }>("POST", "/api/v1/gitops/validate", { text }, () => {
    const errors: string[] = [];
    const summary: string[] = [];
    let doc: Record<string, unknown>;
    try { doc = parse(text) ?? {}; } catch (e) { return { ok: false, errors: [`YAML: ${(e as Error).message.split("\n")[0]}`], summary }; }
    if (doc.kind !== "CorazaPolicy") errors.push('kind must be "CorazaPolicy"');
    const sites = (doc.sites as Record<string, unknown>[] | undefined) ?? [];
    sites.forEach((s, i) => {
      const pl = s.paranoiaLevel as number;
      if (![1, 2, 3, 4].includes(pl)) errors.push(`sites[${i}].paranoiaLevel must be 1-4`);
      const cur = db.sites.find((x) => x.domain_name === s.domain);
      if (!cur) summary.push(`+ new site ${s.domain}`);
      else if (cur.paranoia_level !== pl) summary.push(`~ ${s.domain}: PL${cur.paranoia_level} -> PL${pl}`);
    });
    const crs = (doc.customRules as { id: number; seclang: string }[] | undefined) ?? [];
    const ids: number[] = [];
    crs.forEach((r, i) => {
      lint(r.seclang ?? "", { existingIds: ids }).filter((d) => d.severity === "error").forEach((d) => errors.push(`customRules[${i}] (id ${r.id}) line ${d.line}: ${d.message}`));
      ids.push(r.id);
      if (!db.customRules.some((x) => x.rule_id === r.id)) summary.push(`+ rule ${r.id}`);
    });
    db.customRules.filter((x) => !ids.includes(x.rule_id)).forEach((x) => summary.push(`- rule ${x.rule_id}`));
    if (!summary.length && !errors.length) summary.push("No changes against the running policy");
    return { ok: errors.length === 0, errors, summary };
  }),
  killchainMapping: () => call<KillchainMapping[]>("GET", "/api/v1/killchain-mapping", undefined, () => db.killchainMapping),
  saveMapping: (m: KillchainMapping) => call<KillchainMapping>("PUT", `/api/v1/killchain-mapping/${m.id}`, m, () => {
    requireRole("Admin");
    if (m.rule_id_from > m.rule_id_to) throw new ApiError(422, "Range start must be <= end");
    if (db.killchainMapping.some((x) => x.id !== m.id && x.rule_id_from === m.rule_id_from && x.rule_id_to === m.rule_id_to)) throw new ApiError(409, "That rule range is already mapped");
    const i = db.killchainMapping.findIndex((x) => x.id === m.id);
    if (i < 0) db.killchainMapping.push(m); else db.killchainMapping[i] = m;
    audit("Kill chain mapping changed", `${m.rule_id_from}-${m.rule_id_to} -> ${m.killchain_stage}`);
    return m;
  }),
  correlation: () => call<CorrelationSettings[]>("GET", "/api/v1/correlation-settings", undefined, () => db.correlationSettings),
  saveCorrelation: (c: CorrelationSettings) => call<CorrelationSettings>("PUT", `/api/v1/correlation-settings/${c.site_id}`, c, () => {
    requireRole("Admin");
    if (c.idle_timeout_minutes < 1 || c.idle_timeout_minutes > 1440) throw new ApiError(422, "Idle timeout must be 1-1440 minutes");
    if (c.min_events_to_open < 1 || c.min_events_to_open > 1000) throw new ApiError(422, "Minimum events must be 1-1000");
    const i = db.correlationSettings.findIndex((x) => x.site_id === c.site_id);
    db.correlationSettings[i] = c;
    audit("Correlation settings changed", `${db.sites.find((s) => s.id === c.site_id)?.domain_name}: ${c.actor_key_mode}, ${c.idle_timeout_minutes}m, min ${c.min_events_to_open}`);
    return c;
  }),
};

// ---------------- Attack mapping (Module 6) ----------------
export interface AttackQuery { from?: number; to?: number; siteId?: string }
export const attacks = {
  campaigns: () => call<Campaign[]>("GET", "/api/v1/campaigns", undefined, () => [...db.campaigns].sort((a, b) => b.last_seen - a.last_seen)),
  events: (q: AttackQuery) => call<AttackEvent[]>("GET", `/api/v1/attack-events?from=${q.from ?? ""}&to=${q.to ?? ""}`, undefined, () =>
    db.events.filter((e) => (!q.from || e.timestamp >= q.from) && (!q.to || e.timestamp <= q.to) && (!q.siteId || e.site_id === q.siteId))),
  campaign: (id: string) => call<{ campaign: Campaign; events: AttackEvent[] }>("GET", `/api/v1/campaigns/${id}`, undefined, () => {
    const c = db.campaigns.find((x) => x.id === id);
    if (!c) throw new ApiError(404, "Campaign not found");
    return { campaign: c, events: db.events.filter((e) => e.campaign_id === id) };
  }),
  update: (id: string, patch: { status?: Campaign["status"]; assignee?: string | null; note?: string }) => call<Campaign>("PATCH", `/api/v1/campaigns/${id}`, patch, () => {
    requireRole("Admin", "SecOps Analyst");
    const c = db.campaigns.find((x) => x.id === id)!;
    if (patch.status) { audit(patch.status === "FALSE_POSITIVE" ? "Campaign marked false positive" : `Campaign ${patch.status.toLowerCase()}`, id); c.status = patch.status; }
    if (patch.assignee !== undefined) { audit("Campaign assigned", `${id} -> ${patch.assignee ?? "unassigned"}`); c.assignee = patch.assignee; }
    if (patch.note?.trim()) { c.notes.push({ author: session.name, at: Date.now(), text: patch.note.trim() }); audit("Note added", id); }
    return c;
  }),
};

// ---------------- Live attack stream (WebSocket /ws/attacks; mock emitter below) ----------------
export type StreamMsg = { event: AttackEvent; log: AuditLog; campaign: Campaign; isNewCampaign: boolean; escalatedTo: StageKey | null };
type Listener = (m: StreamMsg) => void;
const listeners = new Set<Listener>();
let timer: ReturnType<typeof setInterval> | null = null;
let ws: WebSocket | null = null;

// Scripted newcomer so the live view shows a campaign opening and escalating (Recon -> Delivery -> Exploitation).
const NEWCOMERS = [
  { ip: "198.51.100.201", cc: "SG", asn: 64590, as_name: "AS64590 Sample VPS H", geo: [103.8, 1.3] as [number, number] },
  { ip: "203.0.113.57", cc: "KR", asn: 64591, as_name: "AS64591 Sample VPS I", geo: [126.98, 37.57] as [number, number] },
  { ip: "192.0.2.150", cc: "FR", asn: 64592, as_name: "AS64592 Sample Cloud J", geo: [2.35, 48.86] as [number, number] },
];
const NEW_SCRIPT: { stage: StageKey; rule: number; host: string; uris: string[]; action: Action; okRatio?: number; method?: string; n: number }[] = [
  { stage: "RECON", rule: 913100, host: "portal.domain.com", uris: ["/.env", "/config.json", "/admin/"], action: "DENY", n: 4 },
  { stage: "DELIVERY", rule: 920270, host: "portal.domain.com", uris: ["/account/profile"], action: "DENY", n: 2, method: "POST" },
  { stage: "EXPLOIT", rule: 942100, host: "portal.domain.com", uris: ["/account/profile"], action: "DENY", n: 3, method: "POST" },
  { stage: "EXPLOIT", rule: 942190, host: "portal.domain.com", uris: ["/reports?sort=1"], action: "LOG", okRatio: 1, n: 1 },
];
let newcomer = { idx: 0, step: 0, i: 0 };

function correlate(ev: AttackEvent, log: AuditLog, actor: { as_name: string; geo: [number, number] }): StreamMsg {
  const settings = db.correlationSettings.find((s) => s.site_id === ev.site_id)!;
  const idle = settings.idle_timeout_minutes * 60_000;
  const key = ev.client_ip.startsWith("203.0.113.") && ev.client_ip !== "203.0.113.57" ? "203.0.113.0/24" : ev.client_ip;
  let c = db.campaigns.find((x) => x.actor_key === key && x.status !== "CLOSED" && x.status !== "FALSE_POSITIVE" && ev.timestamp - x.last_seen < idle);
  const isNew = !c;
  if (!c) {
    const d = new Date(ev.timestamp).toISOString().slice(0, 10).replace(/-/g, "");
    c = {
      id: `cmp_${d}_${String(db.int(1000, 9999))}`, actor_key: key, actor_mode: "IP", country_code: ev.country_code, asn: ev.asn, as_name: actor.as_name, geo: actor.geo,
      correlation_confidence: "HIGH", first_seen: ev.timestamp, last_seen: ev.timestamp, highest_stage: ev.killchain_stage, stages: [ev.killchain_stage],
      risk_score: 0, event_count: 0, status: "ACTIVE", assignee: null, notes: [], targets: [], possibly_successful: 0,
    };
    db.campaigns.unshift(c);
  }
  ev.campaign_id = c.id;
  const esc = isNew ? null : escalation(c, ev.killchain_stage);
  c.event_count++;
  c.last_seen = ev.timestamp;
  if (!c.stages.includes(ev.killchain_stage)) c.stages = [...c.stages, ev.killchain_stage].sort((a, b) => stageIndex(a) - stageIndex(b));
  if (esc) c.highest_stage = esc;
  if (ev.outcome === "POSSIBLY_SUCCESSFUL") c.possibly_successful++;
  const target = `${ev.host}${ev.uri.split("?")[0]}`;
  if (!c.targets.includes(target)) c.targets.push(target);
  const evs = db.events.filter((e) => e.campaign_id === c!.id);
  c.risk_score = riskScore({ highestStage: c.highest_stage, targets: c.targets.length, categories: new Set([...evs, ev].map((e) => e.rule_category)).size, possiblySuccessful: c.possibly_successful, events: c.event_count });
  db.events.push(ev);
  db.auditLogs.unshift(log);
  return { event: ev, log, campaign: structuredClone(c), isNewCampaign: isNew, escalatedTo: esc };
}

function tick() {
  const out: StreamMsg[] = [];
  // Newcomer script advances on about half the ticks, so a full Recon -> Exploitation run takes ~1 minute.
  if (db.rand() < 0.5) {
  const nc = NEWCOMERS[newcomer.idx % NEWCOMERS.length];
  const st = NEW_SCRIPT[newcomer.step];
  const { ev, log } = db.makeEvent({ ...nc, ua: "Mozilla/5.0 (compatible; scanner)" }, { ...st, spanMin: 1 }, Date.now(), "", newcomer.i);
  ev.outcome = classifyOutcome(st.action, ev.response_status);
  out.push(correlate(ev, log, nc));
  if (++newcomer.i >= st.n) { newcomer.i = 0; newcomer.step++; }
  if (newcomer.step >= NEW_SCRIPT.length) newcomer = { idx: newcomer.idx + 1, step: 0, i: 0 };
  }
  // Existing active actors continue their latest step.
  if (db.rand() < 0.75) {
    const a = db.pick(db.LIVE_ACTORS);
    const step = a.steps[a.steps.length - 1 - (db.rand() < 0.3 ? 1 : 0)] ?? a.steps[0];
    const ip = db.pick(a.ips);
    const r2 = db.makeEvent({ ip, cc: a.cc, asn: a.asn, geo: a.geo, ua: a.ua }, step, Date.now(), "", db.int(0, 9));
    out.push(correlate(r2.ev, r2.log, a));
  }
  out.forEach((m) => listeners.forEach((l) => l(m)));
}

export function subscribeAttackStream(fn: Listener) {
  listeners.add(fn);
  if (BASE && !ws) {
    connect();
  } else if (!BASE && !timer) {
    timer = setInterval(tick, 1800);
  }
  return () => {
    listeners.delete(fn);
    if (!listeners.size) { if (timer) clearInterval(timer); timer = null; if (retry) clearTimeout(retry); retry = null; const w = ws; ws = null; w?.close(); }
  };
}

// The stream reconnects on its own: a control plane restart must not leave the console silently stale.
let retry: ReturnType<typeof setTimeout> | null = null;
function connect() {
  const sock = new WebSocket(BASE!.replace(/^http/, "ws") + "/ws/attacks");
  ws = sock;
  sock.onmessage = (e) => { const m = JSON.parse(e.data) as StreamMsg; listeners.forEach((l) => l(m)); };
  sock.onclose = () => { if (ws === sock && listeners.size) retry = setTimeout(connect, 3000); };
}
