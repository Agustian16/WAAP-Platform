// SecLang tooling used by the Rule Editor (FR-2.3), Test Sandbox (FR-2.4) and One-Click Exception (FR-3.3).
// Pure functions, no DOM. Covered by lib/seclang.test.ts (run: npm test).

export type Diagnostic = { line: number; endLine: number; severity: "error" | "warning"; message: string };

export const DIRECTIVES = [
  "SecRule", "SecAction", "SecMarker", "SecDefaultAction", "SecRuleEngine", "SecRuleRemoveById", "SecRuleRemoveByTag",
  "SecRuleRemoveByMsg", "SecRuleUpdateTargetById", "SecRuleUpdateTargetByTag", "SecRuleUpdateActionById",
  "SecRequestBodyAccess", "SecResponseBodyAccess", "SecRequestBodyLimit", "SecComponentSignature", "Include",
];

export const VARIABLES = [
  "ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_POST", "ARGS_GET_NAMES", "ARGS_POST_NAMES", "ARGS_COMBINED_SIZE",
  "QUERY_STRING", "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_LINE",
  "REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_COOKIES",
  "REQUEST_COOKIES_NAMES", "REQUEST_BODY", "REQUEST_BODY_LENGTH", "REQBODY_ERROR", "REQBODY_PROCESSOR", "FILES", "FILES_NAMES",
  "RESPONSE_BODY", "RESPONSE_STATUS", "RESPONSE_HEADERS", "RESPONSE_CONTENT_TYPE", "REMOTE_ADDR", "REMOTE_PORT",
  "TX", "IP", "GEO", "XML", "MATCHED_VAR", "MATCHED_VARS", "MATCHED_VAR_NAME", "MATCHED_VARS_NAMES", "UNIQUE_ID",
  "DURATION", "MULTIPART_STRICT_ERROR", "SERVER_NAME", "AUTH_TYPE",
];

export const OPERATORS = [
  "rx", "pm", "pmFromFile", "contains", "containsWord", "streq", "strmatch", "beginsWith", "endsWith", "within",
  "eq", "ge", "gt", "le", "lt", "ipMatch", "ipMatchFromFile", "detectSQLi", "detectXSS", "validateByteRange",
  "validateUrlEncoding", "validateUtf8Encoding", "unconditionalMatch", "noMatch", "geoLookup", "rbl", "restpath",
];

export const ACTIONS = [
  "id", "phase", "deny", "block", "pass", "allow", "drop", "redirect", "status", "msg", "logdata", "tag", "severity",
  "t", "log", "nolog", "auditlog", "noauditlog", "chain", "ctl", "setvar", "capture", "skipAfter", "skip", "ver", "rev",
  "accuracy", "maturity", "multiMatch", "initcol", "expirevar", "exec", "sanitiseArg", "sanitiseMatched", "append",
];
const DISRUPTIVE = ["deny", "block", "pass", "allow", "drop", "redirect"];
const SEVERITIES = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"];
export const TRANSFORMS = [
  "none", "lowercase", "uppercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode",
  "base64Decode", "hexDecode", "trim", "compressWhitespace", "removeWhitespace", "removeNulls", "replaceComments",
  "normalizePath", "normalisePath", "cmdLine", "length", "utf8toUnicode", "sha1", "md5",
];

/** Join backslash-continued lines into logical statements, remembering their line span. */
function statements(src: string) {
  const out: { text: string; line: number; endLine: number }[] = [];
  const lines = src.split(/\r?\n/);
  let buf = "";
  let start = -1;
  lines.forEach((raw, i) => {
    const l = raw.trimEnd();
    if (start < 0) {
      if (!l.trim() || l.trim().startsWith("#")) return;
      start = i + 1;
    }
    if (l.endsWith("\\")) buf += l.slice(0, -1) + " ";
    else {
      buf += l;
      out.push({ text: buf.trim(), line: start, endLine: i + 1 });
      buf = "";
      start = -1;
    }
  });
  if (start > 0) out.push({ text: buf.trim(), line: start, endLine: lines.length });
  return out;
}

/** Split on whitespace, keeping double-quoted strings (with \" escapes) as single tokens (quotes stripped). */
export function tokenize(s: string): { tokens: string[]; unbalanced: boolean } {
  const tokens: string[] = [];
  let i = 0;
  while (i < s.length) {
    if (/\s/.test(s[i])) { i++; continue; }
    if (s[i] === '"') {
      let j = i + 1, t = "";
      while (j < s.length && s[j] !== '"') {
        if (s[j] === "\\" && s[j + 1] === '"') { t += '"'; j += 2; continue; }
        t += s[j++];
      }
      if (j >= s.length) return { tokens: [...tokens, t], unbalanced: true };
      tokens.push(t);
      i = j + 1;
    } else {
      let j = i;
      while (j < s.length && !/\s/.test(s[j])) j++;
      const t = s.slice(i, j);
      if (t.includes('"')) return { tokens: [...tokens, t], unbalanced: true };
      tokens.push(t);
      i = j;
    }
  }
  return { tokens, unbalanced: false };
}

/** Split an action list on commas that are not inside single quotes. */
export function splitActions(s: string) {
  const out: string[] = [];
  let cur = "", q = false;
  for (const ch of s) {
    if (ch === "'") q = !q;
    if (ch === "," && !q) { if (cur.trim()) out.push(cur.trim()); cur = ""; } else cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function parseActions(s: string) {
  return splitActions(s).map((a) => {
    const k = a.indexOf(":");
    const name = k < 0 ? a : a.slice(0, k);
    let value = k < 0 ? "" : a.slice(k + 1);
    if (value.startsWith("'") && value.endsWith("'")) value = value.slice(1, -1);
    return { name: name.trim(), value };
  });
}

/** Convert a Go/PCRE-style regex (inline (?i)) into a JS RegExp. Throws on invalid syntax. */
export function toJsRegex(pattern: string) {
  let flags = "";
  let p = pattern;
  const m = p.match(/^\(\?([a-z]+)\)/);
  if (m) {
    if (m[1].includes("i")) flags += "i";
    if (m[1].includes("s")) flags += "s";
    if (m[1].includes("m")) flags += "m";
    p = p.slice(m[0].length);
  }
  return new RegExp(p, flags);
}

export function lint(src: string, opts: { existingIds?: number[] } = {}): Diagnostic[] {
  const diags: Diagnostic[] = [];
  const seen = new Set<number>(opts.existingIds ?? []);
  let chainOpen = false;
  const srcLines = src.split(/\r?\n/);
  for (const st of statements(src)) {
    // Point at the physical line holding `near` when given, so markers land on the offending action.
    const d = (severity: Diagnostic["severity"], message: string, near?: string) => {
      let line = st.line;
      if (near) for (let i = st.line; i <= st.endLine; i++) if (srcLines[i - 1]?.includes(near)) { line = i; break; }
      diags.push({ line, endLine: near ? line : st.endLine, severity, message });
    };
    const { tokens, unbalanced } = tokenize(st.text);
    if (unbalanced) { d("error", "Unbalanced double quote"); continue; }
    const [dir, ...args] = tokens;
    if (!DIRECTIVES.includes(dir)) { d("error", `Unknown directive "${dir}"`); continue; }

    if (dir === "SecRule" || dir === "SecAction") {
      const need = dir === "SecRule" ? 3 : 1;
      if (args.length < need) { d("error", `${dir} expects ${dir === "SecRule" ? "VARIABLES \"OPERATOR\" \"ACTIONS\"" : "\"ACTIONS\""}`); continue; }
      if (args.length > need) { d("error", `Unexpected extra argument "${args[need]}" (missing quotes?)`); continue; }
      if (dir === "SecRule") {
        for (const v of args[0].split("|")) {
          const name = v.replace(/^[!&]/, "").split(":")[0];
          if (!VARIABLES.includes(name)) d("warning", `Unknown variable "${name}"`);
        }
        const op = args[1].replace(/^!/, "");
        if (op.startsWith("@")) {
          const opName = op.slice(1).split(/\s/)[0];
          if (!OPERATORS.includes(opName)) d("error", `Unknown operator "@${opName}"`);
          if (opName === "rx") {
            try { toJsRegex(op.slice(3).trim()); } catch (e) { d("error", `Invalid regex: ${(e as Error).message}`); }
          }
        } else {
          try { toJsRegex(op); } catch (e) { d("error", `Invalid regex: ${(e as Error).message}`); }
        }
      }
      const actions = parseActions(args[args.length - 1]);
      const names = actions.map((a) => a.name);
      for (const a of actions) {
        const at = a.value ? `${a.name}:` : a.name;
        if (!ACTIONS.includes(a.name)) d("error", `Unknown action "${a.name}"`, a.name);
        if (a.name === "phase" && !/^([1-5]|request|response|logging)$/.test(a.value)) d("error", `Invalid phase "${a.value}" (1-5)`, at);
        if (a.name === "severity" && !SEVERITIES.includes(a.value.toUpperCase()) && !/^[0-7]$/.test(a.value)) d("error", `Invalid severity "${a.value}"`, at);
        if (a.name === "status" && !/^[1-5]\d\d$/.test(a.value)) d("error", `Invalid status "${a.value}"`, at);
        if (a.name === "t" && !TRANSFORMS.includes(a.value)) d("warning", `Unknown transformation "${a.value}"`, `t:${a.value}`);
      }
      const isChained = chainOpen;
      if (isChained) {
        if (names.includes("id")) d("error", "Chained rule must not declare id");
      } else {
        const idA = actions.find((a) => a.name === "id");
        if (!idA) d("error", "Missing required action: id");
        else if (!/^\d+$/.test(idA.value) || +idA.value < 1) d("error", `Invalid id "${idA.value}"`, "id:");
        else if (seen.has(+idA.value)) d("error", `Duplicate rule id ${idA.value}`, `id:${idA.value}`);
        else seen.add(+idA.value);
        if (dir === "SecRule" && !names.includes("phase")) d("warning", "No phase set; defaults to phase 2");
      }
      if (names.filter((n) => DISRUPTIVE.includes(n)).length > 1) d("warning", "More than one disruptive action; only the last applies");
      if (names.includes("msg") === false && !isChained && names.some((n) => n === "deny" || n === "block")) d("warning", "Blocking rule without msg is hard to triage");
      chainOpen = names.includes("chain");
    } else if (dir === "SecRuleRemoveById" || dir === "SecRuleUpdateTargetById") {
      if (!args[0] || !/^\d+(-\d+)?$/.test(args[0])) d("error", `${dir} expects a rule id or id range`);
    }
  }
  if (chainOpen) diags.push({ line: statements(src).at(-1)?.line ?? 1, endLine: statements(src).at(-1)?.endLine ?? 1, severity: "error", message: "Rule declares chain but no rule follows" });
  return diags;
}

// ---------- Visual builder (FR-2.3 GUI mode) ----------

export interface BuilderRule {
  id: number;
  variables: string[];
  operator: string;
  value: string;
  negate: boolean;
  transforms: string[];
  phase: number;
  action: "deny" | "block" | "pass" | "log";
  status: number;
  severity: string;
  msg: string;
  tags: string[];
}

const esc = (s: string) => s.replace(/"/g, '\\"');

export function buildRule(r: BuilderRule) {
  const op = `${r.negate ? "!" : ""}@${r.operator}${r.value ? " " + r.value : ""}`;
  const acts = [
    `id:${r.id}`,
    `phase:${r.phase}`,
    r.action === "log" ? "pass" : r.action,
    ...(r.action === "deny" ? [`status:${r.status}`] : []),
    ...r.transforms.map((t) => `t:${t}`),
    "log",
    `msg:'${r.msg.replace(/'/g, "")}'`,
    "logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}'",
    ...r.tags.map((t) => `tag:'${t}'`),
    `severity:'${r.severity}'`,
  ];
  return `SecRule ${r.variables.join("|")} "${esc(op)}" \\\n    "${acts.join(",\\\n    ")}"`;
}

/** Best-effort reverse of buildRule so Code mode -> Visual mode keeps edits. Returns null for rules the GUI cannot express. */
export function parseToBuilder(src: string): BuilderRule | null {
  const sts = statements(src).filter((s) => s.text.startsWith("SecRule"));
  if (sts.length !== 1) return null;
  const { tokens, unbalanced } = tokenize(sts[0].text);
  if (unbalanced || tokens.length !== 4) return null;
  const [, vars, opRaw, actRaw] = tokens;
  const negate = opRaw.startsWith("!");
  const op = opRaw.replace(/^!/, "");
  const m = op.match(/^@(\w+)\s?([\s\S]*)$/);
  const acts = parseActions(actRaw);
  if (acts.some((a) => a.name === "chain")) return null;
  const get = (n: string) => acts.find((a) => a.name === n)?.value;
  const disruptive = acts.find((a) => DISRUPTIVE.includes(a.name))?.name ?? "pass";
  return {
    id: Number(get("id") ?? 0),
    variables: vars.split("|"),
    operator: m ? m[1] : "rx",
    value: m ? m[2] : op,
    negate,
    transforms: acts.filter((a) => a.name === "t").map((a) => a.value),
    phase: Number(get("phase") ?? 2),
    action: (disruptive === "pass" ? "log" : disruptive) as BuilderRule["action"],
    status: Number(get("status") ?? 403),
    severity: (get("severity") ?? "CRITICAL").toUpperCase(),
    msg: get("msg") ?? "",
    tags: acts.filter((a) => a.name === "tag").map((a) => a.value),
  };
}

// ---------- One-click exception (FR-3.3) ----------

export interface ExceptionInput {
  ruleId: number;
  path: string; // exact path, or prefix ending with *
  parameter?: string | null; // e.g. ARGS:username; null removes the whole rule for the path
  scope: "endpoint" | "global";
  exceptionId: number;
  comment?: string;
}

export function buildException(x: ExceptionInput) {
  const header = `# ${x.comment ?? `Exception for rule ${x.ruleId}`}`;
  if (x.scope === "global") {
    if (!x.parameter) return `${header}\nSecRuleRemoveById ${x.ruleId}`;
    return `${header}\nSecRuleUpdateTargetById ${x.ruleId} "!${x.parameter}"`;
  }
  const prefix = x.path.endsWith("*");
  const op = prefix ? `@beginsWith ${x.path.slice(0, -1)}` : `@streq ${x.path}`;
  const ctl = x.parameter ? `ctl:ruleRemoveTargetById=${x.ruleId};${x.parameter}` : `ctl:ruleRemoveById=${x.ruleId}`;
  return `${header}\nSecRule REQUEST_FILENAME "${op}" \\\n    "id:${x.exceptionId},phase:1,pass,nolog,${ctl}"`;
}

export function nextFreeId(used: number[], from: number, to: number) {
  const s = new Set(used);
  for (let i = from; i <= to; i++) if (!s.has(i)) return i;
  throw new Error(`No free rule id in ${from}-${to}`);
}

// ---------- Sandbox preview evaluator (FR-2.4) ----------

export interface SandboxRequest { method: string; url: string; headers: Record<string, string>; body: string }
export interface SandboxResult { status: "MATCHED" | "PASSED"; matched: { ruleId: number; variable: string; data: string; msg: string }[]; skipped: string[] }

function collect(req: SandboxRequest) {
  const u = new URL(req.url, "http://sandbox.local");
  const vars: Record<string, [string, string][]> = {};
  const add = (col: string, name: string, v: string) => (vars[col] ??= []).push([name, v]);
  const post = new URLSearchParams(/=/.test(req.body) && !req.body.trim().startsWith("{") ? req.body : "");
  u.searchParams.forEach((v, k) => { add("ARGS", k, v); add("ARGS_GET", k, v); add("ARGS_NAMES", k, k); });
  post.forEach((v, k) => { add("ARGS", k, v); add("ARGS_POST", k, v); add("ARGS_NAMES", k, k); });
  if (req.body.trim().startsWith("{")) {
    try {
      const walk = (o: unknown, p: string) => {
        if (o && typeof o === "object") Object.entries(o).forEach(([k, v]) => walk(v, p ? `${p}.${k}` : `json.${k}`));
        else { add("ARGS", p, String(o)); add("ARGS_POST", p, String(o)); add("ARGS_NAMES", p, p); }
      };
      walk(JSON.parse(req.body), "");
    } catch { /* body stays available as REQUEST_BODY */ }
  }
  Object.entries(req.headers).forEach(([k, v]) => { add("REQUEST_HEADERS", k, v); add("REQUEST_HEADERS_NAMES", k, k); });
  (req.headers.Cookie ?? req.headers.cookie ?? "").split(";").filter(Boolean).forEach((c) => {
    const [k, ...rest] = c.trim().split("=");
    add("REQUEST_COOKIES", k, rest.join("="));
  });
  add("REQUEST_URI", "REQUEST_URI", u.pathname + u.search);
  add("REQUEST_FILENAME", "REQUEST_FILENAME", u.pathname);
  add("QUERY_STRING", "QUERY_STRING", u.search.slice(1));
  add("REQUEST_METHOD", "REQUEST_METHOD", req.method);
  add("REQUEST_LINE", "REQUEST_LINE", `${req.method} ${u.pathname}${u.search} HTTP/1.1`);
  add("REQUEST_BODY", "REQUEST_BODY", req.body);
  return vars;
}

function selectVars(spec: string, vars: Record<string, [string, string][]>) {
  let out: [string, string][] = [];
  const excludes: string[] = [];
  for (const part of spec.split("|")) {
    if (part.startsWith("&")) continue; // counts are not evaluated in preview
    if (part.startsWith("!")) { excludes.push(part.slice(1)); continue; }
    const [col, sel] = part.split(/:(.*)/s);
    const list = vars[col] ?? [];
    const picked = !sel
      ? list
      : sel.startsWith("/") && sel.endsWith("/")
        ? list.filter(([k]) => new RegExp(sel.slice(1, -1), "i").test(k))
        : list.filter(([k]) => k.toLowerCase() === sel.toLowerCase());
    out = out.concat(picked.map(([k, v]) => [col === k ? col : `${col}:${k}`, v] as [string, string]));
  }
  return out.filter(([n]) => !excludes.some((e) => n.toLowerCase() === e.toLowerCase()));
}

function transform(v: string, ts: string[]) {
  for (const t of ts) {
    if (t === "lowercase") v = v.toLowerCase();
    else if (t === "uppercase") v = v.toUpperCase();
    else if (t === "urlDecode" || t === "urlDecodeUni") { try { v = decodeURIComponent(v.replace(/\+/g, " ")); } catch { /* keep raw */ } }
    else if (t === "htmlEntityDecode") v = v.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, "&");
    else if (t === "trim") v = v.trim();
    else if (t === "compressWhitespace") v = v.replace(/\s+/g, " ");
    else if (t === "removeWhitespace") v = v.replace(/\s+/g, "");
    else if (t === "removeNulls") v = v.replace(/\0/g, "");
    else if (t === "base64Decode") { try { v = atob(v); } catch { /* keep raw */ } }
  }
  return v;
}

// Approximations of libinjection for the browser preview only; the Go FTW run is authoritative.
const SQLI_HINT = /('|"|`)\s*(or|and)\s+[\w'"]+\s*=\s*[\w'"]+|union(\s|\/\*.*?\*\/)+(all\s+)?select|;\s*(drop|delete|insert|update)\s|sleep\s*\(\s*\d|benchmark\s*\(|@@version|information_schema|'\s*--|or\s+1\s*=\s*1/i;
const XSS_HINT = /<\s*script|javascript:|on(error|load|click|mouseover|focus)\s*=|<\s*(img|svg|iframe|body)[^>]*\son\w+=|document\.cookie|alert\s*\(/i;

function operatorMatch(op: string, v: string): string | null {
  const neg = op.startsWith("!");
  const o = op.replace(/^!/, "");
  const m = o.match(/^@(\w+)\s?([\s\S]*)$/);
  const name = m ? m[1] : "rx";
  const arg = m ? m[2] : o;
  let hit: string | null = null;
  switch (name) {
    case "rx": { const r = toJsRegex(arg).exec(v); hit = r ? r[0] : null; break; }
    case "contains": hit = v.includes(arg) ? arg : null; break;
    case "containsWord": hit = new RegExp(`\\b${arg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(v) ? arg : null; break;
    case "streq": hit = v === arg ? v : null; break;
    case "beginsWith": hit = v.startsWith(arg) ? arg : null; break;
    case "endsWith": hit = v.endsWith(arg) ? arg : null; break;
    case "within": hit = arg.split(/\s+/).includes(v) ? v : null; break;
    case "pm": hit = arg.split(/\s+/).filter(Boolean).find((w) => v.toLowerCase().includes(w.toLowerCase())) ?? null; break;
    case "eq": hit = Number(v) === Number(arg) ? v : null; break;
    case "gt": hit = Number(v) > Number(arg) ? v : null; break;
    case "lt": hit = Number(v) < Number(arg) ? v : null; break;
    case "detectSQLi": { const r = SQLI_HINT.exec(v); hit = r ? r[0] : null; break; }
    case "detectXSS": { const r = XSS_HINT.exec(v); hit = r ? r[0] : null; break; }
    case "unconditionalMatch": hit = v; break;
    default: throw new Error(`@${name} is not supported in preview`);
  }
  if (neg) return hit === null ? v : null;
  return hit;
}

export function evaluate(src: string, req: SandboxRequest): SandboxResult {
  const vars = collect(req);
  const res: SandboxResult = { status: "PASSED", matched: [], skipped: [] };
  const sts = statements(src).map((s) => tokenize(s.text).tokens).filter((t) => t[0] === "SecRule" && t.length === 4);
  let chainState: { ok: boolean; ruleId: number; msg: string; first?: { variable: string; data: string } } | null = null;
  for (const [, varSpec, op, actRaw] of sts) {
    const acts = parseActions(actRaw);
    const ts = acts.filter((a) => a.name === "t").map((a) => a.value);
    const isChainLink: boolean = chainState !== null;
    const ruleId: number = isChainLink ? chainState!.ruleId : Number(acts.find((a) => a.name === "id")?.value ?? 0);
    const msg: string = isChainLink ? chainState!.msg : acts.find((a) => a.name === "msg")?.value ?? "";
    let match: { variable: string; data: string } | null = null;
    try {
      for (const [name, value] of selectVars(varSpec, vars)) {
        const hit = operatorMatch(op, transform(value, ts));
        if (hit !== null) { match = { variable: name, data: hit }; break; }
      }
    } catch (e) {
      res.skipped.push(`${ruleId}: ${(e as Error).message}`);
    }
    const ok: boolean = (isChainLink ? chainState!.ok : true) && match !== null;
    const first: { variable: string; data: string } | undefined = isChainLink ? chainState!.first : match ?? undefined;
    if (acts.some((a) => a.name === "chain")) { chainState = { ok, ruleId, msg, first }; continue; }
    chainState = null;
    if (ok && first) res.matched.push({ ruleId, variable: first.variable, data: first.data, msg });
  }
  if (res.matched.length) res.status = "MATCHED";
  return res;
}
