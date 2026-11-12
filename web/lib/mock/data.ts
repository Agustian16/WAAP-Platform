// Deterministic mock dataset standing in for PostgreSQL + ClickHouse until the Go control plane is reachable.
// Attacker IPs use RFC 5737 documentation ranges (plus the two PRD examples); ASNs use the RFC 6996 private range
// except where the PRD names one. Nothing here describes a real organization.
import { DEFAULT_MAPPING, mapRule, riskScore, stageIndex, classifyOutcome, STAGES } from "../killchain";
import type {
  AttackEvent, AuditLog, AuditTrailEntry, Campaign, CorrelationSettings, CustomRule, EdgeNode, IpListEntry,
  KillchainMapping, RuleException, Severity, Site, StageKey, ThreatFeed, User, Action,
} from "../types";

export function rng(seed: number) {
  return () => {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const r = rng(20260824);
const pick = <T,>(a: T[]) => a[Math.floor(r() * a.length)];
const int = (a: number, b: number) => Math.floor(a + r() * (b - a + 1));
const hex = (n: number) => Array.from({ length: n }, () => Math.floor(r() * 16).toString(16)).join("");
const uuid = () => `${hex(8)}-${hex(4)}-4${hex(3)}-a${hex(3)}-${hex(12)}`;

const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
export const NOW = Date.now();

// ---------------- Sites ----------------
const CRS_ON = { "913": true, "920": true, "921": true, "930": true, "931": true, "932": true, "933": true, "941": true, "942": true, "944": true, "950": true, "955": true };
export const sites: Site[] = [
  { id: "s-api", name: "Public API", domain_name: "api.domain.com", paranoia_level: 2, inbound_threshold: 5, outbound_threshold: 4, crs_categories: { ...CRS_ON }, updated_at: new Date(NOW - 3 * DAY).toISOString() },
  { id: "s-shop", name: "Storefront", domain_name: "shop.domain.com", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4, crs_categories: { ...CRS_ON, "944": false }, updated_at: new Date(NOW - 9 * DAY).toISOString() },
  { id: "s-portal", name: "Customer Portal", domain_name: "portal.domain.com", paranoia_level: 2, inbound_threshold: 7, outbound_threshold: 4, crs_categories: { ...CRS_ON }, updated_at: new Date(NOW - 20 * DAY).toISOString() },
  { id: "s-cms", name: "Marketing CMS", domain_name: "cms.domain.com", paranoia_level: 1, inbound_threshold: 5, outbound_threshold: 4, crs_categories: { ...CRS_ON, "933": false }, updated_at: new Date(NOW - 41 * DAY).toISOString() },
];
const siteByHost = (h: string) => sites.find((s) => s.domain_name === h)!;

// ---------------- Nodes ----------------
const nodeSeed: [string, string, EdgeNode["proxy"], string, [number, number], number, string, EdgeNode["status"]][] = [
  ["edge-sg-caddy-01", "10.10.1.15", "Caddy", "Singapore", [103.82, 1.35], 1.2, "CRS v4.0.0", "ONLINE"],
  ["edge-sg-envoy-02", "10.10.1.16", "Envoy", "Singapore", [103.85, 1.29], 1.8, "CRS v4.0.0", "ONLINE"],
  ["edge-id-spoa-01", "10.10.2.10", "SPOA", "Jakarta", [106.85, -6.21], 8.5, "CRS v3.3.4", "WARN"],
  ["edge-de-caddy-03", "10.20.1.11", "Caddy", "Frankfurt", [8.68, 50.11], 1.4, "CRS v4.0.0", "ONLINE"],
  ["edge-us-envoy-04", "10.30.1.21", "Envoy", "Virginia", [-77.49, 39.04], 1.6, "CRS v4.0.0", "ONLINE"],
  ["edge-jp-caddy-05", "10.40.1.31", "Caddy", "Tokyo", [139.69, 35.69], 0, "CRS v4.0.0", "OFFLINE"],
];
export const CONFIG_VERSION = 104;
export const nodes: EdgeNode[] = nodeSeed.map(([name, ip, proxy, region, geo, lat, crs, status], i) => {
  const base = [2400, 1900, 640, 1500, 2100, 0][i];
  return {
    id: `n-${name}`,
    node_name: name,
    hostname: ip,
    ip_address: ip,
    proxy,
    version: proxy === "SPOA" ? "coraza-spoa 0.3.1" : proxy === "Envoy" ? "coraza-proxy-wasm 0.5.0" : "coraza-caddy 2.0.0",
    crs_version: crs,
    status,
    current_config_version: status === "ONLINE" ? CONFIG_VERSION : CONFIG_VERSION - 2,
    sync_status: status === "ONLINE" ? "IN_SYNC" : "PENDING_UPDATE",
    cpu: status === "OFFLINE" ? 0 : status === "WARN" ? 87 : int(18, 46),
    memory: status === "OFFLINE" ? 0 : status === "WARN" ? 71 : int(30, 58),
    rps: base,
    latency_ms: lat,
    last_heartbeat: new Date(NOW - (status === "OFFLINE" ? 47 * MIN : int(1, 9) * 1000)).toISOString(),
    region,
    geo,
    history: Array.from({ length: 60 }, (_, k) => ({
      t: NOW - (59 - k) * MIN,
      rps: status === "OFFLINE" && k > 12 ? 0 : Math.round(base * (0.85 + 0.3 * Math.sin(k / 9) * 0.5 + r() * 0.1)),
      latency: status === "OFFLINE" && k > 12 ? 0 : +(lat * (0.8 + r() * 0.4) + (status === "WARN" && k > 40 ? 3 : 0)).toFixed(2),
      cpu: status === "OFFLINE" && k > 12 ? 0 : Math.round((status === "WARN" ? 70 : 30) + r() * 18),
    })),
  };
});

// ---------------- Actors & campaigns ----------------
interface Step { stage: StageKey; rule: number; host: string; uris: string[]; n: number; action: Action; okRatio?: number; method?: string; spanMin: number }
interface Actor {
  ips: string[]; cc: string; asn: number; as_name: string; geo: [number, number]; mode: Campaign["actor_mode"];
  conf: Campaign["correlation_confidence"]; startAgo: number; status: Campaign["status"]; assignee: string | null; steps: Step[];
  ua: string; notes?: Campaign["notes"];
}

const ACTORS: Actor[] = [
  {
    ips: ["185.220.101.5"], cc: "RU", asn: 13335, as_name: "AS13335", geo: [37.62, 55.75], mode: "IP", conf: "HIGH",
    startAgo: 52 * MIN, status: "ACTIVE", assignee: "Ahmad", ua: "Mozilla/5.0 (X11; Linux x86_64) python-requests/2.31",
    steps: [
      { stage: "RECON", rule: 913100, host: "api.domain.com", uris: ["/.env", "/.git/config", "/admin", "/backup.zip"], n: 14, action: "DENY", spanMin: 6 },
      { stage: "DELIVERY", rule: 920270, host: "api.domain.com", uris: ["/api/v1/login"], n: 6, action: "DENY", spanMin: 8, method: "POST" },
      { stage: "EXPLOIT", rule: 942100, host: "api.domain.com", uris: ["/api/v1/login"], n: 38, action: "DENY", spanMin: 30, method: "POST" },
      { stage: "EXPLOIT", rule: 942190, host: "api.domain.com", uris: ["/api/v1/orders?sort=1"], n: 2, action: "LOG", okRatio: 1, spanMin: 8 },
    ],
  },
  {
    ips: ["103.21.244.12"], cc: "CN", asn: 64512, as_name: "AS64512 Sample Hosting A", geo: [116.4, 39.9], mode: "IP", conf: "HIGH",
    startAgo: 26 * MIN, status: "ACTIVE", assignee: null, ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
    steps: [
      { stage: "EXPLOIT", rule: 941100, host: "shop.domain.com", uris: ["/products/search"], n: 7, action: "DENY", spanMin: 20 },
      { stage: "EXPLOIT", rule: 941160, host: "shop.domain.com", uris: ["/products/search", "/reviews/new"], n: 5, action: "DENY", spanMin: 5, method: "POST" },
    ],
  },
  {
    ips: ["198.51.100.23"], cc: "BR", asn: 64520, as_name: "AS64520 Sample Cloud B", geo: [-46.63, -23.55], mode: "IP", conf: "HIGH",
    startAgo: 3 * HOUR + 10 * MIN, status: "ACTIVE", assignee: "Budi", ua: "curl/8.4.0",
    notes: [{ author: "Budi", at: NOW - 40 * MIN, text: "Upload endpoint returned 200 for a .php payload. Checking CMS host for dropped files." }],
    steps: [
      { stage: "RECON", rule: 913120, host: "cms.domain.com", uris: ["/wp-login.php", "/xmlrpc.php", "/wp-content/plugins/"], n: 22, action: "DENY", spanMin: 25 },
      { stage: "EXPLOIT", rule: 932160, host: "cms.domain.com", uris: ["/wp-admin/admin-ajax.php"], n: 18, action: "LOG", okRatio: 0.3, spanMin: 40, method: "POST" },
      { stage: "INSTALL", rule: 955110, host: "cms.domain.com", uris: ["/wp-content/uploads/2026/11/img_ico.php"], n: 3, action: "LOG", okRatio: 1, spanMin: 10, method: "POST" },
      { stage: "C2", rule: 955120, host: "cms.domain.com", uris: ["/wp-content/uploads/2026/11/img_ico.php?c=id"], n: 26, action: "LOG", okRatio: 1, spanMin: 70 },
      { stage: "OBJECTIVES", rule: 951220, host: "cms.domain.com", uris: ["/wp-content/uploads/2026/11/img_ico.php?c=dump"], n: 5, action: "DENY", spanMin: 20 },
    ],
  },
  {
    ips: Array.from({ length: 36 }, (_, i) => `203.0.113.${10 + i * 6}`), cc: "NL", asn: 64530, as_name: "AS64530 Sample Bulletproof C", geo: [4.9, 52.37], mode: "CIDR24", conf: "LOW",
    startAgo: 5 * HOUR, status: "ACTIVE", assignee: null, ua: "Mozilla/5.0 zgrab/0.x",
    steps: [
      { stage: "RECON", rule: 913100, host: "portal.domain.com", uris: ["/.env", "/phpinfo.php", "/server-status", "/actuator/env"], n: 140, action: "DENY", spanMin: 280 },
      { stage: "RECON", rule: 913100, host: "api.domain.com", uris: ["/.env", "/swagger.json"], n: 60, action: "DENY", spanMin: 260 },
    ],
  },
  {
    ips: ["192.0.2.77"], cc: "US", asn: 64540, as_name: "AS64540 Sample ISP D", geo: [-87.63, 41.88], mode: "IP", conf: "MEDIUM",
    startAgo: 9 * HOUR, status: "CONTAINED", assignee: "Ahmad", ua: "Mozilla/5.0 (Macintosh) Firefox/131.0",
    notes: [{ author: "Ahmad", at: NOW - 7 * HOUR, text: "Blocked 192.0.2.77 for 24h. All traversal attempts were denied." }],
    steps: [
      { stage: "EXPLOIT", rule: 930100, host: "portal.domain.com", uris: ["/download?file=../../etc/passwd", "/download?file=..%2f..%2fwindows/win.ini"], n: 31, action: "DENY", spanMin: 50 },
      { stage: "EXPLOIT", rule: 930120, host: "portal.domain.com", uris: ["/download?file=/proc/self/environ"], n: 9, action: "DENY", spanMin: 15 },
    ],
  },
  {
    ips: ["198.51.100.140"], cc: "DE", asn: 64550, as_name: "AS64550 Sample Transit E", geo: [13.4, 52.52], mode: "FINGERPRINT", conf: "MEDIUM",
    startAgo: 80 * MIN, status: "ACTIVE", assignee: null, ua: "Go-http-client/1.1",
    steps: [
      { stage: "DELIVERY", rule: 921110, host: "api.domain.com", uris: ["/api/v1/cart", "/api/v1/checkout"], n: 16, action: "DENY", spanMin: 40, method: "POST" },
      { stage: "DELIVERY", rule: 920100, host: "shop.domain.com", uris: ["/"], n: 8, action: "DENY", spanMin: 10 },
    ],
  },
  {
    ips: ["192.0.2.10"], cc: "ID", asn: 64560, as_name: "AS64560 Corporate egress (sample)", geo: [106.82, -6.18], mode: "IP", conf: "HIGH",
    startAgo: 20 * HOUR, status: "FALSE_POSITIVE", assignee: "Ahmad", ua: "InternalReportingTool/3.2",
    notes: [{ author: "Ahmad", at: NOW - 18 * HOUR, text: "Reporting tool sends SQL-like filter strings. Exception requested for /api/v1/search ARGS:filter." }],
    steps: [{ stage: "EXPLOIT", rule: 942100, host: "api.domain.com", uris: ["/api/v1/search?filter=status='open' OR priority='high'"], n: 44, action: "LOG", okRatio: 1, spanMin: 300 }],
  },
  {
    ips: ["203.0.113.201"], cc: "VN", asn: 64570, as_name: "AS64570 Sample Mobile F", geo: [105.85, 21.03], mode: "IP", conf: "MEDIUM",
    startAgo: 3 * DAY, status: "CLOSED", assignee: "Budi", ua: "sqlmap/1.8.2#stable",
    steps: [
      { stage: "RECON", rule: 913100, host: "shop.domain.com", uris: ["/robots.txt", "/sitemap.xml"], n: 12, action: "DENY", spanMin: 10 },
      { stage: "EXPLOIT", rule: 942100, host: "shop.domain.com", uris: ["/products?id=1"], n: 120, action: "DENY", spanMin: 50 },
      { stage: "EXPLOIT", rule: 942440, host: "shop.domain.com", uris: ["/products?id=1"], n: 30, action: "DENY", spanMin: 20 },
    ],
  },
  {
    ips: ["198.51.100.66"], cc: "IN", asn: 64580, as_name: "AS64580 Sample Hosting G", geo: [72.88, 19.08], mode: "IP", conf: "HIGH",
    startAgo: 9 * DAY, status: "CLOSED", assignee: "Budi", ua: "Mozilla/5.0 (compatible; Nuclei)",
    steps: [
      { stage: "RECON", rule: 913100, host: "api.domain.com", uris: ["/actuator/health", "/v2/api-docs"], n: 40, action: "DENY", spanMin: 30 },
      { stage: "EXPLOIT", rule: 944110, host: "api.domain.com", uris: ["/api/v1/import"], n: 12, action: "DENY", spanMin: 15, method: "POST" },
    ],
  },
];

const PAYLOAD: Record<number, { var: string; data: string; msg: string; sev: Severity }> = {
  913100: { var: "REQUEST_HEADERS:User-Agent", data: "zgrab", msg: "Found User-Agent associated with security scanner", sev: "CRITICAL" },
  913120: { var: "REQUEST_FILENAME", data: "/wp-login.php", msg: "Found request filename/argument associated with security scanner", sev: "CRITICAL" },
  920270: { var: "ARGS:username", data: "%00", msg: "Invalid character in request (null character)", sev: "ERROR" },
  920100: { var: "REQUEST_LINE", data: "GET /\\x0d\\x0a HTTP/1.1", msg: "Invalid HTTP Request Line", sev: "WARNING" },
  921110: { var: "REQUEST_BODY", data: "\\r\\nPOST /admin HTTP/1.1", msg: "HTTP Request Smuggling Attack", sev: "CRITICAL" },
  930100: { var: "ARGS:file", data: "../../", msg: "Path Traversal Attack (/../)", sev: "CRITICAL" },
  930120: { var: "ARGS:file", data: "/proc/self/environ", msg: "OS File Access Attempt", sev: "CRITICAL" },
  932160: { var: "ARGS:cmd", data: "/bin/sh -c id", msg: "Remote Command Execution: Unix Shell Code Found", sev: "CRITICAL" },
  941100: { var: "ARGS:q", data: "<script>alert(document.cookie)</script>", msg: "XSS Attack Detected via libinjection", sev: "CRITICAL" },
  941160: { var: "ARGS:body", data: "<img src=x onerror=fetch('//x')>", msg: "NoScript XSS InjectionChecker: HTML Injection", sev: "CRITICAL" },
  942100: { var: "ARGS:username", data: "' OR '1'='1", msg: "SQL Injection Attack Detected via libinjection", sev: "CRITICAL" },
  942190: { var: "ARGS:sort", data: "1 UNION SELECT password FROM users", msg: "Detects MSSQL code execution and information gathering attempts", sev: "CRITICAL" },
  942440: { var: "ARGS:id", data: "1/**/AND/**/1=1--", msg: "SQL Comment Sequence Detected", sev: "CRITICAL" },
  944110: { var: "REQUEST_BODY", data: "java.lang.Runtime", msg: "Remote Command Execution: Java process spawn", sev: "CRITICAL" },
  951220: { var: "RESPONSE_BODY", data: "mysql_fetch_array()", msg: "SQL Information Leakage", sev: "ERROR" },
  955110: { var: "FILES:upload", data: "<?php @eval($_POST['x']);", msg: "Web shell detected", sev: "CRITICAL" },
  955120: { var: "RESPONSE_BODY", data: "uid=33(www-data)", msg: "Web shell command output detected", sev: "CRITICAL" },
};
export const ruleMeta = (id: number) => PAYLOAD[id] ?? { var: "ARGS", data: "", msg: `Rule ${id}`, sev: "WARNING" as Severity };

const dayId = (t: number) => new Date(t).toISOString().slice(0, 10).replace(/-/g, "");

export const events: AttackEvent[] = [];
export const auditLogs: AuditLog[] = [];
export const campaigns: Campaign[] = [];

function nodeForHost(host: string, i: number) {
  const pool = nodes.filter((n) => n.status !== "OFFLINE");
  return pool[(host.length + i) % pool.length];
}

export function makeEvent(a: { ip: string; cc: string; asn: number; geo: [number, number]; ua: string }, step: Step, t: number, campaignId: string, i: number): { ev: AttackEvent; log: AuditLog } {
  const m = mapRule(step.rule)!;
  const ok = step.action === "LOG" && r() < (step.okRatio ?? 0);
  const status = step.action === "DENY" ? 403 : ok ? 200 : pick([404, 400, 500]);
  const uri = step.uris[i % step.uris.length];
  const site = siteByHost(step.host);
  const node = nodeForHost(step.host, i);
  const meta = ruleMeta(step.rule);
  const tx = `${hex(4)}${hex(4)}-${hex(6)}`;
  const id = `log_${int(100000000, 999999999)}`;
  const method = step.method ?? "GET";
  const ev: AttackEvent = {
    id, timestamp: t, transaction_id: tx, campaign_id: campaignId, node_id: node.id, site_id: site.id, host: step.host,
    client_ip: a.ip, country_code: a.cc, asn: a.asn, geo: a.geo, method, uri, rule_id: step.rule,
    rule_category: m.rule_category, killchain_stage: step.stage, severity: meta.sev, outcome: classifyOutcome(step.action, status), response_status: status,
  };
  const body = method === "POST" ? (step.rule === 942100 ? `username=${encodeURIComponent(meta.data)}&password=********` : `${meta.var.split(":")[1] ?? "data"}=${encodeURIComponent(meta.data)}`) : "";
  const log: AuditLog = {
    id, timestamp: new Date(t).toISOString(), transaction_id: tx, node_id: node.id, site_id: site.id, host: step.host,
    client_ip: a.ip, client_port: int(30000, 65000), country_code: a.cc, asn: a.asn, http_method: method, uri, http_version: "HTTP/1.1",
    response_status: status, action_taken: step.action, matched_rule_ids: step.stage === "EXPLOIT" && step.action === "DENY" ? [step.rule, 949110] : [step.rule],
    matched_messages: step.stage === "EXPLOIT" && step.action === "DENY" ? [meta.msg, "Inbound Anomaly Score Exceeded (Total Score: 10)"] : [meta.msg],
    matched_data: [meta.data], matched_vars: [meta.var], severity: meta.sev,
    request_headers: {
      Host: step.host, "User-Agent": a.ua, Accept: "*/*", "X-Forwarded-For": a.ip,
      Authorization: "[masked]", Cookie: "session_id=[masked]; theme=dark",
      ...(method === "POST" ? { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(body.length) } : {}),
    },
    request_body: body,
    latency_us: int(600, 2400),
  };
  return { ev, log };
}

ACTORS.forEach((a, ai) => {
  const start = NOW - a.startAgo;
  const id = `cmp_${dayId(start)}_${String(190 + ai * 7).padStart(4, "0")}`;
  let t = start;
  const evs: AttackEvent[] = [];
  for (const st of a.steps) {
    for (let i = 0; i < st.n; i++) {
      const ts = Math.min(t + (i / st.n) * st.spanMin * MIN + r() * 20000, a.status === "ACTIVE" ? NOW - 5000 : NOW - 2 * HOUR);
      const { ev, log } = makeEvent({ ip: a.ips[i % a.ips.length], cc: a.cc, asn: a.asn, geo: a.geo, ua: a.ua }, st, ts, id, i);
      evs.push(ev); auditLogs.push(log);
    }
    t += st.spanMin * MIN * 0.8;
  }
  events.push(...evs);
  const stages = [...new Set(evs.map((e) => e.killchain_stage))].sort((x, y) => stageIndex(x) - stageIndex(y));
  const highest = stages[stages.length - 1];
  const ps = evs.filter((e) => e.outcome === "POSSIBLY_SUCCESSFUL").length;
  const targets = [...new Set(evs.map((e) => `${e.host}${e.uri.split("?")[0]}`))];
  campaigns.push({
    id, actor_key: a.mode === "CIDR24" ? "203.0.113.0/24" : a.mode === "FINGERPRINT" ? `ja3:${hex(12)} + ${a.ua}` : a.ips[0],
    actor_mode: a.mode, country_code: a.cc, asn: a.asn, as_name: a.as_name, geo: a.geo, correlation_confidence: a.conf,
    first_seen: Math.min(...evs.map((e) => e.timestamp)), last_seen: Math.max(...evs.map((e) => e.timestamp)), highest_stage: highest, stages,
    risk_score: riskScore({ highestStage: highest, targets: targets.length, categories: new Set(evs.map((e) => e.rule_category)).size, possiblySuccessful: ps, events: evs.length }),
    event_count: evs.length, status: a.status, assignee: a.assignee, notes: a.notes ?? [], targets, possibly_successful: ps,
  });
});
events.sort((x, y) => x.timestamp - y.timestamp);
auditLogs.sort((x, y) => (x.timestamp < y.timestamp ? 1 : -1));

/** Sample actor profiles the live mock stream draws from for new traffic. */
export const LIVE_ACTORS = ACTORS.filter((a) => a.status === "ACTIVE");
export type LiveActor = (typeof ACTORS)[number];

// ---------------- Traffic series (overview) ----------------
export const traffic = Array.from({ length: 288 }, (_, i) => {
  const t = NOW - (287 - i) * 5 * MIN;
  const hour = new Date(t).getHours();
  const diurnal = 0.55 + 0.45 * Math.sin(((hour - 6) / 24) * Math.PI * 2);
  const total = Math.round(8200 * diurnal * (0.92 + r() * 0.16));
  const inWindow = events.filter((e) => e.timestamp >= t && e.timestamp < t + 5 * MIN);
  return { t, total, blocked: inWindow.filter((e) => e.outcome === "BLOCKED").length + int(2, 9), detected: inWindow.filter((e) => e.outcome !== "BLOCKED").length };
});

// ---------------- Rules / exceptions / lists ----------------
export const customRules: CustomRule[] = [
  {
    id: uuid(), rule_id: 900001, site_id: "s-api", name: "CUSTOM_SQLI_BYPASS_900001", is_active: true, created_by: "Budi", updated_at: new Date(NOW - 2 * DAY).toISOString(),
    seclang_raw: `SecRule ARGS:user_id "@rx (?i)(union\\s+select|select\\s+@@version)" \\\n    "id:900001,\\\n    phase:2,\\\n    deny,\\\n    status:403,\\\n    msg:'Custom SQL Injection Pattern Detected',\\\n    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\\\n    tag:'application-multi',\\\n    severity:'CRITICAL'"`,
  },
  {
    id: uuid(), rule_id: 900010, site_id: null, name: "BLOCK_SCANNER_USER_AGENTS", is_active: true, created_by: "Budi", updated_at: new Date(NOW - 12 * DAY).toISOString(),
    seclang_raw: `SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto nuclei zgrab masscan" \\\n    "id:900010,\\\n    phase:1,\\\n    deny,\\\n    status:403,\\\n    t:lowercase,\\\n    msg:'Known scanner user agent',\\\n    tag:'attack-reputation-scanner',\\\n    severity:'CRITICAL'"`,
  },
  {
    id: uuid(), rule_id: 900020, site_id: "s-cms", name: "DENY_PHP_IN_UPLOADS", is_active: true, created_by: "Budi", updated_at: new Date(NOW - 1 * DAY).toISOString(),
    seclang_raw: `SecRule REQUEST_FILENAME "@rx ^/wp-content/uploads/.*\\.php" \\\n    "id:900020,\\\n    phase:1,\\\n    deny,\\\n    status:403,\\\n    msg:'PHP execution from uploads directory',\\\n    tag:'attack-webshell',\\\n    severity:'CRITICAL'"`,
  },
  {
    id: uuid(), rule_id: 900030, site_id: "s-api", name: "LOGIN_RATE_HINT (draft)", is_active: false, created_by: "Ahmad", updated_at: new Date(NOW - 5 * HOUR).toISOString(),
    seclang_raw: `SecRule REQUEST_FILENAME "@streq /api/v1/login" \\\n    "id:900030,\\\n    phase:1,\\\n    pass,\\\n    log,\\\n    msg:'Login attempt observed',\\\n    severity:'NOTICE'"`,
  },
];

export const exceptions: RuleException[] = [
  { id: uuid(), site_id: "s-api", rule_id: 942100, path_pattern: "/api/v1/search", parameter_name: "ARGS:filter", reason: "Internal reporting tool sends SQL-like filter expressions (cmp FALSE_POSITIVE).", created_by: "Ahmad", created_at: new Date(NOW - 17 * HOUR).toISOString() },
  { id: uuid(), site_id: "s-cms", rule_id: 941160, path_pattern: "/wp-admin/post.php", parameter_name: "ARGS:content", reason: "Editors save HTML in post body.", created_by: "Budi", created_at: new Date(NOW - 30 * DAY).toISOString() },
];

export const ipList: IpListEntry[] = [
  { id: uuid(), cidr: "192.0.2.77/32", list: "block", source: "manual", reason: "Path traversal campaign, contained", expires_at: new Date(NOW + 15 * HOUR).toISOString(), created_by: "Ahmad", created_at: new Date(NOW - 7 * HOUR).toISOString() },
  { id: uuid(), cidr: "203.0.113.0/24", list: "block", source: "Sample scanner feed", reason: "Feed import", expires_at: null, created_by: "system", created_at: new Date(NOW - 2 * DAY).toISOString() },
  { id: uuid(), cidr: "10.0.0.0/8", list: "allow", source: "manual", reason: "Internal health checks", expires_at: null, created_by: "Deni", created_at: new Date(NOW - 60 * DAY).toISOString() },
  { id: uuid(), cidr: "192.0.2.10/32", list: "allow", source: "manual", reason: "Corporate reporting egress", expires_at: null, created_by: "Ahmad", created_at: new Date(NOW - 17 * HOUR).toISOString() },
];

export const feeds: ThreatFeed[] = [
  { id: uuid(), name: "Sample scanner feed", url: "https://feeds.example.net/scanners.txt", format: "text", interval_minutes: 60, last_pulled: new Date(NOW - 22 * MIN).toISOString(), entries: 1840, status: "OK" },
  { id: uuid(), name: "Sample abuse CSV", url: "https://intel.example.org/abuse.csv", format: "csv", interval_minutes: 360, last_pulled: new Date(NOW - 7 * HOUR).toISOString(), entries: 0, status: "ERROR", error: "HTTP 404 from feed URL" },
];

export const users: User[] = [
  { id: "u1", name: "Ahmad", email: "ahmad@domain.com", role: "SecOps Analyst", mfa: true, last_login: new Date(NOW - 20 * MIN).toISOString() },
  { id: "u2", name: "Budi", email: "budi@domain.com", role: "Admin", mfa: true, last_login: new Date(NOW - 2 * HOUR).toISOString() },
  { id: "u3", name: "Deni", email: "deni@domain.com", role: "Admin", mfa: true, last_login: new Date(NOW - 1 * DAY).toISOString() },
  { id: "u4", name: "External Auditor", email: "audit@domain.com", role: "Auditor", mfa: true, last_login: null },
];

export const auditTrail: AuditTrailEntry[] = [
  { id: uuid(), at: new Date(NOW - 40 * MIN).toISOString(), actor: "Budi", role: "Admin", action: "Note added", target: campaigns[2].id, source_ip: "10.8.0.21", target_nodes: "-" },
  { id: uuid(), at: new Date(NOW - 5 * HOUR).toISOString(), actor: "Ahmad", role: "SecOps Analyst", action: "Rule drafted", target: "900030 LOGIN_RATE_HINT", source_ip: "10.8.0.14", target_nodes: "-" },
  { id: uuid(), at: new Date(NOW - 7 * HOUR).toISOString(), actor: "Ahmad", role: "SecOps Analyst", action: "IP blocked", target: "192.0.2.77/32 (TTL 24h)", source_ip: "10.8.0.14", target_nodes: "all (5)" },
  { id: uuid(), at: new Date(NOW - 17 * HOUR).toISOString(), actor: "Ahmad", role: "SecOps Analyst", action: "Exception created", target: "942100 @ api.domain.com/api/v1/search ARGS:filter", source_ip: "10.8.0.14", target_nodes: "all (5)" },
  { id: uuid(), at: new Date(NOW - 1 * DAY).toISOString(), actor: "Budi", role: "Admin", action: "Policy deployed", target: `config v${CONFIG_VERSION}`, source_ip: "10.8.0.21", target_nodes: "5 of 6 (edge-jp-caddy-05 unreachable)" },
  { id: uuid(), at: new Date(NOW - 1 * DAY - 20 * MIN).toISOString(), actor: "Budi", role: "Admin", action: "Rule added", target: "900020 DENY_PHP_IN_UPLOADS", source_ip: "10.8.0.21", target_nodes: "-" },
  { id: uuid(), at: new Date(NOW - 3 * DAY).toISOString(), actor: "Deni", role: "Admin", action: "Paranoia level changed", target: "api.domain.com PL1 -> PL2", source_ip: "10.8.0.30", target_nodes: "all (6)" },
];

export const killchainMapping: KillchainMapping[] = DEFAULT_MAPPING.map((m, i) => ({ ...m, id: `km-${i}` }));
export const correlationSettings: CorrelationSettings[] = sites.map((s) => ({ site_id: s.id, actor_key_mode: "IP", idle_timeout_minutes: 30, min_events_to_open: 3 }));

export { STAGES, uuid, int, pick, r as rand, hex, MIN, HOUR, DAY };
