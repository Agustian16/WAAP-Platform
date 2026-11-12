import type { Campaign, KillchainMapping, Outcome, RuleCategory, StageKey } from "./types";

// PRD 4.6.2: WAF-observable kill chain. Weaponization is never drawn as fact.
export const STAGES: { key: StageKey; n: number; name: string; short: string; observable: boolean; attack: string }[] = [
  { key: "RECON", n: 1, name: "Reconnaissance", short: "Recon", observable: true, attack: "T1595" },
  { key: "WEAPON", n: 2, name: "Weaponization", short: "Weapon", observable: false, attack: "-" },
  { key: "DELIVERY", n: 3, name: "Delivery", short: "Deliv", observable: true, attack: "T1190" },
  { key: "EXPLOIT", n: 4, name: "Exploitation", short: "Exploit", observable: true, attack: "T1190, T1059" },
  { key: "INSTALL", n: 5, name: "Installation", short: "Install", observable: true, attack: "T1505.003" },
  { key: "C2", n: 6, name: "Command & Control", short: "C2", observable: true, attack: "T1071" },
  { key: "OBJECTIVES", n: 7, name: "Actions on Objectives", short: "Actions", observable: true, attack: "T1041, T1530" },
];

export const stageIndex = (s: StageKey) => STAGES.findIndex((x) => x.key === s);
export const stageMeta = (s: StageKey) => STAGES[stageIndex(s)];
/** CSS var for a stage color; weaponization maps to the neutral "not observable" step. */
export const stageVar = (s: StageKey) => {
  const i = stageIndex(s);
  return i === 1 ? "var(--stage-0)" : `var(--stage-${i === 0 ? 1 : i})`;
};

export const CATEGORIES: { key: RuleCategory; name: string }[] = [
  { key: "SQLI", name: "SQL Injection" },
  { key: "XSS", name: "Cross-site Scripting" },
  { key: "RCE", name: "Remote Code Exec" },
  { key: "LFI", name: "File Inclusion" },
  { key: "SCANNER", name: "Scanner" },
  { key: "PROTOCOL", name: "Protocol" },
  { key: "LEAKAGE", name: "Data Leakage" },
];
export const catVar = (c: RuleCategory) => `var(--cat-${CATEGORIES.findIndex((x) => x.key === c) + 1})`;

// Default mapping table (killchain_rule_mapping seed). Admin can override in Admin > Kill chain mapping.
export const DEFAULT_MAPPING: Omit<KillchainMapping, "id">[] = [
  { rule_id_from: 913000, rule_id_to: 913999, tag: "attack-reputation-scanner", rule_category: "SCANNER", killchain_stage: "RECON", mitre_technique: "T1595.002" },
  { rule_id_from: 920000, rule_id_to: 920999, tag: "attack-protocol", rule_category: "PROTOCOL", killchain_stage: "DELIVERY", mitre_technique: "T1190" },
  { rule_id_from: 921000, rule_id_to: 921999, tag: "attack-protocol", rule_category: "PROTOCOL", killchain_stage: "DELIVERY", mitre_technique: "T1190" },
  { rule_id_from: 930000, rule_id_to: 930999, tag: "attack-lfi", rule_category: "LFI", killchain_stage: "EXPLOIT", mitre_technique: "T1190" },
  { rule_id_from: 931000, rule_id_to: 931999, tag: "attack-rfi", rule_category: "LFI", killchain_stage: "EXPLOIT", mitre_technique: "T1190" },
  { rule_id_from: 932000, rule_id_to: 932999, tag: "attack-rce", rule_category: "RCE", killchain_stage: "EXPLOIT", mitre_technique: "T1059.004" },
  { rule_id_from: 933000, rule_id_to: 933999, tag: "attack-injection-php", rule_category: "RCE", killchain_stage: "EXPLOIT", mitre_technique: "T1059" },
  { rule_id_from: 941000, rule_id_to: 941999, tag: "attack-xss", rule_category: "XSS", killchain_stage: "EXPLOIT", mitre_technique: "T1059.007" },
  { rule_id_from: 942000, rule_id_to: 942999, tag: "attack-sqli", rule_category: "SQLI", killchain_stage: "EXPLOIT", mitre_technique: "T1190" },
  { rule_id_from: 944000, rule_id_to: 944999, tag: "attack-injection-java", rule_category: "RCE", killchain_stage: "EXPLOIT", mitre_technique: "T1059" },
  { rule_id_from: 950000, rule_id_to: 954999, tag: "attack-disclosure", rule_category: "LEAKAGE", killchain_stage: "OBJECTIVES", mitre_technique: "T1041" },
  { rule_id_from: 955000, rule_id_to: 955999, tag: "attack-webshell", rule_category: "RCE", killchain_stage: "INSTALL", mitre_technique: "T1505.003" },
  { rule_id_from: 900000, rule_id_to: 909999, tag: null, rule_category: "SQLI", killchain_stage: "EXPLOIT", mitre_technique: "T1190" },
];

export function mapRule(ruleId: number, table: Omit<KillchainMapping, "id">[] = DEFAULT_MAPPING) {
  // Narrowest range wins so admin overrides for single custom rules beat the CRS family range.
  const hits = table.filter((m) => ruleId >= m.rule_id_from && ruleId <= m.rule_id_to);
  hits.sort((a, b) => a.rule_id_to - a.rule_id_from - (b.rule_id_to - b.rule_id_from));
  return hits[0] ?? null;
}

export function classifyOutcome(action: "DENY" | "LOG" | "ALLOW", status: number): Outcome {
  if (action === "DENY") return "BLOCKED";
  return status >= 200 && status < 300 ? "POSSIBLY_SUCCESSFUL" : "DETECTED";
}

/**
 * FR-6.3 Campaign Risk Score (0-100): stage reached, distinct targets, category variety, success signal.
 * Weights are a starting heuristic; the backend owns the authoritative score.
 */
export function riskScore(input: { highestStage: StageKey; targets: number; categories: number; possiblySuccessful: number; events: number }) {
  const stage = [8, 8, 25, 50, 62, 68, 75][stageIndex(input.highestStage)];
  const targets = Math.min(input.targets - 1, 4) * 3;
  const variety = Math.min(input.categories - 1, 4) * 3;
  const success = input.possiblySuccessful > 0 ? 15 + Math.min(input.possiblySuccessful, 5) : 0;
  const volume = Math.min(Math.log10(Math.max(input.events, 1)) * 2.5, 5);
  return Math.max(0, Math.min(100, Math.round(stage + targets + variety + success + volume)));
}

export const riskBand = (r: number) => (r >= 75 ? "crit" : r >= 50 ? "serious" : r >= 25 ? "warn" : "muted");

/** Stage escalation check (FR-6.3): returns the new highest stage if `next` is higher than the campaign's. */
export function escalation(c: Pick<Campaign, "highest_stage">, next: StageKey): StageKey | null {
  return stageIndex(next) > stageIndex(c.highest_stage) ? next : null;
}

// MITRE ATT&CK techniques observable from HTTP, grouped by kill chain stage (Kill Chain Matrix tab).
export const ATTACK_TECHNIQUES: { key?: string; id: string; name: string; tactic: string; stage: StageKey; categories: RuleCategory[] }[] = [
  { id: "T1595.002", name: "Vulnerability Scanning", tactic: "Reconnaissance", stage: "RECON", categories: ["SCANNER"] },
  { id: "T1595.003", name: "Wordlist Scanning", tactic: "Reconnaissance", stage: "RECON", categories: ["SCANNER"] },
  { id: "T1592", name: "Gather Victim Host Info", tactic: "Reconnaissance", stage: "RECON", categories: ["SCANNER"] },
  { id: "T1190", name: "Exploit Public-Facing App (protocol abuse)", tactic: "Initial Access", stage: "DELIVERY", categories: ["PROTOCOL"] },
  { key: "T1190/SQLI", id: "T1190", name: "Exploit Public-Facing App (SQLi)", tactic: "Initial Access", stage: "EXPLOIT", categories: ["SQLI"] },
  { id: "T1059.004", name: "Unix Shell", tactic: "Execution", stage: "EXPLOIT", categories: ["RCE"] },
  { id: "T1059.007", name: "JavaScript", tactic: "Execution", stage: "EXPLOIT", categories: ["XSS"] },
  { id: "T1083", name: "File & Directory Discovery", tactic: "Discovery", stage: "EXPLOIT", categories: ["LFI"] },
  { id: "T1505.003", name: "Web Shell", tactic: "Persistence", stage: "INSTALL", categories: ["RCE"] },
  { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", stage: "C2", categories: ["RCE"] },
  { id: "T1041", name: "Exfiltration Over C2", tactic: "Exfiltration", stage: "OBJECTIVES", categories: ["LEAKAGE"] },
  { id: "T1530", name: "Data from Cloud Storage", tactic: "Collection", stage: "OBJECTIVES", categories: ["LEAKAGE"] },
];

export const techKey = (t: { key?: string; id: string }) => t.key ?? t.id;

/** Assign one ATT&CK technique per event so matrix cells never double-count. */
export function techniqueOf(e: { killchain_stage: StageKey; rule_category: RuleCategory; uri: string; rule_id: number }) {
  switch (e.killchain_stage) {
    case "RECON":
      if (/phpinfo|server-status|actuator|swagger|api-docs|robots\.txt|sitemap/.test(e.uri)) return "T1592";
      if (e.rule_id === 913120 || /\.env|\.git|admin|backup|wp-|xmlrpc|config/.test(e.uri)) return "T1595.003";
      return "T1595.002";
    case "DELIVERY": return "T1190";
    case "EXPLOIT": return e.rule_category === "XSS" ? "T1059.007" : e.rule_category === "RCE" ? "T1059.004" : e.rule_category === "LFI" ? "T1083" : "T1190/SQLI";
    case "INSTALL": return "T1505.003";
    case "C2": return "T1071.001";
    case "OBJECTIVES": return /bucket|storage|s3/.test(e.uri) ? "T1530" : "T1041";
    default: return null;
  }
}
