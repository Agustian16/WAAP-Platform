// Run: npm test  (Node >= 22.6 strips TypeScript types natively)
import { test } from "node:test";
import assert from "node:assert/strict";
import { lint, buildException, evaluate, buildRule, parseToBuilder, nextFreeId } from "./seclang.ts";
import { mapRule, riskScore, classifyOutcome, escalation } from "./killchain.ts";

const PRD_RULE = `SecRule ARGS:user_id "@rx (?i)(union\\s+select|select\\s+@@version)" \\
    "id:900001,\\
    phase:2,\\
    deny,\\
    status:403,\\
    msg:'Custom SQL Injection Pattern Detected',\\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}',\\
    tag:'application-multi',\\
    severity:'CRITICAL'"`;

test("PRD sample rule lints clean", () => {
  assert.deepEqual(lint(PRD_RULE), []);
});

test("lint catches missing id, bad phase, unknown operator, duplicates, open chain", () => {
  const msgs = (s: string, ids?: number[]) => lint(s, { existingIds: ids }).map((d) => d.message).join(" | ");
  assert.match(msgs(`SecRule ARGS "@rx a" "phase:2,deny,msg:'x'"`), /Missing required action: id/);
  assert.match(msgs(`SecRule ARGS "@rx a" "id:1,phase:9,deny,msg:'x'"`), /Invalid phase/);
  assert.match(msgs(`SecRule ARGS "@foo a" "id:1,phase:2,pass"`), /Unknown operator/);
  assert.match(msgs(`SecRule ARGS "@rx a" "id:5,phase:2,pass"`, [5]), /Duplicate rule id 5/);
  assert.match(msgs(`SecRule ARGS "@rx a" "id:6,phase:2,pass,chain"`), /no rule follows/);
  assert.match(msgs(`SecRule ARGS "@rx (unclosed" "id:7,phase:2,pass"`), /Invalid regex/);
  assert.match(msgs(`SecRule ARGS "@rx a "id:8,phase:2,pass"`), /Unbalanced|extra argument/);
});

test("sandbox matches PRD payload and passes clean traffic", () => {
  const bad = evaluate(PRD_RULE, { method: "GET", url: "/api/v1/users?user_id=1%20UNION%20SELECT%20password", headers: {}, body: "" });
  assert.equal(bad.status, "MATCHED");
  assert.equal(bad.matched[0].ruleId, 900001);
  assert.equal(bad.matched[0].variable, "ARGS:user_id");
  const ok = evaluate(PRD_RULE, { method: "GET", url: "/api/v1/users?user_id=42", headers: {}, body: "" });
  assert.equal(ok.status, "PASSED");
});

test("sandbox evaluates chained rules as AND", () => {
  const src = `SecRule REQUEST_METHOD "@streq POST" "id:900100,phase:2,deny,msg:'chain',chain"\nSecRule ARGS:q "@contains evil" "t:lowercase"`;
  assert.equal(evaluate(src, { method: "POST", url: "/?q=EVIL", headers: {}, body: "" }).status, "MATCHED");
  assert.equal(evaluate(src, { method: "GET", url: "/?q=EVIL", headers: {}, body: "" }).status, "PASSED");
});

test("exception builder emits endpoint ctl and global target exclusions", () => {
  const ep = buildException({ ruleId: 942100, path: "/api/v1/login", parameter: "ARGS:username", scope: "endpoint", exceptionId: 10001 });
  assert.match(ep, /SecRule REQUEST_FILENAME "@streq \/api\/v1\/login"/);
  assert.match(ep, /ctl:ruleRemoveTargetById=942100;ARGS:username/);
  assert.deepEqual(lint(ep), []);
  const pre = buildException({ ruleId: 941100, path: "/cms/*", parameter: null, scope: "endpoint", exceptionId: 10002 });
  assert.match(pre, /@beginsWith \/cms\//);
  assert.match(pre, /ctl:ruleRemoveById=941100/);
  assert.match(buildException({ ruleId: 942100, path: "", parameter: "ARGS:q", scope: "global", exceptionId: 0 }), /SecRuleUpdateTargetById 942100 "!ARGS:q"/);
  assert.equal(nextFreeId([10000, 10001], 10000, 10010), 10002);
});

test("visual builder round-trips through code", () => {
  const r = { id: 900200, variables: ["ARGS", "REQUEST_HEADERS:User-Agent"], operator: "rx", value: "(?i)sqlmap", negate: false, transforms: ["lowercase"], phase: 1, action: "deny" as const, status: 403, severity: "CRITICAL", msg: "Scanner UA", tags: ["attack-reputation-scanner"] };
  const code = buildRule(r);
  assert.deepEqual(lint(code), []);
  assert.deepEqual(parseToBuilder(code), r);
});

test("kill chain mapping, outcome, risk", () => {
  assert.equal(mapRule(942100)?.killchain_stage, "EXPLOIT");
  assert.equal(mapRule(913100)?.killchain_stage, "RECON");
  assert.equal(mapRule(955110)?.killchain_stage, "INSTALL");
  assert.equal(mapRule(951120)?.killchain_stage, "OBJECTIVES");
  assert.equal(mapRule(123), null);
  assert.equal(classifyOutcome("DENY", 403), "BLOCKED");
  assert.equal(classifyOutcome("LOG", 200), "POSSIBLY_SUCCESSFUL");
  assert.equal(classifyOutcome("LOG", 404), "DETECTED");
  const recon = riskScore({ highestStage: "RECON", targets: 1, categories: 1, possiblySuccessful: 0, events: 5 });
  const exploit = riskScore({ highestStage: "EXPLOIT", targets: 3, categories: 3, possiblySuccessful: 2, events: 200 });
  assert.ok(recon < 25 && exploit >= 75, `${recon} ${exploit}`);
  assert.equal(riskScore({ highestStage: "OBJECTIVES", targets: 99, categories: 99, possiblySuccessful: 9, events: 1e9 }), 100);
  assert.equal(escalation({ highest_stage: "RECON" }, "EXPLOIT"), "EXPLOIT");
  assert.equal(escalation({ highest_stage: "EXPLOIT" }, "RECON"), null);
});

import { parseCidr } from "./utils.ts";
test("CIDR parsing normalizes and validates (blocklist trust boundary)", () => {
  assert.equal(parseCidr("192.168.1.77/24")?.normalized, "192.168.1.0/24");
  assert.equal(parseCidr("10.0.0.5")?.normalized, "10.0.0.5/32");
  assert.equal(parseCidr("256.1.1.1"), null);
  assert.equal(parseCidr("1.2.3.4/33"), null);
  assert.equal(parseCidr("abc"), null);
  assert.ok(parseCidr("203.0.113.0/24")!.contains("203.0.113.199"));
  assert.ok(!parseCidr("203.0.113.0/24")!.contains("203.0.114.1"));
  assert.ok(parseCidr("0.0.0.0/0")!.contains("8.8.8.8"));
});

test("lint pins action errors to their physical line", () => {
  const src = ['SecRule ARGS "@rx a" \\', '    "id:900500,\\', "    phase:9,\\", "    deny,\\", `    msg:'x'"`].join("\n");
  const d = lint(src).find((x) => x.message.startsWith("Invalid phase"))!;
  assert.equal(d.line, 3);
  assert.equal(d.endLine, 3);
});
