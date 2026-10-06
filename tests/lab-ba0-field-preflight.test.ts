import assert from "node:assert/strict";
import { test } from "node:test";
import { DISPOSABLE_MARKER_CONTENT, isSingleHostSource, parseUfwStatus, ruleCoversPort, runFieldPreflight, type FieldEnvironment, type PreflightInput } from "../lab/defense/field-preflight";
import { BA0_FIELD_V1, evaluateBudgetGates } from "../lab/defense/field-thresholds";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { FakeProc, RUNNER, SSHD } from "./support/fake-proc";

const UFW_OK = [
  "Status: active", "", "     To                         Action      From", "     --                         ------      ----",
  "[ 1] 22/tcp                     ALLOW IN    198.51.100.7               # limitmark-lab ssh",
  "[ 2] 8080/tcp                   ALLOW IN    203.0.113.9                # limitmark-lab ba0 plane",
  "[ 3] 22/tcp (v6)                ALLOW IN    2001:db8::7                # limitmark-lab ssh", "",
].join("\n");

function preBind(): FakeProc {
  const proc = new FakeProc();
  proc.addProcess(RUNNER).addProcess(SSHD);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  return proc;
}

const environment = (overrides: Partial<FieldEnvironment> = {}): FieldEnvironment => ({
  platform: "linux", reader: preBind(), pid: RUNNER, readMarker: () => DISPOSABLE_MARKER_CONTENT, unitState: async () => "inactive", ufwStatus: async () => UFW_OK,
  localIpv4Addresses: () => ["10.0.0.5", "127.0.0.1"], ...overrides,
});

const input = (overrides: Partial<PreflightInput> = {}, env: FieldEnvironment = environment()): PreflightInput => ({
  env, thresholds: BA0_FIELD_V1, plane: { ip: "10.0.0.5", port: 8080 }, treeIsClean: true, budgetGates: evaluateBudgetGates(BA0_FIELD_V1, 3_600_000), ...overrides,
});

const failed = (result: Awaited<ReturnType<typeof runFieldPreflight>>): string[] => result.checks.filter((check) => !check.ok).map((check) => check.id);

test("the happy path passes every check, and the evidence it produces is safe", async () => {
  const result = await runFieldPreflight(input());
  assert.deepEqual(failed(result), []);
  assert.equal(result.ok, true);
  assert.deepEqual(result.firewall, { readable: true, port3000Rules: 0, planePortSources: 1 });
  assert.deepEqual(result.ambientNonLoopbackPorts, [22]);
  assert.doesNotThrow(() => assertEvidenceSafe({ checks: result.checks, firewall: result.firewall, ambient: result.ambientNonLoopbackPorts }, "$preflight"));
});

// ------------------------------------------------------------------------------------------------ D2: the old Next service is not a parallel exposed target
test("D2: an active, activating or unreadable old application service refuses before any bind; inactive and failed (not running) are accepted", async () => {
  for (const state of ["active", "activating", "reloading", "deactivating", "unknown", "", "garbage"]) assert.ok(failed(await runFieldPreflight(input({}, environment({ unitState: async () => state })))).includes("old_service.inactive"), state);
  assert.ok(failed(await runFieldPreflight(input({}, environment({ unitState: async () => null })))).includes("old_service.inactive"), "could not be asked");
  for (const state of ["inactive", "failed"]) assert.equal((await runFieldPreflight(input({}, environment({ unitState: async () => state })))).ok, true, state);
});

test("D2: a non-loopback listener on port 3000, whoever owns it, refuses; a private one does not", async () => {
  const exposed = preBind();
  exposed.addProcess(600);
  exposed.addSocket({ family: 4, ip: "0.0.0.0", port: 3000, inode: 70 }, [600]);
  const refused = await runFieldPreflight(input({}, environment({ reader: exposed })));
  assert.ok(failed(refused).includes("exposure.pre_bind_clean"));
  assert.ok(refused.exposure?.violations.includes("ambient_forbidden_port"));
  const loopbackOnly = preBind();
  loopbackOnly.addProcess(601);
  loopbackOnly.addSocket({ family: 4, ip: "127.0.0.1", port: 3000, inode: 71 }, [601]);
  assert.equal((await runFieldPreflight(input({}, environment({ reader: loopbackOnly })))).ok, true);
});

test("D2: any firewall allow rule for port 3000 refuses, whatever its source; an allow-all rule refuses; unreadable firewall state refuses", async () => {
  const withRule = (extra: string) => environment({ ufwStatus: async () => `${UFW_OK}${extra}\n` });
  assert.ok(failed(await runFieldPreflight(input({}, withRule("[ 4] 3000/tcp                   ALLOW IN    203.0.113.9                # limitmark-lab app")))).includes("firewall.no_old_app_port_rule"));
  assert.ok(failed(await runFieldPreflight(input({}, withRule("[ 4] 3000                       ALLOW IN    Anywhere")))).includes("firewall.no_old_app_port_rule"));
  assert.ok(failed(await runFieldPreflight(input({}, withRule("[ 4] 2900:3100/tcp              ALLOW IN    203.0.113.9")))).includes("firewall.no_old_app_port_rule"), "a range that covers 3000");
  assert.ok(failed(await runFieldPreflight(input({}, withRule("[ 4] Anywhere                  ALLOW IN    203.0.113.9")))).includes("firewall.no_allow_all"));
  const unreadable = await runFieldPreflight(input({}, environment({ ufwStatus: async () => null })));
  assert.ok(failed(unreadable).includes("firewall.readable"));
  assert.ok(failed(unreadable).includes("firewall.no_old_app_port_rule"), "an unreadable firewall cannot prove the old rule is absent");
  assert.equal(unreadable.ok, false);
  const notUfw = await runFieldPreflight(input({}, environment({ ufwStatus: async () => "command not found" })));
  assert.ok(failed(notUfw).includes("firewall.readable"), "text that is not ufw output is unreadable, not an empty rule set");
  const inactive = await runFieldPreflight(input({}, environment({ ufwStatus: async () => UFW_OK.replace("Status: active", "Status: inactive") })));
  assert.ok(failed(inactive).includes("firewall.active"));
});

test("the plane port must be allowed from exactly ONE source, a single host: none, two, a network, or Anywhere all refuse", async () => {
  const body = (rules: string[]) => ["Status: active", "", ...rules, ""].join("\n");
  const cases: [string, string[], boolean][] = [
    ["one /32", ["[ 1] 8080/tcp                   ALLOW IN    203.0.113.9/32"], true],
    ["one bare host", ["[ 1] 8080/tcp                   ALLOW IN    203.0.113.9"], true],
    ["no rule", ["[ 1] 22/tcp                     ALLOW IN    198.51.100.7"], false],
    ["two hosts", ["[ 1] 8080/tcp                   ALLOW IN    203.0.113.9", "[ 2] 8080/tcp                   ALLOW IN    203.0.113.10"], false],
    ["a /24", ["[ 1] 8080/tcp                   ALLOW IN    203.0.113.0/24"], false],
    ["Anywhere", ["[ 1] 8080/tcp                   ALLOW IN    Anywhere"], false],
    ["one host and a network", ["[ 1] 8080/tcp                   ALLOW IN    203.0.113.9", "[ 2] 8080/tcp                   ALLOW IN    203.0.113.0/24"], false],
    ["a range covering the port", ["[ 1] 8000:8100/tcp              ALLOW IN    203.0.113.9"], true],
  ];
  for (const [label, rules, ok] of cases) {
    const result = await runFieldPreflight(input({}, environment({ ufwStatus: async () => body(rules) })));
    assert.equal(!failed(result).includes("firewall.plane_port_single_source"), ok, label);
  }
});

// ------------------------------------------------------------------------------------------------ host and authorization checks
test("the platform, the tree, the disposable marker and the bind address are all fail-closed", async () => {
  assert.ok(failed(await runFieldPreflight(input({}, environment({ platform: "win32" })))).includes("platform.linux"));
  assert.equal((await runFieldPreflight(input({ skipPlatformCheck: true }, environment({ platform: "win32" })))).ok, true, "the test seam only");
  assert.ok(failed(await runFieldPreflight(input({ treeIsClean: false }))).includes("tree.clean"));
  assert.ok(failed(await runFieldPreflight(input({}, environment({ readMarker: () => null })))).includes("host.disposable_marker"));
  assert.ok(failed(await runFieldPreflight(input({}, environment({ readMarker: () => "something-else" })))).includes("host.disposable_marker"));
  assert.ok(failed(await runFieldPreflight(input({ plane: { ip: "127.0.0.1", port: 8080 } }))).includes("bind.not_loopback"));
  assert.equal(failed(await runFieldPreflight(input({ plane: { ip: "127.0.0.1", port: 8080 }, allowLoopbackIngress: true }))).includes("bind.not_loopback"), false, "the test seam only");
  assert.ok(failed(await runFieldPreflight(input({}, environment({ localIpv4Addresses: () => ["10.0.0.9"] })))).includes("bind.address_is_local"), "a NAT'd or foreign address cannot be bound; it is never replaced by a wildcard");
  for (const port of [22, 80, 443, 3000, 5432, 55_416, 55_417, 1023, 80]) assert.ok(failed(await runFieldPreflight(input({ plane: { ip: "10.0.0.5", port } }))).includes("bind.port_allowed"), String(port));
});

test("the budget gates are part of the preflight: a failing gate refuses before any bind", async () => {
  const smaller = { ...BA0_FIELD_V1, l2: { ...BA0_FIELD_V1.l2, ledgerCapacity: 10 } };
  const result = await runFieldPreflight(input({ budgetGates: evaluateBudgetGates(smaller, 3_600_000) }));
  assert.ok(failed(result).includes("budget.l2.ledger_capacity"));
  assert.equal(result.ok, false);
});

// ------------------------------------------------------------------------------------------------ ufw parsing
test("ufw status is parsed rule by rule; v6 lines, ranges and Anywhere are understood", () => {
  const parsed = parseUfwStatus(UFW_OK)!;
  assert.equal(parsed.active, true);
  assert.deepEqual(parsed.rules.map((rule) => [rule.number, rule.to, rule.action, rule.from]), [
    [1, "22/tcp", "ALLOW", "198.51.100.7"], [2, "8080/tcp", "ALLOW", "203.0.113.9"], [3, "22/tcp (v6)", "ALLOW", "2001:db8::7"],
  ]);
  assert.equal(parseUfwStatus("nonsense"), null);
  assert.equal(ruleCoversPort({ number: 1, to: "3000/tcp", action: "ALLOW", from: "x" }, 3000), true);
  assert.equal(ruleCoversPort({ number: 1, to: "3000/tcp (v6)", action: "ALLOW", from: "x" }, 3000), true);
  assert.equal(ruleCoversPort({ number: 1, to: "3000/tcp", action: "ALLOW", from: "x" }, 3001), false);
  assert.equal(ruleCoversPort({ number: 1, to: "2900:3100/tcp", action: "ALLOW", from: "x" }, 3000), true);
  assert.equal(ruleCoversPort({ number: 1, to: "Anywhere", action: "ALLOW", from: "x" }, 1), true);
  assert.equal(ruleCoversPort({ number: 1, to: "30000", action: "ALLOW", from: "x" }, 3000), false);
  for (const from of ["203.0.113.9", "203.0.113.9/32"]) assert.equal(isSingleHostSource(from), true, from);
  for (const from of ["203.0.113.0/24", "Anywhere", "203.0.113.9/31", "2001:db8::7", "203.0.113"]) assert.equal(isSingleHostSource(from), false, from);
});
