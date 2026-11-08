import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { TALLY_EXIT, m1TallyCheck } from "../lab/defense/ba0-m1-tally-check";
import { evaluateTallyAgainstLedger, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { writeFieldLikeEvidence, type EvidenceOptions } from "./support/m1-evidence-dir";
import { connectionsOf, externalOf, receiptFins, remoteWorkload, validInput, workload } from "./support/m1-tally-fixture";

// Criterion 9 closure R-1..R-4 and the acceptance-path audit: every artifact the PASS path reads is removed, truncated, substituted or contradicted, and nothing may PASS.
// Evaluator-level cases use the fixtures; artifact-level cases write a finalized, checksummed evidence directory and run the real CLI over it.

/** A deep copy of `root` with the value at the dotted path replaced (undefined deletes it). */
function withPath<T>(root: T, dotted: string, value: unknown): T {
  const copy = structuredClone(root) as Record<string, unknown>;
  const keys = dotted.split(".");
  let node: Record<string, unknown> = copy;
  for (const key of keys.slice(0, -1)) node = node[key] as Record<string, unknown>;
  const last = keys[keys.length - 1];
  if (value === undefined) delete node[last]; else node[last] = value;
  return copy as T;
}
const reasonsOf = (input: TallyCheckInput): string[] => evaluateTallyAgainstLedger(input).reasons;
const base = (): TallyCheckInput => validInput();
const level = (input: TallyCheckInput, dotted: string, value: unknown): TallyCheckInput => ({ ...input, level: withPath(input.level, dotted, value) });
const external = (input: TallyCheckInput, dotted: string, value: unknown): TallyCheckInput => ({ ...input, external: withPath(input.external, dotted, value) });

test("baseline: complete valid evidence with an active external lane passes", () => {
  assert.deepEqual(evaluateTallyAgainstLedger(base()), { evaluated: true, outcome: "PASS", reasons: [], differences: [], ledgerSource: "kind-ledger" });
});

// ---------------------------------------------------------------------------------------------- R-1: authoritative external-lane activity
test("R-1: canary traffic alone never satisfies the external-lane requirement (previously PASS)", () => {
  const canaryOnly = validInput(workload(), []);
  assert.ok(reasonsOf(canaryOnly).includes("m1.tally.external_lane_inactive"));
  assert.equal(evaluateTallyAgainstLedger(canaryOnly).outcome, "REJECT");
  // the same canary traffic with ten times the volume is still not an external lane
  const loud = validInput([...workload(), ...workload(), ...workload()], []);
  assert.ok(reasonsOf(loud).includes("m1.tally.external_lane_inactive"));
  // no arbitrary threshold: a single remote request is enough
  const single = validInput(workload(), remoteWorkload().slice(0, 9));
  assert.equal(evaluateTallyAgainstLedger(single).outcome, "PASS", reasonsOf(single).join(","));
});

test("R-1: external.accepted must equal server-level reconcileInput.externalAccepted (a copy of one source: substitution and truncation)", () => {
  for (const wrong of [0, 4, 6, 999]) assert.ok(reasonsOf(level(base(), "serverLevel.reconcileInput.externalAccepted", wrong)).includes("m1.tally.external_accepted_vs_reconcile_input"), String(wrong));
  assert.ok(reasonsOf({ ...base(), level: withPath(base().level, "serverLevel.reconcileInput", undefined) }).includes("m1.tally.reconcile_input_missing"));
  assert.equal(evaluateTallyAgainstLedger(level(base(), "serverLevel.reconcileInput.externalAccepted", "5")).outcome, "ERROR", "a non-count is malformed, not zero");
  assert.equal(evaluateTallyAgainstLedger(level(base(), "serverLevel.reconcileInput.externalAccepted", -1)).outcome, "ERROR");
});

test("R-1: independent ingress evidence must not contradict (listener connections, terminal outcomes, plane ingress)", () => {
  assert.ok(reasonsOf({ ...base(), connections: connectionsOf(0) }).includes("m1.tally.external_without_remote_connection"));
  assert.ok(reasonsOf({ ...base(), connections: connectionsOf(7) }).includes("m1.tally.connections_vs_reconcile_input"));
  assert.ok(reasonsOf({ ...base(), connections: undefined }).includes("m1.tally.connections_missing"));
  assert.ok(reasonsOf({ ...base(), connections: { final: "not_available" } }).includes("m1.tally.connections_missing"));
  assert.equal(evaluateTallyAgainstLedger({ ...base(), connections: { final: { acceptedRemote: "3" } } }).outcome, "ERROR");
  assert.ok(reasonsOf(external(base(), "terminal", { status_200: 1 })).includes("m1.tally.external_terminal_vs_accepted"));
  assert.ok(reasonsOf(external(base(), "terminal", { status_200: 3, status_503: 2, unresolved: 1 })).includes("m1.tally.external_unresolved"));
  // the plane's own ingress cannot be smaller than the external lane's share of it
  const small = validInput(workload(), remoteWorkload());
  const tally = withPath(small.tally, "events.INGRESS_ACCEPTED", 2);
  assert.ok(reasonsOf({ ...small, tally }).includes("m1.tally.external_exceeds_plane_ingress"));
});

test("R-1: independent receipt evidence must not contradict (boundary and origin app counters, attempts)", () => {
  const fins = receiptFins(remoteWorkload());
  assert.ok(reasonsOf({ ...base(), boundaryFin: withPath(fins.boundaryFin, "stats.arrived", 0) }).includes("m1.tally.boundary_receipts_contradict"));
  for (const key of ["admitted", "rejected", "relayed", "responded"]) assert.ok(reasonsOf({ ...base(), boundaryFin: withPath(fins.boundaryFin, `stats.${key}`, 0) }).includes("m1.tally.boundary_receipts_contradict") || key === "rejected", key);
  assert.ok(reasonsOf({ ...base(), appFin: withPath(fins.appFin, "stats.counters.admitted", 0) }).includes("m1.tally.app_receipts_contradict"));
  assert.ok(reasonsOf({ ...base(), appFin: withPath(fins.appFin, "stats.counters.executed", 0) }).includes("m1.tally.app_receipts_contradict"));
  assert.ok(reasonsOf(external(base(), "egress.attempted", 1)).includes("m1.tally.receipt_exceeds_attempts"));
  for (const missing of [undefined, null, "no_fin"]) {
    assert.ok(reasonsOf({ ...base(), boundaryFin: missing }).includes("m1.tally.receipt_evidence_missing"), String(missing));
    assert.ok(reasonsOf({ ...base(), appFin: missing }).includes("m1.tally.receipt_evidence_missing"), String(missing));
  }
  assert.equal(evaluateTallyAgainstLedger({ ...base(), boundaryFin: { drained: true, stats: { arrived: -1 } } }).outcome, "ERROR");
  assert.equal(evaluateTallyAgainstLedger({ ...base(), appFin: { drained: true, stats: {} } }).outcome, "ERROR");
});

// ---------------------------------------------------------------------------------------------- R-2: reconcileInput copies
test("R-2: every copy in reconcileInput equals its source counter", () => {
  const cases: [string, unknown][] = [
    ["serverLevel.reconcileInput.statusHistogram", { "200": 1 }], ["serverLevel.reconcileInput.status503.total", 9], ["serverLevel.reconcileInput.status503.expectedShed", 0],
    ["serverLevel.reconcileInput.status503.unexplained", 1], ["serverLevel.reconcileInput.classes", { open: 9 }], ["serverLevel.reconcileInput.l1Rejected", 4], ["serverLevel.reconcileInput.egressFailed", 2],
  ];
  for (const [dotted, value] of cases) assert.ok(reasonsOf(level(base(), dotted, value)).includes("m1.tally.reconcile_input_vs_external"), dotted);
  // a zero entry and an absent entry mean the same in a status histogram; a different count does not
  assert.equal(evaluateTallyAgainstLedger(level(base(), "serverLevel.reconcileInput.statusHistogram", { ...(base().external as { statusHistogram: object }).statusHistogram, "404": 0 })).outcome, "PASS");
});

// ---------------------------------------------------------------------------------------------- R-4: level binding
test("R-4: identity fields must agree across server-level.json, core.json and manifest.json", () => {
  const cases: [string, unknown, string][] = [
    ["serverLevel.levelId", "ba0-l7-c2", "m1.tally.level_identity_mismatch"], ["serverLevel.campaignId", "campaign-b", "m1.tally.level_campaign_mismatch"],
    ["serverLevel.paramsFingerprintSha256", "d".repeat(64), "m1.tally.level_params_mismatch"], ["core.parameters.sha256", "d".repeat(64), "m1.tally.level_params_mismatch"],
    ["serverLevel.workloadFingerprintSha256", "d".repeat(64), "m1.tally.level_workload_mismatch"], ["serverLevel.workers", 2, "m1.tally.level_workers_mismatch"],
    ["serverLevel.gitSha", "e".repeat(40), "m1.tally.level_git_mismatch"], ["manifest.git.gitSha", "e".repeat(40), "m1.tally.level_git_mismatch"],
    ["serverLevel.serverSide.status", "stopped", "m1.tally.level_status_mismatch"], ["core.serverSide.failureClass", "defense", "m1.tally.level_status_mismatch"],
    ["serverLevel.serverSide.reasons", [{ code: "x" }], "m1.tally.level_status_mismatch"],
  ];
  for (const [dotted, value, reason] of cases) assert.ok(reasonsOf(level(base(), dotted, value)).includes(reason), `${dotted} -> ${reason}`);
});

test("R-4: completion and failure indicators prevent PASS (non-null failure reason, incomplete finalization, bad window, failure class)", () => {
  const complete: [string, unknown, string][] = [
    ["core.firstReason", { code: "stop" }, "m1.tally.level_first_reason_set"],
    ["serverLevel.serverSide.status", "stopped", "m1.tally.level_not_complete"], ["core.serverSide.status", "stopped", "m1.tally.level_not_complete"],
    ["serverLevel.serverSide.failureClass", "defense", "m1.tally.level_not_complete"], ["core.serverSide.failureClass", "measurement", "m1.tally.level_not_complete"],
    ["core.machine.phasesCompleted", false, "m1.tally.level_not_complete"], ["manifest.result", "SERVER-ABORTED", "m1.tally.level_not_complete"],
    ["serverLevel.window", null, "m1.tally.level_window_invalid"], ["serverLevel.window.closedAt", "2026-11-08T09:00:00.000Z", "m1.tally.level_window_invalid"],
    ["serverLevel.window.openedAt", "not a date", "m1.tally.level_window_invalid"], ["serverLevel.window.elapsedMs", -1, "m1.tally.level_window_invalid"],
    ["core.sequence", [], "m1.tally.level_finalization_incomplete"],
  ];
  for (const [dotted, value, reason] of complete) assert.ok(reasonsOf(level(base(), dotted, value)).includes(reason), `${dotted} -> ${reason}`);
  const steps = (mutate: (step: Record<string, unknown>) => void) => { const s = (base().level as { core: { sequence: Record<string, unknown>[] } }).core.sequence.map((x) => ({ ...x })); mutate(s[1]); return s; };
  assert.ok(reasonsOf(level(base(), "core.sequence", steps((s) => { s.ok = false; }))).includes("m1.tally.level_finalization_incomplete"));
  assert.ok(reasonsOf(level(base(), "core.sequence", steps((s) => { s.timedOut = true; }))).includes("m1.tally.level_finalization_incomplete"));
  assert.ok(reasonsOf(level(base(), "core.sequence", steps((s) => { s.skippedByCap = true; }))).includes("m1.tally.level_finalization_incomplete"));
  assert.ok(reasonsOf(level(base(), "core.sequence", (base().level as { core: { sequence: unknown[] } }).core.sequence.slice(0, 3))).includes("m1.tally.level_finalization_incomplete"), "a required step missing");
});

test("R-4: a missing or malformed identity field is ERROR (nothing is defaulted, no anchor is invented)", () => {
  for (const dotted of ["serverLevel.campaignId", "serverLevel.gitSha", "serverLevel.paramsFingerprintSha256", "serverLevel.workloadFingerprintSha256", "serverLevel.workers", "serverLevel.levelId",
    "core.level.id", "core.level.campaignId", "core.level.workers", "core.parameters.sha256", "core.workloadSha256", "core.sequence", "core.machine.phasesCompleted", "manifest.git.gitSha", "manifest.result", "core.serverSide.reasons"]) {
    assert.equal(evaluateTallyAgainstLedger(level(base(), dotted, undefined)).outcome, "ERROR", dotted);
  }
  for (const [dotted, bad] of [["serverLevel.gitSha", "xyz"], ["serverLevel.paramsFingerprintSha256", "abc"], ["manifest.git.gitSha", 7], ["serverLevel.workers", -1], ["serverLevel.schema", "v0"]] as const) {
    assert.equal(evaluateTallyAgainstLedger(level(base(), dotted, bad)).outcome, "ERROR", dotted);
  }
  // `firstReason` and `failureClass` must be PRESENT (null is a statement; absence is not)
  assert.equal(evaluateTallyAgainstLedger(level(base(), "core.firstReason", undefined)).outcome, "ERROR");
  assert.equal(evaluateTallyAgainstLedger(level(base(), "serverLevel.serverSide.failureClass", undefined)).outcome, "ERROR");
});

// ---------------------------------------------------------------------------------------------- R-3 and the artifact-level audit, through the real CLI
const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-c9closure-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
function run(options: EvidenceOptions): { exit: number; reasons: string[] } {
  const root = testRoot();
  try {
    const id = writeFieldLikeEvidence(root, options);
    const outcome = m1TallyCheck({ serverId: id }, root);
    return { exit: outcome.exit, reasons: outcome.result?.reasons ?? [] };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const NOT_PASS = (label: string, options: EvidenceOptions): void => { const r = run(options); assert.notEqual(r.exit, TALLY_EXIT.pass, `${label}: ${r.reasons.join(",")}`); };

test("artifact level: complete valid evidence passes through the CLI (the audit's control)", () => {
  const r = run({});
  assert.deepEqual([r.exit, r.reasons], [TALLY_EXIT.pass, []]);
});

test("R-3: duplicate keys are rejected in accounting.json and in every journal record; spellings and nesting covered; distinct case-sensitive keys are not rejected", () => {
  const dupOverflow = (text: string) => text.replace('"overflow":false', '"overflow":true,"overflow":false');
  const escaped = (text: string) => text.replace('"overflow":false', '"overflow":true,"\\u006fverflow":false');
  const nestedAccounting = (text: string) => text.replace('"journal":{', '"journal":{"lines":1,');
  for (const [label, transform] of [["ordinary", dupOverflow], ["escaped spelling", escaped], ["nested object", nestedAccounting]] as const) {
    const r = run({ rawTransform: { "accounting.json": transform } });
    assert.equal(r.exit, TALLY_EXIT.reject, `${label}: ${r.reasons.join(",")}`);
    assert.ok(r.reasons.includes("m1.tally.duplicate_json_keys"), label);
  }
  // an array containing objects (telemetry ring) and the tally object itself
  assert.ok(run({ rawTransform: { "telemetry.json": (text) => text.replace('"final":true', '"final":false,"final":true') } }).reasons.includes("m1.tally.duplicate_json_keys"));
  assert.ok(run({ rawTransform: { "telemetry.json": (text) => text.replace('"L1_ENTERED":', '"L1_ENTERED":0,"L1_ENTERED":') } }).reasons.includes("m1.tally.duplicate_json_keys"));
  assert.ok(run({ rawTransform: { "kind-ledger.json": (text) => text.replace('"collector":{', '"collector":{"received":0,') } }).reasons.includes("m1.tally.duplicate_json_keys"));
  // journal records: every line is scanned
  const journal = run({ journalLine: (line, index) => (index === 3 ? line.replace('"src":"p"', '"src":"x","src":"p"') : line) });
  assert.equal(journal.exit, TALLY_EXIT.reject);
  assert.ok(journal.reasons.includes("m1.tally.duplicate_json_keys"));
  // keys that differ only in case are different keys and must not be rejected
  const caseOnly = run({ rawTransform: { "accounting.json": (text) => text.replace('"overflow":false', '"overflow":false,"Overflow":true') } });
  assert.deepEqual([caseOnly.exit, caseOnly.reasons], [TALLY_EXIT.pass, []]);
  // malformed JSON keeps the parser's handling: ERROR for the artifacts that become unreadable
  assert.equal(run({ rawTransform: { "accounting.json": (text) => `${text.slice(0, -1)},}` } }).exit, TALLY_EXIT.error);
});

test("audit: each artifact removed, truncated, replaced by nonsense, or substituted by a self-consistent but different one -> never PASS", () => {
  const names = ["telemetry.json", "kind-ledger.json", "processes.json", "external.json", "connections.json", "server-level.json", "core.json", "accounting.json"];
  for (const name of names) {
    NOT_PASS(`${name} removed`, { artifacts: { [name]: null } });
    NOT_PASS(`${name} truncated`, { rawArtifacts: { [name]: '{"truncated":' } });
    NOT_PASS(`${name} empty file`, { rawArtifacts: { [name]: "" } });
    NOT_PASS(`${name} array instead of object`, { rawArtifacts: { [name]: "[]" } });
    NOT_PASS(`${name} empty object`, { artifacts: { [name]: {} } });
    NOT_PASS(`${name} null`, { rawArtifacts: { [name]: "null" } });
  }
  // substitution: a different, internally consistent run's artifact in this run's directory
  const other = remoteWorkload().slice(0, 9);
  NOT_PASS("external.json of another run", { artifacts: { "external.json": { counters: externalOf(other) } } });
  NOT_PASS("connections.json of an idle listener", { artifacts: { "connections.json": connectionsOf(0) } });
  NOT_PASS("kind-ledger.json of a canary-only run", { ledgerEvents: workload() });
});

test("audit: contradictions between artifacts that describe the same thing never PASS", () => {
  NOT_PASS("reconcileInput says 4", { mutate: { "server-level.json": (c) => { (c.reconcileInput as { externalAccepted: number }).externalAccepted = 4; } } });
  NOT_PASS("server-level campaign differs from core", { mutate: { "server-level.json": (c) => { c.campaignId = "other"; } } });
  NOT_PASS("core firstReason set", { mutate: { "core.json": (c) => { c.firstReason = { code: "stop", cls: "defense", atMs: 1 }; } } });
  NOT_PASS("plane lastSeq differs from the ledger", { mutate: { "processes.json": (c) => { (c.plane as { channel: { lastSeq: number } }).channel.lastSeq += 1; } } });
  NOT_PASS("boundary reports fewer arrivals than the reducer attributes", { mutate: { "processes.json": (c) => { (c.boundary as { stats: { arrived: number } }).stats.arrived = 0; } } });
  NOT_PASS("journal digest not matching", { journalMutator: (text) => `${text}\n` });
  NOT_PASS("final tick not final", { final: false });
  NOT_PASS("tally absent", { omitTally: true });
});
