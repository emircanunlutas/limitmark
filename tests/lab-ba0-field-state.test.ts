import assert from "node:assert/strict";
import { test } from "node:test";
import { FieldMachine, IllegalTransition, runSequence, type SequenceStep } from "../lab/defense/field-state";
import {
  FIELD_EXIT, REASON_CLASS, REASON_CODES, classOf, decideFinal, decideServerSide, dominantClass, type Reason, type ReasonCode,
} from "../lab/defense/field-verdict";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const clock = () => { let now = 0; return { now: () => now, advance: (ms: number) => { now += ms; } }; };

// ------------------------------------------------------------------------------------------------ the machine
test("the normal path is exactly PREFLIGHT -> TOPOLOGY_UP -> BASELINE -> ARMED -> WINDOW -> RESIDUAL -> QUIET -> RECOVERY -> FINALIZING -> DONE", () => {
  const t = clock();
  const m = new FieldMachine(t.now);
  for (const state of ["PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY", "FINALIZING", "DONE"] as const) { t.advance(10); m.advance(state); }
  assert.deepEqual(m.transitions().map((entry) => entry.state), ["CREATED", "PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY", "FINALIZING", "DONE"]);
  assert.equal(m.stopped, false);
  assert.equal(m.firstReason, null);
});

test("no state can be skipped, repeated or reversed", () => {
  const m = new FieldMachine(() => 0);
  m.advance("PREFLIGHT");
  assert.throws(() => m.advance("BASELINE"), IllegalTransition);
  m.advance("TOPOLOGY_UP");
  assert.throws(() => m.advance("TOPOLOGY_UP"), IllegalTransition);
  assert.throws(() => m.advance("PREFLIGHT"), IllegalTransition);
  assert.throws(() => m.advance("DONE"), IllegalTransition);
});

test("the FIRST reason is latched atomically: later reasons are recorded and never replace it, whatever their class", () => {
  const t = clock();
  const m = new FieldMachine(t.now, () => 1_700_000_000_000);
  for (const state of ["PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW"] as const) m.advance(state);
  t.advance(500);
  assert.equal(m.latch({ code: "exposure_violation", detail: "first" }), true);
  t.advance(100);
  assert.equal(m.latch({ code: "operator_abort" }), false);
  assert.equal(m.latch({ code: "process_crash" }), false);
  assert.equal(m.firstReason?.code, "exposure_violation");
  assert.equal(m.firstReason?.cls, "measurement");
  assert.equal(m.firstReason?.atMs, 500);
  assert.equal(m.firstReason?.wallMs, 1_700_000_000_000);
  assert.deepEqual(m.allReasons().map((entry) => entry.code), ["exposure_violation", "operator_abort", "process_crash"]);
});

test("a STOP begins at once from any stoppable state, and no new work may start after it", () => {
  for (const from of ["TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY"] as const) {
    const m = new FieldMachine(() => 0);
    const path = ["PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY"] as const;
    for (const state of path.slice(0, path.indexOf(from) + 1)) m.advance(state);
    assert.equal(m.canStartWork(), true, from);
    m.latch({ code: "process_crash" });
    assert.equal(m.state, "STOPPING", from);
    assert.equal(m.stopped, true);
    assert.equal(m.canStartWork(), false, `no new phase, canary or work after a STOP from ${from}`);
  }
});

test("after a STOP the only legal path is STOPPING -> DRAINING -> SNAPSHOT -> FINALIZING -> DONE", () => {
  const m = new FieldMachine(() => 0);
  for (const state of ["PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW"] as const) m.advance(state);
  m.latch({ code: "tick_gap" });
  assert.throws(() => m.advance("RESIDUAL"), IllegalTransition, "the normal flow is closed");
  assert.throws(() => m.advance("FINALIZING"), IllegalTransition, "no shortcut past the drain and the snapshot");
  m.advance("DRAINING");
  assert.throws(() => m.advance("DONE"), IllegalTransition);
  m.advance("SNAPSHOT");
  m.advance("FINALIZING");
  m.advance("DONE");
  assert.deepEqual(m.transitions().map((entry) => entry.state).slice(-5), ["STOPPING", "DRAINING", "SNAPSHOT", "FINALIZING", "DONE"]);
});

test("a non-stopping reason is recorded without beginning a STOP; a preflight refusal goes straight to DONE and binds nothing", () => {
  const m = new FieldMachine(() => 0);
  for (const state of ["PREFLIGHT", "TOPOLOGY_UP"] as const) m.advance(state);
  m.latch({ code: "canary_starved" }, false);
  assert.equal(m.stopped, false);
  assert.equal(m.state, "TOPOLOGY_UP");
  const refused = new FieldMachine(() => 0);
  refused.advance("PREFLIGHT");
  refused.refuse({ code: "preflight_refused", detail: "firewall.readable" });
  assert.equal(refused.state, "DONE");
  assert.equal(refused.refused, true);
  assert.equal(refused.firstReason?.cls, "operational");
});

test("a reason raised while still in PREFLIGHT cannot start a STOP (there is nothing to stop yet)", () => {
  const m = new FieldMachine(() => 0);
  m.advance("PREFLIGHT");
  m.latch({ code: "operator_abort" });
  assert.equal(m.stopped, false);
  assert.equal(m.firstReason?.code, "operator_abort");
});

// ------------------------------------------------------------------------------------------------ the bounded sequence
const step = (name: string, run: () => Promise<void>, budgetMs: number, essential = false, before?: () => void): SequenceStep => ({ name, run, budgetMs, essential, before });

test("D5: the steps run in the declared order, each bounded by its own budget, and every result is recorded", async () => {
  const order: string[] = [];
  const results = await runSequence([
    step("close_ingress", async () => { order.push("close_ingress"); }, 200),
    step("drain", async () => { await sleep(20); order.push("drain"); }, 200),
    step("snapshot", async () => { order.push("snapshot"); }, 200),
    step("finalize_evidence", async () => { order.push("finalize_evidence"); }, 200, true),
    step("terminate", async () => { order.push("terminate"); }, 200, true),
  ], 5_000);
  assert.deepEqual(order, ["close_ingress", "drain", "snapshot", "finalize_evidence", "terminate"]);
  assert.deepEqual(results.map((entry) => [entry.name, entry.ok, entry.timedOut, entry.skippedByCap]), [
    ["close_ingress", true, false, false], ["drain", true, false, false], ["snapshot", true, false, false], ["finalize_evidence", true, false, false], ["terminate", true, false, false],
  ]);
});

test("a step that HANGS times out, is recorded as timed out, and never stops the sequence: evidence and termination still run", async () => {
  const order: string[] = [];
  const results = await runSequence([
    step("drain", async () => { await sleep(10_000); order.push("never"); }, 60),
    step("snapshot", async () => { order.push("snapshot"); }, 200),
    step("finalize_evidence", async () => { order.push("finalize_evidence"); }, 200, true),
    step("terminate", async () => { order.push("terminate"); }, 200, true),
  ], 5_000);
  assert.deepEqual(order, ["snapshot", "finalize_evidence", "terminate"]);
  assert.deepEqual([results[0].ok, results[0].timedOut], [false, true]);
  assert.ok(results[0].ms < 500, "bounded by its own budget, not by the hang");
});

test("a step that THROWS is recorded with its error class and never stops the sequence", async () => {
  const results = await runSequence([
    step("drain", async () => { throw new TypeError("boom"); }, 200),
    step("finalize_evidence", async () => undefined, 200, true),
  ], 5_000);
  assert.equal(results[0].ok, false);
  assert.equal(results[0].error, "TypeError");
  assert.equal(results[1].ok, true);
});

test("the whole sequence has a HARD CAP: once it is spent every non-essential step is skipped (and recorded), while the essential ones still run", async () => {
  const order: string[] = [];
  const results = await runSequence([
    // A non-essential step is bounded by what is LEFT of the cap, so a hang spends the whole cap...
    step("drain", async () => { await sleep(2_000); order.push("drain"); }, 1_000),
    step("final_telemetry", async () => { order.push("final_telemetry"); }, 1_000),
    step("snapshot", async () => { order.push("snapshot"); }, 1_000),
    // ...and from then on only the essential steps run.
    step("finalize_evidence", async () => { order.push("finalize_evidence"); }, 1_000, true),
    step("terminate", async () => { order.push("terminate"); }, 1_000, true),
  ], 150);
  assert.deepEqual(order, ["finalize_evidence", "terminate"]);
  assert.deepEqual(results.map((entry) => entry.timedOut), [true, false, false, false, false]);
  assert.deepEqual(results.map((entry) => entry.skippedByCap), [false, true, true, false, false]);
  assert.ok(results[0].ms < 600, "the hang was cut at the cap, not at its own budget");
});

test("the state machine is advanced from inside the sequence (the `before` hook), and a throwing hook never stops it", async () => {
  const m = new FieldMachine(() => 0);
  for (const state of ["PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW"] as const) m.advance(state);
  m.latch({ code: "process_crash" });
  const seen: string[] = [];
  await runSequence([
    step("close_ingress", async () => { seen.push(m.state); }, 100, false, () => m.advance("DRAINING")),
    step("snapshot", async () => { seen.push(m.state); }, 100, false, () => { m.advance("SNAPSHOT"); throw new Error("hook failure"); }),
    step("finalize_evidence", async () => { seen.push(m.state); }, 100, true, () => m.advance("FINALIZING")),
  ], 1_000);
  assert.deepEqual(seen, ["DRAINING", "SNAPSHOT", "FINALIZING"]);
});

test("SIGKILL is never the first move: the terminate step is the LAST step, after the evidence step, in the sequence the runner builds", async () => {
  const { readFileSync } = await import("node:fs");
  const path = await import("node:path");
  const source = readFileSync(path.join(__dirname, "..", "lab", "defense", "ba0-field-run.ts"), "utf8");
  const names = [...source.matchAll(/\{ name: "([a-z_]+)", budgetMs/g)].map((match) => match[1]);
  assert.deepEqual(names, ["close_ingress", "drain", "final_telemetry", "snapshot", "finalize_evidence", "terminate"]);
  assert.doesNotMatch(source, /SIGKILL/, "the runner never kills a child itself; the handles' bounded graceful stop is the only fallback");
  const processes = readFileSync(path.join(__dirname, "..", "lab", "defense", "field-processes.ts"), "utf8");
  assert.match(processes, /send\(\{ type: "stop" \}\);[\s\S]*?SIGKILL/, "stop is sent first; a kill is the bounded last fallback after the wait");
});

// ------------------------------------------------------------------------------------------------ verdict classes
test("every reason code has exactly one class, and every class is used", () => {
  assert.ok(REASON_CODES.length >= 30);
  for (const code of REASON_CODES) assert.ok(["measurement", "defense", "operational"].includes(REASON_CLASS[code]), code);
  assert.deepEqual([...new Set(REASON_CODES.map(classOf))].sort(), ["defense", "measurement", "operational"]);
});

test("the three failure classes keep their meanings: measurement, measured defense failure, operational abort", () => {
  const measurement: ReasonCode[] = ["exposure_violation", "exposure_unproven", "evidence_gap", "tick_gap", "unattributed_503", "unexplained_traffic", "traffic_in_quiet", "canary_starved", "generator_saturation", "generator_ambiguity", "generator_in_flight_exceeded", "generator_report_mismatch"];
  const defense: ReasonCode[] = ["process_crash", "app_bypass", "mutation_over_budget", "jcr_below_minimum", "legitimate_refusal", "l1_false_reject", "l2_legitimate_non_admit", "resource_ceiling", "recovery_failed", "residual_denial"];
  const operational: ReasonCode[] = ["operator_abort", "target_expired", "generator_not_started", "preflight_refused", "level_incomplete"];
  for (const code of measurement) assert.equal(classOf(code), "measurement", code);
  for (const code of defense) assert.equal(classOf(code), "defense", code);
  for (const code of operational) assert.equal(classOf(code), "operational", code);
});

test("precedence is measurement, then defense, then operational; every reason stays recorded", () => {
  const r = (...codes: ReasonCode[]): Reason[] => codes.map((code) => ({ code }));
  assert.equal(dominantClass(r("operator_abort", "jcr_below_minimum", "tick_gap")), "measurement");
  assert.equal(dominantClass(r("operator_abort", "jcr_below_minimum")), "defense");
  assert.equal(dominantClass(r("operator_abort")), "operational");
  assert.equal(dominantClass([]), null);
  const decided = decideServerSide(r("operator_abort", "tick_gap"), true);
  assert.deepEqual([decided.status, decided.failureClass, decided.reasons.length], ["invalid", "measurement", 2]);
});

test("server side: complete only when every phase ran and nothing was raised; an incomplete level can never be complete", () => {
  assert.deepEqual(decideServerSide([], true), { status: "complete", failureClass: null, reasons: [] });
  const incomplete = decideServerSide([], false);
  assert.equal(incomplete.status, "aborted");
  assert.equal(incomplete.failureClass, "operational");
  assert.ok(incomplete.reasons.some((reason) => reason.code === "level_incomplete"));
  assert.equal(decideServerSide([{ code: "jcr_below_minimum" }], true).status, "invalid");
  assert.equal(decideServerSide([{ code: "generator_not_started" }], false).status, "aborted");
});

test("the FINAL verdict comes only from the server decision plus the reconcile's reasons, and VALID needs both clean", () => {
  const clean = decideServerSide([], true);
  assert.equal(decideFinal(clean, []).verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  assert.equal(decideFinal(clean, [{ code: "unexplained_traffic" }]).verdict, "INVALID");
  assert.equal(decideFinal(clean, [{ code: "generator_ambiguity" }]).failureClass, "measurement");
  const defenseFailed = decideServerSide([{ code: "mutation_over_budget" }], true);
  assert.deepEqual([decideFinal(defenseFailed, []).verdict, decideFinal(defenseFailed, []).failureClass], ["INVALID", "defense"]);
  const aborted = decideServerSide([{ code: "operator_abort" }], false);
  assert.equal(decideFinal(aborted, []).verdict, "ABORTED");
  assert.equal(decideFinal(aborted, [{ code: "generator_report_missing" }]).verdict, "INVALID", "a measurement reason found at reconcile outranks the abort");
  assert.deepEqual({ ...FIELD_EXIT }, { complete: 0, invalid: 1, refused: 2, aborted: 3, error: 4 });
});
