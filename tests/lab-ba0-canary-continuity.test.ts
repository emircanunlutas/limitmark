import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import {
  CANARY_CONTINUITY_LIMITS, CANARY_CONTINUITY_SCHEMA, MAX_LATENCY_MS, CONTINUITY_LANES, CONTINUITY_PHASES, CONTINUITY_STEPS, FAILURE_CATEGORIES, REJECT_REASONS,
  aggregateCanaryContinuity, buildCanaryContinuity, classifyFailure, serializedBytes, type ContinuityOk, type ContinuityRow,
} from "../lab/defense/canary-continuity";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { writeFieldEvidence, type FieldEvidenceBundle } from "../lab/defense/field-evidence";
import { BA0_FIELD_V1, BA0_FIELD_C2_V1, BA0_FIELD_C2_SALVO_V1, ba0FieldFingerprint, evaluateBudgetGates } from "../lab/defense/field-thresholds";
import { WORKLOADS } from "../lab/policy/workloads";
import { workloadFingerprint } from "../lab/defense/generator-report";

const root = path.join(__dirname, "..");
const NO_INTERRUPTED: ReadonlySet<string> = new Set();
const NAMES = CONTINUITY_STEPS;

type StepSpec = { ok?: boolean; failure?: string | null; status?: number | null; latencyMs?: number };
const step = (index: number, spec: StepSpec = {}) => {
  const ok = spec.ok ?? true;
  return { step: index, name: NAMES[index - 1], ok, failure: ok ? null : (spec.failure ?? "status_503"), status: spec.status === undefined ? (ok ? 200 : 503) : spec.status, latencyMs: spec.latencyMs ?? 10 + index, bodyDigest: "d".repeat(64), headerNames: [] as string[] };
};
/** A journey whose first `okSteps` steps succeed, then optionally one failing step, then nothing (a journey stops at its first failure). */
const journey = (phase: string, lane: string, n: number, okSteps = 5, failing?: StepSpec, latency = (i: number) => 10 + i) => {
  const steps = Array.from({ length: okSteps }, (_, i) => step(i + 1, { latencyMs: latency(i + 1) }));
  if (failing && okSteps < 5) steps.push(step(okSteps + 1, { ...failing, ok: false }));
  return { lane, phase, journey: n, completed: steps.length === 5 && steps.every((s) => s.ok), steps };
};
const row = (artifact: ContinuityOk, phase: string, lane: string): ContinuityRow => artifact.rows.find((entry) => entry.phase === phase && entry.lane === lane)!;
const run = (journeys: unknown[], interrupted: ReadonlySet<string> = NO_INTERRUPTED) => aggregateCanaryContinuity(journeys, interrupted);

test("the artifact has a fixed, closed shape: 4 phases x 2 lanes x the five journey steps, in a deterministic order", () => {
  const artifact = run([]);
  assert.equal(artifact.schema, CANARY_CONTINUITY_SCHEMA);
  assert.equal(artifact.status, "ok");
  assert.equal(artifact.influencesVerdict, false);
  assert.deepEqual(artifact.steps, ["homepage", "privacy", "form", "valid_post", "thank_you"]);
  assert.deepEqual(artifact.rows.map((entry) => `${entry.phase}/${entry.lane}`), CONTINUITY_PHASES.flatMap((phase) => CONTINUITY_LANES.map((lane) => `${phase}/${lane}`)));
  for (const entry of artifact.rows) {
    assert.deepEqual(entry.steps.map((s) => s.name), [...NAMES]);
    assert.deepEqual(Object.keys(entry.steps[0].failures), [...FAILURE_CATEGORIES]);
    assert.equal(entry.journeys, 0, "a phase that did not run is journeys 0: unknown, never success");
    assert.ok(entry.steps.every((s) => s.latencyMs.p50 === null && s.latencyMs.samples === 0), "no samples means null percentiles, never 0");
  }
  assert.equal(JSON.stringify(run([])), JSON.stringify(run([])), "deterministic serialization");
});

test("all five steps, every phase and both lanes: attempted/ok/failed/notAttempted and completion are counted per row", () => {
  const journeys: unknown[] = [];
  for (const phase of CONTINUITY_PHASES) for (const lane of CONTINUITY_LANES) { journeys.push(journey(phase, lane, 1), journey(phase, lane, 2)); }
  const artifact = run(journeys);
  assert.equal(artifact.input.accepted, 16);
  for (const entry of artifact.rows) {
    assert.equal(entry.journeys, 2); assert.equal(entry.completed, 2); assert.equal(entry.incomplete, 0);
    for (const s of entry.steps) assert.deepEqual([s.attempted, s.ok, s.failed, s.notAttempted, s.missingLatency], [2, 2, 0, 0, 0]);
    assert.deepEqual(entry.firstFailureByStep, [0, 0, 0, 0, 0]);
  }
});

test("percentiles are nearest-rank per step and per phase/lane, with exact values", () => {
  const journeys = Array.from({ length: 100 }, (_, i) => journey("window", "protected", i + 1, 5, undefined, (s) => (s === 1 ? 100 - i : 5)));
  const entry = row(run(journeys), "window", "protected");
  assert.deepEqual(entry.steps[0].latencyMs, { samples: 100, p50: 50, p95: 95, p99: 99, max: 100 });
  assert.deepEqual(entry.steps[1].latencyMs, { samples: 100, p50: 5, p95: 5, p99: 5, max: 5 });
  const small = row(run([10, 20, 30].map((ms, i) => journey("baseline", "control", i + 1, 5, undefined, (s) => (s === 3 ? ms : 1)))), "baseline", "control");
  assert.deepEqual(small.steps[2].latencyMs, { samples: 3, p50: 20, p95: 30, p99: 30, max: 30 });
  // Other phases/lanes are untouched by these samples.
  assert.equal(row(run(journeys), "window", "control").steps[0].latencyMs.samples, 0);
});

test("latency of failed steps is reported separately from latency of successful steps", () => {
  const artifact = run([journey("window", "protected", 1, 0, { failure: "client_timeout", status: null, latencyMs: 5000 }), journey("window", "protected", 2, 5)]);
  const first = row(artifact, "window", "protected").steps[0];
  assert.equal(first.latencyMs.max, 5000); assert.equal(first.okLatencyMs.max, 11); assert.deepEqual([first.attempted, first.ok, first.failed], [2, 1, 1]);
});

test("missing latency samples are counted as missing, never as 0 and never as a failure", () => {
  const broken = journey("baseline", "protected", 1);
  (broken.steps[1] as { latencyMs: unknown }).latencyMs = Number.NaN;
  (broken.steps[2] as { latencyMs: unknown }).latencyMs = -1;
  (broken.steps[3] as { latencyMs: unknown }).latencyMs = "12";
  const entry = row(run([broken]), "baseline", "protected");
  assert.deepEqual(entry.steps.map((s) => s.missingLatency), [0, 1, 1, 1, 0]);
  assert.deepEqual(entry.steps.map((s) => s.latencyMs.samples), [1, 0, 0, 0, 1]);
  assert.equal(entry.steps[1].latencyMs.p50, null);
  assert.equal(entry.steps[1].ok, 1, "the step still succeeded");
  assert.equal(entry.completed, 1);
});

test("a first-step failure leaves steps 2-5 NOT ATTEMPTED (not failed, not ok)", () => {
  const entry = row(run([journey("window", "protected", 1, 0, { failure: "status_429", status: 429 })]), "window", "protected");
  assert.deepEqual(entry.steps.map((s) => [s.attempted, s.ok, s.failed, s.notAttempted]), [[1, 0, 1, 0], [0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1], [0, 0, 0, 1]]);
  assert.deepEqual(entry.firstFailureByStep, [1, 0, 0, 0, 0]);
  assert.deepEqual([entry.completed, entry.incomplete], [0, 1]);
});

test("a mid-journey failure keeps the earlier steps ok and attributes the first failing step", () => {
  const entry = row(run([journey("residual", "protected", 1, 3, { failure: "post_not_redirect", status: 200 }), journey("residual", "protected", 2, 4, { failure: "thank_you_content", status: 200 })]), "residual", "protected");
  assert.deepEqual(entry.firstFailureByStep, [0, 0, 0, 1, 1]);
  assert.deepEqual(entry.steps.map((s) => s.ok), [2, 2, 2, 1, 0]);
  assert.deepEqual(entry.steps.map((s) => s.notAttempted), [0, 0, 0, 0, 1]);
  assert.equal(entry.steps[3].failures.content_mismatch, 1); assert.equal(entry.steps[4].failures.content_mismatch, 1);
});

test("every failure category is classified into the closed vocabulary", () => {
  const cases: [string, number | null, (typeof FAILURE_CATEGORIES)[number]][] = [
    ["status_429", 429, "status_429"], ["status_403", 403, "status_4xx_other"], ["status_404", 404, "status_4xx_other"], ["status_499", 499, "status_4xx_other"],
    ["status_500", 500, "status_5xx"], ["status_503", 503, "status_5xx"], ["status_599", 599, "status_5xx"], ["status_302", 302, "status_other"],
    ["client_timeout", null, "timeout"], ["client_reset", null, "reset"], ["client_error", null, "client_error"],
    ["homepage_content", 200, "content_mismatch"], ["privacy_content", 200, "content_mismatch"], ["post_not_redirect", 200, "content_mismatch"], ["post_not_json", 200, "content_mismatch"], ["thank_you_content", 200, "content_mismatch"],
    ["form_token_missing", 200, "anti_forgery_missing"], ["something_new", 200, "unrecognized"], ["status_99", 200, "unrecognized"],
  ];
  // each failure sits on the step where runJourney can emit it (F-01)
  const stepOf: Record<string, number> = { privacy_content: 1, form_token_missing: 2, post_not_redirect: 3, post_not_json: 3, thank_you_content: 4 };
  const journeys = cases.map(([failure, status], i) => journey("window", "protected", i + 1, stepOf[failure] ?? 0, { failure, status }));
  const artifact = run(journeys);
  const entry = row(artifact, "window", "protected");
  for (const [failure, , category] of cases) assert.equal(classifyFailure(failure).category, category, failure);
  const expected = Object.fromEntries(FAILURE_CATEGORIES.map((c) => [c, cases.filter(([, , category]) => category === c).length]));
  assert.deepEqual(artifact.totals.protected, expected);
  assert.deepEqual(Object.fromEntries(FAILURE_CATEGORIES.map((c) => [c, entry.steps.reduce((total, s) => total + s.failures[c], 0)])), expected);
  assert.deepEqual(artifact.totals.control, Object.fromEntries(FAILURE_CATEGORIES.map((c) => [c, 0])));
  assert.equal(artifact.input.rejected, 0);
});

test("HTTP 429 is its own counter and never merged into other 4xx; 4xx and 5xx are separate", () => {
  const artifact = run([
    journey("window", "protected", 1, 0, { failure: "status_429", status: 429 }), journey("window", "protected", 2, 0, { failure: "status_429", status: 429 }),
    journey("window", "protected", 3, 0, { failure: "status_403", status: 403 }), journey("window", "protected", 4, 0, { failure: "status_502", status: 502 }),
  ]);
  assert.deepEqual([artifact.totals.protected.status_429, artifact.totals.protected.status_4xx_other, artifact.totals.protected.status_5xx], [2, 1, 1]);
});

test("timeouts, resets, content mismatches and anti-forgery (token) failures are counted per step", () => {
  const artifact = run([
    journey("recovery", "protected", 1, 2, { failure: "form_token_missing", status: 200 }), journey("recovery", "protected", 2, 0, { failure: "client_timeout", status: null }),
    journey("recovery", "protected", 3, 1, { failure: "client_reset", status: null }), journey("recovery", "protected", 4, 0, { failure: "homepage_content", status: 200 }),
  ]);
  const entry = row(artifact, "recovery", "protected");
  assert.equal(entry.steps[2].failures.anti_forgery_missing, 1);
  assert.equal(entry.steps[0].failures.timeout, 1); assert.equal(entry.steps[1].failures.reset, 1); assert.equal(entry.steps[0].failures.content_mismatch, 1);
  assert.deepEqual(entry.firstFailureByStep, [2, 1, 1, 0, 0]);
});

test("control-lane, residual and recovery summaries are separate rows from the protected lane", () => {
  const artifact = run([
    journey("baseline", "control", 1, 5, undefined, () => 3), journey("baseline", "protected", 1, 5, undefined, () => 4),
    journey("residual", "protected", 1, 5, undefined, () => 7), journey("recovery", "protected", 1, 5, undefined, () => 9),
  ]);
  assert.equal(row(artifact, "baseline", "control").steps[0].latencyMs.p50, 3);
  assert.equal(row(artifact, "baseline", "protected").steps[0].latencyMs.p50, 4);
  assert.equal(row(artifact, "residual", "protected").steps[0].latencyMs.p99, 7);
  assert.equal(row(artifact, "recovery", "protected").steps[4].latencyMs.max, 9);
  assert.equal(row(artifact, "residual", "control").journeys, 0);
});

test("a journey flagged completed that its steps do not support is NOT counted as completed", () => {
  const lie = journey("window", "protected", 1, 3);
  (lie as { completed: boolean }).completed = true;
  const inverse = journey("window", "protected", 2, 5);
  (inverse as { completed: boolean }).completed = false;
  const unexplained = { lane: "window" as string, phase: "window", journey: 3, completed: false, steps: [] as unknown[] };
  unexplained.lane = "protected";
  const entry = row(run([lie, inverse, unexplained]), "window", "protected");
  assert.equal(entry.completed, 1, "only the genuinely complete journey");
  assert.equal(entry.completionMismatch, 2);
  assert.equal(entry.unexplainedIncomplete, 2, "no failing step on record: the cause is unobservable, not invented");
  assert.deepEqual(entry.firstFailureByStep, [0, 0, 0, 0, 0]);
});

test("journeys a STOP interrupted are counted apart and excluded from the step statistics, as the existing rates exclude them", () => {
  const artifact = run([journey("window", "protected", 1), journey("window", "protected", 2, 1, { failure: "client_reset", status: null }), journey("window", "control", 2, 5)], new Set(["window/2"]));
  const protectedRow = row(artifact, "window", "protected");
  assert.deepEqual([protectedRow.journeys, protectedRow.interrupted, protectedRow.steps[1].failures.reset], [1, 1, 0]);
  assert.equal(row(artifact, "window", "control").journeys, 1, "the exclusion applies to the protected lane only, like the runner's");
});

test("missing or malformed records are rejected whole, counted by a closed reason, and never become a success", () => {
  const good = journey("baseline", "protected", 1);
  const withStep = (mutate: (j: ReturnType<typeof journey>) => void) => { const copy = structuredClone(good); mutate(copy); return copy; };
  const bad: [unknown, (typeof REJECT_REASONS)[number]][] = [
    [null, "shape"], [42, "shape"], ["x", "shape"], [[], "shape"], [{}, "shape"], [{ ...good, extra: 1 }, "shape"], [{ ...good, steps: "no" }, "shape"], [{ ...good, completed: "yes" }, "shape"],
    [{ ...good, lane: "other" }, "identity"], [{ ...good, phase: "setup" }, "identity"], [{ ...good, journey: 0 }, "identity"], [{ ...good, journey: 1.5 }, "identity"],
    [withStep((j) => { j.steps[0].step = 2; }), "step_sequence"], [withStep((j) => { (j.steps[0] as { name: string }).name = "privacy"; }), "step_sequence"],
    [withStep((j) => { j.steps.push(step(6)); }), "step_sequence"],
    [withStep((j) => { j.steps[2] = step(3, { ok: false, failure: "status_503" }); }), "step_sequence"],
    [withStep((j) => { (j.steps[0] as { ok: unknown }).ok = "true"; }), "shape"], [withStep((j) => { (j.steps[0] as { failure: unknown }).failure = 5; }), "shape"],
    [withStep((j) => { (j.steps[0] as { failure: unknown }).failure = "status_503"; }), "outcome"], [withStep((j) => { j.steps[0] = step(1, { ok: false, failure: null as never }); (j.steps[0] as { failure: unknown }).failure = null; }), "outcome"],
    [withStep((j) => { (j.steps[0] as { status: unknown }).status = 99; }), "status"], [withStep((j) => { (j.steps[0] as { status: unknown }).status = 700; }), "status"], [withStep((j) => { (j.steps[0] as { status: unknown }).status = 204; }), "status"],
    [withStep((j) => { (j.steps[0] as { status: unknown }).status = null; }), "status"],
    [journey("window", "protected", 1, 0, { failure: "status_429", status: 200 }), "status"],
  ];
  const artifact = run([good, ...bad.map(([record]) => record)]);
  const reasons = Object.fromEntries(REJECT_REASONS.map((reason) => [reason, bad.filter(([, r]) => r === reason).length]));
  assert.deepEqual(artifact.input.rejectedByReason, reasons);
  assert.equal(artifact.input.rejected, bad.length);
  assert.equal(artifact.input.accepted, 1);
  assert.equal(row(artifact, "baseline", "protected").journeys, 1);
  assert.equal(artifact.input.journeysSupplied, bad.length + 1);
});

test("a flood of records is bounded: only maxJourneys are read, the rest are counted as rejected", () => {
  const many = Array.from({ length: CANARY_CONTINUITY_LIMITS.maxJourneys + 50 }, (_, i) => journey("window", "protected", i + 1));
  const artifact = run(many);
  assert.equal(artifact.input.accepted, CANARY_CONTINUITY_LIMITS.maxJourneys);
  assert.equal(artifact.input.rejected, 50);
  assert.ok(serializedBytes(artifact) <= CANARY_CONTINUITY_LIMITS.maxSerializedBytes);
});

test("recovery time and challenge outcomes are UNAVAILABLE, not fabricated", () => {
  const artifact = run([journey("recovery", "protected", 1)]);
  assert.equal(artifact.recovery.timeToRecovery, "UNAVAILABLE");
  assert.equal(artifact.challenge.observed, "UNAVAILABLE");
  assert.ok(!JSON.stringify(artifact).includes('"challenges"'));
});

test("worst-case serialized size is data-independent in shape and stays under the ceiling and the evidence allowance", () => {
  const widen = (value: unknown): unknown => {
    if (typeof value === "number") return 99_999_999.99;
    if (Array.isArray(value)) return value.map(widen);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, v === null ? 99_999_999.99 : widen(v)]));
    return value;
  };
  const small = run([]);
  const widest = widen(small);
  const rowsCount = (small.rows.length); const stepRows = small.rows.reduce((total, entry) => total + entry.steps.length, 0);
  assert.equal(rowsCount, CANARY_CONTINUITY_LIMITS.rows); assert.equal(stepRows, CANARY_CONTINUITY_LIMITS.stepRows);
  // The fixed shape is identical no matter how many journeys were summarised.
  assert.equal(Object.keys(run(Array.from({ length: 300 }, (_, i) => journey("window", "protected", i + 1))) as object).join(","), Object.keys(small).join(","));
  const widestBytes = serializedBytes(widest);
  assert.ok(widestBytes <= CANARY_CONTINUITY_LIMITS.maxSerializedBytes, `widest ${widestBytes} bytes`);
  // Evidence allowance: the salvo evidence gate already charges journal + pair + diagnostic artifacts against half the 48 MiB journal cap.
  const gate = evaluateBudgetGates(BA0_FIELD_C2_SALVO_V1, 3_600_000).find((entry) => entry.id === "salvo.evidence_with_diagnostics")!;
  const modeledMiB = Number(/modeled journal, pair artifacts and diagnostic artifacts ([\d.]+) MiB vs half of 48\.0 MiB/.exec(gate.detail)![1]);
  assert.ok(modeledMiB + CANARY_CONTINUITY_LIMITS.maxSerializedBytes / 1_048_576 <= 24, `evidence ${modeledMiB} MiB plus ${CANARY_CONTINUITY_LIMITS.maxSerializedBytes} bytes within the 24 MiB allowance`);
  // Aggregation memory: at most the reviewed canary step records (320 for the salvo level), twice (live and sorted copy), as numbers.
  assert.ok(320 * 2 * 8 < 8 * 1024, "temporary aggregation memory is a few KiB");
});

test("the artifact passes the evidence scanner (no forbidden keys, token-like strings or name=value text) in its widest form", () => {
  const artifact = run(Array.from({ length: 40 }, (_, i) => journey(CONTINUITY_PHASES[i % 4], CONTINUITY_LANES[i % 2], i + 1, i % 6)));
  assert.doesNotThrow(() => assertEvidenceSafe(artifact, "$artifact(canary-continuity.json)"));
  assert.doesNotThrow(() => assertEvidenceSafe(buildCanaryContinuity([], NO_INTERRUPTED, () => { throw new Error("boom"); })));
  const text = JSON.stringify(artifact);
  assert.ok(!/bodyDigest|headerNames|nonce|cookie|authorization|127\.0\.0\.1/i.test(text));
});

test("a diagnostic failure is contained: the builder returns a small failed artifact and never throws", () => {
  const boom = buildCanaryContinuity([], NO_INTERRUPTED, () => { throw new Error("injected"); });
  assert.deepEqual([boom.status, boom.influencesVerdict], ["failed", false]);
  assert.equal((boom as { failure: string }).failure, "aggregation_error");
  assert.ok(!JSON.stringify(boom).includes("injected"), "the error text is not recorded");
  const oversized = buildCanaryContinuity([], NO_INTERRUPTED, () => ({ ...run([]), padding: "x".repeat(60 * 1024) } as unknown as ContinuityOk));
  assert.equal(oversized.status, "failed"); assert.equal((oversized as { failure: string }).failure, "size_limit");
  assert.ok(serializedBytes(boom) < 2048);
});

test("the aggregation does not mutate its input", () => {
  const input = [journey("window", "protected", 1, 2, { failure: "status_429", status: 429 })];
  const before = JSON.stringify(input);
  run(input, new Set(["window/9"]));
  assert.equal(JSON.stringify(input), before);
});

// ------------------------------------------------------------------------------------------------ evidence writer and isolation
test("the evidence writer emits the sibling artifact last and in isolation; a scanner refusal costs only this artifact", () => {
  assert.equal(typeof writeFieldEvidence, "function");
  const optional: Pick<FieldEvidenceBundle, "canaryContinuity"> = {}; // optional: a bundle without it writes exactly the artifacts it always wrote
  assert.equal(optional.canaryContinuity, undefined);
  const source = readFileSync(path.join(root, "lab/defense/field-evidence.ts"), "utf8");
  assert.match(source, /put\("salvo-diagnostics\.json"[\s\S]*?put\("canary-continuity\.json", bundle\.canaryContinuity\);\s*\n  return result;/);
  const poisoned = { ...run([]), provenance: { source: "api_key=abcd" } };
  assert.throws(() => assertEvidenceSafe(poisoned));
});

test("nothing reads the artifact back: only the field runner builds it and only the evidence writer consumes it", () => {
  const hits = execFileSync("git", ["grep", "--untracked", "-l", "-E", "canaryContinuity|canary-continuity", "--", "lab", "defense", "src", "workers"], { cwd: root, encoding: "utf8" }).split("\n").filter((file) => file.endsWith(".ts")).sort();
  assert.deepEqual(hits, ["lab/defense/ba0-field-run.ts", "lab/defense/canary-continuity.ts", "lab/defense/field-evidence.ts"]);
  const run_ = readFileSync(path.join(root, "lab/defense/ba0-field-run.ts"), "utf8");
  const built = run_.indexOf("buildCanaryContinuity(journeys"); const decided = run_.indexOf("const serverSide = decideServerSide");
  assert.ok(decided > 0 && built > decided, "computed after the server-side decision");
  assert.equal((run_.match(/canaryContinuity/g) ?? []).length, 3, "built once, handed to the bundle once, and nowhere read");
});

test("historical qualification is immutable: verdict-path files are byte-identical to the merge commit, and every fingerprint is unchanged", () => {
  const BASE = "64ccc9dabdde81fbc844807f8c104d707151de5e";
  const paths = ["defense", "src", "workers", "lab/policy", "lab/evidence", "lab/defense/canary.ts", "lab/defense/field-canary.ts", "lab/defense/field-verdict.ts", "lab/defense/field-state.ts", "lab/defense/field-thresholds.ts",
    "lab/defense/reconcile.ts", "lab/defense/salvo-spec.ts", "lab/defense/salvo-reconcile.ts", "lab/defense/salvo-diagnostics.ts", "lab/defense/salvo-diagnostic-check.ts", "lab/defense/salvo-measurement.ts",
    "lab/defense/n2-measurement.ts", "lab/defense/external-reducer.ts", "lab/defense/external-accounting.ts", "lab/defense/collector.ts", "lab/defense/generator-report.ts", "lab/defense/ba0-field-reconcile.ts"];
  assert.equal(execFileSync("git", ["diff", BASE, "--", ...paths], { cwd: root, encoding: "utf8" }), "");
  assert.equal(ba0FieldFingerprint(BA0_FIELD_V1).sha256, "5f7fbb865fcc8f44219a01af4cb02a48113a20fb75436a7f42f5ddd772b3e625");
  assert.equal(ba0FieldFingerprint(BA0_FIELD_C2_V1).sha256, "cf56f4e3272c9a4cd8257deacf153eaaf154501ceb3749e31179d756134917ab");
  assert.equal(ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1).sha256, "eda312909c18c7a7cd9c4525f2071b474f10b1b27c3b181e9e1a12ea27208f46");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c1"]), "a91b1014db56a16b808703b3616a73ab2b8f19492e61de81727737a33a2f5cec");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]), "0fa05c0ca19bfa898d7784e75d4ae1d403fe7d5ea1324be2ddc9f7d724182239");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]), "43ee3f7c0aaacea44384cc7e614eb58fe126bb042698417cf6c65f8f138d4264");
  const gates = evaluateBudgetGates(BA0_FIELD_C2_SALVO_V1, 3_600_000);
  assert.equal(gates.length, 37); assert.ok(gates.every((gate) => gate.ok));
});

// ------------------------------------------------------------------------------------------------ remediation: F-01, F-03, F-04, F-05
test("F-01: a failure that contradicts its own recorded status is rejected whole under the existing vocabulary; every real combination is accepted", () => {
  const one = (failure: string, status: number | null, at = 0) => journey("window", "protected", 1, at, { failure, status });
  const contradictory: [string, number | null, number][] = [
    ["client_timeout", 200, 0], ["client_timeout", 503, 0], ["client_reset", 503, 0], ["client_reset", 200, 0], ["client_error", 404, 0], ["client_error", 200, 0],
    ["homepage_content", null, 0], ["homepage_content", 404, 0], ["homepage_content", 500, 0],
    ["privacy_content", null, 1], ["privacy_content", 503, 1], ["form_token_missing", 404, 2], ["form_token_missing", null, 2],
    ["post_not_redirect", 500, 3], ["post_not_redirect", null, 3], ["post_not_json", 302, 3], ["thank_you_content", 404, 4], ["thank_you_content", null, 4],
    ["status_200", 200, 0], ["status_503", null, 0], ["status_503", 200, 0], ["status_404", 503, 0],
    // a content failure on a step where runJourney cannot emit it
    ["homepage_content", 200, 1], ["thank_you_content", 200, 0], ["form_token_missing", 200, 0], ["post_not_redirect", 200, 2],
  ];
  const artifact = run(contradictory.map(([failure, status, at], i) => ({ ...one(failure, status, at), journey: i + 1 })));
  assert.equal(artifact.input.accepted, 0);
  assert.equal(artifact.input.rejected, contradictory.length);
  assert.equal(artifact.input.rejectedByReason.status + artifact.input.rejectedByReason.outcome, contradictory.length);
  assert.ok(artifact.rows.every((entry) => entry.journeys === 0 && entry.steps.every((s) => s.failed === 0)));
  assert.deepEqual(artifact.totals.protected, Object.fromEntries(FAILURE_CATEGORIES.map((c) => [c, 0])));
  const legitimate: [string, number | null, number][] = [
    ["client_timeout", null, 0], ["client_reset", null, 1], ["client_error", null, 4], ["status_503", 503, 2], ["status_429", 429, 0], ["status_404", 404, 3], ["status_302", 302, 4],
    ["homepage_content", 200, 0], ["privacy_content", 200, 1], ["form_token_missing", 200, 2], ["post_not_redirect", 200, 3], ["post_not_json", 200, 3], ["thank_you_content", 200, 4],
  ];
  const accepted = run(legitimate.map(([failure, status, at], i) => ({ ...one(failure, status, at), journey: i + 1 })));
  assert.equal(accepted.input.rejected, 0); assert.equal(accepted.input.accepted, legitimate.length);
});

test("F-01: an unrecognized failure code is still counted as unrecognized (any in-range status or null) and never smuggles an impossible status combination", () => {
  const artifact = run([
    journey("window", "protected", 1, 0, { failure: "something_new", status: 200 }), journey("window", "protected", 2, 0, { failure: "something_new", status: null }),
    journey("window", "protected", 3, 0, { failure: "something_new", status: 777 }), journey("window", "protected", 4, 0, { failure: "status_099", status: 99 }),
  ]);
  assert.equal(artifact.totals.protected.unrecognized, 2);
  assert.equal(artifact.input.rejectedByReason.status, 2);
});

test("F-03: a finite but astronomically large latency is a missing sample, never Infinity or a JSON null percentile", () => {
  const huge = journey("window", "protected", 1);
  (huge.steps[0] as { latencyMs: number }).latencyMs = Number.MAX_VALUE;
  (huge.steps[1] as { latencyMs: number }).latencyMs = MAX_LATENCY_MS + 1;
  (huge.steps[2] as { latencyMs: number }).latencyMs = MAX_LATENCY_MS;
  const artifact = run([huge]);
  const entry = row(artifact, "window", "protected");
  assert.deepEqual(entry.steps.map((s) => s.missingLatency), [1, 1, 0, 0, 0]);
  assert.equal(entry.steps[0].latencyMs.samples, 0); assert.equal(entry.steps[0].latencyMs.p50, null);
  assert.deepEqual(entry.steps[2].latencyMs, { samples: 1, p50: MAX_LATENCY_MS, p95: MAX_LATENCY_MS, p99: MAX_LATENCY_MS, max: MAX_LATENCY_MS });
  const text = JSON.stringify(artifact);
  assert.ok(!text.includes("Infinity") && !text.includes("1.7976931348623157e+308"));
  assert.equal(entry.steps[0].okLatencyMs.max, null, "no percentile fabricated");
  assert.equal(entry.completed, 1, "the step outcome is unaffected");
});

test("F-04: a duplicate (phase, lane, journey) is rejected as `duplicate`, never double-counted; the same number in another lane or phase is legitimate", () => {
  const first = journey("window", "protected", 1, 2, { failure: "status_429", status: 429 });
  const artifact = run([first, structuredClone(first), journey("window", "protected", 1), journey("window", "control", 1), journey("baseline", "protected", 1), journey("window", "protected", 2)]);
  assert.equal(artifact.input.rejectedByReason.duplicate, 2);
  assert.equal(artifact.input.accepted, 4); assert.equal(artifact.input.rejected, 2);
  const protectedRow = row(artifact, "window", "protected");
  assert.deepEqual([protectedRow.journeys, protectedRow.completed, protectedRow.incomplete], [2, 1, 1]);
  assert.equal(protectedRow.steps[2].failures.status_429, 1, "the duplicate's failure is not counted again");
  assert.equal(row(artifact, "window", "control").journeys, 1); assert.equal(row(artifact, "baseline", "protected").journeys, 1);
  // a duplicate across lanes is two different identities
  const lanes = run([journey("window", "protected", 7), journey("window", "control", 7)]);
  assert.equal(lanes.input.rejectedByReason.duplicate, 0); assert.equal(lanes.input.accepted, 2);
  // a rejected malformed record does not reserve its identity
  const malformed = { ...journey("window", "protected", 9), completed: "yes" };
  const after = run([malformed, journey("window", "protected", 9)]);
  assert.deepEqual([after.input.accepted, after.input.rejectedByReason.shape, after.input.rejectedByReason.duplicate], [1, 1, 0]);
});

test("F-05: the interruption key uses the validated journey identifier carried through the checked structure", () => {
  const source = readFileSync(path.join(root, "lab/defense/canary-continuity.ts"), "utf8");
  assert.ok(!/journeys\[index\] as \{ journey/.test(source), "no re-cast of the original input");
  const artifact = run([journey("window", "protected", 3), journey("window", "protected", 4)], new Set(["window/3"]));
  const entry = row(artifact, "window", "protected");
  assert.deepEqual([entry.journeys, entry.interrupted], [1, 1]);
});
