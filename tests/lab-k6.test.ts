import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { buildK6Plan, judgeK6Run, parseK6Summary, type K6Summary } from "../lab/load/k6";
import { HARD, buildModel, validatePlan, type K6PlanShape } from "../lab/load/k6/plan.mjs";
import { authorizeRun, buildRegistry, type AuthorizedRun, type EffectiveLimits } from "../lab/policy/target-policy";
import { THRESHOLD_SETS } from "../lab/policy/thresholds";
import { HARD_CEILINGS, WORKLOADS, type WorkloadId } from "../lab/policy/workloads";

const phase = (over: Partial<K6PlanShape["phases"][number]> = {}) => ({ name: "latency", seconds: 60, rate: 5, vus: 2, timeoutMs: 5000, measured: true, ...over });
const plan = (over: Partial<K6PlanShape> = {}): K6PlanShape => ({
  schema: 2, baseUrl: "http://127.0.0.1:3000", maxTotalRequests: 300, requests: [{ method: "GET", path: "/" }], phases: [phase()],
  thresholds: { passErrorRate: 0.005, stopErrorRate: 0.05, passP95Ms: 250, passP99Ms: 800, stopP99Ms: 3000 }, ...over,
});
const rejects = (candidate: unknown, pattern: RegExp) => assert.throws(() => validatePlan(candidate), pattern);

function runOf(workloadId: WorkloadId, limits?: Partial<EffectiveLimits>): AuthorizedRun {
  const now = new Date();
  const run = authorizeRun({ targetId: "local-app", workloadId, registry: buildRegistry([], now), now });
  return limits ? { ...run, limits: { ...run.limits, ...limits } } : run;
}

// ------------------------------------------------------------------------------------------------ the shared ceilings
test("F3: the plan validator's ceilings are the policy's hard ceilings (they cannot drift apart)", () => {
  assert.equal(HARD.rate, HARD_CEILINGS.maxRequestsPerSecond);
  assert.equal(HARD.vus, HARD_CEILINGS.maxConcurrency);
  assert.equal(HARD.seconds, HARD_CEILINGS.maxDurationSeconds);
  assert.equal(HARD.timeoutMs, HARD_CEILINGS.maxRequestTimeoutMs);
  assert.equal(HARD.totalRequests, HARD_CEILINGS.maxTotalRequests);
  assert.equal(HARD.responseBytes, HARD_CEILINGS.maxResponseBytes);
});

test("F3 regression: a self-consistent plan that schedules 90,000 requests is refused when the hard total is 20,000", () => {
  // 100 req/s x 900 s = 90,000. Hashing it (as a generator would) does not make it acceptable: the validator re-derives the total.
  const huge = plan({ maxTotalRequests: HARD.totalRequests, phases: [phase({ seconds: 900, rate: 100, vus: 50 })] });
  rejects(huge, /scheduled requests 90000 exceed the hard ceiling 20000/);
  // Also when the plan CLAIMS a larger total than the hard ceiling...
  rejects(plan({ maxTotalRequests: 90_000, phases: [phase({ seconds: 900, rate: 100, vus: 50 })] }), /total request ceiling/);
  // ...and when its own claimed ceiling is lower than what its phases schedule.
  rejects(plan({ maxTotalRequests: 100, phases: [phase({ seconds: 60, rate: 5 })] }), /exceed the plan ceiling 100/);
  // The exact hard total is accepted, one more request is not.
  assert.doesNotThrow(() => validatePlan(plan({ maxTotalRequests: HARD.totalRequests, phases: [phase({ seconds: 200, rate: 100, vus: 50 })] })));
  rejects(plan({ maxTotalRequests: HARD.totalRequests, phases: [phase({ seconds: 200, rate: 100, vus: 50 }), phase({ name: "x", seconds: 1, rate: 1, vus: 1 })] }), /exceed the hard ceiling/);
});

test("F3: every other plan field is bounded independently of the plan's own hash", () => {
  rejects(plan({ schema: 1 as never }), /schema/);
  rejects({ ...plan(), extra: 1 }, /unknown field/);
  rejects(plan({ baseUrl: "http://999.1.1.1:3000" }), /base URL/);
  rejects(plan({ baseUrl: "http://example.test:3000" }), /base URL/);
  rejects(plan({ baseUrl: "http://127.0.0.1:99999" }), /port/);
  rejects(plan({ baseUrl: "http://10.0.0.1:3000/x" }), /base URL/);
  rejects(plan({ requests: [] }), /requests/);
  rejects(plan({ requests: [{ method: "GET", path: "/admin" }] }), /path/);
  rejects(plan({ requests: [{ method: "GET", path: "/%2e%2e/" }] }), /path/);
  rejects(plan({ requests: [{ method: "POST", path: "/" }] }), /method/);
  rejects(plan({ requests: [{ method: "DELETE" as never, path: "/" }] }), /method/);
  rejects(plan({ phases: [] }), /phases/);
  rejects(plan({ phases: Array.from({ length: 9 }, (_, index) => phase({ name: `p${index}`, seconds: 1, rate: 1, vus: 1 })) }), /phases/);
  rejects(plan({ phases: [phase({ rate: 101 })] }), /rate ceiling/);
  rejects(plan({ phases: [phase({ vus: 51 })] }), /concurrency ceiling/);
  rejects(plan({ phases: [phase({ timeoutMs: 10_001 })] }), /timeout ceiling/);
  rejects(plan({ phases: [phase({ seconds: 901 })] }), /phase duration/);
  rejects(plan({ phases: [phase({ seconds: 600, rate: 1 }), phase({ name: "b", seconds: 301, rate: 1 })] , maxTotalRequests: 20_000 }), /duration/);
  rejects(plan({ phases: [phase({ rate: 1.5 })] }), /rate ceiling/);
  rejects(plan({ phases: [phase({ rate: Number.NaN })] }), /rate ceiling/);
  rejects(plan({ phases: [phase({ name: "x\"; throw 1; //" })] }), /phase name/);
  rejects(plan({ phases: [phase(), phase()] }), /duplicate phase name/);
  rejects(plan({ phases: [{ ...phase(), vus: 2, extra: true } as never] }), /unknown phase field/);
  rejects(plan({ thresholds: { passErrorRate: "0.1); fail(" as never, stopErrorRate: 0.05, passP95Ms: 1, passP99Ms: 1, stopP99Ms: 1 } }), /passErrorRate/);
  rejects(plan({ thresholds: { passErrorRate: 0.1, stopErrorRate: 2.5, passP95Ms: 1, passP99Ms: 1, stopP99Ms: 1 } }), /stopErrorRate/);
  rejects(plan({ thresholds: { passErrorRate: 0.1, stopErrorRate: 0.2, passP95Ms: -1, passP99Ms: 1, stopP99Ms: 1 } }), /passP95Ms/);
  rejects(null, /not an object/);
  rejects([], /not an object/);
});

// ------------------------------------------------------------------------------------------------ the scenario model
function intervals(model: ReturnType<typeof buildModel>, source: K6PlanShape) {
  return source.phases.map((entry, index) => {
    const key = Object.keys(model.scenarios)[index];
    const scenario = model.scenarios[key] as { startTime: string; duration: string; gracefulStop: string; maxVUs: number };
    const start = Number.parseInt(scenario.startTime, 10);
    return { key, start, end: start + Number.parseInt(scenario.duration, 10) + Number.parseInt(scenario.gracefulStop, 10), vus: scenario.maxVUs };
  });
}

test("F3 regression: phases never overlap, so the process-wide concurrency is the largest phase, not a sum (8 -> 16 reproduced 24 before)", () => {
  const controlled = plan({
    maxTotalRequests: 4000,
    phases: [1, 2, 4, 8, 16].map((vus) => phase({ name: `concurrency-${vus}`, seconds: 20, rate: 40, vus, timeoutMs: 5000 })),
  });
  const model = buildModel(controlled);
  const spans = intervals(model, controlled);
  for (let index = 1; index < spans.length; index++) {
    // A phase starts only after the previous one's dispatch window AND its graceful-stop (in-flight drain) are over.
    assert.ok(spans[index].start >= spans[index - 1].end, `phase ${index} starts at ${spans[index].start}s before the previous ends at ${spans[index - 1].end}s`);
  }
  // Worst-case concurrent VUs at every second of the run.
  let worst = 0;
  for (let second = 0; second <= model.wallSeconds; second++) {
    worst = Math.max(worst, spans.filter((span) => second >= span.start && second < span.end).reduce((sum, span) => sum + span.vus, 0));
  }
  assert.equal(worst, 16);
  assert.equal(model.windowSeconds, 100);
  assert.equal(model.wallSeconds, 5 * (20 + 6), "each phase adds its graceful stop (timeout + 1 s); the wall clock is stated, not hidden");
  // The old schedule, for the record: start = sum of previous DURATIONS while each phase kept a 5 s graceful stop => overlap.
  assert.ok(Number.parseInt((model.scenarios[Object.keys(model.scenarios)[4]] as { startTime: string }).startTime, 10) > 80, "the 16-VU phase starts after the 8-VU drain");
});

test("F3 regression: every phase has an iteration cap of rate x seconds, so the total is an upper bound (1 s at 2 rps could emit 3)", () => {
  const model = buildModel(plan({ maxTotalRequests: 2, phases: [phase({ name: "tiny", seconds: 1, rate: 2, vus: 1 })] }));
  const caps = Object.values(model.caps);
  assert.deepEqual(caps, [2]);
  assert.equal(model.totalRequests, 2);
  const burst = plan({
    maxTotalRequests: 1200,
    phases: [phase({ name: "warmup", seconds: 5, rate: 5, vus: 4 }), phase({ name: "burst", seconds: 10, rate: 100, vus: 50 }), phase({ name: "cooldown", seconds: 15, rate: 5, vus: 4 })],
  });
  const burstModel = buildModel(burst);
  assert.equal(burstModel.totalRequests, 25 + 1000 + 75);
  assert.ok(burstModel.totalRequests <= burst.maxTotalRequests);
  for (const [key, cap] of Object.entries(burstModel.caps)) {
    const scenario = burstModel.scenarios[key] as { rate: number; duration: string };
    assert.equal(cap, scenario.rate * Number.parseInt(scenario.duration, 10));
  }
});

test("F3: graceful stop covers the phase's own request timeout, so no request is cut off or left running into the next phase", () => {
  const model = buildModel(plan({ phases: [phase({ timeoutMs: 10_000 }), phase({ name: "b", timeoutMs: 1 })], maxTotalRequests: 1000 }));
  const [first, second] = Object.values(model.scenarios) as { gracefulStop: string }[];
  assert.equal(first.gracefulStop, "11s");
  assert.equal(second.gracefulStop, "2s");
});

test("F3: STOP and PASS thresholds are generated for measured phases only, with the exact expressions the wrapper later requires", () => {
  const model = buildModel(plan({ phases: [phase({ name: "a", measured: true }), phase({ name: "b", measured: false })], maxTotalRequests: 1000 }));
  assert.deepEqual(Object.keys(model.thresholds).sort(), ["http_req_duration{scenario:p0_a}", "http_req_failed{scenario:p0_a}"]);
  assert.deepEqual(model.expectedThresholds.map((entry) => `${entry.metric} ${entry.expression}`).sort(), [
    "http_req_duration{scenario:p0_a} p(95)<=250", "http_req_duration{scenario:p0_a} p(99)<3000", "http_req_duration{scenario:p0_a} p(99)<=800",
    "http_req_failed{scenario:p0_a} rate<0.05", "http_req_failed{scenario:p0_a} rate<=0.005",
  ]);
});

test("F3: every reviewed workload serialises to a plan the script's own validator accepts, within the hard total", () => {
  for (const id of Object.keys(WORKLOADS) as WorkloadId[]) {
    if (WORKLOADS[id].engine !== "http") continue;
    const run = runOf(id);
    const built = buildK6Plan(run, THRESHOLD_SETS["local-loopback-v1"].http[id as keyof typeof THRESHOLD_SETS["local-loopback-v1"]["http"]]);
    const model = buildModel(built);
    assert.ok(model.totalRequests <= HARD.totalRequests, id);
    assert.ok(model.totalRequests <= run.limits.maxTotalRequests, id);
  }
});

test("F3 regression: a copied AuthorizedRun with inflated limits cannot be turned into an accepted k6 plan", () => {
  const inflated = runOf("sustained-soak", { phases: [{ name: "soak", durationSeconds: 900, ratePerSecond: 100, concurrency: 50, timeoutMs: 5000 }], maxTotalRequests: 20_000 });
  assert.throws(() => buildK6Plan(inflated, THRESHOLD_SETS["local-loopback-v1"].http["sustained-soak"]), /scheduled requests 90000 exceed the hard ceiling/);
  const tooFast = runOf("sustained-soak", { phases: [{ name: "soak", durationSeconds: 10, ratePerSecond: 500, concurrency: 5, timeoutMs: 5000 }], maxTotalRequests: 5000 });
  assert.throws(() => buildK6Plan(tooFast, THRESHOLD_SETS["local-loopback-v1"].http["sustained-soak"]), /rate ceiling/);
});

// ------------------------------------------------------------------------------------------------ the script itself
test("F3: the k6 script enforces the per-phase cap, the wall clock and the response size, and reads its model from the shared validator", () => {
  const source = readFileSync(path.join(__dirname, "..", "lab", "load", "k6", "lab-load.js"), "utf8");
  assert.match(source, /from "\.\/plan\.mjs"/);
  assert.match(source, /buildModel\(plan\)/);
  assert.match(source, /iterationInTest >= cap\) return/);
  assert.match(source, /exec\.test\.abort\(/);
  assert.match(source, /response\.body\.byteLength/);
  assert.match(source, /responseType: "binary"/);
  assert.match(source, /HARD\.responseBytes/);
  assert.doesNotMatch(source, /discardResponseBodies: true/, "bodies must be kept as bytes to be measured");
  assert.doesNotMatch(source, /gracefulStop: "5s"/);
  assert.doesNotMatch(source, /__ENV\.(?!LAB_PLAN|PHASE_TIMEOUT_MS)/, "nothing but the plan may steer the script");
  // The honest limit is documented in the script, not only in the README.
  assert.match(source, /cannot truncate a body/);
});

// ------------------------------------------------------------------------------------------------ F7: no false green
const model = buildModel(plan({ maxTotalRequests: 300, phases: [phase()] }));
const healthy = (): K6Summary => ({ metrics: {
  "http_req_failed{scenario:p0_latency}": { thresholds: { "rate<0.05": false, "rate<=0.005": false }, value: 0 },
  "http_req_duration{scenario:p0_latency}": { thresholds: { "p(99)<3000": false, "p(95)<=250": false, "p(99)<=800": false }, "p(95)": 7.3, "p(99)": 8.9, med: 2.7, max: 17.9 },
  http_req_duration: { "p(95)": 7.3, "p(99)": 8.9, med: 2.7, max: 17.9 }, http_reqs: { count: 300 }, http_req_failed: { value: 0 },
} });
const judge = (summary: K6Summary | null, over: Partial<Parameters<typeof judgeK6Run>[0]> = {}) => judgeK6Run({ summary, model, maxTotalRequests: 300, exitCode: 0, stoppedBy: null, ...over });

test("F7: PASS needs positive evidence: a complete summary, every required threshold, a clean exit and an emission within the ceiling", () => {
  assert.deepEqual(judge(healthy()), { result: "PASS", reasons: [], metrics: { requests: 300, failedRate: 0, p50Ms: 2.7, p95Ms: 7.3, p99Ms: 8.9, maxMs: 17.9 } });
});

test("F7 regression: missing metrics or thresholds are never read as success", () => {
  assert.equal(judge(null).result, "STOP");
  assert.equal(judge({}).result, "ERROR");
  assert.equal(judge({ metrics: {} }).result, "ERROR");
  // No request count at all.
  const noRequests = healthy(); delete noRequests.metrics!.http_reqs;
  const noCount = judge(noRequests);
  assert.equal(noCount.result, "ERROR");
  assert.match(noCount.reasons.join(";"), /no http_reqs/);
  // Zero requests recorded.
  const zero = healthy(); zero.metrics!.http_reqs = { count: 0 };
  assert.equal(judge(zero).result, "ERROR");
  // Each required threshold removed in turn: the summary "looks" fine but a criterion was never evaluated.
  for (const entry of model.expectedThresholds) {
    const summary = healthy();
    delete summary.metrics![entry.metric].thresholds![entry.expression];
    const verdict = judge(summary);
    assert.equal(verdict.result, "ERROR", `${entry.metric} ${entry.expression}`);
    assert.match(verdict.reasons.join(";"), /required threshold missing/);
  }
  // A whole sub-metric missing.
  const lost = healthy(); delete lost.metrics!["http_req_duration{scenario:p0_latency}"];
  assert.equal(judge(lost).result, "ERROR");
  // parseK6Summary reports the gap too, instead of defaulting to zero.
  assert.equal(parseK6Summary({ metrics: {} }, model.expectedThresholds).missing.length, model.expectedThresholds.length);
  assert.equal(parseK6Summary({ metrics: {} }).extras.requestsPresent, false);
});

test("F7: crossed thresholds, non-zero exits, overruns, aborts and kills are each reported as what they are", () => {
  const crossedPass = healthy(); crossedPass.metrics!["http_req_duration{scenario:p0_latency}"].thresholds!["p(95)<=250"] = true;
  assert.equal(judge(crossedPass).result, "FAIL");
  const crossedStop = healthy(); crossedStop.metrics!["http_req_failed{scenario:p0_latency}"].thresholds!["rate<0.05"] = true;
  assert.equal(judge(crossedStop).result, "STOP");
  assert.equal(judge(healthy(), { exitCode: 99 }).result, "FAIL");
  assert.equal(judge(healthy(), { exitCode: null }).result, "FAIL");
  const over = healthy(); over.metrics!.http_reqs = { count: 301 };
  const overrun = judge(over);
  assert.equal(overrun.result, "STOP");
  assert.match(overrun.reasons[0], /emitted 301 requests, above the 300 ceiling/);
  const aborted = judge(healthy(), { exitCode: 108 });
  assert.equal(aborted.result, "STOP");
  assert.match(aborted.reasons[0], /envelope violation/);
  assert.equal(judge(healthy(), { stoppedBy: "wall-clock" }).result, "STOP");
  const expiry = judge(healthy(), { stoppedBy: "authorization-expiry" });
  assert.equal(expiry.result, "STOP");
  assert.match(expiry.reasons[0], /authorization expired/);
});

test("F7: the k6 summary formats are still read in both export shapes", () => {
  const object = parseK6Summary({ metrics: { "http_req_failed{scenario:p0}": { thresholds: { "rate<=0.005": { ok: false } } }, http_reqs: { values: { count: 5 } } } });
  assert.deepEqual(object.failed.pass, ["http_req_failed rate<=0.005"]);
  assert.equal(object.metrics.requests, 5);
});

test("F3 (property): no random plan is accepted unless its scheduled requests, duration and concurrency are within the ceilings, and an accepted plan's model is sequential and capped", () => {
  let seed = 99;
  const rand = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 2 ** 32; };
  const between = (low: number, high: number) => low + Math.floor(rand() * (high - low + 1));
  let accepted = 0, rejected = 0;
  for (let n = 0; n < 3_000; n++) {
    const phases = Array.from({ length: between(1, 9) }, (_, index) => phase({ name: `p${index}`, seconds: between(1, 400), rate: between(1, 120), vus: between(1, 60), timeoutMs: between(1, 11_000), measured: rand() < 0.5 }));
    const scheduled = phases.reduce((sum, entry) => sum + entry.seconds * entry.rate, 0);
    const candidate = plan({ phases, maxTotalRequests: between(1, 25_000) });
    const withinCeilings = phases.length <= 8 && phases.every((entry) => entry.rate <= 100 && entry.vus <= 50 && entry.timeoutMs <= 10_000) &&
      phases.reduce((sum, entry) => sum + entry.seconds, 0) <= 900 && scheduled <= 20_000 && scheduled <= candidate.maxTotalRequests && candidate.maxTotalRequests <= 20_000;
    let model: ReturnType<typeof buildModel> | null = null;
    try { model = buildModel(candidate); } catch { /* rejected */ }
    assert.equal(model !== null, withinCeilings, JSON.stringify({ scheduled, max: candidate.maxTotalRequests }));
    if (!model) { rejected++; continue; }
    accepted++;
    assert.ok(model.totalRequests <= 20_000 && model.totalRequests <= candidate.maxTotalRequests);
    const spans = intervals(model, candidate);
    for (let index = 1; index < spans.length; index++) assert.ok(spans[index].start >= spans[index - 1].end);
    assert.equal(spans[spans.length - 1].end, model.wallSeconds);
  }
  assert.ok(accepted > 20 && rejected > 20, `accepted ${accepted}, rejected ${rejected}`);
});

test("F7 round 2 regression: a summary with a positive request count and satisfied thresholds but MISSING numeric metrics is ERROR, never PASS on fabricated zeros", () => {
  // The reproduced shape: thresholds present and not crossed, http_reqs present, no failure-rate and no duration values.
  const reproduction: K6Summary = { metrics: {
    "http_req_failed{scenario:p0_latency}": { thresholds: { "rate<0.05": false, "rate<=0.005": false } },
    "http_req_duration{scenario:p0_latency}": { thresholds: { "p(99)<3000": false, "p(95)<=250": false, "p(99)<=800": false } },
    http_reqs: { count: 300 },
  } };
  const verdict = judge(reproduction);
  assert.equal(verdict.result, "ERROR");
  const text = verdict.reasons.join(";");
  for (const name of ["http_req_failed.rate", "http_req_duration.med", "http_req_duration.p(95)", "http_req_duration.p(99)", "http_req_duration.max"]) assert.ok(text.includes(name), name);
  assert.deepEqual(parseK6Summary(reproduction).missingMetrics, ["http_req_failed.rate", "http_req_duration.med", "http_req_duration.p(95)", "http_req_duration.p(99)", "http_req_duration.max"]);
  // Each required number removed in turn, and non-numbers (NaN, strings, null) are missing too.
  const removals: [string, (summary: K6Summary) => void][] = [
    ["failed rate", (summary) => { delete summary.metrics!.http_req_failed; }],
    ["median", (summary) => { delete summary.metrics!.http_req_duration.med; }],
    ["p95", (summary) => { delete summary.metrics!.http_req_duration["p(95)"]; }],
    ["p99", (summary) => { delete summary.metrics!.http_req_duration["p(99)"]; }],
    ["max", (summary) => { delete summary.metrics!.http_req_duration.max; }],
    ["NaN p95", (summary) => { summary.metrics!.http_req_duration["p(95)"] = Number.NaN; }],
    ["string p99", (summary) => { (summary.metrics!.http_req_duration as Record<string, unknown>)["p(99)"] = "8.9"; }],
    ["null rate", (summary) => { summary.metrics!.http_req_failed = { value: null } as never; }],
  ];
  for (const [name, mutate] of removals) {
    const summary = healthy(); mutate(summary);
    const result = judge(summary);
    assert.equal(result.result, "ERROR", name);
    assert.match(result.reasons.join(";"), /required numeric metric missing/, name);
  }
  assert.equal(judge(healthy()).result, "PASS", "the complete summary still passes");
});
