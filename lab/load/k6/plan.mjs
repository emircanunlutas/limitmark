// Shared, dependency-free plan validation and scenario model for the lab's k6 engine.
//
// It is imported by lab-load.js INSIDE k6 (so it is the code that actually runs) and by the Node wrapper and tests
// (so what is tested is what runs). It never trusts the plan's own hash: the hash only proves the plan was not changed
// in transit, not that it is within the safety envelope. Every ceiling is re-derived here from the phases themselves.
//
// Scope of the ceilings: they bound ONE k6 process. They are not campaign- or fleet-wide limits; two valid processes
// double the rate and the connection count.

export const HARD = Object.freeze({
  rate: 100,
  vus: 50,
  /** Sum of phase durations (the dispatch window), seconds. */
  seconds: 900,
  timeoutMs: 10000,
  /** Total requests one process may issue. */
  totalRequests: 20000,
  /** Largest response the lab accepts. k6 cannot truncate a body mid-transfer; see lab-load.js. */
  responseBytes: 1048576,
  phases: 8,
  requests: 8,
});

export const PATHS = Object.freeze(["/", "/gizlilik", "/test-talep-et", "/test-talep-et/tesekkurler", "/api/public-inquiries"]);
export const DEMO_POST_PATH = "/api/public-inquiries";

export function reject(message) {
  throw new Error("lab plan rejected: " + message);
}

function integer(value, min, max, what) {
  if (!Number.isSafeInteger(value) || value < min || value > max) reject(what);
  return value;
}

function ipv4Origin(baseUrl) {
  const match = /^https?:\/\/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})$/.exec(typeof baseUrl === "string" ? baseUrl : "");
  if (!match) reject("base URL");
  for (let i = 1; i <= 4; i++) {
    if (Number(match[i]) > 255 || String(Number(match[i])) !== match[i]) reject("base URL octet");
  }
  integer(Number(match[5]), 1, 65535, "base URL port");
  return baseUrl;
}

// A STOP error rate above 1 (the catalogue uses 1.01) can never be reached: it means "this set never stops on errors".
function ratio(value, what) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 2) reject(what);
  return value;
}

function millis(value, what) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 1 || value > 600000) reject(what);
  return value;
}

const PLAN_KEYS = ["schema", "baseUrl", "maxTotalRequests", "requests", "phases", "thresholds"];
const PHASE_KEYS = ["name", "seconds", "rate", "vus", "timeoutMs", "measured"];
const THRESHOLD_KEYS = ["passErrorRate", "stopErrorRate", "passP95Ms", "passP99Ms", "stopP99Ms"];

/** Throws on anything outside the envelope; returns the plan unchanged otherwise. */
export function validatePlan(plan) {
  if (typeof plan !== "object" || plan === null || Array.isArray(plan)) reject("not an object");
  for (const key of Object.keys(plan)) if (PLAN_KEYS.indexOf(key) < 0) reject("unknown field " + key);
  if (plan.schema !== 2) reject("schema");
  ipv4Origin(plan.baseUrl);
  if (/limitmark\.com/i.test(plan.baseUrl)) reject("base URL");
  integer(plan.maxTotalRequests, 1, HARD.totalRequests, "total request ceiling");

  if (!Array.isArray(plan.requests) || plan.requests.length < 1 || plan.requests.length > HARD.requests) reject("requests");
  for (const request of plan.requests) {
    if (typeof request !== "object" || request === null || PATHS.indexOf(request.path) < 0) reject("path");
    if (request.method !== "GET" && !(request.method === "POST" && request.path === DEMO_POST_PATH)) reject("method");
  }

  if (!Array.isArray(plan.phases) || plan.phases.length < 1 || plan.phases.length > HARD.phases) reject("phases");
  let seconds = 0;
  let requests = 0;
  const names = [];
  for (const phase of plan.phases) {
    if (typeof phase !== "object" || phase === null) reject("phase");
    for (const key of Object.keys(phase)) if (PHASE_KEYS.indexOf(key) < 0) reject("unknown phase field " + key);
    if (typeof phase.name !== "string" || !/^[A-Za-z0-9_-]{1,40}$/.test(phase.name)) reject("phase name");
    if (names.indexOf(phase.name) >= 0) reject("duplicate phase name");
    names.push(phase.name);
    integer(phase.seconds, 1, HARD.seconds, "phase duration");
    integer(phase.rate, 1, HARD.rate, "phase rate ceiling");
    integer(phase.vus, 1, HARD.vus, "phase concurrency ceiling");
    integer(phase.timeoutMs, 1, HARD.timeoutMs, "phase timeout ceiling");
    if (typeof phase.measured !== "boolean") reject("phase measured flag");
    seconds += phase.seconds;
    requests += phase.rate * phase.seconds;
  }
  if (seconds > HARD.seconds) reject("duration");
  // The scheduled requests are what the process WILL emit; they must fit both the hard ceiling and the plan's own.
  if (requests > HARD.totalRequests) reject("scheduled requests " + requests + " exceed the hard ceiling " + HARD.totalRequests);
  if (requests > plan.maxTotalRequests) reject("scheduled requests " + requests + " exceed the plan ceiling " + plan.maxTotalRequests);

  if (typeof plan.thresholds !== "object" || plan.thresholds === null) reject("thresholds");
  for (const key of Object.keys(plan.thresholds)) if (THRESHOLD_KEYS.indexOf(key) < 0) reject("unknown threshold " + key);
  ratio(plan.thresholds.passErrorRate, "threshold passErrorRate");
  ratio(plan.thresholds.stopErrorRate, "threshold stopErrorRate");
  millis(plan.thresholds.passP95Ms, "threshold passP95Ms");
  millis(plan.thresholds.passP99Ms, "threshold passP99Ms");
  millis(plan.thresholds.stopP99Ms, "threshold stopP99Ms");
  return plan;
}

/**
 * Scenario model. Phases run strictly one after another: each starts only after the previous one's dispatch window
 * AND its graceful-stop period (long enough for every in-flight request to finish or time out) are over, so two phases
 * never overlap and the process-wide concurrency is the largest single phase's, not a sum.
 */
export function buildModel(plan) {
  validatePlan(plan);
  const scenarios = {};
  const thresholds = {};
  const caps = {};
  const expectedThresholds = [];
  let start = 0;
  let windowSeconds = 0;
  let totalRequests = 0;
  plan.phases.forEach(function (phase, index) {
    const name = "p" + index + "_" + phase.name;
    const graceSeconds = Math.ceil(phase.timeoutMs / 1000) + 1;
    scenarios[name] = {
      executor: "constant-arrival-rate",
      rate: phase.rate,
      timeUnit: "1s",
      duration: phase.seconds + "s",
      startTime: start + "s",
      preAllocatedVUs: Math.min(phase.vus, 10),
      maxVUs: phase.vus,
      gracefulStop: graceSeconds + "s",
      env: { PHASE_TIMEOUT_MS: String(phase.timeoutMs) },
      tags: { lab_phase: phase.name },
    };
    // constant-arrival-rate can start one iteration more than rate x duration; the per-scenario cap makes the
    // phase total an upper bound: iteration numbers at or beyond it return without sending anything.
    caps[name] = phase.rate * phase.seconds;
    totalRequests += caps[name];
    start += phase.seconds + graceSeconds;
    windowSeconds += phase.seconds;
    if (phase.measured) {
      const tag = "{scenario:" + name + "}";
      const failed = [
        { threshold: "rate<" + plan.thresholds.stopErrorRate, abortOnFail: true, delayAbortEval: "10s" },
        "rate<=" + plan.thresholds.passErrorRate,
      ];
      const duration = [
        { threshold: "p(99)<" + plan.thresholds.stopP99Ms, abortOnFail: true, delayAbortEval: "10s" },
        "p(95)<=" + plan.thresholds.passP95Ms,
        "p(99)<=" + plan.thresholds.passP99Ms,
      ];
      thresholds["http_req_failed" + tag] = failed;
      thresholds["http_req_duration" + tag] = duration;
      for (const entry of failed) expectedThresholds.push({ metric: "http_req_failed" + tag, expression: typeof entry === "string" ? entry : entry.threshold });
      for (const entry of duration) expectedThresholds.push({ metric: "http_req_duration" + tag, expression: typeof entry === "string" ? entry : entry.threshold });
    }
  });
  return {
    scenarios,
    thresholds,
    caps,
    expectedThresholds,
    windowSeconds,
    /** Last scenario's start + its dispatch window + its grace: the latest instant any request can be in flight. */
    wallSeconds: start,
    totalRequests,
  };
}
