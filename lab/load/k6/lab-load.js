// k6 engine for the lab. Run only through lab/load/k6.ts (it writes and hashes the plan).
// The script cannot be pointed anywhere by environment: it reads ONE integrity-checked plan
// produced by lab/policy/target-policy.ts and re-validates it with independent, minimal rules.
import http from "k6/http";
import crypto from "k6/crypto";
import encoding from "k6/encoding";
import exec from "k6/execution";

const HARD = { rate: 100, vus: 50, seconds: 900, timeoutMs: 10000 };
const PATHS = ["/", "/gizlilik", "/test-talep-et", "/test-talep-et/tesekkurler", "/api/public-inquiries"];
const planText = open(__ENV.LAB_PLAN);
if (!__ENV.LAB_PLAN_SHA256 || crypto.sha256(planText, "hex") !== __ENV.LAB_PLAN_SHA256) {
  throw new Error("lab plan integrity check failed");
}
const plan = JSON.parse(planText);

function fail(message) { throw new Error("lab plan rejected: " + message); }
if (plan.schema !== 1) fail("schema");
if (!/^https?:\/\/(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/.test(plan.baseUrl) || /limitmark\.com/i.test(plan.baseUrl)) fail("base URL");
if (!Array.isArray(plan.requests) || plan.requests.length < 1 || plan.requests.length > 8) fail("requests");
for (const r of plan.requests) {
  if (PATHS.indexOf(r.path) < 0) fail("path");
  if (r.method !== "GET" && !(r.method === "POST" && r.path === "/api/public-inquiries")) fail("method");
}
let totalSeconds = 0;
const scenarios = {};
const thresholds = {};
plan.phases.forEach((phase, index) => {
  if (phase.rate > HARD.rate || phase.vus > HARD.vus || phase.timeoutMs > HARD.timeoutMs) fail("phase ceiling");
  const name = "p" + index + "_" + phase.name.replace(/[^A-Za-z0-9_-]/g, "_");
  scenarios[name] = {
    executor: "constant-arrival-rate", rate: phase.rate, timeUnit: "1s", duration: phase.seconds + "s",
    startTime: totalSeconds + "s", preAllocatedVUs: Math.min(phase.vus, 10), maxVUs: phase.vus,
    gracefulStop: "5s", env: { PHASE_TIMEOUT_MS: String(phase.timeoutMs) }, tags: { lab_phase: phase.name },
  };
  totalSeconds += phase.seconds;
  if (phase.measured) {
    const tag = "{scenario:" + name + "}";
    thresholds["http_req_failed" + tag] = [
      { threshold: "rate<" + plan.thresholds.stopErrorRate, abortOnFail: true, delayAbortEval: "10s" },
      "rate<=" + plan.thresholds.passErrorRate,
    ];
    thresholds["http_req_duration" + tag] = [
      { threshold: "p(99)<" + plan.thresholds.stopP99Ms, abortOnFail: true, delayAbortEval: "10s" },
      "p(95)<=" + plan.thresholds.passP95Ms, "p(99)<=" + plan.thresholds.passP99Ms,
    ];
  }
});
if (totalSeconds > HARD.seconds) fail("duration");

export const options = {
  scenarios, thresholds,
  discardResponseBodies: true,
  noConnectionReuse: false,
  userAgent: "limitmark-lab-k6/1",
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)"],
  insecureSkipTLSVerify: false,
};

export default function labIteration() {
  const r = plan.requests[exec.scenario.iterationInTest % plan.requests.length];
  const params = {
    redirects: 0,
    timeout: __ENV.PHASE_TIMEOUT_MS + "ms",
    headers: { "Accept-Encoding": "identity" },
  };
  if (r.method === "POST") {
    const token = encoding.b64encode(crypto.randomBytes(32), "rawurl");
    const body = "name=Lab+Synthetic&email=lab%40example.test&company=Synthetic+Co&service=web&system=synthetic&objective=synthetic" +
      "&environment=staging&authority=authorized&protection=unknown&provider=&notes=&submissionToken=" + token;
    params.headers["Content-Type"] = "application/x-www-form-urlencoded";
    params.headers["Origin"] = plan.baseUrl;
    http.post(plan.baseUrl + r.path, body, params);
  } else {
    http.get(plan.baseUrl + r.path, params);
  }
}
