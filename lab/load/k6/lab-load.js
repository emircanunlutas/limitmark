// k6 engine for the lab. Run only through lab/load/k6.ts (it writes and hashes the plan).
// The script cannot be pointed anywhere by environment: it reads ONE integrity-checked plan produced from an
// authorized run and re-validates it with independent rules (plan.mjs, shared with the Node wrapper and tests).
//
// Envelope (per k6 PROCESS, not per campaign): rate, concurrency, duration and request counts below are upper bounds.
//  - phases never overlap (see buildModel), so concurrency is the largest phase's vus;
//  - every phase has a request cap of rate x seconds, enforced per iteration, so the process total is an upper bound;
//  - the process aborts itself when its wall-clock bound is exceeded;
//  - a response larger than HARD.responseBytes aborts the process. k6 cannot truncate a body while it is being read,
//    so the FIRST oversized response is read in full (bounded by the container memory limit and the request timeout)
//    before the abort; the Node engine, by contrast, cancels at the limit.
import http from "k6/http";
import crypto from "k6/crypto";
import encoding from "k6/encoding";
import exec from "k6/execution";
import { HARD, buildModel } from "./plan.mjs";

const planText = open(__ENV.LAB_PLAN);
if (!__ENV.LAB_PLAN_SHA256 || crypto.sha256(planText, "hex") !== __ENV.LAB_PLAN_SHA256) {
  throw new Error("lab plan integrity check failed");
}
const plan = JSON.parse(planText);
const model = buildModel(plan);
const WALL_MS = model.wallSeconds * 1000 + 2000;

export const options = {
  scenarios: model.scenarios,
  thresholds: model.thresholds,
  // Bodies are kept (as bytes) only so their size can be checked; at <= 100 requests/second this is negligible.
  discardResponseBodies: false,
  noConnectionReuse: false,
  userAgent: "limitmark-lab-k6/1",
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)"],
  insecureSkipTLSVerify: false,
};

function declaredLength(headers) {
  for (const name of Object.keys(headers || {})) {
    if (name.toLowerCase() === "content-length") return Number(headers[name]);
  }
  return 0;
}

export default function labIteration() {
  const cap = model.caps[exec.scenario.name];
  // Hard per-phase request cap: constant-arrival-rate may schedule one iteration more than rate x duration.
  if (cap === undefined || exec.scenario.iterationInTest >= cap) return;
  if (exec.instance.currentTestRunDuration > WALL_MS) exec.test.abort("lab wall-clock bound exceeded");

  const r = plan.requests[exec.scenario.iterationInTest % plan.requests.length];
  const params = {
    redirects: 0,
    timeout: __ENV.PHASE_TIMEOUT_MS + "ms",
    headers: { "Accept-Encoding": "identity" },
    responseType: "binary",
  };
  let response;
  if (r.method === "POST") {
    const token = encoding.b64encode(crypto.randomBytes(32), "rawurl");
    const body = "name=Lab+Synthetic&email=lab%40example.test&company=Synthetic+Co&service=web&system=synthetic&objective=synthetic" +
      "&environment=staging&authority=authorized&protection=unknown&provider=&notes=&submissionToken=" + token;
    params.headers["Content-Type"] = "application/x-www-form-urlencoded";
    params.headers["Origin"] = plan.baseUrl;
    response = http.post(plan.baseUrl + r.path, body, params);
  } else {
    response = http.get(plan.baseUrl + r.path, params);
  }
  const received = response.body ? response.body.byteLength : 0;
  if (received > HARD.responseBytes || declaredLength(response.headers) > HARD.responseBytes) {
    exec.test.abort("response larger than " + HARD.responseBytes + " bytes");
  }
}
