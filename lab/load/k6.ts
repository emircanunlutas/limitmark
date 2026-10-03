/**
 * k6 engine wrapper. The policy decides everything (`authorizeRun`); this module only serialises
 * the AUTHORIZED run into an integrity-hashed plan and runs k6 in a lab-owned Docker container. The k6 script
 * (k6/lab-load.js) accepts nothing but that plan and re-validates it (k6/plan.mjs, the same module this file uses).
 *
 * Network model: the k6 container joins the network namespace of a lab-owned APPLICATION container
 * (`--network container:<id>`), so `127.0.0.1:<port>` inside it is that container's loopback; for remote targets later
 * it runs on the default bridge with the plan's IP literal.
 *
 * Confinement
 *  - the container is created first (not `docker run`), its effective configuration is read back from the daemon and
 *    checked (labels, network mode, NO proxy variable that could redirect traffic, however it got there: an explicit
 *    flag or Docker's automatic injection from the CLI config) and only then started;
 *  - the container is addressed by id, supervised, killed on the wall-clock bound or when the target authorization
 *    lapses, and always removed; removal is verified;
 *  - the namespace-donor container is accepted only on its LABELS (disposable + role app) and while running.
 *
 * Ceilings are per k6 process. They are not campaign- or fleet-wide limits.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { containerExists, docker, inspectContainer, inspectLabContainer, removeLabContainer, type ContainerFacts } from "../host/docker";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { PolicyRefusal, assertLabContainer, type AuthorizedRun } from "../policy/target-policy";
import { ruleFor, type HttpThresholds } from "../policy/thresholds";
import { buildModel, validatePlan, type K6Model, type K6PlanShape } from "./k6/plan.mjs";

export const K6_IMAGE = "grafana/k6:latest";

export type K6Plan = K6PlanShape;

/**
 * Serialises the authorized run. The plan is validated by the SAME module the k6 script uses before it is returned, so
 * a plan the script would reject (a total above the hard ceiling, an overlong duration, ...) never reaches disk.
 */
export function buildK6Plan(run: AuthorizedRun, thresholds: HttpThresholds): K6Plan {
  run.assertStillAuthorized();
  const requests = run.workload.methods.flatMap((method) => run.workload.paths.map((requestPath) => {
    // Eager policy authorization of each request the plan will contain.
    const authorized = run.authorizeRequest(method, requestPath);
    return { method: authorized.method, path: authorized.path };
  }));
  const plan: K6Plan = {
    schema: 2,
    baseUrl: run.target.origin,
    maxTotalRequests: run.limits.maxTotalRequests,
    requests,
    phases: run.limits.phases.map((phase) => ({
      name: phase.name, seconds: phase.durationSeconds, rate: phase.ratePerSecond, vus: phase.concurrency,
      timeoutMs: phase.timeoutMs, measured: ruleFor(thresholds, phase.name) === "measured",
    })),
    thresholds: {
      passErrorRate: thresholds.pass.maxErrorRate, stopErrorRate: thresholds.stop.errorRate,
      passP95Ms: thresholds.pass.maxP95Ms, passP99Ms: thresholds.pass.maxP99Ms, stopP99Ms: thresholds.stop.p99Ms,
    },
  };
  return validatePlan(plan);
}

// ---------------------------------------------------------------------------
// Container confinement
// ---------------------------------------------------------------------------

/** Every spelling of a proxy variable the docker CLI / Go / curl-style clients honour. */
export const PROXY_VARIABLES = ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "FTP_PROXY", "ftp_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] as const;

export type K6ContainerSpec = {
  name: string;
  image: string;
  /** Immutable id of the lab-owned container whose network namespace k6 joins; omitted for the default bridge. */
  netnsContainerId?: string;
  planDirectory: string;
  scriptDirectory: string;
  planSha256: string;
};

/**
 * `docker create` arguments. Every proxy variable is set EXPLICITLY (empty, NO_PROXY=*): the docker CLI injects
 * `proxies` from its config file only for variables the caller did not set. The result is still verified against the
 * daemon's record afterwards (`assertK6ContainerConfinement`), not trusted.
 */
export function k6CreateArguments(spec: K6ContainerSpec): string[] {
  return [
    "create", "--name", spec.name,
    "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=k6",
    "--memory", "512m", "--pids-limit", "512", "--read-only", "--tmpfs", "/tmp",
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    ...(spec.netnsContainerId ? ["--network", `container:${spec.netnsContainerId}`] : []),
    "-v", `${spec.planDirectory}:/lab`, "-v", `${spec.scriptDirectory}:/script:ro`,
    "-e", "LAB_PLAN=/lab/plan.json", "-e", `LAB_PLAN_SHA256=${spec.planSha256}`,
    ...PROXY_VARIABLES.flatMap((name) => ["-e", `${name}=${name.toUpperCase() === "NO_PROXY" ? "*" : ""}`]),
    spec.image, "run", "--quiet", "--no-usage-report", "--summary-export=/lab/summary.json", "/script/lab-load.js",
  ];
}

/** Pure check of the daemon's record of the created container. Throws PolicyRefusal when it could carry traffic elsewhere. */
export function assertK6ContainerConfinement(facts: ContainerFacts, expected: { image: string; netnsContainerId?: string }): void {
  assertLabContainer(facts.name, facts.labels, "k6");
  if (facts.image !== expected.image) throw new PolicyRefusal("target-unknown", "the k6 container is not using the reviewed image reference");
  for (const entry of facts.env) {
    const separator = entry.indexOf("=");
    const name = entry.slice(0, separator);
    const value = entry.slice(separator + 1);
    if (/^(?:https?|ftp|all)_proxy$/i.test(name) && value !== "") throw new PolicyRefusal("target-unknown", `the k6 container carries a proxy setting (${name}); traffic could be redirected`);
    if (/^no_proxy$/i.test(name) && value !== "" && value !== "*") throw new PolicyRefusal("target-unknown", "the k6 container carries an unexpected NO_PROXY value");
  }
  const expectedMode = expected.netnsContainerId ? `container:${expected.netnsContainerId}` : null;
  if (expectedMode !== null && facts.networkMode !== expectedMode) throw new PolicyRefusal("target-unknown", "the k6 container is not attached to the verified lab container's network namespace");
  if (expectedMode === null && (facts.networkMode === "host" || facts.networkMode.startsWith("container:"))) throw new PolicyRefusal("target-unknown", "the k6 container must not share the host or another container's network");
}

// ---------------------------------------------------------------------------
// Summary judgement (pure)
// ---------------------------------------------------------------------------

export type K6Outcome = {
  result: "PASS" | "FAIL" | "STOP" | "ERROR";
  reasons: string[];
  planSha256: string;
  k6Version: string | null;
  imageId: string | null;
  metrics: Record<string, number>;
  /** Process-level bound facts, recorded so the per-process scope is visible in the evidence. */
  envelope: { maxTotalRequests: number; windowSeconds: number; wallSeconds: number; scope: "per-process" };
  containerRemoved: boolean;
  stoppedBy: "wall-clock" | "authorization-expiry" | null;
};

type SummaryMetric = { values?: Record<string, number>; thresholds?: Record<string, boolean | { ok: boolean }> } & Record<string, unknown>;
export type K6Summary = { metrics?: Record<string, SummaryMetric> };

/**
 * k6 summary-export formats differ by version: metric values are either nested under `values` or flat, and a
 * threshold is either `{ ok: boolean }` or a bare boolean whose value is TRUE when the threshold was crossed.
 *
 * `expected` lists the thresholds the plan REQUIRES. A required threshold that is absent from the summary is reported in
 * `missing`; absence is never read as "not crossed".
 */
export function parseK6Summary(summary: K6Summary, expected: readonly { metric: string; expression: string }[] = []): {
  failed: { stop: string[]; pass: string[] };
  metrics: Record<string, number>;
  missing: string[];
  /** Required NUMERIC metrics that are absent or not finite numbers. Never defaulted to zero. */
  missingMetrics: string[];
  extras: { iterations: number | null; droppedIterations: number | null; requestsPresent: boolean };
} {
  const failed = { stop: [] as string[], pass: [] as string[] };
  for (const [metricName, metric] of Object.entries(summary.metrics ?? {})) {
    for (const [expression, outcome] of Object.entries(metric.thresholds ?? {})) {
      const crossed = typeof outcome === "boolean" ? outcome : !outcome.ok;
      if (!crossed) continue;
      // The plan uses strict "<" (abortOnFail) for STOP and "<=" for PASS criteria.
      (expression.includes("<=") ? failed.pass : failed.stop).push(`${metricName.replace(/{.*}/, "")} ${expression}`);
    }
  }
  const missing = expected.filter(({ metric, expression }) => {
    const entry = summary.metrics?.[metric]?.thresholds;
    return !entry || !(expression in entry);
  }).map(({ metric, expression }) => `${metric.replace(/{.*}/, "")} ${expression}`);
  const metricOf = (name: string): SummaryMetric | undefined => summary.metrics?.[name];
  const values = (name: string): Record<string, number> => {
    const metric = metricOf(name) as (SummaryMetric & Record<string, number>) | undefined;
    return (metric?.values ?? metric ?? {}) as Record<string, number>;
  };
  const duration = values("http_req_duration");
  const failedMetric = values("http_req_failed");
  const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
  // A required number that is missing is reported, not replaced by 0: 0 would read as "no failures" and "instant responses".
  const missingMetrics = [
    ["http_reqs.count", values("http_reqs").count], ["http_req_failed.rate", failedMetric.rate ?? failedMetric.value],
    ["http_req_duration.med", duration.med], ["http_req_duration.p(95)", duration["p(95)"]], ["http_req_duration.p(99)", duration["p(99)"]], ["http_req_duration.max", duration.max],
  ].filter(([, value]) => !finite(value)).map(([name]) => name as string);
  const round = (value: number | undefined) => Math.round((value ?? 0) * 100) / 100;
  const count = (name: string): number | null => {
    const value = values(name).count;
    return typeof value === "number" ? value : null;
  };
  return {
    failed,
    missing,
    missingMetrics,
    metrics: {
      requests: values("http_reqs").count ?? 0,
      failedRate: Math.round((values("http_req_failed").rate ?? values("http_req_failed").value ?? 0) * 10_000) / 10_000,
      p50Ms: round(duration.med), p95Ms: round(duration["p(95)"]), p99Ms: round(duration["p(99)"]), maxMs: round(duration.max),
    },
    extras: { iterations: count("iterations"), droppedIterations: count("dropped_iterations"), requestsPresent: typeof values("http_reqs").count === "number" },
  };
}

export type K6Judgement = { result: "PASS" | "FAIL" | "STOP" | "ERROR"; reasons: string[]; metrics: Record<string, number> };

/**
 * The verdict for a finished k6 process. PASS requires positive evidence: a readable summary that contains the
 * request count and EVERY required threshold, an emission within the plan's ceiling, a clean exit and no crossed
 * threshold. Anything missing is ERROR (the tool could not establish the result), never PASS.
 */
export function judgeK6Run(input: {
  summary: K6Summary | null;
  model: K6Model;
  maxTotalRequests: number;
  exitCode: number | null;
  stoppedBy: K6Outcome["stoppedBy"];
  /** False when a requested stop (expiry, wall clock) could not be confirmed by the daemon. Defaults to true for callers that never stopped it. */
  terminationProven?: boolean;
}): K6Judgement {
  const { summary, model, maxTotalRequests, exitCode, stoppedBy } = input;
  if (stoppedBy !== null && input.terminationProven === false) {
    return { result: "ERROR", reasons: [`the run was due to stop (${stoppedBy}) but the container could NOT be proven stopped; treat the destination as still receiving traffic`], metrics: {} };
  }
  if (stoppedBy === "authorization-expiry") return { result: "STOP", reasons: ["target authorization expired while k6 was running; the container was killed"], metrics: {} };
  if (stoppedBy === "wall-clock") return { result: "STOP", reasons: ["k6 exceeded its wall-clock bound; the container was killed"], metrics: {} };
  if (!summary) return { result: "STOP", reasons: ["k6 produced no summary (script rejected the plan or aborted early)"], metrics: {} };
  const parsed = parseK6Summary(summary, model.expectedThresholds);
  const reasons = [...parsed.failed.stop, ...parsed.failed.pass];
  const evidenceGaps: string[] = [];
  if (!parsed.extras.requestsPresent) evidenceGaps.push("summary has no http_reqs count");
  else if (parsed.metrics.requests < 1) evidenceGaps.push("k6 recorded zero requests");
  for (const name of parsed.missingMetrics) if (name !== "http_reqs.count") evidenceGaps.push(`required numeric metric missing or not a number: ${name}`);
  for (const entry of parsed.missing) evidenceGaps.push(`required threshold missing from the summary: ${entry}`);
  const violations: string[] = [];
  if (parsed.metrics.requests > maxTotalRequests) violations.push(`k6 emitted ${parsed.metrics.requests} requests, above the ${maxTotalRequests} ceiling`);
  if (exitCode === 108) violations.push("the script aborted itself on an envelope violation (for example an oversized response or wall-clock overrun)");
  if (violations.length > 0) return { result: "STOP", reasons: [...violations, ...reasons], metrics: parsed.metrics };
  if (parsed.failed.stop.length > 0) return { result: "STOP", reasons, metrics: parsed.metrics };
  if (evidenceGaps.length > 0) return { result: "ERROR", reasons: [...evidenceGaps, ...reasons], metrics: parsed.metrics };
  if (parsed.failed.pass.length > 0) return { result: "FAIL", reasons, metrics: parsed.metrics };
  if (exitCode !== 0) return { result: "FAIL", reasons: [`k6 exited with code ${exitCode ?? "unknown"} without a threshold breach`], metrics: parsed.metrics };
  return { result: "PASS", reasons: [], metrics: parsed.metrics };
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

const K6_CONTAINER_NAME = /^limitmark-lab-k6-[a-f0-9]{12}$/;

type DockerFn = (args: readonly string[], options?: { timeoutMs?: number }) => Promise<{ stdout: string }>;

export type Supervised = {
  exitCode: number | null;
  /** Why the supervisor ASKED the container to stop (null: it ended on its own). It is a cause, not a proof. */
  stoppedBy: K6Outcome["stoppedBy"];
  /** True only when the daemon reported the container stopped/gone afterwards. A requested stop that could not be proven is false. */
  terminationProven: boolean;
  /** How many kill attempts failed (never swallowed: they decide the verdict when the stop could not be proven). */
  killFailures: number;
};

type ContainerState = "running" | "stopped" | "gone" | "unknown";

/**
 * Starts the container and waits for it. When the wall-clock bound passes or the target authorization lapses the container is
 * killed, retried, forced, and then its state is READ BACK from the daemon: a stop is reported as proven only when the daemon says
 * so. A stop requested while `docker start` is still pending is deferred until the start has returned (a kill against a container
 * that is not running yet fails, and the container would then come up unsupervised). `docker` is injectable for tests.
 */
export async function superviseContainer(
  id: string, limits: { timeoutMs: number; untilMs: number | null }, run: DockerFn = docker, tuning: { killAttempts?: number; retryMs?: number } = {},
): Promise<Supervised> {
  const attempts = tuning.killAttempts ?? 4;
  const retryMs = tuning.retryMs ?? 500;
  let stopRequested: NonNullable<K6Outcome["stoppedBy"]> | null = null;
  let started = false;
  let killing: Promise<boolean> | null = null;
  let killFailures = 0;
  // Resolves when the kill procedure has finished, successfully or not, so waiting on a container that will not die cannot hang the supervisor.
  let killFinished!: () => void;
  const killFinishedPromise = new Promise<"killed">((resolve) => { killFinished = () => resolve("killed"); });
  const beginKill = () => { killing ??= killUntilStopped().finally(killFinished); };

  const stateOf = async (): Promise<ContainerState> => {
    try {
      const { stdout } = await run(["inspect", "--format", "{{.State.Running}}", id]);
      return stdout.trim() === "true" ? "running" : stdout.trim() === "false" ? "stopped" : "unknown";
    } catch (error) {
      // Only an explicit "no such container" is absence; a daemon error is UNKNOWN and is never read as stopped.
      return /No such (?:container|object)/i.test(String((error as Error)?.message ?? error)) ? "gone" : "unknown";
    }
  };
  const proven = (state: ContainerState) => state === "stopped" || state === "gone";
  const killUntilStopped = async (): Promise<boolean> => {
    for (let attempt = 0; attempt < attempts; attempt++) {
      try { await run(["kill", id]); } catch { killFailures++; }
      if (proven(await stateOf())) return true;
      await new Promise((resolve) => setTimeout(resolve, retryMs));
    }
    try { await run(["rm", "-f", id]); } catch { killFailures++; }
    return proven(await stateOf());
  };
  const request = (why: NonNullable<K6Outcome["stoppedBy"]>) => {
    stopRequested ??= why;
    if (started) beginKill();
  };

  const timers = [setTimeout(() => request("wall-clock"), limits.timeoutMs)];
  if (limits.untilMs !== null) timers.push(setTimeout(() => request("authorization-expiry"), Math.max(0, limits.untilMs - Date.now())));
  let exitCode: number | null = null;
  let waitFailed = false;
  try {
    await run(["start", id]);
    started = true;
    // The limit may have passed while start was pending: act now that there is something to stop.
    if (stopRequested) beginKill();
    try {
      const waiting = run(["wait", id], { timeoutMs: limits.timeoutMs + 60_000 });
      waiting.catch(() => undefined);
      const first = await Promise.race([waiting, killFinishedPromise]);
      if (first === "killed") {
        // The kill procedure ended. If the container is really gone, wait returns promptly; if it is not, do not hang on it.
        const settled = await Promise.race([waiting.then((value) => value, () => null), new Promise<null>((resolve) => setTimeout(() => resolve(null), retryMs * 4 + 50))]);
        if (settled === null) waitFailed = true; else { const parsed = Number(settled.stdout.trim()); exitCode = Number.isInteger(parsed) ? parsed : null; }
      } else {
        const parsed = Number(first.stdout.trim());
        exitCode = Number.isInteger(parsed) ? parsed : null;
      }
    } catch { waitFailed = true; }
  } finally { for (const timer of timers) clearTimeout(timer); }
  if (waitFailed) { stopRequested ??= "wall-clock"; beginKill(); }
  const killed = killing ? await killing : true;
  // Whatever the cause, never report a requested stop as successful unless the daemon confirms it.
  const terminationProven = stopRequested === null && !waitFailed ? true : killed && proven(await stateOf());
  return { exitCode, stoppedBy: stopRequested, terminationProven, killFailures };
}

export async function runK6(run: AuthorizedRun, thresholds: HttpThresholds, options: { netnsContainer?: string; runId: string; /** Test seam: a shorter supervision bound than the plan's wall clock. */ superviseMs?: number }): Promise<K6Outcome> {
  const plan = buildK6Plan(run, thresholds);
  const model = buildModel(plan);
  // Authorization must outlive the run: refuse to start a run that could not finish inside it.
  const wallMs = (model.wallSeconds + 30) * 1000;
  if (run.authorizedUntilMs !== null && run.authorizedUntilMs - Date.now() < wallMs) {
    throw new PolicyRefusal("target-expired", "the target authorization would expire before the k6 run could finish");
  }
  const donor = options.netnsContainer ? await inspectLabContainer(options.netnsContainer, "app") : null;
  if (donor && !donor.running) throw new PolicyRefusal("target-listener-unproven", "the application container is not running");

  const planText = `${JSON.stringify(plan)}\n`;
  const planSha256 = createHash("sha256").update(planText).digest("hex");
  // Plan and summary live outside the evidence tree: the plan names the target address.
  const directory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "k6", options.runId);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, "plan.json"), planText);
  const scriptDirectory = path.join(REPOSITORY_ROOT, "lab", "load", "k6");

  const imageId = await docker(["image", "inspect", "--format", "{{.Id}}", K6_IMAGE]).then((r) => r.stdout.trim() || null, () => null);
  const k6Version = await docker(["run", "--rm", "--label", "limitmark.lab=disposable", "--label", "limitmark.lab.role=k6", K6_IMAGE, "version"])
    .then((r) => /k6 v?([0-9.]+)/.exec(r.stdout)?.[1] ?? null).catch(() => null);

  const name = `limitmark-lab-k6-${randomBytes(6).toString("hex")}`;
  if (!K6_CONTAINER_NAME.test(name)) throw new Error("internal: k6 container name");
  const spec: K6ContainerSpec = { name, image: K6_IMAGE, netnsContainerId: donor?.id, planDirectory: directory, scriptDirectory, planSha256 };
  let judgement: K6Judgement;
  let stoppedBy: K6Outcome["stoppedBy"] = null;
  let containerRemoved = false;
  try {
    const created = await docker(k6CreateArguments(spec));
    const id = created.stdout.trim().split("\n").pop() ?? "";
    if (!/^[0-9a-f]{64}$/.test(id)) throw new Error("docker create returned no container id");
    // The daemon's record, not our command line, decides whether the container may start.
    assertK6ContainerConfinement(await inspectContainer(id), { image: K6_IMAGE, netnsContainerId: donor?.id });
    // The donor must still be the same running lab container immediately before traffic starts.
    if (donor) {
      const again = await inspectLabContainer(donor.id, "app");
      if (!again.running) throw new PolicyRefusal("target-listener-unproven", "the application container stopped before the run");
    }
    const supervised = await superviseContainer(id, { timeoutMs: Math.min(wallMs, options.superviseMs ?? wallMs), untilMs: run.authorizedUntilMs });
    stoppedBy = supervised.terminationProven ? supervised.stoppedBy : null;
    let summary: K6Summary | null = null;
    try { summary = JSON.parse(readFileSync(path.join(directory, "summary.json"), "utf8")) as K6Summary; } catch { summary = null; }
    judgement = judgeK6Run({ summary, model, maxTotalRequests: plan.maxTotalRequests, exitCode: supervised.exitCode, stoppedBy: supervised.stoppedBy, terminationProven: supervised.terminationProven });
  } finally {
    // Whatever happened, the container must be gone, and we verify it rather than assume it.
    try { containerRemoved = (await removeLabContainer(name, "k6")) || !(await containerExists(name)); }
    catch { containerRemoved = false; }
  }
  const reasons = [...judgement.reasons];
  let result = judgement.result;
  if (!containerRemoved) { reasons.push("the k6 container could not be verified as removed"); if (result === "PASS") result = "ERROR"; }
  return {
    result, reasons, planSha256, k6Version, imageId, metrics: judgement.metrics, containerRemoved, stoppedBy,
    envelope: { maxTotalRequests: plan.maxTotalRequests, windowSeconds: model.windowSeconds, wallSeconds: model.wallSeconds, scope: "per-process" },
  };
}
