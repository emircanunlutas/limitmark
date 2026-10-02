/**
 * k6 engine wrapper. The policy decides everything (`authorizeRun`); this module only serialises
 * the AUTHORIZED run into an integrity-hashed plan and launches k6 in Docker. The k6 script
 * (k6/lab-load.js) accepts nothing but that plan.
 *
 * Network model: the k6 container joins the network namespace of a lab-owned container
 * (`--network container:limitmark-lab-...`) so `127.0.0.1:<port>` inside it is that container's
 * loopback; for remote targets later it runs on the default bridge with the plan's IP literal.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { docker } from "../host/docker";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { LAB_CONTAINER_PREFIX, type AuthorizedRun } from "../policy/target-policy";
import { ruleFor, type HttpThresholds } from "../policy/thresholds";

export const K6_IMAGE = "grafana/k6:latest";

export type K6Plan = {
  schema: 1;
  baseUrl: string;
  requests: { method: "GET" | "POST"; path: string }[];
  phases: { name: string; seconds: number; rate: number; vus: number; timeoutMs: number; measured: boolean }[];
  thresholds: { passErrorRate: number; stopErrorRate: number; passP95Ms: number; passP99Ms: number; stopP99Ms: number };
};

export function buildK6Plan(run: AuthorizedRun, thresholds: HttpThresholds): K6Plan {
  const requests = run.workload.methods.flatMap((method) => run.workload.paths.map((requestPath) => {
    // Eager policy authorization of each request the plan will contain.
    const authorized = run.authorizeRequest(method, requestPath);
    return { method: authorized.method, path: authorized.path };
  }));
  return {
    schema: 1,
    baseUrl: run.target.origin,
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
}

export type K6Outcome = {
  result: "PASS" | "FAIL" | "STOP";
  reasons: string[];
  planSha256: string;
  k6Version: string | null;
  metrics: Record<string, number>;
};

type SummaryMetric = { values?: Record<string, number>; thresholds?: Record<string, boolean | { ok: boolean }> } & Record<string, unknown>;

export async function runK6(run: AuthorizedRun, thresholds: HttpThresholds, options: { netnsContainer?: string; runId: string }): Promise<K6Outcome> {
  if (options.netnsContainer && !new RegExp(`^${LAB_CONTAINER_PREFIX}[a-z0-9-]{1,40}$`).test(options.netnsContainer)) {
    throw new Error("--k6-netns-container must be a lab-owned container");
  }
  const plan = buildK6Plan(run, thresholds);
  const planText = `${JSON.stringify(plan)}\n`;
  const planSha256 = createHash("sha256").update(planText).digest("hex");
  // Plan and summary live outside the evidence tree: the plan names the target address.
  const directory = path.join(REPOSITORY_ROOT, "artifacts", "lab", "k6", options.runId);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, "plan.json"), planText);
  const scriptDirectory = path.join(REPOSITORY_ROOT, "lab", "load", "k6");
  const version = await docker(["run", "--rm", K6_IMAGE, "version"]).then((r) => /k6 v?([0-9.]+)/.exec(r.stdout)?.[1] ?? null).catch(() => null);
  const limitSeconds = run.limits.phases.reduce((sum, phase) => sum + phase.durationSeconds, 0) + 30;
  let exitedNonZero = false;
  try {
    await docker([
      "run", "--rm", "--memory", "512m", "--pids-limit", "512", "--read-only", "--tmpfs", "/tmp",
      ...(options.netnsContainer ? ["--network", `container:${options.netnsContainer}`] : []),
      "-v", `${directory}:/lab`, "-v", `${scriptDirectory}:/script:ro`,
      "-e", "LAB_PLAN=/lab/plan.json", "-e", `LAB_PLAN_SHA256=${planSha256}`,
      K6_IMAGE, "run", "--quiet", "--no-usage-report", "--summary-export=/lab/summary.json", "/script/lab-load.js",
    ], { timeoutMs: limitSeconds * 1000 });
  } catch { exitedNonZero = true; }

  let summary: { metrics?: Record<string, SummaryMetric> };
  try { summary = JSON.parse(readFileSync(path.join(directory, "summary.json"), "utf8")); }
  catch { return { result: "STOP", reasons: ["k6 produced no summary (script rejected the plan or aborted early)"], planSha256, k6Version: version, metrics: {} }; }

  const { failed, metrics } = parseK6Summary(summary);
  const reasons = [...failed.stop, ...failed.pass];
  const result = failed.stop.length > 0 ? "STOP" : failed.pass.length > 0 || exitedNonZero ? "FAIL" : "PASS";
  if (exitedNonZero && reasons.length === 0) reasons.push("k6 exited non-zero without a threshold breach");
  return { result, reasons, planSha256, k6Version: version, metrics };
}

/**
 * k6 summary-export formats differ by version: metric values are either nested under `values` or flat, and a
 * threshold is either `{ ok: boolean }` or a bare boolean whose value is TRUE when the threshold was crossed.
 */
export function parseK6Summary(summary: { metrics?: Record<string, SummaryMetric> }): { failed: { stop: string[]; pass: string[] }; metrics: Record<string, number> } {
  const failed = { stop: [] as string[], pass: [] as string[] };
  for (const [metricName, metric] of Object.entries(summary.metrics ?? {})) {
    for (const [expression, outcome] of Object.entries(metric.thresholds ?? {})) {
      const crossed = typeof outcome === "boolean" ? outcome : !outcome.ok;
      if (!crossed) continue;
      // The plan uses strict "<" (abortOnFail) for STOP and "<=" for PASS criteria.
      (expression.includes("<=") ? failed.pass : failed.stop).push(`${metricName.replace(/{.*}/, "")} ${expression}`);
    }
  }
  const values = (name: string): Record<string, number> => {
    const metric = summary.metrics?.[name] as (SummaryMetric & Record<string, number>) | undefined;
    return (metric?.values ?? metric ?? {}) as Record<string, number>;
  };
  const duration = values("http_req_duration");
  const round = (value: number | undefined) => Math.round((value ?? 0) * 100) / 100;
  return {
    failed,
    metrics: {
      requests: values("http_reqs").count ?? 0,
      failedRate: Math.round((values("http_req_failed").rate ?? values("http_req_failed").value ?? 0) * 10_000) / 10_000,
      p50Ms: round(duration.med), p95Ms: round(duration["p(95)"]), p99Ms: round(duration["p(99)"]), maxMs: round(duration.max),
    },
  };
}
