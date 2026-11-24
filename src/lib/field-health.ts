import { z } from "zod";

const count = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const comparison = z.object({ id: z.string(), left: count, right: count, ok: z.boolean() });
const accountingSchema = z.object({
  identities: z.array(comparison).max(160),
  identitiesOk: z.boolean(),
  summary: z.object({ externalAccepted: count }),
});
const canarySchema = z.object({
  l1FalseRejects: count, l2NonAdmits: count,
  jcr: z.array(z.object({ lane: z.string(), phase: z.string(), attempted: count, completed: count, rate: z.number() })).max(64),
});
const countersSchema = z.object({
  accepted: count,
  l1: z.object({ entered: count, error: count }),
  l2: z.object({ decided: count, byKey: z.record(z.string(), count) }),
  boundary: z.object({ admitted: count, forwardFailed: count, aborted: count }),
  app: z.object({ admitted: count, executed: count, completed: count, aborted: count }),
});

export const reviewManifestSchema = z.object({
  schemaVersion: z.literal(1), kind: z.literal("field-level"), engine: z.literal("node-http-field-level"),
  startedAt: z.iso.datetime(), endedAt: z.iso.datetime(),
  result: z.enum(["SERVER-COMPLETE", "ABORTED", "INVALID", "REFUSED"]),
  resultReasons: z.array(z.string().max(200)),
  metrics: z.object({
    serverSide: z.enum(["complete", "invalid", "aborted"]), externalAccepted: count.optional(),
    anomalyTotal: count.optional(), artifactsRefused: count.optional(), networkActivity: z.boolean().optional(),
  }),
  artifacts: z.array(z.object({ name: z.string(), sha256: z.string().regex(/^[0-9a-f]{64}$/), bytes: count })).max(128),
});
type Manifest = z.infer<typeof reviewManifestSchema>;
type Counters = z.infer<typeof countersSchema>;
type Comparison = z.infer<typeof comparison>;

export type HealthState = "Healthy" | "Degraded" | "Unavailable" | "Unknown";
export type ComponentHealth = { name: string; state: HealthState; detail: string; observations?: number };
export type FieldHealthReview = {
  endedAt: string; reviewedAt: string; stale: boolean; result: Manifest["result"]; diagnostics: string[]; components: ComponentHealth[];
};

// This is the age of an operator's snapshot at review, never an admission or qualification deadline.
export const REVIEW_AGE_MS = 24 * 60 * 60 * 1000;
type Check = readonly [id: string, diagnostic: string, expected?: number];
type Component = {
  name: string; checks: readonly Check[]; observed: (c: Counters) => number;
  fault: (c: Counters, canary: z.infer<typeof canarySchema>) => string | null;
};

const components: Component[] = [
  {
    name: "L1 request screening", observed: c => c.l1.entered,
    checks: [
      ["e2.l1_in_equals_ingress", "Compare external ingress with L1 entries."],
      ["e2.l1_in_equals_outcomes", "Reconcile L1 entries with their terminal decisions."],
    ],
    fault: (c, canary) => canary.l1FalseRejects ? "Review the protected canary requests rejected by L1."
      : c.l1.error ? "Review the errors recorded by the L1 evaluator." : null,
  },
  {
    name: "L2 admission", observed: c => c.l2.decided,
    checks: [
      ["e2.l2_decided_equals_entered", "Reconcile L2 entries with their decisions."],
      ["e2.l2_in_equals_l1_pass", "Compare L1 passes with L2 entries."],
      ["e2.l2_decisions_partition", "Inspect the L2 outcome counts."],
      ["e7.plane_l2_counters_equal_ledger", "Compare the plane's final decision counters with the ledger.", 0],
      ["e8.status_503_equals_expected_shed", "Review responses outside the expected shedding budget."],
    ],
    fault: (c, canary) => canary.l2NonAdmits ? "Inspect the protected canary requests that L2 did not admit."
      : Object.entries(c.l2.byKey).some(([key, n]) => n > 0 && /\.(error|degraded)$/.test(key))
        ? "Inspect the L2 error and degraded decisions." : null,
  },
  {
    name: "Origin boundary", observed: c => c.boundary.admitted,
    checks: [
      ["e5.external_admitted_equals_app_proofs", "Compare external admissions with app proofs issued."],
      ["e5.boundary_arrived_equals_ledger", "Compare boundary arrivals with the request ledger."],
      ["e5.boundary_admitted_equals_ledger", "Reconcile the final boundary admission count."],
      ["e5.boundary_rejected_is_zero", "Review boundary rejections during the run.", 0],
      ["e5.boundary_refusals_zero", "Review parser and protocol refusals at the boundary.", 0],
    ],
    fault: c => c.boundary.forwardFailed || c.boundary.aborted ? "Inspect failed forwards and aborted boundary requests." : null,
  },
  {
    name: "Protected app", observed: c => c.app.admitted,
    checks: [
      ["e5.external_app_admitted_equals_forwarded", "Reconcile external app admissions with boundary responses."],
      ["e5.app_executed_equals_ledger", "Compare app executions with the combined canary and external ledger."],
      ["e5.app_admitted_equals_ledger", "Compare app admissions with the request ledger."],
      ["e5.app_refused_is_zero", "Review refusals at the protected app.", 0],
      ["e6.app_counter_equals_ledger_mutations", "Compare the app mutation counter with the ledger."],
      ["e6.canary_ledger_equals_client", "Compare canary mutations with client-observed successes."],
    ],
    fault: c => c.app.aborted || c.app.completed !== c.app.executed || c.app.executed !== c.app.admitted
      ? "Inspect aborted or incomplete external executions." : null,
  },
];
const coverage: Check[] = [
  ["e10.no_dropped_events", "Inspect dropped events in the process channels.", 0],
  ["e10.streams_drained", "Check which process failed to drain its event queue.", 0],
  ["e10.final_ticks_present", "Inspect the missing final heartbeats.", 3],
  ["e10.no_tick_gaps", "Inspect the gaps in the telemetry record.", 0],
];
const unavailable = (detail: string): ComponentHealth[] => components.map(({ name }) => ({ name, state: "Unavailable", detail }));
const unknown = (detail: string): ComponentHealth[] => components.map(({ name }) => ({ name, state: "Unknown", detail }));

export type Artifact = { kind: "present"; value: unknown } | { kind: "unavailable" | "unknown"; detail: string };

function interpret(manifest: Manifest, external: Artifact, canary: Artifact): ComponentHealth[] {
  if (external.kind !== "present") return external.kind === "unavailable" ? unavailable(external.detail) : unknown(external.detail);
  const record = z.object({ counters: countersSchema, accounting: z.unknown() }).safeParse(external.value);
  if (!record.success) return unknown("External request counters are incomplete or malformed.");
  if (record.data.accounting === "not_derived") return unknown("The runner could not derive request accounting.");
  const parsed = accountingSchema.safeParse(record.data.accounting);
  if (!parsed.success) return unknown("The request accounting comparisons are incomplete or malformed.");
  const { identities, identitiesOk, summary } = parsed.data;
  const byId = new Map(identities.map(row => [row.id, row]));
  const { counters } = record.data;
  const canaryCounts = canary.kind === "present" ? canarySchema.safeParse(canary.value).data : undefined;
  const complete = manifest.result === "SERVER-COMPLETE";
  if (identities.length !== byId.size || identities.some(row => row.ok !== (row.left === row.right))
    || identitiesOk !== identities.every(row => row.ok) || summary.externalAccepted !== counters.accepted
    || manifest.metrics.externalAccepted !== counters.accepted
    || (complete && (!identitiesOk || manifest.metrics.anomalyTotal !== 0))) {
    return unknown("The run summary and accounting records disagree. Check the original evidence before interpreting component health.");
  }
  const coverageIssue = problemWithChecks(coverage, byId);
  const windowCanary = canaryCounts?.jcr.filter(row => row.phase === "window" && row.lane === "protected");
  if (canaryCounts && (canaryCounts.jcr.some(row => row.completed > row.attempted ||
    row.rate !== (row.attempted ? row.completed / row.attempted : 0)) || (windowCanary?.length ?? 0) > 1 ||
    (complete && (canaryCounts.l1FalseRejects > 0 || canaryCounts.l2NonAdmits > 0 || canaryCounts.jcr.some(row => row.rate < 1)))))
    return unknown("Canary observations conflict with the recorded completion rates or server outcome.");
  return components.map(({ name, checks, observed, fault }) => {
    const observations = observed(counters);
    const row = (state: HealthState, detail: string): ComponentHealth => ({ name, state, detail, observations });
    const issue = problemWithChecks(checks, byId);
    if (issue) return row(issue.state, issue.detail);
    // The first comparison for each stage measures the same external population as the displayed count.
    const witness = byId.get(checks[0][0])!;
    if (observations > counters.accepted || observations !== witness.left)
      return row("Unknown", "The external count disagrees with the component accounting. Compare the original records.");
    if (coverageIssue) return row("Unknown", coverageIssue.detail);
    if (!canaryCounts) return row(canary.kind === "unavailable" ? "Unavailable" : "Unknown",
      canary.kind === "present" ? "Canary observations are incomplete or malformed." : canary.detail);
    const failure = fault(counters, canaryCounts);
    if (failure) return row("Degraded", failure);
    if (!complete || manifest.metrics.artifactsRefused !== 0)
      return row("Unknown", "Review the server outcome and evidence omissions before interpreting successful checks.");
    if (!windowCanary?.[0]?.completed) return row("Unknown", "No completed protected canary journey was observed during the field window.");
    if (observations === 0) return row("Unknown", "No external exercise was recorded for this component.");
    return row("Healthy", "The recorded component checks agreed for the observed requests.");
  });
}

function problemWithChecks(checks: readonly Check[], rows: Map<string, Comparison>): {state: "Unknown"; detail: string} | null {
  for (const [id, diagnostic, expected] of checks) {
    const check = rows.get(id);
    if (check && expected !== undefined && check.right !== expected)
      return { state: "Unknown", detail: `The recorded comparison ${id} has an unexpected reference value. ${diagnostic}` };
    if (check && !check.ok) return { state: "Unknown", detail: `${diagnostic} Recorded comparison (${check.left} vs ${check.right}).` };
  }
  const missing = checks.find(([id]) => !rows.has(id));
  return missing ? { state: "Unknown", detail: `Missing comparison ${missing[0]}. ${missing[1]}` } : null;
}

export function assessFieldRun(manifest: Manifest, external: Artifact, canary: Artifact, now: number): FieldHealthReview | null {
  const end = Date.parse(manifest.endedAt);
  const serverStatus = { "SERVER-COMPLETE": "complete", INVALID: "invalid", REFUSED: "aborted", ABORTED: "aborted" } as const;
  if (!Number.isFinite(now) || end > now || Date.parse(manifest.startedAt) > end ||
      serverStatus[manifest.result] !== manifest.metrics.serverSide ||
      (manifest.result === "SERVER-COMPLETE" && manifest.resultReasons.length > 0)) return null;
  if (manifest.result === "REFUSED" && (manifest.metrics.networkActivity !== false ||
    manifest.artifacts.some(entry => entry.name === "external.json" || entry.name === "canary.json") ||
    external.kind !== "unavailable" || canary.kind !== "unavailable")) return null;
  // Only the writer's known reason codes select text. Its free-form details can contain host diagnostics.
  const messages = new Map([
    ["tick_gap", "Check for missing heartbeats in the observation window."],
    ["telemetry_incomplete", "Check which process failed to return its final heartbeat."],
    ["process_crash", "Review the process finalization records for an unexpected exit."],
    ["resource_ceiling", "Compare process and host measurements with this run's resource ceilings."],
    ["app_bypass", "Review the app execution and proof-chain discrepancies in the ledger."],
    ["recovery_failed", "Inspect the post-window recovery checks."],
    ["identity_failed", "Compare the failing accounting identities with the component observations."],
    ["preflight_refused", "Review the preflight checks before interpreting component observations."],
  ]);
  const diagnostics = new Set<string>();
  for (const reason of manifest.resultReasons) {
    const [prefix, code] = reason.split(".", 2);
    const message = prefix === "field" ? messages.get(code) : undefined;
    if (message) diagnostics.add(message);
  }
  if (manifest.result !== "SERVER-COMPLETE" && diagnostics.size === 0) diagnostics.add("Inspect the recorded stop reasons in the original run.");
  return {
    endedAt: manifest.endedAt, reviewedAt: new Date(now).toISOString(), stale: now - end > REVIEW_AGE_MS,
    result: manifest.result, diagnostics: [...diagnostics], components: manifest.result === "REFUSED" ? unavailable("Preflight refused this run before component observations were collected.")
      : interpret(manifest, external, canary),
  };
}
