import { z } from "zod";
import { readFieldReasons, type FieldReason } from "./field-reasons";

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
  clientAborted: count.optional(),
  terminal: z.object({ client_aborted: count.optional() }).optional(),
  l1: z.object({ entered: count, passed: count.optional(), error: count }),
  l2: z.object({ entered: count.optional(), decided: count, byKey: z.record(z.string(), count) }),
  boundary: z.object({ admitted: count, forwardResponded: count.optional(), forwardFailed: count, aborted: count }),
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
export type IncidentFinding = { title: string; facts: string[]; conclusion: string; uncertainty: string; guidance: string };
type Assessment = { components: ComponentHealth[]; findings: IncidentFinding[] };
export type FieldHealthReview = Assessment & {
  endedAt: string; reviewedAt: string; stale: boolean; result: Manifest["result"]; diagnostics: string[];
};

// This is the age of an operator's snapshot at review, never an admission or qualification deadline.
export const REVIEW_AGE_MS = 24 * 60 * 60 * 1000;
type Check = readonly [id: string, diagnostic: string, expected?: number];
type Signal = { group: "canary" | "decision" | "interruption"; fact: string; detail: string };
type Canary = z.infer<typeof canarySchema>;
type Component = {
  name: string; checks: readonly Check[]; observed: (c: Counters) => number;
  signals: (c: Counters, canary: Canary) => Signal[];
};

const components: Component[] = [
  {
    name: "L1 request screening", observed: c => c.l1.entered,
    checks: [
      ["e2.l1_in_equals_ingress", "Compare external ingress with L1 entries."],
      ["e2.l1_in_equals_outcomes", "Reconcile L1 entries with their terminal decisions."],
    ],
    signals(c, canary) {
      const signals: Signal[] = [];
      if (canary.l1FalseRejects) signals.push({ group: "canary", fact: `canary.json · ${canary.l1FalseRejects} protected requests rejected at L1.`,
        detail: "Review the protected canary requests rejected by L1." });
      if (c.l1.error) signals.push({ group: "decision", fact: `external.json · ${c.l1.error} L1 evaluator errors.`,
        detail: "Review the errors recorded by the L1 evaluator." });
      return signals;
    },
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
    signals(c, canary) {
      const signals: Signal[] = [];
      if (canary.l2NonAdmits) signals.push({ group: "canary", fact: `canary.json · ${canary.l2NonAdmits} protected requests without L2 admission.`,
        detail: "Inspect the protected canary requests that L2 did not admit." });
      for (const outcome of ["error", "degraded"]) {
        const total = Object.entries(c.l2.byKey).reduce((sum, [key, n]) => sum + (key.endsWith(`.${outcome}`) ? n : 0), 0);
        if (total) signals.push({ group: "decision", fact: `external.json · ${total} L2 decisions with outcome ${outcome}.`,
          detail: "Inspect the L2 error and degraded decisions." });
      }
      return signals;
    },
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
    signals: ({ boundary }) => boundary.forwardFailed || boundary.aborted ? [{
      group: "interruption", fact: `external.json · boundary forward failures ${boundary.forwardFailed}, boundary aborts ${boundary.aborted}.`,
      detail: "Inspect failed forwards and aborted boundary requests.",
    }] : [],
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
    signals: ({ app }) => app.aborted || app.completed !== app.executed || app.executed !== app.admitted ? [{
      group: "interruption", fact: `external.json · app admissions ${app.admitted}, executions ${app.executed}, completions ${app.completed}, aborts ${app.aborted}.`,
      detail: "Inspect aborted or incomplete external executions.",
    }] : [],
  },
];
// Both sides of each handoff refer to external requests from the same run.
const handoffs = [
  { id: "e2.l2_in_equals_l1_pass", left: "L2 entries", right: "L1 passes",
    counts: (c: Counters) => [c.l2.entered, c.l1.passed] as const },
  { id: "e5.external_app_admitted_equals_forwarded", left: "App admissions", right: "answered boundary forwards",
    counts: (c: Counters) => [c.app.admitted, c.boundary.forwardResponded] as const },
];
const coverage: Check[] = [
  ["e10.no_dropped_events", "Inspect dropped events in the process channels.", 0],
  ["e10.streams_drained", "Check which process failed to drain its event queue.", 0],
  ["e10.final_ticks_present", "Inspect the missing final heartbeats.", 3],
  ["e10.no_tick_gaps", "Inspect the gaps in the telemetry record.", 0],
];
export type Artifact = { kind: "present"; value: unknown } | { kind: "unavailable" | "unknown"; detail: string };

function limited(state: "Unavailable" | "Unknown", finding: IncidentFinding): Assessment {
  return {
    components: components.map(({ name }) => ({ name, state, detail: finding.facts[0] })),
    findings: [finding],
  };
}

function interpret(manifest: Manifest, external: Artifact, canary: Artifact, reasons: ReadonlySet<FieldReason>): Assessment {
  const canaryEvidence = readCanary(canary);
  const canaryCounts = canaryEvidence.state === "Reviewed" ? canaryEvidence.counts : undefined;
  function incomplete(detail: string, state: "Unknown" | "Unavailable" = "Unknown") {
    return limited(state, {
      title: "Evidence needed for component review",
      facts: canaryEvidence.state === "Reviewed" ? [detail] : [detail, canaryEvidence.detail],
      conclusion: "The external accounting needed to compare stages is unavailable.",
      uncertainty: "Component condition during the run is unresolved.",
      guidance: "Check the finalized inventory and select the matching records from the trusted archive.",
    });
  }
  function conflict(facts: string[]) {
    return limited("Unknown", {
      title: "Conflicting run records", facts, conclusion: "The records disagree on the observations used to assess these stages.",
      uncertainty: "The supplied files cannot establish which observation is correct.",
      guidance: "Compare the original manifest, final counters and ledger for the same run before attributing a fault.",
    });
  }
  if (manifest.result === "REFUSED") return limited("Unavailable", {
    title: "Run refused before observation", facts: ["Preflight refused this run before component observations were collected."],
    conclusion: "This run supplies no component exercise.", uncertainty: "No component condition can be inferred.",
    guidance: "Review the preflight record in the original evidence.",
  });
  if (external.kind !== "present") return incomplete(external.detail, external.kind === "unavailable" ? "Unavailable" : "Unknown");
  const record = z.object({ counters: countersSchema, accounting: z.unknown() }).safeParse(external.value);
  if (!record.success) return incomplete("External request counters are incomplete or malformed.");
  if (record.data.accounting === "not_derived") return incomplete("The runner could not derive request accounting.");
  const parsed = accountingSchema.safeParse(record.data.accounting);
  if (!parsed.success) return incomplete("The request accounting comparisons are incomplete or malformed.");
  const { identities, identitiesOk, summary } = parsed.data;
  const byId = new Map(identities.map(row => [row.id, row]));
  const { counters } = record.data;
  const complete = manifest.result === "SERVER-COMPLETE";
  if (identities.length !== byId.size) return conflict(["The accounting record repeats a comparison identifier."]);
  if (identities.some(row => row.ok !== (row.left === row.right)) || identitiesOk !== identities.every(row => row.ok))
    return conflict(["The accounting pass flags disagree with the recorded comparison values."]);
  if (manifest.metrics.externalAccepted === undefined) return incomplete("The manifest omits the external acceptance count.");
  if (summary.externalAccepted !== counters.accepted || manifest.metrics.externalAccepted !== counters.accepted)
    return conflict([`External acceptances · manifest ${manifest.metrics.externalAccepted}, accounting summary ${summary.externalAccepted}, counters ${counters.accepted}.`]);
  if (complete && manifest.metrics.anomalyTotal === undefined) return incomplete("The completed run omits its anomaly count.");
  if (complete && (!identitiesOk || manifest.metrics.anomalyTotal !== 0))
    return conflict(["The manifest records server completion alongside failed accounting or a nonzero anomaly count."]);
  if (counters.l1.error > counters.l1.entered)
    return conflict([`L1 recorded ${counters.l1.error} evaluator errors for ${counters.l1.entered} entries.`]);
  const decisionTotal = Object.values(counters.l2.byKey).reduce((sum, count) => sum + count, 0);
  if (decisionTotal !== counters.l2.decided)
    return conflict([`L2 outcome counts sum to ${decisionTotal} for ${counters.l2.decided} recorded decisions.`]);
  const app = counters.app;
  if (app.completed + app.aborted > app.admitted || app.executed > app.admitted)
    return conflict([`App admissions ${app.admitted}, executions ${app.executed}, completions ${app.completed}, aborts ${app.aborted}.`]);
  const clientAborted = counters.clientAborted ?? counters.terminal?.client_aborted;
  if (clientAborted !== undefined && (clientAborted > counters.accepted ||
      (counters.terminal && clientAborted !== (counters.terminal.client_aborted ?? 0))))
    return conflict(["The client abort count disagrees with the external request accounting."]);

  const windowCanary = canaryCounts?.jcr.filter(row => row.phase === "window" && row.lane === "protected");
  if (canaryCounts && (canaryCounts.jcr.some(row => row.completed > row.attempted ||
    row.rate !== (row.attempted ? row.completed / row.attempted : 0)) || (windowCanary?.length ?? 0) > 1))
    return conflict(["The recorded canary counts, rates or window rows are inconsistent."]);
  if (canaryCounts && complete && (canaryCounts.l1FalseRejects > 0 || canaryCounts.l2NonAdmits > 0 || canaryCounts.jcr.some(row => row.rate < 1)))
    return conflict(["Canary failures appear alongside a server-complete result."]);
  if (canaryCounts && ((reasons.has("l1_false_reject") && !canaryCounts.l1FalseRejects) ||
      (reasons.has("l2_legitimate_non_admit") && !canaryCounts.l2NonAdmits)))
    return conflict(["The manifest records a protected canary admission failure where canary.json reports zero for that stage."]);

  // A failed equality is diagnostic evidence. A row that misquotes its inputs is conflicting evidence.
  for (const handoff of handoffs) {
    const check = byId.get(handoff.id);
    const [left, right] = handoff.counts(counters);
    if (check && ((left !== undefined && left !== check.left) || (right !== undefined && right !== check.right)))
      return conflict([`${handoff.left} / ${handoff.right} · counters ${left ?? "unavailable"} / ${right ?? "unavailable"}, recorded comparison ${check.left} / ${check.right}.`]);
  }

  return diagnoseRun(manifest, reasons, { counters, byId, canary: canaryEvidence, window: windowCanary?.[0] });
}

type CanaryEvidence = { state: "Reviewed"; counts: Canary } | { state: "Unknown" | "Unavailable"; detail: string };

function readCanary(artifact: Artifact): CanaryEvidence {
  if (artifact.kind !== "present") return { state: artifact.kind === "unavailable" ? "Unavailable" : "Unknown", detail: artifact.detail };
  const result = canarySchema.safeParse(artifact.value);
  return result.success ? { state: "Reviewed", counts: result.data } : { state: "Unknown", detail: "Canary observations are incomplete or malformed." };
}

type RunObservations = {
  counters: Counters; byId: Map<string, Comparison>; canary: CanaryEvidence; window?: Canary["jcr"][number];
};

function diagnoseRun(manifest: Manifest, reasons: ReadonlySet<FieldReason>, observations: RunObservations): Assessment {
  const { counters, byId, canary, window } = observations;
  const complete = manifest.result === "SERVER-COMPLETE";
  const clientAborted = counters.clientAborted ?? counters.terminal?.client_aborted;
  const findings: IncidentFinding[] = [];
  const coverageIssues = checkProblems(coverage, byId);
  const coverageReasons = (["tick_gap", "telemetry_incomplete", "evidence_gap", "journal_overflow"] as const).filter(code => reasons.has(code));
  const coverageFacts = [...coverageIssues.map(issue => issue.fact), ...coverageReasons.map(code => `Manifest stop reason · ${code}.`)];
  if (coverageFacts.length) findings.push({
    title: "Telemetry coverage across stages", facts: coverageFacts,
    conclusion: "The record cannot confirm complete observation across the defense plane, boundary and app.",
    uncertainty: "The affected requests and the condition of each stage during the gap are unresolved.",
    guidance: "Compare the final heartbeats and stream-drain records with the ledger for this run.",
  });
  if (canary.state !== "Reviewed") findings.push({
    title: canary.state === "Unavailable" ? "Missing canary evidence" : "Unverified canary evidence", facts: [canary.detail],
    conclusion: "External counts alone cannot establish the protected journey outcome.",
    uncertainty: "The protected requests' admission and completion outcomes are unresolved.",
    guidance: "Check the manifest inventory for the matching canary.json.",
  });
  if (clientAborted) findings.push({
    title: "Client-side aborts", facts: [`external.json recorded ${clientAborted} client-aborted requests.`],
    conclusion: "The runner classified these terminal outcomes as client-side aborts.",
    uncertainty: "The reason for disconnection and any relationship to a stage interruption are unresolved.",
    guidance: "Compare authorized client-side records with the same run interval.",
  });

  const signals: Signal[] = [];
  const assessed = components.map(({ name, checks, observed, signals: observeSignals }) => {
    const observations = observed(counters);
    const row = (state: HealthState, detail: string): ComponentHealth => ({ name, state, detail, observations });
    const issues = checkProblems(checks, byId);
    const witness = byId.get(checks[0][0]);
    if (observations > counters.accepted || (witness && observations !== witness.left))
      issues.push({ fact: `External stage count ${observations}, accepted ${counters.accepted}, comparison count ${witness?.left ?? "unavailable"}.`,
        guidance: "Compare the stage counters with the original ledger." });
    if (issues.length) {
      findings.push({ title: `${name} accounting`, facts: issues.map(issue => issue.fact),
        conclusion: "The available comparisons do not reconcile this stage with the request ledger.",
        uncertainty: "The discrepancy alone cannot locate a component fault.",
        guidance: issues[0].guidance,
      });
      return row("Unknown", `${issues[0].fact} ${issues[0].guidance}`);
    }
    if (coverageFacts.length) return row("Unknown", coverageIssues[0]?.guidance ?? coverageFacts[0]);
    if (canary.state !== "Reviewed") return row(canary.state, canary.detail);
    const stageSignals = observeSignals(counters, canary.counts);
    if (stageSignals.length) {
      signals.push(...stageSignals);
      return row("Degraded", stageSignals[0].detail);
    }
    if (!complete || manifest.metrics.artifactsRefused !== 0)
      return row("Unknown", "Review the server outcome and evidence omissions before interpreting successful checks.");
    if (!window?.completed) return row("Unknown", "No completed protected canary journey was observed during the field window.");
    if (observations === 0) {
      findings.push({
        title: `${name} exercise`, facts: [`external.json · 0 external requests observed at ${name}.`],
        conclusion: "The run supplies no external exercise at this stage.",
        uncertainty: "Successful checks on an empty population cannot establish how the stage handled external requests.",
        guidance: "Review the upstream decision counts to determine how many requests were eligible to reach this stage.",
      });
      return row("Unknown", "No external exercise was recorded for this component.");
    }
    return row("Healthy", "The recorded component checks agreed for the observed requests.");
  });

  if (assessed.some(stage => stage.state === "Unknown") && (!complete || manifest.metrics.artifactsRefused !== 0)) {
    findings.push({
      title: "Limits of the run outcome",
      facts: [`Recorded server result · ${manifest.result}. Artifacts refused · ${manifest.metrics.artifactsRefused ?? "unreported"}.`],
      conclusion: "Successful individual checks cannot establish overall component health for this record.",
      uncertainty: "The server result alone cannot locate a component fault.",
      guidance: "Review the recorded stop reasons and artifact inventory alongside the stage observations.",
    });
  }
  if (canary.state === "Reviewed" && (!window?.attempted || window.completed < window.attempted)) findings.push({
    title: "Protected window coverage",
    facts: [window ? `Protected window journeys completed · ${window.completed} of ${window.attempted}.` : "canary.json contains no protected window journey summary."],
    conclusion: window?.attempted ? "Some protected journeys attempted in the window did not complete."
      : "This record supplies no observed protected journey for the window.",
    uncertainty: "The journey summary alone cannot distinguish a component interruption from incomplete measurement.",
    guidance: "Inspect the phase and journey records from the same run.",
  });
  return { components: assessed, findings: [...findings, ...relateSignals(signals, window)] };
}

// Callers supply only observations that passed the stage and shared coverage checks.
function relateSignals(signals: Signal[], window?: Canary["jcr"][number]): IncidentFinding[] {
  const findings: IncidentFinding[] = [];
  const factsFor = (group: Signal["group"]) => signals.filter(signal => signal.group === group).map(signal => signal.fact);
  const screening = factsFor("canary");
  if (screening.length) findings.push({
    title: "Protected request admission",
    facts: [...screening, ...(window ? [`Protected window journeys completed · ${window.completed} of ${window.attempted}.`] : [])],
    conclusion: screening.length === 2 ? "Protected requests encountered adverse admission decisions at both stages during this run."
      : "The canary recorded adverse admission decisions at the indicated stage.",
    uncertainty: "Run-wide decision counts cannot identify which window journey, if any, encountered those decisions.",
    guidance: "Compare the protected request decisions with the phase and journey records in the archived ledger.",
  });
  const decisions = factsFor("decision");
  if (decisions.length) findings.push({
    title: "External request decisions", facts: decisions,
    conclusion: "The stage counters record exceptional outcomes during external request evaluation.",
    uncertainty: "Aggregate decisions cannot establish the cause or the impact on individual requests.",
    guidance: "Reconcile the recorded decision outcomes with the finalized evaluator counters.",
  });
  const interruptions = factsFor("interruption");
  if (interruptions.length) findings.push({
    title: interruptions.length === 2 ? "Boundary and app interruptions" : "Interrupted external requests",
    facts: interruptions, conclusion: interruptions.length === 2 ? "Both stages recorded interrupted or incomplete work in the same run."
      : "The stage recorded interrupted or incomplete work during this run.",
    uncertainty: "The totals do not link individual requests or identify where an interruption began.",
    guidance: "Compare the boundary forwarding records and app completion records for the same requests in the archived ledger.",
  });
  return findings;
}

// Only identifiers from the reviewed check list reach the UI. Keep every applicable discrepancy.
function checkProblems(checks: readonly Check[], rows: Map<string, Comparison>) {
  const issues: { fact: string; guidance: string }[] = [];
  for (const [id, guidance, expected] of checks) {
    const check = rows.get(id);
    if (!check) issues.push({ fact: `Missing comparison ${id}.`, guidance });
    else if (expected !== undefined && check.right !== expected)
      issues.push({ fact: `Comparison ${id} used reference value ${check.right}, expected ${expected}.`, guidance });
    else if (!check.ok) {
      const handoff = handoffs.find(handoff => handoff.id === id);
      const fact = handoff ? `${handoff.left} · ${check.left}, ${handoff.right} · ${check.right} (${id}).`
        : `Recorded comparison ${id} · ${check.left} vs ${check.right}.`;
      issues.push({ fact, guidance });
    }
  }
  return issues;
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
  const { known, diagnostics } = readFieldReasons(manifest.resultReasons);
  if (manifest.result !== "SERVER-COMPLETE" && !diagnostics.length) diagnostics.push("No stop reason was supplied. Inspect the finalized run record.");
  return {
    endedAt: manifest.endedAt, reviewedAt: new Date(now).toISOString(), stale: now - end > REVIEW_AGE_MS,
    result: manifest.result, diagnostics, ...interpret(manifest, external, canary, known),
  };
}
