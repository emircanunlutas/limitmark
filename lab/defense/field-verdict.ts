/**
 * Field qualification: the closed list of reasons a level can be stopped or invalidated, their CLASS, and the verdict rules.
 *
 *   measurement  the evidence cannot support a claim (a gap, an unexplained request, an exposure violation, an unattributed 503...)
 *   defense      the measurement is sound and the defense failed (JCR below 100%, a legitimate 503, a bypass, a crash, a ceiling...)
 *   operational  the operator or the environment ended the level (SIGINT, target expiry, the generator never started, a preflight refusal)
 *
 * Precedence is measurement, then defense, then operational: every reason is recorded, the verdict follows the highest class present.
 * The server-side stage can only conclude `complete | invalid | aborted`; the FINAL verdict
 * (EXTERNAL-L7-QUALIFICATION-VALID | INVALID | ABORTED) exists only after the offline reconcile of the server evidence and the generator report.
 */
export type ReasonClass = "measurement" | "defense" | "operational";

export const REASON_CLASS = Object.freeze({
  // ---- measurement
  exposure_violation: "measurement",
  exposure_unproven: "measurement",
  evidence_gap: "measurement",
  tick_gap: "measurement",
  telemetry_incomplete: "measurement",
  journal_overflow: "measurement",
  ledger_anomaly: "measurement",
  external_state_overflow: "measurement",
  identity_failed: "measurement",
  unexplained_traffic: "measurement",
  unattributed_503: "measurement",
  traffic_in_quiet: "measurement",
  canary_starved: "measurement",
  runner_internal_error: "measurement",
  generator_saturation: "measurement",
  generator_ambiguity: "measurement",
  generator_in_flight_exceeded: "measurement",
  generator_report_missing: "measurement",
  generator_report_mismatch: "measurement",
  identity_binding_mismatch: "measurement",
  // ---- defense
  process_crash: "defense",
  app_bypass: "defense",
  mutation_over_budget: "defense",
  jcr_below_minimum: "defense",
  legitimate_refusal: "defense",
  l1_false_reject: "defense",
  l2_legitimate_non_admit: "defense",
  parity_mismatch: "defense",
  latency_envelope_exceeded: "defense",
  resource_ceiling: "defense",
  residual_denial: "defense",
  recovery_failed: "defense",
  // ---- operational
  operator_abort: "operational",
  target_expired: "operational",
  generator_not_started: "operational",
  preflight_refused: "operational",
  level_incomplete: "operational",
} as const satisfies Record<string, ReasonClass>);

export type ReasonCode = keyof typeof REASON_CLASS;
export type Reason = { code: ReasonCode; detail?: string };

export const REASON_CODES = Object.keys(REASON_CLASS) as ReasonCode[];
export const classOf = (code: ReasonCode): ReasonClass => REASON_CLASS[code];

const ORDER: readonly ReasonClass[] = ["measurement", "defense", "operational"];

/** The highest-precedence class among the reasons, or null when there are none. */
export function dominantClass(reasons: readonly Reason[]): ReasonClass | null {
  for (const cls of ORDER) if (reasons.some((reason) => classOf(reason.code) === cls)) return cls;
  return null;
}

export type ServerSideStatus = "complete" | "invalid" | "aborted";
export type ServerSideDecision = { status: ServerSideStatus; failureClass: ReasonClass | null; reasons: Reason[] };

/**
 * The server-side stage. `phasesCompleted` is true only when every phase of the level ran to its end (baseline, window, residual, quiet,
 * recovery); a level that did not complete can never be `complete`.
 */
export function decideServerSide(reasons: readonly Reason[], phasesCompleted: boolean): ServerSideDecision {
  const all = [...reasons];
  if (!phasesCompleted && !all.some((reason) => reason.code === "level_incomplete")) all.push({ code: "level_incomplete" });
  const cls = dominantClass(all);
  if (cls === "measurement" || cls === "defense") return { status: "invalid", failureClass: cls, reasons: all };
  if (cls === "operational") return { status: "aborted", failureClass: "operational", reasons: all };
  return { status: "complete", failureClass: null, reasons: all };
}

export type FinalVerdict = "EXTERNAL-L7-QUALIFICATION-VALID" | "INVALID" | "ABORTED";
export type FinalDecision = { verdict: FinalVerdict; failureClass: ReasonClass | null; reasons: Reason[] };

/** The only function that may produce a final verdict: the server-side decision plus the reconcile's own reasons. */
export function decideFinal(server: ServerSideDecision, reconcileReasons: readonly Reason[]): FinalDecision {
  const reasons = [...server.reasons, ...reconcileReasons];
  const cls = dominantClass(reasons);
  if (cls === "measurement" || cls === "defense") return { verdict: "INVALID", failureClass: cls, reasons };
  if (cls === "operational" || server.status !== "complete") return { verdict: "ABORTED", failureClass: "operational", reasons };
  return { verdict: "EXTERNAL-L7-QUALIFICATION-VALID", failureClass: null, reasons };
}

/** Exit codes of the field runner: 0 server-side complete, 1 invalid, 2 refused at preflight, 3 aborted, 4 internal error. */
export const FIELD_EXIT = Object.freeze({ complete: 0, invalid: 1, refused: 2, aborted: 3, error: 4 });
