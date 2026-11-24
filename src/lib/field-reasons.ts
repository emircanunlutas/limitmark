// Only reviewed labels may leave the interpreter. The writer can append private detail after the code.
const guidance = {
  exposure_violation: "Review the recorded exposure checks.",
  exposure_unproven: "Check which exposure observations were available.",
  evidence_gap: "Check the evidence stream for missing observations.",
  tick_gap: "Check for missing heartbeats in the observation window.",
  telemetry_incomplete: "Check which process failed to return its final heartbeat.",
  journal_overflow: "Check the journal for omitted observations.",
  ledger_anomaly: "Reconcile the ledger with the finalized process records.",
  external_state_overflow: "Check the completeness of external request accounting.",
  identity_failed: "Compare the failing accounting identities with the component observations.",
  unexplained_traffic: "Reconcile the observed requests with the run inventory.",
  unattributed_503: "Check response accounting for unexplained refusals.",
  traffic_in_quiet: "Compare the phase record with requests recorded in the quiet period.",
  canary_starved: "Review the canary scheduling record before interpreting journey coverage.",
  runner_internal_error: "Check which measurements the runner completed.",
  generator_saturation: "Review the generator's measurement capacity for this run.",
  generator_ambiguity: "Review ambiguities in the generator's recorded outcomes.",
  generator_in_flight_exceeded: "Check the generator's recorded concurrency measurements.",
  generator_report_missing: "Locate the matching generator report in the trusted archive.",
  generator_report_mismatch: "Check that the generator report belongs to this run.",
  identity_binding_mismatch: "Verify the recorded association between the run and its report.",
  process_crash: "Review the process finalization records for an unexpected exit.",
  app_bypass: "Review app execution and proof-chain discrepancies in the ledger.",
  mutation_over_budget: "Review the ledger comparisons for recorded mutations.",
  jcr_below_minimum: "Compare attempted and completed canary journeys by phase.",
  legitimate_refusal: "Review refusal observations for protected requests.",
  l1_false_reject: "Compare the L1 stop reason with protected canary rejections.",
  l2_legitimate_non_admit: "Compare the L2 stop reason with protected canary admissions.",
  parity_mismatch: "Compare the recorded control and protected journey results.",
  latency_envelope_exceeded: "Review recorded journey latency by phase.",
  resource_ceiling: "Compare process and host measurements with this run's resource ceilings.",
  residual_denial: "Review the protected journey results after the field window.",
  recovery_failed: "Inspect the post-window recovery checks.",
  operator_abort: "Check the recorded stop time against the completed phases.",
  target_expired: "Check which phases completed before authorization expired.",
  generator_not_started: "Check whether the external exercise began.",
  preflight_refused: "Review the preflight checks before interpreting component observations.",
  level_incomplete: "Check which phases the runner completed.",
};

export type FieldReason = keyof typeof guidance;

export function readFieldReasons(entries: readonly string[]) {
  const known = new Set<FieldReason>();
  let unrecognized = 0;
  for (const entry of entries) {
    const [prefix, code] = entry.split(".", 2);
    if (prefix === "field" && Object.hasOwn(guidance, code)) known.add(code as FieldReason);
    else unrecognized++;
  }
  const diagnostics = Array.from(known, code => `${code} · ${guidance[code]}`);
  if (unrecognized) diagnostics.push(`Unrecognized reason entries · ${unrecognized}. Consult the original runner version and its reason definitions.`);
  return { known, diagnostics };
}
