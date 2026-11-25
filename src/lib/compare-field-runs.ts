import { contextLabels, type ContextDimension } from "./field-comparison-context";
import { requiredFieldChecks, type ComponentHealth, type IncidentFinding } from "./field-health";
import type { RecordedRun } from "./read-field-health";

export function comparisonLimits(baseline: RecordedRun, comparison: RecordedRun, identityLimits: readonly string[] = []) {
  const limits: string[] = [];
  if (baseline.manifestDigest === comparison.manifestDigest) limits.push("Both selections contain the same manifest.");
  else if (!baseline.runKey || !comparison.runKey) limits.push("A recorded run identifier is missing or unsupported.");
  else if (baseline.runKey === comparison.runKey) limits.push("Different manifests claim the same run identifier.");
  if (Date.parse(comparison.startedAt) < Date.parse(baseline.endedAt) || Date.parse(comparison.endedAt) <= Date.parse(baseline.endedAt))
    limits.push("Choose a comparison recorded after the baseline interval.");
  for (const key of Object.keys(contextLabels) as ContextDimension[]) {
    const a = baseline.dimensions[key], b = comparison.dimensions[key];
    if (!a || !b) limits.push(`${contextLabels[key]} information is missing or unsupported.`);
    else if (a !== b) limits.push(`Different recorded context · ${contextLabels[key]}.`);
  }
  for (const [label, run] of [["Baseline", baseline], ["Comparison", comparison]] as const) {
    if (run.accounting !== "Reviewed") limits.push(`${label} accounting · ${run.accounting.toLowerCase()}.`);
  }
  if (!baseline.canaryProtocol || !comparison.canaryProtocol) limits.push("Canary journey or phase coverage is unavailable.");
  else if (baseline.canaryProtocol !== comparison.canaryProtocol) limits.push("The recorded canary journey or exercised phase coverage differs.");
  return [...new Set([...limits, ...identityLimits])];
}

function observed(component: ComponentHealth, run: RecordedRun) {
  return run.artifactsRefused === 0 && (run.protectedAttempts ?? 0) > 0 &&
    (component.observations ?? 0) > 0 && (component.state === "Degraded" || component.state === "Healthy");
}

// A single-run diagnostic can be suppressed by an earlier evidence gate.
// Require exercise and complete diagnostic coverage before interpreting absence.
function canAssessAbsence(run: RecordedRun, id: string) {
  if (run.result === "ABORTED" || run.telemetry !== "Checks agreed" || run.requiredChecksPresent !== requiredFieldChecks.length ||
      !run.protectedAttempts || run.artifactsRefused !== 0 || run.findings.some(f => f.id === "canary-evidence" || f.id.startsWith("accounting/")) ||
      !run.components.every(c => (c.observations ?? 0) > 0)) return false;
  if (id === "client-aborts") return run.clientAbortsReported;
  if (id.startsWith("exercise/")) return run.result === "SERVER-COMPLETE";
  return true;
}

type FindingChange = {
  id: string; baseline?: IncidentFinding; comparison?: IncidentFinding;
  status: "Newly observed" | "Persistent" | "No longer observed" | "Cannot assess";
};

export function compareFieldRuns(baseline: RecordedRun, comparison: RecordedRun, identityLimits: readonly string[] = []) {
  const limits = comparisonLimits(baseline, comparison, identityLimits);
  const components = baseline.components.map(before => {
    const after = comparison.components.find(c => c.name === before.name)!;
    const comparable = !limits.length && observed(before, baseline) && observed(after, comparison);
    return { before, after, conclusion: !comparable ? "Cannot assess condition change" :
      before.state === after.state ? "Same observed condition" : "Observed condition changed" };
  });
  const before = new Map(baseline.findings.map(f => [f.id, f]));
  const after = new Map(comparison.findings.map(f => [f.id, f]));
  const findings: FindingChange[] = Array.from(new Set([...before.keys(), ...after.keys()]), id => {
    const first = before.get(id), second = after.get(id);
    let status: FindingChange["status"] = "Cannot assess";
    if (!limits.length) {
      if (first && second) status = "Persistent";
      else if (first && canAssessAbsence(comparison, id)) status = "No longer observed";
      else if (second && canAssessAbsence(baseline, id)) status = "Newly observed";
    }
    return { id, baseline: first, comparison: second, status };
  });
  return { limits, components, findings };
}
