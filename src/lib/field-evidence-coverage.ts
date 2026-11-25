import { requiredFieldChecks } from "./field-health";
import type { RecordedRun } from "./read-field-health";

const fileState = { present: "Checksum matched · JSON readable", unknown: "Unverified", unavailable: "Unavailable" };
export const coverageRows: [string, (r: RecordedRun) => string | number][] = [
  ["External observations", r => fileState[r.files["external.json"]]],
  ["Canary observations", r => fileState[r.files["canary.json"]]],
  ["Cross-record accounting", r => r.accounting],
  ["Stages with accounting discrepancies", r => r.accounting === "Reviewed" ? r.findings.filter(f => f.id.startsWith("accounting/")).length : "Unknown"],
  ["Required accounting and telemetry checks present", r => r.requiredChecksPresent === null ? "Unknown" : `${r.requiredChecksPresent} of ${requiredFieldChecks.length}`],
  ["Telemetry consistency", r => r.telemetry],
  ["Protected window attempts", r => r.protectedAttempts ?? "Unknown"],
  ["Client abort count available", r => r.clientAbortsReported ? "Reported" : "Unavailable"],
  ["Artifacts refused by writer", r => r.artifactsRefused ?? "Unknown"],
];
