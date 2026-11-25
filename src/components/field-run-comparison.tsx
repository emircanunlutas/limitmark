import type { ReactNode } from "react";
import { compareFieldRuns } from "../lib/compare-field-runs";
import { requiredFieldChecks, type ComponentHealth } from "../lib/field-health";
import type { RecordedRun } from "../lib/read-field-health";

function ComparisonTable({ name, headings, rows }: { name: string; headings: string[]; rows: [string, ...ReactNode[]][] }) {
  return <div className="admin-table-wrap" role="region" aria-label={name} tabIndex={0}>
    <table className="admin-table field-comparison-table" aria-label={name}>
      <thead><tr>{headings.map(h => <th key={h} scope="col">{h}</th>)}</tr></thead>
      <tbody>{rows.map(([label, ...cells]) => <tr key={label}>
        <th scope="row">{label}</th>{cells.map((cell, i) => <td key={headings[i + 1]}>{cell}</td>)}
      </tr>)}</tbody>
    </table>
  </div>;
}

const fileState = { present: "Checksum matched · JSON readable", unknown: "Unverified", unavailable: "Unavailable" };
const coverageRows: [string, (r: RecordedRun) => string | number][] = [
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

function condition(stage: ComponentHealth) {
  return <>{stage.state}<br /><small>{stage.observations === undefined ? "Exercise unknown" : `${stage.observations} external observations`}</small></>;
}

function contextMatch(first: string | null, second: string | null) {
  return !first || !second ? "Unconfirmed" : first === second ? "Matching" : "Different";
}

export function FieldRunComparison({ baseline, comparison }: { baseline: RecordedRun; comparison: RecordedRun }) {
  const result = compareFieldRuns(baseline, comparison);
  return <section className="admin-panel field-comparison" aria-labelledby="comparison-heading">
    <h2 id="comparison-heading">Defensive run comparison</h2>
    {result.limits.length ? <><h3>Runs cannot be meaningfully compared</h3>
      <ul>{result.limits.map(limit => <li key={limit}>{limit}</li>)}</ul></> :
      <p>The recorded target, workload, threshold profile and observation limits match. Counts describe the requests observed in each interval.</p>}
    <p>Recorded software revision · {contextMatch(baseline.revision, comparison.revision)}.
      Recorded environment · {contextMatch(baseline.environment, comparison.environment)}.
      Differences or unknowns limit attribution across runs.</p>
    <h3>Evidence coverage and consistency</h3>
    <ComparisonTable name="Evidence coverage and consistency" headings={["Evidence", "Baseline", "Comparison", "Recorded difference"]}
      rows={coverageRows.map(([name, value]) => {
        const before = value(baseline), after = value(comparison);
        return [name, before, after, before === after ? "Same entry" : "Changed"];
      })} />
    <h3>Component conditions</h3>
    <ComparisonTable name="Component conditions" headings={["Component", "Baseline observation", "Comparison observation", "Supported conclusion"]}
      rows={result.components.map(r => [r.before.name, condition(r.before), condition(r.after), r.conclusion])} />
    {result.components.some(r => r.conclusion === "Cannot assess condition change") &&
      <p>A condition comparison requires compatible runs, exercise at that stage, protected window observations,
        and a supported condition in each run. The individual diagnostics below give the evidence for each stage.</p>}
    <h3>Diagnostic finding changes</h3>
    <p>Persistent means the same finding category appeared in both records. The affected stages or requests may differ.
      A finding’s absence cannot establish resolution. Cause, current production health and qualification remain undetermined.</p>
    {result.findings.length ? <ul className="admin-delivery-list">{result.findings.map(f => <li key={f.id}>
      <div><h4>{(f.comparison ?? f.baseline)?.title}</h4><span className="admin-status">{f.status}</span></div>
      <dl className="admin-incident-evidence">{(["baseline", "comparison"] as const).map(side => <div key={side}>
        <dt>{side === "baseline" ? "Baseline facts" : "Comparison facts"}</dt><dd>
          {f[side] ? <ul>{f[side].facts.map(fact => <li key={fact}>{fact}</li>)}</ul> : "No finding recorded"}
        </dd></div>)}</dl>
      {f.status === "Cannot assess" && <p>Evidence or observation context limits classification of this finding.</p>}
    </li>)}</ul> : <p>Neither review identified a diagnostic finding.</p>}
  </section>;
}
