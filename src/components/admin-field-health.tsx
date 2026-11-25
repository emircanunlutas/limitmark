"use client";

import { useId, useState, useSyncExternalStore } from "react";
import { fieldReviewFiles } from "../lib/read-field-health";
import type { FieldHealthReview } from "../lib/field-health";
import { ObservationHistory, observationTimeline, reviewedRun, type Observation } from "../lib/field-observation-history";
import { FieldRunComparison } from "./field-run-comparison";
import { FieldObservationHistory } from "./field-observation-history";

export function FieldHealthResults({ review }: { review: FieldHealthReview }) {
  const id = useId();
  return <>
    <section className="admin-panel" aria-labelledby={id + "-run"}>
      <h2 id={id + "-run"}>Recorded run</h2>
      <dl className="admin-definition-list">
        <div><dt>Run ended (UTC)</dt><dd><time dateTime={review.endedAt}>{review.endedAt}</time></dd></div>
        <div><dt>Server-side result</dt><dd>{review.result}</dd></div>
        <div><dt>Age at review</dt><dd>{review.stale ? "Stale · older than 24 hours" : "Within 24 hours"}<br />
          <small>Reviewed <time dateTime={review.reviewedAt}>{review.reviewedAt}</time></small></dd></div>
      </dl>
      <p className="admin-section-intro">These observations describe the recorded run. Current service health is unknown.
        Matching checksums establish file consistency. Evidence provenance requires a trusted source.</p>
      {review.diagnostics.length > 0 && <>
        <h3>Recorded stop reasons</h3>
        <ul>{review.diagnostics.map(message => <li key={message}>{message}</li>)}</ul>
      </>}
    </section>
    <section className="admin-panel" aria-labelledby={id + "-incident"}>
      <h2 id={id + "-incident"}>Incident diagnostics</h2>
      {review.findings.length ? <div className="admin-long-fields">{review.findings.map(finding => <article key={finding.title}>
        <h3>{finding.title}</h3>
        <dl className="admin-incident-evidence">
          <dt>Observed facts</dt><dd><ul>{finding.facts.map(fact => <li key={fact}>{fact}</li>)}</ul></dd>
          <dt>Supported conclusion</dt><dd>{finding.conclusion}</dd>
          <dt>Unresolved</dt><dd>{finding.uncertainty}</dd>
          <dt>Administrator follow-up</dt><dd>{finding.guidance}</dd>
        </dl>
      </article>)}</div> : <p>No incident finding was identified by the reviewed checks.</p>}
    </section>
    <section className="admin-panel" aria-labelledby={id + "-components"}>
      <h2 id={id + "-components"}>Component observations</h2>
      <ul className="admin-delivery-list">{review.components.map(component => <li key={component.name}>
        <div><h3>{component.name}</h3><span className="admin-status">{component.state}</span></div>
        {component.observations !== undefined && <p>External requests observed at this stage · {component.observations}</p>}
        <p>{component.detail}</p>
      </li>)}</ul>
    </section>
  </>;
}

function RunSelection({ side, entry, entries, history, assign }: {
  side: "Baseline" | "Comparison"; entry?: Observation; entries: Observation[];
  history: ObservationHistory; assign: (id?: number) => void;
}) {
  const result = entry?.result;
  const run = reviewedRun(entry);
  return <section className="admin-panel field-selection" aria-label={side + " selection"}>
    <h2>{side} run</h2>
    <div className="admin-filters"><label>{side} observation from history
      <select value={entry?.id ?? ""} onChange={event => assign(Number(event.target.value) || undefined)}>
        <option value="">No selection</option>
        {entries.map(item => <option key={item.id} value={item.id}>Observation {item.id} · {reviewedRun(item)?.endedAt ??
          (item.result === "reading" ? "Reading" : item.result.state)}</option>)}
      </select></label>
      <label><span>{side === "Baseline" ? "Field-run evidence files (baseline)" : "Comparison evidence files"}</span>
        <input type="file" multiple aria-describedby="evidence-instructions" onChange={event => {
          const files = event.currentTarget.files;
          if (files?.length) {
            const id = history.select(files, entry?.id);
            if (id !== undefined) assign(id);
          } else if (entry) history.remove(entry.id);
          event.currentTarget.value = "";
        }} /></label>
      <button type="button" className="button" disabled={!entry} onClick={() => entry && history.remove(entry.id)}>
        Clear {side.toLowerCase()}</button></div>
    <div role="status">{!result ? "Unknown · select evidence to review a run." : result === "reading" ? "Reading field evidence…"
      : result.state === "Reviewed" ? "Field evidence reviewed." : `${result.state} · ${result.detail}`}</div>
    {run && <dl className="admin-definition-list">
      <div><dt>Run reference</dt><dd>{run.runKey?.slice(0, 16) ?? "Unavailable"}<br />
        <small>Manifest SHA-256 · {run.manifestDigest.slice(0, 16)}…</small></dd></div>
      <div><dt>Recorded interval (UTC)</dt><dd><time dateTime={run.startedAt}>{run.startedAt}</time><br />
        <time dateTime={run.endedAt}>{run.endedAt}</time></dd></div>
      <div><dt>Historical result</dt><dd>{run.result}<br />{run.stale ? "Stale · older than 24 hours" : "Within 24 hours"} at review<br />
        <small>Reviewed <time dateTime={run.reviewedAt}>{run.reviewedAt}</time></small></dd></div>
    </dl>}
  </section>;
}

export function AdminFieldHealth() {
  const [history] = useState(() => new ObservationHistory());
  const snapshot = useSyncExternalStore(history.subscribe, history.getSnapshot, history.getSnapshot);
  const { entries } = snapshot;
  const [baseline, setBaseline] = useState<number>();
  const [comparison, setComparison] = useState<number>();
  const baseEntry = entries.find(entry => entry.id === baseline);
  const otherEntry = entries.find(entry => entry.id === comparison);
  const first = reviewedRun(baseEntry), second = reviewedRun(otherEntry);
  const single = first ?? second;
  const timeline = observationTimeline(entries);
  const identityLimits = timeline.filter(entry => entry.id === baseline || entry.id === comparison).flatMap(entry => entry.identityLimits);
  return <>
    <p id="evidence-instructions">Select {fieldReviewFiles.join(", ")} together from one trusted run per selection.
      Files stay in this browser. Matching checksums establish file consistency.
      Evidence provenance requires a trusted source.</p>
    <FieldObservationHistory history={history} snapshot={snapshot} timeline={timeline}
      reviewAlone={id => { setBaseline(id); setComparison(undefined); }}
      reviewPair={(before, after) => { setBaseline(before); setComparison(after); }} />
    <h2 id="field-detail" tabIndex={-1}>Detailed run review</h2>
    <p>Choose one observation for diagnostics or choose a baseline and a later observation for comparison.
      Selecting files here adds or replaces that observation in history. Clearing a run removes it from history.</p>
    <RunSelection side="Baseline" entry={baseEntry} entries={entries} history={history} assign={setBaseline} />
    <RunSelection side="Comparison" entry={otherEntry} entries={entries} history={history} assign={setComparison} />
    {first && second ? <>
      <FieldRunComparison baseline={first} comparison={second} identityLimits={identityLimits} />
      <details><summary>Baseline run diagnostics</summary><FieldHealthResults review={first} /></details>
      <details><summary>Comparison run diagnostics</summary><FieldHealthResults review={second} /></details>
    </> : single && <FieldHealthResults review={single} />}
  </>;
}
