"use client";

import { useId, useRef, useState } from "react";
import { readFieldHealth, fieldReviewFiles, type ReviewResult } from "../lib/read-field-health";
import type { FieldHealthReview } from "../lib/field-health";
import { FieldRunComparison } from "./field-run-comparison";

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

type Selection = ReviewResult | "reading" | null;

function reviewedRun(result: Selection) {
  return result && result !== "reading" && result.state === "Reviewed" ? result.review : null;
}

function RunSelection({ side, result, setResult }: {
  side: "Baseline" | "Comparison"; result: Selection; setResult: (next: Selection) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const selection = useRef(0);
  async function review(files: File[]) {
    const current = ++selection.current;
    setResult(files.length ? "reading" : null);
    if (!files.length) return;
    const next = await readFieldHealth(files, Date.now());
    if (selection.current === current) setResult(next);
  }
  const run = reviewedRun(result);
  return <section className="admin-panel field-selection" aria-label={side + " selection"}>
    <h2>{side} run</h2>
    <div className="admin-filters"><label><span>{side === "Baseline" ? "Field-run evidence files (baseline)" : "Comparison evidence files"}</span>
      <input ref={input} type="file" multiple aria-describedby="evidence-instructions"
        onChange={event => void review(Array.from(event.currentTarget.files ?? []))} />
    </label><button type="button" className="button" disabled={!result} onClick={() => {
      if (input.current) input.current.value = "";
      void review([]);
    }}>Clear {side.toLowerCase()}</button></div>
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
  const [baseline, setBaseline] = useState<Selection>(null);
  const [comparison, setComparison] = useState<Selection>(null);
  const first = reviewedRun(baseline), second = reviewedRun(comparison);
  const single = first ?? second;
  return <>
    <p id="evidence-instructions">Select {fieldReviewFiles.join(", ")} together from one trusted run per selection.
      Add a later run to compare observations. Files stay in this browser. Matching checksums establish file consistency.
      Evidence provenance requires a trusted source.</p>
    <RunSelection side="Baseline" result={baseline} setResult={setBaseline} />
    <RunSelection side="Comparison" result={comparison} setResult={setComparison} />
    {first && second ? <>
      <FieldRunComparison baseline={first} comparison={second} />
      <details><summary>Baseline run diagnostics</summary><FieldHealthResults review={first} /></details>
      <details><summary>Comparison run diagnostics</summary><FieldHealthResults review={second} /></details>
    </> : single && <FieldHealthResults review={single} />}
  </>;
}
