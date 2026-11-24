"use client";

import { useRef, useState } from "react";
import { readFieldHealth, fieldReviewFiles, type ReviewResult } from "../lib/read-field-health";
import type { FieldHealthReview } from "../lib/field-health";

export function FieldHealthResults({ review }: { review: FieldHealthReview }) {
  return <>
    <section className="admin-panel" aria-labelledby="run-heading">
      <h2 id="run-heading">Recorded run</h2>
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
    <section className="admin-panel" aria-labelledby="incident-heading">
      <h2 id="incident-heading">Incident diagnostics</h2>
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
    <section className="admin-panel" aria-labelledby="component-heading">
      <h2 id="component-heading">Component observations</h2>
      <ul className="admin-delivery-list">{review.components.map(component => <li key={component.name}>
        <div><h3>{component.name}</h3><span className="admin-status">{component.state}</span></div>
        {component.observations !== undefined && <p>External requests observed at this stage · {component.observations}</p>}
        <p>{component.detail}</p>
      </li>)}</ul>
    </section>
  </>;
}

export function AdminFieldHealth() {
  const [result, setResult] = useState<ReviewResult | "reading" | null>(null);
  const selection = useRef(0);
  async function review(files: File[]) {
    const current = ++selection.current;
    setResult(files.length ? "reading" : null);
    if (!files.length) return;
    const next = await readFieldHealth(files, Date.now());
    if (selection.current === current) setResult(next);
  }
  return <>
    <div className="admin-filters"><label><span>Field-run evidence files</span>
      <input type="file" multiple aria-describedby="evidence-instructions"
        onChange={event => void review(Array.from(event.currentTarget.files ?? []))} />
      <span id="evidence-instructions">Select {fieldReviewFiles.join(", ")} together from one trusted run. Files stay in this browser.</span>
    </label></div>
    <div role="status">{!result ? "Unknown · select evidence to review a run." : result === "reading" ? "Reading field evidence…"
      : result.state === "Reviewed" ? "Field evidence reviewed." : `${result.state} · ${result.detail}`}</div>
    {result && result !== "reading" && result.state === "Reviewed" && <FieldHealthResults review={result.review} />}
  </>;
}
