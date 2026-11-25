import { coverageRows } from "../lib/field-evidence-coverage";
import { historicalPairLimits, historyLimits, observationTimeline, recurringFindings, reviewedRun,
  type ObservationHistory } from "../lib/field-observation-history";

type Props = {
  history: ObservationHistory;
  snapshot: ReturnType<ObservationHistory["getSnapshot"]>;
  timeline: ReturnType<typeof observationTimeline>;
  reviewAlone: (id: number) => void;
  reviewPair: (first: number, second: number) => void;
};

function ManageObservation({ history, id }: { history: ObservationHistory; id: number }) {
  return <div className="admin-filters">
    <label>Replace observation {id}<input type="file" multiple aria-describedby="evidence-instructions" onChange={event => {
      if (event.currentTarget.files) history.select(event.currentTarget.files, id);
      event.currentTarget.value = "";
    }} /></label>
    <button type="button" className="button" onClick={() => history.remove(id)}>Remove observation {id}</button>
  </div>;
}

export function FieldObservationHistory({ history, snapshot, timeline, reviewAlone, reviewPair }: Props) {
  const { entries, notice, pendingReads, reservedBytes } = snapshot;
  const categories = recurringFindings(timeline);
  const undated = entries.filter(entry => !reviewedRun(entry));
  return <section className="admin-panel field-selection field-history" aria-labelledby="history-heading">
    <h2 id="history-heading">Defensive observation history</h2>
    <p>Each entry describes one recorded interval. Gaps between observations have unknown conditions.
      These records cannot establish continuous availability, incident duration, remediation success, causation or current production health.</p>
    <div className="admin-filters"><label>Add observation files<input type="file" multiple aria-describedby="evidence-instructions history-budget"
      onChange={event => {
        if (event.currentTarget.files) history.select(event.currentTarget.files);
        event.currentTarget.value = "";
      }} /></label>
      <button type="button" className="button" disabled={!entries.length} onClick={() => history.clear()}>Clear history</button>
    </div>
    <p id="history-budget">{entries.length} of {historyLimits.observations} observations · {Math.ceil(reservedBytes / 1024)} KiB of 4 MiB reserved · {pendingReads} reads in progress. Select up to {historyLimits.filesPerObservation} files per run.</p>
    <div role="status">{notice}</div>
    {undated.length > 0 && <div><h3>Selections awaiting verified dates</h3><ul>{undated.map(entry => <li key={entry.id}>
      <strong>Observation {entry.id}</strong>
      <p role="status">{entry.result === "reading" ? "Reading field evidence…" : entry.result.state !== "Reviewed" && `${entry.result.state} · ${entry.result.detail}`}</p>
      <ManageObservation history={history} id={entry.id} />
    </li>)}</ul></div>}
    <h3>Recorded runs in chronological order</h3>
    {timeline.length ? <ol className="field-history-records">{timeline.map((record, index) => {
      const { run, id } = record;
      const previous = timeline[index - 1];
      const limits = previous ? historicalPairLimits(previous, record) : [];
      const changes = previous ? coverageRows.filter(([, value]) => value(previous.run) !== value(run)) : [];
      return <li key={id}><article aria-labelledby={"observation-" + id}>
        <h4 id={"observation-" + id}>Observation {id} · {run.result}</h4>
        <p><time dateTime={run.startedAt}>{run.startedAt}</time> to <time dateTime={run.endedAt}>{run.endedAt}</time> (UTC)</p>
        {record.identityLimits.length > 0 && <p><strong>{record.identityLimits.join(" ")}</strong> Excluded from recurrence counts.</p>}
        <ul className="field-history-conditions">{run.components.map(stage => <li key={stage.name}>{stage.name} · {stage.state}</li>)}</ul>
        <p>Accounting · {run.accounting}. Telemetry · {run.telemetry}.</p>
        {previous && <><p><strong>Compared with observation {previous.id}</strong> · {limits.length ?
          "Comparison limited" : "Comparable recorded context"}</p>
          {limits.length > 0 && <ul>{limits.map(limit => <li key={limit}>{limit}</li>)}</ul>}</>}
        <details><summary>{previous ? `Evidence coverage · ${changes.length} changed entries` : "Evidence coverage"}</summary>
          <dl className="admin-incident-evidence">{coverageRows.map(([label, value]) => <div key={label}>
            <dt>{label}</dt><dd>{previous && value(previous.run) !== value(run) &&
              <>Observation {previous.id} · {value(previous.run)} → </>}{value(run)}</dd>
          </div>)}</dl>
        </details>
        <div className="field-history-actions">
          <a href="#field-detail" className="text-link" onClick={() => reviewAlone(id)}>Review observation {id} alone</a>
          {previous && <a href="#field-detail" className="text-link" onClick={() => reviewPair(previous.id, id)}>
            Review pair {previous.id} and {id}</a>}
        </div>
        <details><summary>Manage observation {id}</summary><ManageObservation history={history} id={id} /></details>
      </article></li>;
    })}</ol> : <p>No verified run dates to display.</p>}
    <h3>Recurring diagnostic categories</h3>
    <p>A category can appear in distinct records with different contexts, stages or requests.
      Repetition does not establish a continuous incident. Counts require distinct, unambiguous run identities.</p>
    {categories.length ? <ul>{categories.map(category => <li key={category.title}>
      <strong>{category.title}</strong> · Observations {category.observations.join(", ")}
    </li>)}</ul> : <p>No category recurs across the eligible selections.</p>}
  </section>;
}
