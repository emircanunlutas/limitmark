import assert from "node:assert/strict";
import { test } from "node:test";
import { comparisonFiles, later, now, type EditableFixture } from "./support/field-health-fixture";
import { compareFieldRuns } from "../src/lib/compare-field-runs";
import { coverageRows } from "../src/lib/field-evidence-coverage";
import { historicalPairLimits, historyLimits, ObservationHistory, observationTimeline, recurringFindings,
  type Observation } from "../src/lib/field-observation-history";
import { readFieldHealth } from "../src/lib/read-field-health";

async function observation(id: number, files: File[]): Promise<Observation> {
  const result = await readFieldHealth(files, later);
  assert.equal(result.state, "Reviewed");
  return { id, bytes: files.reduce((size, file) => size + file.size, 0), result };
}

function incident({ canary, manifest }: EditableFixture) {
  manifest.result = "INVALID";
  manifest.metrics.serverSide = "invalid";
  canary.l1FalseRejects = 1;
}

test("orders dated evidence by end, start and slot; failure and pending reads have no dates", async () => {
  const early = await observation(3, await comparisonFiles("baseline", incident));
  const late = await observation(1, await comparisonFiles("comparison", incident));
  const tie = await observation(2, await comparisonFiles("comparison", data => {
    data.manifest.startedAt = new Date(now + 1000).toISOString();
    data.manifest.runId = "20260102T120000Z-offline-cccccc";
  }));
  const rows = observationTimeline([late, tie, early, { ...early, id: 4, result: "reading" },
    { ...early, id: 5, result: { state: "Unavailable", detail: "Unavailable" } }]);
  assert.deepEqual(rows.map(row => row.id), [3, 2, 1]);
  assert.deepEqual(historicalPairLimits(rows[0], rows[1]), []);
  assert.match(historicalPairLimits(rows[1], rows[2]).join(" "), /after the baseline/);
  assert.deepEqual(recurringFindings(rows).find(f => f.title === "Protected request admission")?.observations, [3, 1]);
  assert.deepEqual(observationTimeline([early, { ...early, id: 2 }]).map(row => row.id), [2, 3]);
});

test("identity ambiguity anywhere in history withholds recurrence and pair conclusions until removed", async () => {
  const early = await observation(1, await comparisonFiles("baseline", incident));
  const late = await observation(2, await comparisonFiles("comparison", incident));
  const conflict = await observation(3, await comparisonFiles("baseline"));
  const anonymous = await observation(4, await comparisonFiles("baseline", data => {
    incident(data);
    data.manifest.runId = "unsupported";
  }));
  const rows = observationTimeline([early, late, conflict, anonymous, { ...early, id: 5 }]);
  const first = rows.find(row => row.id === 1)!, second = rows.find(row => row.id === 2)!;
  assert.deepEqual(first.identityLimits, ["Duplicate manifest in history.", "Conflicting manifests claim this run identity."]);
  assert.match(rows.find(row => row.id === 4)!.identityLimits.join(" "), /identity unavailable/);
  assert.deepEqual(second.identityLimits, []);
  const limits = historicalPairLimits(first, second);
  assert.match(limits.join(" "), /Conflicting/);
  assert.ok(compareFieldRuns(first.run, second.run, limits).findings.every(f => f.status === "Cannot assess"));
  assert.deepEqual(recurringFindings(rows), []);
  const distinct = observationTimeline([early, late]);
  assert.deepEqual(historicalPairLimits(distinct[0], distinct[1]), []);
  assert.deepEqual(recurringFindings(distinct).find(f => f.title === "Protected request admission")?.observations, [1, 2]);
});

test("coverage differences remain descriptive across incompatible and incomplete observations", async () => {
  const early = await observation(1, await comparisonFiles("baseline"));
  const files = await comparisonFiles("comparison", data => { data.manifest.target!.id = "different"; });
  const [first, second] = observationTimeline([early, await observation(2, files.slice(0, 2))]);
  assert.match(historicalPairLimits(first, second).join(" "), /Different recorded context · Target/);
  assert.match(historicalPairLimits(first, second).join(" "), /accounting · insufficient/);
  assert.deepEqual(second.run.components.map(c => c.state), Array(4).fill("Unavailable"));
  const changes = coverageRows.filter(([, value]) => value(first.run) !== value(second.run)).map(([label]) => label);
  for (const label of ["External observations", "Canary observations", "Cross-record accounting", "Telemetry consistency"])
    assert.ok(changes.includes(label));
});

test("bounds unfinished work across repeated removal and clearing, then releases capacity", async () => {
  const history = new ObservationHistory();
  const release = Promise.withResolvers<ArrayBuffer>();
  const manifest = new File(["x"], "manifest.json");
  let reads = 0;
  manifest.arrayBuffer = () => { reads++; return release.promise; };
  const selection = [new File(["bad"], "SHA256SUMS"), manifest];
  for (let i = 0; i < historyLimits.observations; i++) {
    const id = history.select(selection);
    assert.ok(id);
    if (i % 2) history.remove(id);
    else history.clear();
  }
  assert.equal(history.select(selection), undefined);
  assert.match(history.getSnapshot().notice, /reads are still in progress/);
  assert.equal(reads, historyLimits.observations);
  release.resolve(new ArrayBuffer(0));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(history.getSnapshot().entries, []);
  assert.ok(history.select(selection));
});

test("aggregate admission is atomic at the byte limit and rejected replacements preserve the entry", async () => {
  const history = new ObservationHistory();
  const files = await comparisonFiles("baseline");
  const bytes = files.reduce((sum, file) => sum + file.size, 0);
  const padded = [...files, new File([new Uint8Array(historyLimits.bytes - bytes)], "ignored")];
  const id = history.select(padded)!;
  const reading = history.getSnapshot().entries[0];
  assert.equal(reading.bytes, historyLimits.bytes);
  // The old read must remain reserved even when replaced or cleared.
  assert.equal(history.select(files, id), undefined);
  assert.strictEqual(history.getSnapshot().entries[0], reading);
  history.clear();
  assert.equal(history.select(files), undefined);
  assert.match(history.getSnapshot().notice, /4 MiB/);
  assert.equal(history.select(Array<File>(65).fill(files[0])), undefined);
  assert.match(history.getSnapshot().notice, /Too many files/);
});
