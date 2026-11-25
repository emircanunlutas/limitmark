import assert from "node:assert/strict";
import { test } from "node:test";
import { compareFieldRuns } from "../src/lib/compare-field-runs";
import { readFieldHealth } from "../src/lib/read-field-health";
import { comparisonFiles, later, now, type EditableFixture } from "./support/field-health-fixture";

async function review(files: File[]) {
  const result = await readFieldHealth(files, later);
  assert.equal(result.state, "Reviewed");
  return result.review;
}
function incident({ canary, manifest }: EditableFixture) {
  manifest.result = "INVALID";
  manifest.metrics.serverSide = "invalid";
  canary.l1FalseRejects = 1;
}

test("classifies historical changes from independent reviews, preserving stage and finding evidence", async () => {
  for (const [firstFault, secondFault, expected] of [
    [false, true, "Newly observed"], [true, true, "Persistent"], [true, false, "No longer observed"],
  ] as const) {
    const first = await review(await comparisonFiles("baseline", firstFault ? incident : undefined));
    const second = await review(await comparisonFiles("comparison", secondFault ? incident : undefined));
    assert.ok(first.stale && !second.stale);
    assert.notEqual(first.runKey, second.runKey);
    const { limits, components, findings } = compareFieldRuns(first, second);
    assert.deepEqual(limits, []);
    assert.deepEqual([components[0].before.state, components[0].after.state],
      [firstFault ? "Degraded" : "Healthy", secondFault ? "Degraded" : "Healthy"]);
    assert.equal(components[0].conclusion, firstFault === secondFault ? "Same observed condition" : "Observed condition changed");
    const admission = findings.find(f => f.id === "protected-admission")!;
    assert.equal(admission.status, expected);
    assert.equal(!!admission.baseline, firstFault);
    assert.equal(!!admission.comparison, secondFault);
    assert.doesNotMatch(JSON.stringify([first, second]), /private-fixture|offline-aaaaaa/);
  }
});

test("loss of coverage, conflicting records and unverified files cannot clear a prior finding", async () => {
  const baseline = await review(await comparisonFiles("baseline", incident));
  const files = await comparisonFiles("comparison");
  const corrupt = new File(["private-file-contents"], "canary.json");
  for (const selection of [files.slice(0, 2), files.slice(0, 3), [...files.slice(0, 3), corrupt],
    await comparisonFiles("comparison", data => { data.manifest.metrics.externalAccepted++; }),
    await comparisonFiles("comparison", data => { data.external.accounting.identities = data.external.accounting.identities.filter(row => row.id !== "e10.final_ticks_present"); }),
    await comparisonFiles("comparison", data => { data.canary.jcr = []; }),
    await comparisonFiles("comparison", data => { data.manifest.metrics.artifactsRefused = 1; }),
  ]) {
    const second = await review(selection);
    const result = compareFieldRuns(baseline, second);
    assert.equal(result.findings.find(f => f.id === "protected-admission")?.status, "Cannot assess");
    assert.ok(result.components.every(c => c.conclusion === "Cannot assess condition change"));
    assert.doesNotMatch(JSON.stringify(result), /private-file-contents/);
  }
  const partial = await review((await comparisonFiles("baseline")).slice(0, 3));
  const second = await review(await comparisonFiles("comparison", incident));
  assert.equal(compareFieldRuns(partial, second).findings.find(f => f.id === "protected-admission")?.status, "Cannot assess");
  assert.equal((await readFieldHealth([files[0], new File(["invalid"], "manifest.json")], later)).state, "Unknown");
});

test("duplicate, unordered, overlapping, refused and differently scoped observations withhold transitions", async () => {
  const first = await review(await comparisonFiles("baseline"));
  assert.match(compareFieldRuns(first, first).limits.join(" "), /same manifest/);
  for (const [edit, reason] of [
    [(d) => { d.manifest.runId = "20260101T115959Z-offline-aaaaaa"; }, /same run identifier/],
    [(d) => { d.manifest.runId = "untrusted"; }, /identifier/],
    [(d) => { d.manifest.startedAt = new Date(now - 10).toISOString(); }, /after the baseline/],
    [(d) => { d.manifest.workload!.phases = []; }, /Workload.*missing/],
    [(d) => { d.manifest.target!.id = "another-private-target"; }, /Different recorded context · Target/],
    [(d) => { d.manifest.ceilings!.workers = 2; }, /Different recorded context · Observation limits/],
    [(d) => { d.manifest.thresholds!.version++; }, /Different recorded context · Threshold profile/],
    [(d) => { d.canary.jcr = []; }, /phase coverage is unavailable/],
    [(d) => { d.canary.jcr = d.canary.jcr.filter(row => row.phase === "window"); }, /phase coverage differs/],
    [(d) => { d.manifest.workload!.phases = [{ name: "other", durationSeconds: 1, ratePerSecond: 1, concurrency: 1, timeoutMs: 1 }]; }, /Different recorded context · Workload/],
    [(d) => {
      d.manifest.result = "REFUSED"; d.manifest.metrics.serverSide = "aborted"; d.manifest.metrics.networkActivity = false;
      d.manifest.artifacts = d.manifest.artifacts.filter(a => a.name === "core.json");
    }, /refused/],
  ] satisfies [(data: EditableFixture) => void, RegExp][]) {
    const second = await review(await comparisonFiles("comparison", edit));
    const result = compareFieldRuns(first, second);
    assert.match(result.limits.join(" "), reason);
    assert.ok(result.components.every(c => c.conclusion === "Cannot assess condition change"));
    assert.ok(result.findings.every(f => f.status === "Cannot assess"));
  }
  const reversed = compareFieldRuns(await review(await comparisonFiles("comparison")), first);
  assert.match(reversed.limits.join(" "), /after the baseline/);
});

test("aborted observation and omitted terminal counters cannot establish absence", async () => {
  const first = await review(await comparisonFiles("baseline", d => {
    incident(d);
    d.external.counters.clientAborted = d.external.counters.terminal.client_aborted = 1;
    d.external.counters.terminal.proxied--;
  }));
  const aborted = await review(await comparisonFiles("comparison", d => {
    d.manifest.result = "ABORTED";
    d.manifest.metrics.serverSide = "aborted";
  }));
  assert.equal(compareFieldRuns(first, aborted).findings.find(f => f.id === "protected-admission")?.status, "Cannot assess");
  const unknown = await review(await comparisonFiles("comparison", d => {
    Reflect.deleteProperty(d.external.counters, "clientAborted");
    Reflect.deleteProperty(d.external.counters.terminal, "client_aborted");
  }));
  assert.equal(compareFieldRuns(first, unknown).findings.find(f => f.id === "client-aborts")?.status, "Cannot assess");
});

test("partial accounting preserves eligible component comparisons and common finding identity survives a title change", async () => {
  const first = await review(await comparisonFiles("baseline"));
  const partial = await review(await comparisonFiles("comparison", d => {
    d.external.accounting.identities = d.external.accounting.identities.filter(row => row.id !== "e5.boundary_admitted_equals_ledger");
  }));
  assert.deepEqual(compareFieldRuns(first, partial).components.map(c => c.conclusion), [
    "Same observed condition", "Same observed condition", "Cannot assess condition change", "Same observed condition",
  ]);
  assert.ok(partial.requiredChecksPresent! < first.requiredChecksPresent!);
  const prior = await review(await comparisonFiles("baseline", d => { incident(d); d.external.counters.boundary.aborted++; }));
  const next = await review(await comparisonFiles("comparison", d => {
    incident(d); d.external.counters.boundary.aborted++; d.external.counters.app.completed--; d.external.counters.app.aborted++;
  }));
  const f = compareFieldRuns(prior, next).findings.find(f => f.id === "interruptions")!;
  assert.notEqual(f.baseline?.title, f.comparison?.title);
  assert.equal(f.status, "Persistent");
});
