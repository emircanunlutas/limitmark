import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { canaryCounts, deriveExternalAccounting } from "../lab/defense/external-accounting";
import { buildSelftestBundle } from "../lab/defense/field-selftest";
import { writeFieldEvidence } from "../lab/defense/field-evidence";
import { EvidenceRun, EVIDENCE_ROOT } from "../lab/evidence/manifest";
import { REVIEW_AGE_MS } from "../src/lib/field-health";
import { fieldReviewFiles, readFieldHealth } from "../src/lib/read-field-health";

const now = Date.parse("2026-01-01T12:00:00.000Z");
const bundle = buildSelftestBundle();
const c = bundle.external;
// Supply final counters like those published by each process; the producer decides which comparisons exist.
bundle.accounting = deriveExternalAccounting({
  external: c, externalDecisions: [], canary: canaryCounts([], 0),
  planeFin: { advisory: { l2: { lanes: { decisions: c.l2.byKey } } } } as never,
  boundaryFin: { stats: { ...c.boundary, parserRejected: 0, protocolRefused: 0 } } as never,
  appFin: { stats: { counters: { ...c.app, stateMutations: c.app.mutated } } } as never,
  connections: null, l2: bundle.thresholds.l2, windowElapsedMs: 10_000, workers: 1, externalInFlightMax: 1,
  streams: { planeDropped: 0, boundaryDropped: 0, appDropped: 0, drained: true, finalTicks: bundle.telemetry.finalTicks, tickGaps: 0 },
});

function publishedFiles() {
  mkdirSync(EVIDENCE_ROOT, { recursive: true });
  const root = mkdtempSync(path.join(EVIDENCE_ROOT, "review-"));
  try {
    const run = new EvidenceRun("field-level", "offline", new Date(now - 1000), root);
    const write = writeFieldEvidence(run, bundle);
    assert.deepEqual(write.failed, []);
    run.finalize({
      endedAt: new Date(now), git: bundle.git, engine: "node-http-field-level", result: "SERVER-COMPLETE", resultReasons: [],
      environment: { os: "fixture", kernelRelease: "", arch: "", nodeVersion: "", dockerVersion: null, postgresVersion: null, cpuCount: 1, memoryMegabytes: 512 },
      workload: null, target: null, thresholds: bundle.parameters, ceilings: null,
      metrics: { serverSide: "complete", externalAccepted: c.accepted, anomalyTotal: 0, artifactsRefused: 0 },
    });
    return fieldReviewFiles.map(name => new File([readFileSync(path.join(run.directory, name), "utf8")], name));
  } finally { rmSync(root, { recursive: true, force: true }); }
}
const originals = publishedFiles();

async function review(files = originals, time = now) {
  const result = await readFieldHealth(files, time);
  assert.equal(result.state, "Reviewed");
  return result.review;
}

type EditableFixture = {
  manifest: { result: string; resultReasons: string[]; metrics: { serverSide: string; externalAccepted: number; networkActivity?: boolean }; artifacts: { name: string; bytes: number; sha256: string }[] };
  external: { counters: typeof c; accounting: NonNullable<typeof bundle.accounting> };
  canary: typeof bundle.canary;
};

// Re-seal modified fixtures so semantic contradictions reach the interpreter independently of digest errors.
async function changed(edit: (data: EditableFixture) => void) {
  const [, manifestFile, externalFile, canaryFile] = originals;
  const manifest: EditableFixture["manifest"] = JSON.parse(await manifestFile.text());
  const external = JSON.parse(await externalFile.text());
  const canary = JSON.parse(await canaryFile.text());
  edit({ manifest, external, canary });
  const digest = (s: string) => createHash("sha256").update(s).digest("hex");
  const evidence = [new File([JSON.stringify(external)], "external.json"), new File([JSON.stringify(canary)], "canary.json")]
    .filter(file => manifest.artifacts.some(row => row.name === file.name));
  for (const file of evidence) {
    const entry = manifest.artifacts.find(row => row.name === file.name)!;
    entry.bytes = file.size;
    entry.sha256 = digest(await file.text());
  }
  const text = JSON.stringify(manifest);
  const sums = [...manifest.artifacts.map(row => `${row.sha256}  ${row.name}`), `${digest(text)}  manifest.json`].join("\n");
  return [new File([sums], "SHA256SUMS"), new File([text], "manifest.json"), ...evidence];
}

test("published evidence combines four exercised components, preserving expected L2 shedding", async () => {
  const view = await review();
  assert.ok(c.status503.expectedShed > 0);
  assert.deepEqual(view.components.map(row => [row.name, row.state, row.observations]), [
    ["L1 request screening", "Healthy", c.l1.entered], ["L2 admission", "Healthy", c.l2.decided],
    ["Origin boundary", "Healthy", c.boundary.admitted], ["Protected app", "Healthy", c.app.admitted],
  ]);
});

test("recency uses end time and a fixed review clock, independent of historical faults", async () => {
  assert.equal((await review(originals, now + REVIEW_AGE_MS)).stale, false);
  const files = await changed(({ manifest, canary }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid"; canary.l1FalseRejects++;
  });
  const view = await review(files, now + REVIEW_AGE_MS + 1);
  assert.equal(view.stale, true);
  assert.deepEqual(view.components.map(c => c.state), ["Degraded", "Unknown", "Unknown", "Unknown"]);
  assert.match(view.components[0].detail, /canary/);
  assert.equal((await readFieldHealth(files, now - 1)).state, "Unknown");
});

test("integrity and access failures use bounded messages and never disclose raw input", async () => {
  const [sums, manifest, external, canary] = originals;
  const privateText = "private-diagnostic-DO-NOT-RENDER";
  for (const selection of [[sums, manifest, new File([privateText], external.name), canary],
    [sums, manifest, external, { ...canary, name: canary.name, size: canary.size, arrayBuffer: async () => { throw Error(privateText); } }]]) {
    const result = await readFieldHealth(selection, now);
    assert.equal(result.state, "Reviewed");
    assert.ok(result.review.components.every(row => row.state === (selection[2] === external ? "Unavailable" : "Unknown")));
    assert.ok(!JSON.stringify(result).includes(privateText));
  }
  assert.equal((await readFieldHealth([manifest, external, canary], now)).state, "Unavailable");
  assert.equal((await readFieldHealth([...originals, manifest], now)).state, "Unknown");
  assert.equal((await readFieldHealth([sums, new File([privateText], manifest.name)], now)).state, "Unknown");
  const ignored = { name: "unrelated.json", size: 2, arrayBuffer: async () => { assert.fail("unrelated file opened"); } };
  assert.equal((await readFieldHealth([...originals, ignored], now)).state, "Reviewed");
  assert.ok((await review([sums, manifest, canary])).components.every(row => row.state === "Unavailable"));
});

test("contradictions, missing exercise and absent final comparisons cannot yield healthy assessments", async () => {
  for (const mutate of [
    ({ manifest }: EditableFixture) => { manifest.metrics.externalAccepted++; },
    ({ canary }: EditableFixture) => { canary.l2NonAdmits++; },
    ({ canary }: EditableFixture) => { canary.jcr = []; },
    ({ external }: EditableFixture) => { external.accounting.identities[0].left++; },
    ({ external }: EditableFixture) => { external.accounting.identities.push(external.accounting.identities[0]); },
    ({ external }: EditableFixture) => {
      const tick = external.accounting.identities.find(row => row.id === "e10.final_ticks_present")!;
      tick.left = tick.right = 0;
    },
  ]) assert.ok((await review(await changed(mutate))).components.every(row => row.state === "Unknown"));
  const missing = await review(await changed(({ external }) => {
    external.accounting.identities = external.accounting.identities.filter(row => row.id !== "e5.boundary_admitted_equals_ledger");
  }));
  assert.deepEqual(missing.components.map(c => c.state), ["Healthy", "Healthy", "Unknown", "Healthy"]);
  assert.match(missing.components[2].detail, /Missing comparison/);
});

test("transport loss stops positive interpretation even with complete component counters", async () => {
  const view = await review(await changed(({ manifest, external }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid";
    manifest.resultReasons = ["field.tick_gap.private-host-detail"];
    const gap = external.accounting.identities.find(row => row.id === "e10.no_tick_gaps")!;
    gap.left = 2; gap.ok = false; external.accounting.identitiesOk = false;
  }));
  assert.ok(view.components.every(row => row.state === "Unknown" && row.detail.includes("gaps")));
  assert.match(view.diagnostics.join(" "), /missing heartbeats/);
  assert.ok(!JSON.stringify(view).includes("private-host-detail"));
});

test("preflight refusal, an unexercised component, and a component failure remain distinct", async () => {
  const refused = await review(await changed(({ manifest }) => {
    manifest.result = "REFUSED"; manifest.metrics.serverSide = "aborted";
    manifest.metrics.networkActivity = false;
    manifest.artifacts = manifest.artifacts.filter(row => row.name === "core.json");
  }));
  assert.ok(refused.components.every(c => c.state === "Unavailable"));
  const idle = await review(await changed(({ external }) => {
    // Aggregate process comparisons can contain canaries even when the external population is empty.
    external.counters.app.admitted = external.counters.app.executed = external.counters.app.completed = 0;
    const admissions = external.accounting.identities.find(row => row.id === "e5.external_app_admitted_equals_forwarded")!;
    admissions.left = admissions.right = 0;
    external.counters.boundary.forwardResponded = 0;
  }));
  assert.equal(idle.components[3].state, "Unknown");
  assert.match(idle.components[3].detail, /No external exercise/);
  const fault = await review(await changed(({ manifest, external }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid"; external.counters.boundary.forwardFailed = 1;
  }));
  assert.equal(fault.components[2].state, "Degraded");
});

test("review page requires the established admin boundary, with no server upload or public navigation", () => {
  const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), "utf8");
  const page = read("../src/app/admin/field-health/page.tsx");
  assert.match(page, /await requireAdmin\(\);\s*return /);
  assert.match(page, /force-dynamic/);
  assert.match(read("../src/app/admin/page.tsx"), /href="\/admin\/field-health" prefetch=\{false\}/);
  assert.doesNotMatch(read("../src/components/header.tsx"), /field-health/);
});
