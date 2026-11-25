import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { canaryCounts, deriveExternalAccounting } from "../../lab/defense/external-accounting";
import { buildSelftestBundle } from "../../lab/defense/field-selftest";
import { writeFieldEvidence } from "../../lab/defense/field-evidence";
import { EvidenceRun, EVIDENCE_ROOT, type EvidenceManifest } from "../../lab/evidence/manifest";
import { fieldReviewFiles } from "../../src/lib/read-field-health";

export const now = Date.parse("2026-01-01T12:00:00.000Z");
const bundle = buildSelftestBundle();
export const c = bundle.external;
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
export const originals = publishedFiles();

export type EditableFixture = {
  manifest: Pick<EvidenceManifest, "runId" | "startedAt" | "endedAt" | "target" | "workload" | "thresholds" | "ceilings" | "artifacts" | "git" | "environment"> &
    { result: string; resultReasons: string[]; metrics: { serverSide: string; externalAccepted: number; networkActivity?: boolean; artifactsRefused: number } };
  external: { counters: typeof c; accounting: NonNullable<typeof bundle.accounting> };
  canary: typeof bundle.canary;
};

// Re-seal modified fixtures so semantic contradictions reach the interpreter independently of digest errors.
export async function changed(edit: (data: EditableFixture) => void) {
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

export const later = now + 48 * 60 * 60 * 1000;

export function comparisonFiles(side: "baseline" | "comparison", edit?: (data: EditableFixture) => void) {
  return changed(data => {
    const { manifest } = data;
    const end = side === "baseline" ? now : later;
    manifest.startedAt = new Date(end - 1000).toISOString();
    manifest.endedAt = new Date(end).toISOString();
    manifest.runId = side === "baseline" ? "20260101T115959Z-offline-aaaaaa" : "20260103T115959Z-offline-bbbbbb";
    manifest.target = { id: "private-fixture-target", class: "fixture", scheme: "https", port: 443, ownership: "operator-asserted" };
    manifest.workload = { id: "private-fixture-workload", phases: [{ name: "window", durationSeconds: 1, ratePerSecond: 1, concurrency: 1, timeoutMs: 500 }] };
    manifest.ceilings = { level: "fixture", workers: 1, maxTotalRequests: 1, maxRequestsPerSecond: 1, durationSeconds: 1 };
    manifest.git = { gitSha: "a".repeat(40), dirty: false, dirtyFileCount: 0, untrackedFileCount: 0 };
    edit?.(data);
  });
}
