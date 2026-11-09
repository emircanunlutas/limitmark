import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { m1TallyCheck } from "../../lab/defense/ba0-m1-tally-check";
import { m1Reconcile } from "../../lab/defense/ba0-m1-reconcile";
import { m1ReceiptCheck } from "../../lab/defense/ba0-m1-receipt-check";
import { BA0_FIELD_V1, FIELD_LEVELS, ba0FieldFingerprint } from "../../lab/defense/field-thresholds";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../../lab/evidence/manifest";
import type { ComponentName } from "../../lab/m1/acceptance";
import { identityBlock } from "../../lab/m1/identity";
import { runObservation, type FrontFaults } from "../../lab/m1/observation/run";
import { writeObservationResult, writeProvenanceResult } from "../../lab/m1/results";
import { RetainedRecords } from "../../lab/provenance/prototype";
import { writeFieldLikeEvidence, type EvidenceOptions } from "./m1-evidence-dir";
import { generatorReportFor, receiptValidOptions } from "./m1-receipt-fixture";
import type { InputSources } from "../../lab/m1/result-provenance";

// A complete, disposable "world" for ONE run: a finalized server package with an active external lane (the criterion 9 fixture), and the result evidence runs of every M1 component.
// Real: the package, the criterion 9 tally CLI, the loopback observation run and its result writer, the provenance records and verifier. Same-shape synthetic (a disposable fixture
// cannot run the generator pipeline): the status overlay and the receipt reconciliation result, written through EvidenceRun with the identity block the real CLIs write.

const sha = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
export const pinnedParams = ba0FieldFingerprint(FIELD_LEVELS["ba0-l7-c1"].thresholds).sha256;
export const testRoot = (label: string): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${label}-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };

export type World = { root: string; serverId: string; ids: Partial<Record<ComponentName, string>>; observerDirectory: string; retainedDirectory: string; reportDirectory: string; reportPath: string; sources: InputSources };

/** Writes the result artifact of one component for `serverId` (same shape as the real CLI writes it) as a new evidence run. */
export function syntheticResult(root: string, serverId: string, file: string, body: Record<string, unknown>): string {
  const directory = resolveEvidenceDirectory(serverId, root);
  const run = new EvidenceRun("m1-synthetic", "m1-synthetic", new Date(), root);
  run.addJsonArtifact(file, { runId: serverId, ...identityBlock(directory), ...body });
  run.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "test", result: "PASS", resultReasons: [], metrics: {} });
  return run.id;
}

export async function buildWorld(root: string, options: { evidence?: EvidenceOptions; faults?: FrontFaults; fields?: { campaignId?: string } } = {}): Promise<World> {
  const base = receiptValidOptions(); const extra = options.evidence ?? {};
  const mutate: Record<string, (content: Record<string, unknown>) => void> = { ...base.mutate };
  for (const [name, change] of Object.entries(extra.mutate ?? {})) { const before = mutate[name]; mutate[name] = (content) => { before?.(content); change(content); }; }
  const serverId = writeFieldLikeEvidence(root, { ...base, ...extra, mutate });
  const directory = resolveEvidenceDirectory(serverId, root);
  const ids: World["ids"] = {};
  ids.tally = m1TallyCheck({ serverId }, root).evidenceId ?? undefined;
  // the generator report is a separate party's file, kept OUTSIDE every evidence directory; overlay and receipts are the REAL writers
  const reportDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "m1-world-generator-"));
  const reportPath = path.join(reportDirectory, "generator-report.json");
  fs.writeFileSync(reportPath, JSON.stringify(generatorReportFor(options.fields?.campaignId)));
  ids.overlay = m1Reconcile({ serverId, reportPath, finalId: null }, root).evidenceId ?? undefined;
  ids.receipts = m1ReceiptCheck({ serverId, reportPath }, root).evidenceId ?? undefined;
  const observerDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "m1-world-observer-"));
  const block = identityBlock(directory);
  await runObservation({ observerDirectory, runId: serverId, campaignId: block.identity!.campaignId, faults: options.faults ?? {} });
  ids.observation = writeObservationResult(serverId, observerDirectory, root).evidenceId;
  const retainedDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "m1-world-retained-"));
  const retained = new RetainedRecords(retainedDirectory);
  retained.commit({ campaignId: block.identity!.campaignId, levelId: block.identity!.levelId, paramsSha256: block.identity!.paramsSha256, gitSha: block.identity!.gitSha, committedAt: new Date(Date.now() - 3_600_000).toISOString(), nonce: "w".repeat(16) });
  const journal = fs.readFileSync(path.join(directory, "ledger-journal-field.ndjson"));
  const cuts = [...journal.toString("utf8").matchAll(/\n/gu)].map((match) => match.index! + 1);
  for (const cut of [cuts[Math.floor(cuts.length / 2)], journal.length]) retained.beacon(serverId, cut, sha(journal.subarray(0, cut)));
  retained.finalize(serverId, sha(fs.readFileSync(path.join(directory, "SHA256SUMS"))), sha(journal));
  ids.provenance = writeProvenanceResult(serverId, retainedDirectory, root).evidenceId;
  return { root, serverId, ids, observerDirectory, retainedDirectory, reportDirectory, reportPath, sources: { packageDirectory: directory, generatorReportPath: reportPath, observerDirectory, retainedDirectory } };
}
export const disposeWorld = (world: World): void => { fs.rmSync(world.reportDirectory, { recursive: true, force: true }); fs.rmSync(world.observerDirectory, { recursive: true, force: true }); fs.rmSync(world.retainedDirectory, { recursive: true, force: true }); };
