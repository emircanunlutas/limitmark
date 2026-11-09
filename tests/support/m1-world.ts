import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { m1TallyCheck } from "../../lab/defense/ba0-m1-tally-check";
import { BA0_FIELD_V1, FIELD_LEVELS, ba0FieldFingerprint } from "../../lab/defense/field-thresholds";
import { BASE_VERDICT_VALID, evaluateStatusOverlay } from "../../lab/defense/m1-status-contract";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../../lab/evidence/manifest";
import { COMPONENT_FILES, type ComponentName } from "../../lab/m1/acceptance";
import { identityBlock } from "../../lab/m1/identity";
import { runObservation, type FrontFaults } from "../../lab/m1/observation/run";
import { writeObservationResult, writeProvenanceResult } from "../../lab/m1/results";
import { RetainedRecords } from "../../lab/provenance/prototype";
import { writeFieldLikeEvidence, type EvidenceOptions } from "./m1-evidence-dir";

// A complete, disposable "world" for ONE run: a finalized server package with an active external lane (the criterion 9 fixture), and the result evidence runs of every M1 component.
// Real: the package, the criterion 9 tally CLI, the loopback observation run and its result writer, the provenance records and verifier. Same-shape synthetic (a disposable fixture
// cannot run the generator pipeline): the status overlay and the receipt reconciliation result, written through EvidenceRun with the identity block the real CLIs write.

const sha = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
export const pinnedParams = ba0FieldFingerprint(FIELD_LEVELS["ba0-l7-c1"].thresholds).sha256;
export const testRoot = (label: string): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${label}-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };

export type World = { root: string; serverId: string; ids: Partial<Record<ComponentName, string>>; observerDirectory: string; retainedDirectory: string };

/** Writes the result artifact of one component for `serverId` (same shape as the real CLI writes it) as a new evidence run. */
export function syntheticResult(root: string, serverId: string, file: string, body: Record<string, unknown>): string {
  const directory = resolveEvidenceDirectory(serverId, root);
  const run = new EvidenceRun("m1-synthetic", "m1-synthetic", new Date(), root);
  run.addJsonArtifact(file, { runId: serverId, ...identityBlock(directory), ...body });
  run.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "test", result: "PASS", resultReasons: [], metrics: {} });
  return run.id;
}

export async function buildWorld(root: string, options: { evidence?: EvidenceOptions; faults?: FrontFaults; fields?: { campaignId?: string } } = {}): Promise<World> {
  const serverId = writeFieldLikeEvidence(root, options.evidence ?? {});
  const directory = resolveEvidenceDirectory(serverId, root);
  const ids: World["ids"] = {};
  ids.tally = m1TallyCheck({ serverId }, root).evidenceId ?? undefined;
  const overlay = evaluateStatusOverlay({ baseVerdict: BASE_VERDICT_VALID, generatorStatuses: { "200": 6, "503": 2 }, serverStatusHistogram: { "200": 6, "503": 2 }, serverStatus503: { total: 2, expectedShed: 2, unexplained: 0 } });
  ids.overlay = syntheticResult(root, serverId, COMPONENT_FILES.overlay, { baseVerdict: BASE_VERDICT_VALID, statusOverlay: overlay, m1StatusContract: overlay.outcome === "PASS" ? "accepted" : "not_accepted" });
  ids.receipts = syntheticResult(root, serverId, COMPONENT_FILES.receipts, { receiptCheck: { outcome: "PASS", reasons: [] } });
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
  return { root, serverId, ids, observerDirectory, retainedDirectory };
}
export const disposeWorld = (world: World): void => { fs.rmSync(world.observerDirectory, { recursive: true, force: true }); fs.rmSync(world.retainedDirectory, { recursive: true, force: true }); };
