/**
 * Result writers for the two M1 components that had no artifact of their own: the independent observation check and the provenance check. Each writes a NEW evidence run
 * carrying the canonical identity of the server package it evaluated (derived from the package, never from its directory name). Inputs are read, never modified.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "../defense/field-thresholds";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../evidence/manifest";
import { identityBlock } from "./identity";
import { evaluateObservation, type ObservationResult } from "./observation-check";
import { readObservation } from "./observation/run";
import { verifyProvenance, type ProvenanceReport } from "../provenance/prototype";

const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const dotted = (items: readonly string[]): string[] => items.slice(0, 20).map((item) => item.replace(/[_:]/gu, "."));

function finish(evidence: EvidenceRun, engine: string, outcome: "PASS" | "REJECT" | "ERROR", reasons: readonly string[]): void {
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine,
    result: outcome === "PASS" ? "PASS" : outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: reasons.slice(0, 40), metrics: { outcome, networkActivity: false },
  });
}

/** Evaluates the observer's evidence (kept OUTSIDE the SUT evidence directory) against the identity of the server package. */
export function writeObservationResult(serverId: string, observerDirectory: string, root: string = EVIDENCE_ROOT, now = new Date()): { evidenceId: string; result: ObservationResult } {
  const directory = resolveEvidenceDirectory(serverId, root);
  const block = identityBlock(directory);
  const files = { canaryFile: path.join(observerDirectory, "canary-results.json"), receiptsFile: path.join(observerDirectory, "origin-receipts.ndjson"), metaFile: path.join(observerDirectory, "observation-meta.json") };
  const read = readObservation(files);
  const digest = (file: string): string | null => { try { return sha(readFileSync(file)); } catch { return null; } };
  const result = block.identity === null
    ? ({ contract: "m1-observation-check-v1", outcome: "ERROR", reasons: ["m1.obs.identity_missing"], summary: null, limitations: [] } as ObservationResult)
    : evaluateObservation({ identity: { runId: block.identity.runId, campaignId: block.identity.campaignId }, canary: read.canary, receipts: read.receipts, meta: read.meta });
  const evidence = new EvidenceRun("m1-observation-check", "m1-observation-check", now, root);
  evidence.addJsonArtifact("m1-observation-check.json", {
    contract: result.contract, scope: "independent canary and origin receipt collector (separate local loopback processes) against one server package; not independent organizational custody",
    runId: serverId, ...block, observation: { outcome: result.outcome, reasons: dotted(result.reasons) }, summary: result.summary, limitations: dotted(result.limitations),
    inputs: { canarySha256: digest(files.canaryFile), receiptsSha256: digest(files.receiptsFile), metaSha256: digest(files.metaFile) }, claims: { defenseQualification: "not_claimed", independentCustody: "not_established" },
  });
  finish(evidence, "offline-m1-observation-check", result.outcome, result.reasons);
  return { evidenceId: evidence.id, result };
}

/** Runs the separate verifier and records its separate outcomes. `announcementSource` is fixed: beacons from a local run are self-reported by the server process. */
export function writeProvenanceResult(serverId: string, retainedDirectory: string, root: string = EVIDENCE_ROOT, now = new Date()): { evidenceId: string; report: ProvenanceReport } {
  const directory = resolveEvidenceDirectory(serverId, root);
  const block = identityBlock(directory);
  const report = verifyProvenance(directory, retainedDirectory);
  const evidence = new EvidenceRun("m1-provenance-check", "m1-provenance-check", now, root);
  evidence.addJsonArtifact("m1-provenance-check.json", {
    contract: "m1-provenance-check-v1", scope: "pre-run commitment, generator-side beacon chain and finalization digest against one server package (local prototype)",
    runId: serverId, ...block, provenance: { overall: report.overall, levels: report.levels }, claimedProducer: report.claimedProducer, problems: dotted(report.problems),
    announcementSource: "self.reported.by.the.server.process", claims: report.claims, notClaimed: ["authenticity", "independent.custody"],
  });
  finish(evidence, "offline-m1-provenance-check", report.overall === "CONSISTENT_WITH_RECORDS" ? "PASS" : report.overall === "FAILED" ? "REJECT" : "ERROR", dotted(report.problems));
  return { evidenceId: evidence.id, report };
}
