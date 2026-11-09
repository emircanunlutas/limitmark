/**
 * Criterion 7 integration (local prototype). The existing three-run repeatability evaluator (lab/defense/m1-repeatability.ts) is UNCHANGED and still decides the shed-reason
 * and +/-5 percentage-point rules, distinct runs and campaigns, non-overlapping windows, and the same commit, parameters, fixture and level. This wrapper adds the gate in front of it:
 * every candidate run must first be LOCALLY_CONSISTENT under the unified per-run acceptance, and the repeatability facts must be about the same identity as that acceptance.
 *
 * TRUST BOUNDARY: a stored `m1-acceptance.json` is an AUDIT RECORD, never a source of truth. For each run the IO wrapper re-runs the complete per-run evaluation (`evaluateRunFromEvidence`:
 * authoritative package, generator report, observer records and retained provenance records, with every component recomputed) and only that RECOMPUTED result is used. The stored artifact
 * is then compared with the recomputed result (identity, outcome, reasons, components, input digests); a missing record is INCOMPLETE and a disagreeing one is ERROR. The repeatability facts are
 * extracted from the same finalized package by the unchanged `extractRun`.
 *
 * Fresh state: evidence cannot prove a freshly provisioned machine. What it does prove, per run, is that the Boundary and App process counters reconcile from ZERO to exactly the
 * events the run's ledger attributes (receipt reconciliation PASS): a process reused from an earlier run would carry surplus counts and fail it. Machine freshness (empty caches,
 * a new host) stays an operator attestation and is a listed blocker.
 *
 * Result: LOCAL_REPEATABILITY_PASS is NOT a qualified campaign. A qualified campaign is unreachable here for the same reasons as a qualified run.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { extractRun } from "../defense/ba0-m1-repeatability";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "../defense/field-thresholds";
import { evaluateRepeatability, repeatabilityWellFormed, type RepeatabilityResult, type RepeatabilityRun } from "../defense/m1-repeatability";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../evidence/manifest";
import { QUALIFICATION_BLOCKERS, evaluateRunFromEvidence, type AcceptCli, type AcceptanceOutcome, type AcceptanceResult } from "./acceptance";
import { identityDifferences, identityDigest, parseIdentity } from "./identity";
import { canonicalJson } from "./result-provenance";
import { verifyMandatoryInventory } from "./inventory";

export const CAMPAIGN_CONTRACT = "m1-local-campaign-prototype-v1";
export type CampaignOutcome = "LOCAL_REPEATABILITY_PASS" | "REJECT" | "ERROR" | "INCOMPLETE";
/** `audit`: how the STORED acceptance artifact compares with the RECOMPUTED acceptance (see `auditStoredAcceptance`). Anything but "agrees" prevents a campaign pass. */
export type StoredAudit = "agrees" | "missing" | "disagrees";
export type CampaignRun = { acceptance: Pick<AcceptanceResult, "outcome" | "identity" | "components">; repeat: RepeatabilityRun | null; audit?: StoredAudit };
export type CampaignResult = {
  contract: typeof CAMPAIGN_CONTRACT; outcome: CampaignOutcome; reasons: string[]; repeatability: RepeatabilityResult | null;
  freshState: "process_counters_reconciled_from_zero_per_run"; qualification: { reachable: false; blockers: readonly string[] };
};
export const CAMPAIGN_BLOCKERS = [...QUALIFICATION_BLOCKERS, "three_local_runs_are_not_a_remote_qualification_campaign"] as const;

/** Never throws. */
export function evaluateLocalCampaign(runs: readonly CampaignRun[]): CampaignResult {
  const finish = (outcome: CampaignOutcome, reasons: string[], repeatability: RepeatabilityResult | null = null): CampaignResult =>
    ({ contract: CAMPAIGN_CONTRACT, outcome, reasons: [...new Set(reasons)], repeatability, freshState: "process_counters_reconciled_from_zero_per_run", qualification: { reachable: false, blockers: CAMPAIGN_BLOCKERS } });
  try {
    if (!Array.isArray(runs) || runs.length > 3) return finish("ERROR", ["m1.campaign.not_exactly_three_runs"]);
    if (runs.length < 3) return finish("INCOMPLETE", ["m1.campaign.fewer_than_three_runs"]);
    const errors: string[] = []; const rejects: string[] = []; const incomplete: string[] = [];
    runs.forEach((run, index) => {
      const outcome: AcceptanceOutcome | undefined = run?.acceptance?.outcome;
      if (run?.audit === "missing") incomplete.push(`m1.campaign.run${index + 1}.stored_acceptance_missing`);
      else if (run?.audit !== "agrees" && outcome !== "INCOMPLETE") errors.push(`m1.campaign.run${index + 1}.stored_acceptance_not_verified`);
      if (outcome === "ERROR" || outcome === undefined) errors.push(`m1.campaign.run${index + 1}.acceptance_error`);
      else if (outcome === "REJECT") rejects.push(`m1.campaign.run${index + 1}.not_accepted`);
      else if (outcome === "INCOMPLETE") incomplete.push(`m1.campaign.run${index + 1}.acceptance_incomplete`);
      else if (outcome !== "LOCALLY_CONSISTENT") errors.push(`m1.campaign.run${index + 1}.acceptance_outcome_unrecognized`);
      else if (run.acceptance.components?.receipts !== "PASS") rejects.push(`m1.campaign.run${index + 1}.receipts_not_passed`);
      if (run?.repeat === null || run?.repeat === undefined) errors.push(`m1.campaign.run${index + 1}.repeatability_facts_missing`);
    });
    if (errors.length > 0) return finish("ERROR", errors);
    if (rejects.length > 0) return finish("REJECT", rejects);
    if (incomplete.length > 0) return finish("INCOMPLETE", incomplete);
    // the repeatability facts must describe exactly the accepted runs
    runs.forEach((run, index) => {
      const identity = run.acceptance.identity; const facts = run.repeat as RepeatabilityRun;
      if (identity === null || facts.serverRunId !== identity.runId || facts.campaignId !== identity.campaignId || facts.levelId !== identity.levelId || facts.gitSha !== identity.gitSha ||
          facts.paramsFingerprintSha256 !== identity.paramsSha256 || facts.workloadFingerprintSha256 !== identity.workloadSha256) rejects.push(`m1.campaign.run${index + 1}.facts_not_bound_to_accepted_identity`);
    });
    const finalizations = runs.map((run) => run.acceptance.identity?.finalizationSha256);
    if (new Set(finalizations).size !== 3) rejects.push("m1.campaign.runs_not_distinct_packages");
    if (new Set(runs.map((run) => run.acceptance.identity?.runId)).size !== 3) rejects.push("m1.campaign.run_ids_not_distinct");
    if (rejects.length > 0) return finish("REJECT", rejects);
    let repeatability = evaluateRepeatability(runs.map((run) => run.repeat));
    if (!repeatabilityWellFormed(repeatability)) repeatability = { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evaluation_failed"], details: null };
    if (repeatability.outcome === "PASS") return finish("LOCAL_REPEATABILITY_PASS", [], repeatability);
    return finish(repeatability.outcome === "REJECT" ? "REJECT" : "ERROR", repeatability.reasons, repeatability);
  } catch { return finish("ERROR", ["m1.campaign.evaluation_failed"]); }
}

/** Per run: the stored acceptance record (audit only), the authoritative inputs acceptance recomputes from, and the generator report (also the source of the repeatability facts). */
export type CampaignCli = { runs: (AcceptCli & { acceptanceId?: string; reportPath: string })[] };

/** Compares a stored `m1-acceptance.json` with the RECOMPUTED acceptance. The stored artifact decides nothing; it can only agree, be missing, or disagree. */
export function auditStoredAcceptance(root: string, acceptanceId: string | undefined, recomputed: AcceptanceResult, inputs: Record<string, string | null>, serverId: string): StoredAudit {
  if (acceptanceId === undefined) return "missing";
  let directory: string;
  try { directory = resolveEvidenceDirectory(acceptanceId, root); } catch { return "disagrees"; }
  if (!existsSync(directory)) return "missing";
  try {
    const inventory = verifyMandatoryInventory(directory, ["m1-acceptance.json", "manifest.json"]);
    const bytes = inventory.bytes.get("m1-acceptance.json");
    if (inventory.problems.length > 0 || bytes === undefined) return "disagrees";
    const stored = JSON.parse(bytes.toString("utf8")) as Record<string, unknown>;
    const claimed = parseIdentity(stored.identity);
    const same = recomputed.identity !== null && claimed !== null && identityDifferences(claimed, recomputed.identity).length === 0 && stored.identitySha256 === identityDigest(recomputed.identity) && stored.runId === serverId;
    const dotted = (items: readonly string[]): string[] => items.map((item) => item.replace(/_/gu, "."));
    const agrees = same && canonicalJson(stored.acceptance) === canonicalJson({ outcome: recomputed.outcome, reasons: dotted(recomputed.reasons) }) && canonicalJson(stored.components) === canonicalJson(recomputed.components) &&
      canonicalJson(stored.provenanceLevels) === canonicalJson(recomputed.provenanceLevels) && canonicalJson(stored.inputs) === canonicalJson(inputs) &&
      canonicalJson(stored.qualification) === canonicalJson({ reachable: false, blockers: dotted(recomputed.qualification.blockers) });
    return agrees ? "agrees" : "disagrees";
  } catch { return "disagrees"; }
}

export function m1LocalCampaign(cli: CampaignCli, root: string = EVIDENCE_ROOT, now = new Date()): { result: CampaignResult; evidenceId: string } {
  const runs: CampaignRun[] = cli.runs.map((run) => {
    const repeat = existsSync(run.reportPath) ? extractRun(run.serverId, run.reportPath, root) : null;
    try {
      // the RECOMPUTED acceptance is the only one used; the generator report doubles as the acceptance's generator input
      const { result, inputs } = evaluateRunFromEvidence({ serverId: run.serverId, resultIds: run.resultIds ?? {}, generatorReportPath: run.reportPath, observerDirectory: run.observerDirectory ?? null, retainedDirectory: run.retainedDirectory ?? null }, root);
      return { acceptance: { outcome: result.outcome, identity: result.identity, components: result.components }, repeat, audit: auditStoredAcceptance(root, run.acceptanceId, result, inputs, run.serverId) };
    } catch { return { acceptance: { outcome: "ERROR" as const, identity: null, components: {} as AcceptanceResult["components"] }, repeat, audit: "disagrees" as const }; }
  });
  const result = evaluateLocalCampaign(runs);
  const evidence = new EvidenceRun("m1-local-campaign", "m1-local-campaign", now, root);
  evidence.addJsonArtifact("m1-campaign.json", {
    contract: result.contract, scope: "three locally consistent runs plus the unchanged criterion 7 rules; a local repeatability result, NOT a qualified campaign",
    campaign: { outcome: result.outcome, reasons: result.reasons.map((reason) => reason.replace(/_/gu, ".")) }, repeatability: result.repeatability === null ? null : { outcome: result.repeatability.outcome, reasons: result.repeatability.reasons.map((reason) => reason.replace(/_/gu, ".")) },
    runs: cli.runs.map((run, index) => ({ runId: run.serverId, acceptanceOutcome: runs[index].acceptance.outcome, finalizationSha256: runs[index].acceptance.identity?.finalizationSha256 ?? null, reportName: path.basename(run.reportPath), reportSha256: (() => { try { return createHash("sha256").update(readFileSync(run.reportPath)).digest("hex"); } catch { return null; } })() })),
    freshState: result.freshState.replace(/_/gu, "."), qualification: { reachable: result.qualification.reachable, blockers: result.qualification.blockers.map((blocker) => blocker.replace(/_/gu, ".")) }, claims: { defenseQualification: "not_claimed", machineFreshness: "not_provable_from_evidence" },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-local-campaign",
    result: result.outcome === "LOCAL_REPEATABILITY_PASS" ? "PASS" : result.outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: result.reasons.slice(0, 40).map((reason) => reason.replace(/_/gu, ".")), metrics: { outcome: result.outcome, networkActivity: false },
  });
  return { result, evidenceId: evidence.id };
}
