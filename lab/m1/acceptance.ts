/**
 * Unified M1 acceptance evaluator (local prototype). ADDITIVE: it consumes the result artifacts of the existing evaluators and never replaces or reinterprets a base verdict.
 *
 * Inputs for ONE run, each a finalized evidence run carrying the canonical identity block (lab/m1/identity.ts):
 *   overlay      m1-verdict.json            base field verdict + M1 status overlay (they are written together by ba0-m1-reconcile)
 *   tally        m1-tally-check.json        criterion 9
 *   receipts     m1-receipt-check.json      receipt reconciliation
 *   observation  m1-observation-check.json  independent canary AND origin receipt collector (one artifact, two observers)
 *   provenance   m1-provenance-check.json   commitment / beacon chain / finalization digest
 * The identity of the SERVER PACKAGE is re-derived from the package itself. Every component must carry an identity block equal to it in all nine fields.
 *
 * Outcomes, in precedence order:
 *   ERROR              evidence cannot be trusted or read: unreadable/tampered/unlisted artifact, duplicate keys, a component without an identity block (the producer contract is missing),
 *                      a malformed block, a block whose digest does not match, no derivable package identity, a malformed component result
 *   REJECT             a present component did not pass, or its identity differs from the package (mixed runs, campaigns, commits, parameters, fixtures, finalizations)
 *   INCOMPLETE         a required component was not supplied
 *   LOCALLY_CONSISTENT every locally demonstrable check passed for one identity
 *   QUALIFIED          UNREACHABLE. There is no code path, flag or input that produces it: the facts it needs (independent custody, authorized external-lane qualification,
 *                      authenticity) cannot be established by this software and are never asserted by a caller. `qualification.blockers` lists them.
 */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import path from "node:path";
import { findDuplicateObjectKeys } from "../defense/m1-tally-check";
import { m1Accepted } from "../defense/m1-status-contract";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "../defense/field-thresholds";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../evidence/manifest";
import { identityBlock, identityDifferences, identityDigest, identityFromPackage, parseIdentity, type M1Identity } from "./identity";
import { verifyMandatoryInventory } from "./inventory";

export const ACCEPTANCE_CONTRACT = "m1-acceptance-prototype-v1";
export type AcceptanceOutcome = "REJECT" | "ERROR" | "INCOMPLETE" | "LOCALLY_CONSISTENT" | "QUALIFIED";
export const COMPONENT_NAMES = ["overlay", "tally", "receipts", "observation", "provenance"] as const;
export type ComponentName = (typeof COMPONENT_NAMES)[number];
export const COMPONENT_FILES: Record<ComponentName, string> = { overlay: "m1-verdict.json", tally: "m1-tally-check.json", receipts: "m1-receipt-check.json", observation: "m1-observation-check.json", provenance: "m1-provenance-check.json" };

/** Conditions no software in this repository can establish. A caller cannot assert them away. */
export const QUALIFICATION_BLOCKERS = [
  "independent_custody_not_established",
  "authenticity_unverified",
  "authorized_external_lane_qualification_absent",
  "real_remote_target_run_absent",
  "machine_freshness_not_provable_from_evidence",
  "canary_and_origin_collector_are_local_processes",
] as const;

export type LoadedComponent = { state: "loaded"; artifact: unknown } | { state: "absent" } | { state: "unreadable"; problems: string[] };
export type AcceptanceInput = { packageIdentity: M1Identity | null; packageProblems: string[]; components: Partial<Record<ComponentName, LoadedComponent>> };
export type ComponentStatus = "PASS" | "FAIL" | "ABSENT" | "ERROR";
export type AcceptanceResult = {
  contract: typeof ACCEPTANCE_CONTRACT;
  outcome: AcceptanceOutcome;
  reasons: string[];
  identity: M1Identity | null;
  components: Record<ComponentName, ComponentStatus>;
  provenanceLevels: Record<string, string> | null;
  qualification: { reachable: false; blockers: readonly string[] };
};

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** `true` = passed, `false` = failed, `null` = malformed. */
function componentPassed(name: ComponentName, artifact: Record<string, unknown>): boolean | null {
  if (name === "overlay") {
    if (typeof artifact.baseVerdict !== "string" && artifact.baseVerdict !== null) return null;
    if (!isRecord(artifact.statusOverlay) || typeof artifact.statusOverlay.outcome !== "string" || artifact.m1StatusContract === undefined) return null;
    return artifact.m1StatusContract === "accepted" && m1Accepted(artifact.baseVerdict, artifact.statusOverlay);
  }
  const key = name === "tally" ? "tallyCheck" : name === "receipts" ? "receiptCheck" : name === "observation" ? "observation" : "provenance";
  const block = artifact[key];
  if (!isRecord(block)) return null;
  if (name === "provenance") {
    if (typeof block.overall !== "string" || !isRecord(block.levels)) return null;
    return block.overall === "CONSISTENT_WITH_RECORDS" && block.levels.byteIntegrity === "VERIFIED" && block.levels.artifactCompleteness === "VERIFIED" && block.levels.runBinding === "VERIFIED" && block.levels.independentCorroboration === "CONSISTENT";
  }
  if (block.outcome !== "PASS" && block.outcome !== "REJECT" && block.outcome !== "ERROR") return null;
  return block.outcome === "PASS" && Array.isArray(block.reasons) && block.reasons.length === 0;
}

/** Pure; never throws. */
export function evaluateAcceptance(input: AcceptanceInput): AcceptanceResult {
  const components = Object.fromEntries(COMPONENT_NAMES.map((name) => [name, "ABSENT"])) as Record<ComponentName, ComponentStatus>;
  const finish = (outcome: AcceptanceOutcome, reasons: string[], provenanceLevels: Record<string, string> | null = null): AcceptanceResult =>
    ({ contract: ACCEPTANCE_CONTRACT, outcome, reasons: [...new Set(reasons)], identity: input?.packageIdentity ?? null, components, provenanceLevels, qualification: { reachable: false, blockers: QUALIFICATION_BLOCKERS } });
  try {
    if (input.packageIdentity === null) return finish("ERROR", ["m1.accept.package_identity_underivable", ...input.packageProblems.slice(0, 4).map((p) => `m1.accept.package.${p.replace(/[_:]/gu, ".")}`)]);
    const errors: string[] = []; const rejects: string[] = []; const incomplete: string[] = [];
    let provenanceLevels: Record<string, string> | null = null;
    for (const name of COMPONENT_NAMES) {
      const loaded = input.components[name] ?? { state: "absent" as const };
      if (loaded.state === "absent") { incomplete.push(`m1.accept.${name}.absent`); continue; }
      if (loaded.state === "unreadable") { components[name] = "ERROR"; errors.push(`m1.accept.${name}.unreadable`); continue; }
      const artifact = loaded.artifact;
      if (!isRecord(artifact)) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.malformed`); continue; }
      const claimed = parseIdentity(artifact.identity);
      if (artifact.identity === undefined || artifact.identity === null) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.identity_missing.producer_contract`); continue; }
      if (claimed === null) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.identity_malformed`); continue; }
      if (artifact.identitySha256 !== identityDigest(claimed)) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.identity_digest_inconsistent`); continue; }
      const differing = identityDifferences(claimed, input.packageIdentity);
      if (differing.length > 0) { components[name] = "FAIL"; rejects.push(`m1.accept.${name}.identity_mismatch`, ...differing.map((field) => `m1.accept.${name}.identity_differs.${field}`)); continue; }
      const passed = componentPassed(name, artifact);
      if (passed === null) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.result_malformed`); continue; }
      components[name] = passed ? "PASS" : "FAIL";
      if (!passed) rejects.push(`m1.accept.${name}.not_passed`);
      if (name === "provenance" && isRecord(artifact.provenance) && isRecord(artifact.provenance.levels)) {
        provenanceLevels = Object.fromEntries(Object.entries(artifact.provenance.levels).filter(([, v]) => typeof v === "string")) as Record<string, string>;
        // the layers the prototype can never raise: any other claim is contradicted here
        if (provenanceLevels.authenticity !== "UNVERIFIED" || (isRecord(artifact.claims) && (artifact.claims.authenticated !== false || artifact.claims.independent !== false))) { components[name] = "ERROR"; errors.push("m1.accept.provenance.overclaims_authenticity"); }
      }
    }
    if (errors.length > 0) return finish("ERROR", [...errors, ...rejects], provenanceLevels);
    if (rejects.length > 0) return finish("REJECT", rejects, provenanceLevels);
    if (incomplete.length > 0) return finish("INCOMPLETE", incomplete, provenanceLevels);
    return finish("LOCALLY_CONSISTENT", [], provenanceLevels);
  } catch { return finish("ERROR", ["m1.accept.evaluation_failed"]); }
}

/** Loads one result evidence run through the strict inventory: listed, checksummed, no duplicate keys. */
export function loadComponent(root: string, id: string | undefined, name: ComponentName): LoadedComponent & { sha256?: string } {
  if (id === undefined) return { state: "absent" };
  try {
    const directory = resolveEvidenceDirectory(id, root);
    const file = COMPONENT_FILES[name];
    if (!existsSync(path.join(directory, "SHA256SUMS"))) return { state: "unreadable", problems: ["not.finalized"] };
    const inventory = verifyMandatoryInventory(directory, [file, "manifest.json"]);
    const bytes = inventory.bytes.get(file);
    if (inventory.problems.length > 0 || bytes === undefined) return { state: "unreadable", problems: inventory.problems.slice(0, 4) };
    const text = bytes.toString("utf8");
    if (findDuplicateObjectKeys(text).length > 0) return { state: "unreadable", problems: ["duplicate.keys"] };
    return { state: "loaded", artifact: JSON.parse(text) as unknown, sha256: createHash("sha256").update(bytes).digest("hex") };
  } catch { return { state: "unreadable", problems: ["unreadable"] }; }
}

export type AcceptCli = { serverId: string; resultIds: Partial<Record<ComponentName, string>> };
export type AcceptOutcome = { result: AcceptanceResult; evidenceId: string };

/** Re-derives the package identity, loads each supplied result and writes `m1-acceptance.json` as a NEW evidence run. */
export function m1AcceptRun(cli: AcceptCli, root: string = EVIDENCE_ROOT, now = new Date()): AcceptOutcome {
  const packageDirectory = resolveEvidenceDirectory(cli.serverId, root);
  const { identity, problems } = identityFromPackage(packageDirectory);
  const loaded: Partial<Record<ComponentName, LoadedComponent>> = {}; const inputs: Record<string, string | null> = {};
  for (const name of COMPONENT_NAMES) { const component = loadComponent(root, cli.resultIds[name], name); loaded[name] = component; inputs[`${name}Sha256`] = "sha256" in component && component.sha256 ? component.sha256 : null; }
  const result = evaluateAcceptance({ packageIdentity: identity, packageProblems: problems, components: loaded });
  const evidence = new EvidenceRun("m1-acceptance", "m1-acceptance", now, root);
  evidence.addJsonArtifact("m1-acceptance.json", {
    contract: result.contract, scope: "unified M1 acceptance prototype over the result artifacts of ONE run; additive, replaces no base verdict",
    runId: cli.serverId, ...identityBlock(packageDirectory), acceptance: { outcome: result.outcome, reasons: result.reasons.map((reason) => reason.replace(/_/gu, ".")) }, components: result.components, provenanceLevels: result.provenanceLevels,
    inputs, qualification: { reachable: result.qualification.reachable, blockers: result.qualification.blockers.map((blocker) => blocker.replace(/_/gu, ".")) }, claims: { defenseQualification: "not_claimed", authenticity: "not_claimed", independentCustody: "not_established" },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-acceptance",
    result: result.outcome === "LOCALLY_CONSISTENT" ? "PASS" : result.outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: result.reasons.slice(0, 40).map((reason) => reason.replace(/_/gu, ".")), metrics: { outcome: result.outcome, networkActivity: false },
  });
  return { result, evidenceId: evidence.id };
}
