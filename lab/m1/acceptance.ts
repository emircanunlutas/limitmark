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
 *
 * RECOMPUTATION (the correction of the five confirmed false-PASS paths): a matching identity proves only which run a result CLAIMS to describe. Acceptance therefore reads the
 * authoritative inputs itself (package, generator report, observer records, retained provenance records), re-runs the same deterministic evaluators the writers use, and
 * accepts a component only when the recomputed result passes AND the supplied result agrees with it in outcome, reasons and material claims. It also requires a closed
 * result schema, a result-provenance block whose input digests equal the bytes read now, evaluator sources equal to the current sources, and an output digest that matches the
 * artifact. A required input that is not supplied makes the component INCOMPLETE; nothing is fabricated.
 *
 *   QUALIFIED          UNREACHABLE. There is no code path, flag or input that produces it: the facts it needs (independent custody, authorized external-lane qualification,
 *                      authenticity) cannot be established by this software and are never asserted by a caller. `qualification.blockers` lists them.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { evaluateTallyAgainstLedger, findDuplicateObjectKeys, tallyCheckWellFormed } from "../defense/m1-tally-check";
import { gatherTallyInput } from "../defense/ba0-m1-tally-check";
import { gatherReceiptInput } from "../defense/ba0-m1-receipt-check";
import { evaluateReceipts } from "../defense/m1-receipt-check";
import { parseGeneratorReport, type GeneratorReport } from "../defense/generator-report";
import { SERVER_LEVEL_SCHEMA, finalFrom, type ServerLevelEvidence } from "../defense/reconcile";
import { M1_STATUS_CONTRACT_ID, evaluateStatusOverlay, m1Accepted, overlayIsWellFormed } from "../defense/m1-status-contract";
import { BA0_FIELD_V1, ba0FieldFingerprint, fieldLevel } from "../defense/field-thresholds";
import type { ExpectedObservation } from "./observation-profile";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../evidence/manifest";
import { identityBlock, identityDifferences, identityDigest, identityFromPackage, parseIdentity, type M1Identity } from "./identity";
import { verifyMandatoryInventory } from "./inventory";
import { evaluateObservationFiles, observerFiles } from "./observation-bundle";
import { dotted } from "./results";
import { verifyProvenance } from "../provenance/prototype";
import { EVALUATOR_CONTRACT, PRODUCER_CLAIM, RESULT_PROVENANCE_CONTRACT, canonicalJson, evaluatorSources, observedInputs, outputDigest, type InputRole, type InputSources } from "./result-provenance";

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
/** What acceptance itself computed from authoritative bytes. `unavailable` means a required input was not supplied: it is never fabricated. */
export type Recomputed = { state: "computed"; outcome: string; reasons: string[]; material: unknown; passed: boolean } | { state: "unavailable"; reason: string };
export type Authority = {
  recomputed: Partial<Record<ComponentName, Recomputed>>;
  /** The input roles and digests of the bytes read NOW. */
  observed: Partial<Record<ComponentName, InputRole[]>>;
  /** The evaluator sources as they are NOW (git blob ids). */
  sources: Partial<Record<ComponentName, { path: string; gitBlobId: string }[]>>;
};
export type AcceptanceInput = { packageIdentity: M1Identity | null; packageProblems: string[]; components: Partial<Record<ComponentName, LoadedComponent>>; authority?: Authority };
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
const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const same = (a: unknown, b: unknown): boolean => canonicalJson(a) === canonicalJson(b);
const keysAre = (value: Record<string, unknown>, keys: readonly string[]): boolean => same(Object.keys(value).sort(), [...keys].sort());

// ---- closed result schemas: the exact top-level keys, fixed contract strings and fixed claims of each component's artifact (the producers are listed in the header of lab/m1/result-provenance.ts)
const IDENTITY_KEYS = ["identity", "identitySha256", "identityProblems"] as const;
const SCHEMA: Record<ComponentName, { contract: string; keys: readonly string[]; claimKeys: readonly string[]; claims: Record<string, string> }> = {
  overlay: { contract: M1_STATUS_CONTRACT_ID, keys: ["contract", "scope", ...IDENTITY_KEYS, "baseVerdict", "statusOverlay", "m1StatusContract", "allowedStatuses", "inputs", "claims", "resultProvenance"], claimKeys: ["defenseQualification", "notClaimed"], claims: { defenseQualification: "not_claimed" } },
  tally: { contract: "m1-tally-check-v1", keys: ["contract", "scope", "runId", ...IDENTITY_KEYS, "tallyCheck", "differences", "ledgerSource", "claims", "resultProvenance"], claimKeys: ["defenseQualification", "notClaimed"], claims: { defenseQualification: "not_claimed" } },
  receipts: { contract: "m1-receipt-check-v1", keys: ["contract", "scope", "runId", ...IDENTITY_KEYS, "generatorReportSha256", "receiptCheck", "identities", "limitations", "campaignAttribution", "claims", "resultProvenance"], claimKeys: ["defenseQualification", "authenticity"], claims: { defenseQualification: "not_claimed", authenticity: "not_claimed" } },
  observation: { contract: "m1-observation-check-v1", keys: ["contract", "scope", "runId", ...IDENTITY_KEYS, "observation", "summary", "limitations", "inputs", "claims", "resultProvenance"], claimKeys: ["defenseQualification", "independentCustody"], claims: { defenseQualification: "not_claimed", independentCustody: "not_established" } },
  provenance: { contract: "m1-provenance-check-v1", keys: ["contract", "scope", "runId", ...IDENTITY_KEYS, "provenance", "claimedProducer", "problems", "announcementSource", "claims", "notClaimed", "resultProvenance"], claimKeys: ["authenticated", "independent"], claims: {} },
};
const PROVENANCE_KEYS = ["contract", "component", "evaluator", "inputs", "evaluatedAt", "producerClaim", "outputSha256"] as const;

/** Closed-schema and metadata problems of one result artifact (never trusts a value it can recompute). */
function schemaProblems(name: ComponentName, artifact: Record<string, unknown>, identity: M1Identity): string[] {
  const problems: string[] = []; const schema = SCHEMA[name];
  if (!keysAre(artifact, schema.keys)) problems.push("keys_not_closed");
  if (artifact.contract !== schema.contract) problems.push("contract_unexpected");
  if (typeof artifact.scope !== "string") problems.push("scope_missing");
  const runId = name === "overlay" ? (isRecord(artifact.inputs) && isRecord(artifact.inputs.server) ? artifact.inputs.server.runId : undefined) : artifact.runId;
  if (runId !== identity.runId) problems.push("run_id_not_bound");
  const claims = artifact.claims;
  if (!isRecord(claims) || !keysAre(claims, schema.claimKeys)) problems.push("claims_missing_or_open");
  else {
    for (const [key, expected] of Object.entries(schema.claims)) if (claims[key] !== expected) problems.push("claims_overclaim");
    if (name === "overlay" || name === "tally") { if (!Array.isArray(claims.notClaimed) || !claims.notClaimed.every((entry) => typeof entry === "string")) problems.push("claims_missing_or_open"); }
    if (name === "provenance" && (claims.authenticated !== false || claims.independent !== false)) problems.push("claims_overclaim");
  }
  if (name === "provenance") {
    if (artifact.announcementSource !== "self.reported.by.the.server.process") problems.push("announcement_source_unexpected");
    if (!same(artifact.notClaimed, ["authenticity", "independent.custody"])) problems.push("not_claimed_unexpected");
  }
  const block = artifact.resultProvenance;
  if (!isRecord(block) || !keysAre(block, PROVENANCE_KEYS)) problems.push("result_provenance_missing_or_open");
  return problems;
}

/** Verifies the result-provenance block against the bytes and sources read by acceptance itself. */
function provenanceProblems(name: ComponentName, artifact: Record<string, unknown>, observed: InputRole[] | undefined, sources: { path: string; gitBlobId: string }[] | undefined): string[] {
  const block = artifact.resultProvenance as Record<string, unknown>; const problems: string[] = [];
  if (block.contract !== RESULT_PROVENANCE_CONTRACT) problems.push("contract");
  if (block.component !== name) problems.push("component");
  const evaluator = block.evaluator;
  if (!isRecord(evaluator) || !keysAre(evaluator, ["contract", "sources"]) || evaluator.contract !== EVALUATOR_CONTRACT[name]) problems.push("evaluator_contract");
  else if (sources === undefined || !same(evaluator.sources, sources)) problems.push("evaluator_source_changed");
  if (!Array.isArray(block.inputs) || block.inputs.length === 0) problems.push("inputs_empty");
  else if (observed === undefined || !same(block.inputs, observed)) problems.push("inputs_not_the_bytes_read");
  if (typeof block.evaluatedAt !== "string" || Number.isNaN(Date.parse(block.evaluatedAt)) || new Date(Date.parse(block.evaluatedAt)).toISOString() !== block.evaluatedAt) problems.push("evaluated_at");
  if (!same(block.producerClaim, PRODUCER_CLAIM)) problems.push("producer_claim");
  if (block.outputSha256 !== outputDigest(artifact)) problems.push("output_digest");
  return problems;
}

/** The supplied result, normalized exactly as `recompute*` normalizes the authoritative one. `null` = malformed. */
function suppliedView(name: ComponentName, a: Record<string, unknown>): { outcome: string; reasons: string[]; material: unknown } | null {
  const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
  if (name === "tally") { const b = a.tallyCheck; return isRecord(b) && typeof b.outcome === "string" && strings(b.reasons) ? { outcome: b.outcome, reasons: b.reasons, material: { evaluated: b.evaluated, differences: a.differences, ledgerSource: a.ledgerSource } } : null; }
  if (name === "receipts") { const b = a.receiptCheck; return isRecord(b) && typeof b.outcome === "string" && strings(b.reasons) ? { outcome: b.outcome, reasons: b.reasons, material: { identities: a.identities, limitations: a.limitations, campaignAttribution: a.campaignAttribution, generatorReportSha256: a.generatorReportSha256 } } : null; }
  if (name === "overlay") { const b = a.statusOverlay; return isRecord(b) && typeof b.outcome === "string" && strings(b.reasons) ? { outcome: b.outcome, reasons: b.reasons, material: { baseVerdict: a.baseVerdict, statusOverlay: b, m1StatusContract: a.m1StatusContract, inputs: a.inputs } } : null; }
  if (name === "observation") { const b = a.observation; return isRecord(b) && typeof b.outcome === "string" && strings(b.reasons) ? { outcome: b.outcome, reasons: b.reasons, material: { summary: a.summary, limitations: a.limitations, inputs: a.inputs } } : null; }
  const b = a.provenance;
  return isRecord(b) && typeof b.overall === "string" && isRecord(b.levels) && strings(a.problems) ? { outcome: b.overall, reasons: a.problems, material: { levels: b.levels, claimedProducer: a.claimedProducer, claims: a.claims } } : null;
}

// ---- recomputation: the SAME evaluators the result writers call, over bytes read here. Nothing is taken from the supplied result.
export type AuthoritySources = InputSources & { identity: M1Identity };
const unavailable = (reason: string): Recomputed => ({ state: "unavailable", reason });
function readText(file: string | null | undefined): string | null { if (!file) return null; try { return readFileSync(file, "utf8"); } catch { return null; } }

function recomputeOverlay(src: AuthoritySources): Recomputed {
  const reportText = readText(src.generatorReportPath);
  if (reportText === null) return unavailable("generator_report_not_supplied");
  const serverText = readText(path.join(src.packageDirectory, "server-level.json"));
  if (serverText === null) return unavailable("server_level_unreadable");
  let server: ServerLevelEvidence;
  try { server = JSON.parse(serverText) as ServerLevelEvidence; } catch { return unavailable("server_level_not_json"); }
  if (server === null || typeof server !== "object" || server.schema !== SERVER_LEVEL_SCHEMA) return unavailable("server_level_schema");
  let report: GeneratorReport | null = null; let reportParsed = true;
  try { report = parseGeneratorReport(reportText); } catch { reportParsed = false; }
  // identical to ba0-m1-reconcile.ts (the original is not modified; a test proves the two agree): the base decision is the UNCHANGED finalFrom
  let baseVerdict: string | null = null;
  try { if (report !== null) { const field = fieldLevel(server.levelId)?.thresholds ?? BA0_FIELD_V1; baseVerdict = finalFrom(server, report, field.generator).decision.verdict; } } catch { baseVerdict = null; }
  let overlay = evaluateStatusOverlay({ baseVerdict, generatorStatuses: reportParsed ? report?.statuses : { malformed: "report" }, serverStatusHistogram: server.reconcileInput?.statusHistogram, serverStatus503: server.reconcileInput?.status503 });
  if (!overlayIsWellFormed(overlay)) overlay = { evaluated: false, outcome: "ERROR", reasons: ["m1.evaluation_failed"] };
  const accepted = m1Accepted(baseVerdict, overlay);
  return {
    state: "computed", outcome: overlay.outcome, reasons: overlay.reasons, passed: accepted,
    material: { baseVerdict, statusOverlay: overlay, m1StatusContract: accepted ? "accepted" : "not_accepted", inputs: { server: { runId: src.identity.runId, levelSha256: sha256(serverText) }, generator: { reportSha256: sha256(reportText) }, finalCrossChecked: false } },
  };
}
function recomputeTally(src: AuthoritySources): Recomputed {
  let result = evaluateTallyAgainstLedger(gatherTallyInput(src.packageDirectory));
  if (!tallyCheckWellFormed(result)) result = { evaluated: false, outcome: "ERROR", reasons: ["m1.tally.evaluation_failed"], differences: [], ledgerSource: "none" };
  return { state: "computed", outcome: result.outcome, reasons: result.reasons, passed: result.outcome === "PASS" && result.reasons.length === 0, material: { evaluated: result.evaluated, differences: result.differences, ledgerSource: result.ledgerSource } };
}
function recomputeReceipts(src: AuthoritySources): Recomputed {
  const reportText = src.generatorReportPath ? readText(src.generatorReportPath) : null;
  if (src.generatorReportPath && reportText === null) return unavailable("generator_report_unreadable");
  const gathered = gatherReceiptInput(src.packageDirectory, reportText);
  // the generator report is required whenever the level carried remote traffic: without it the receipt result cannot be reproduced, and it is not guessed
  const external = gathered.external as { accepted?: unknown } | undefined;
  if (reportText === null && typeof external?.accepted === "number" && external.accepted > 0) return unavailable("generator_report_not_supplied");
  const result = evaluateReceipts(gathered);
  return {
    state: "computed", outcome: result.outcome, reasons: result.reasons, passed: result.outcome === "PASS" && result.reasons.length === 0,
    material: { identities: result.identities.map((identity) => ({ ...identity, id: identity.id.replace(/_/gu, ".") })), limitations: result.limitations, campaignAttribution: result.campaignAttribution, generatorReportSha256: reportText === null ? null : sha256(reportText) },
  };
}
function recomputeObservation(src: AuthoritySources): Recomputed {
  if (!src.observerDirectory) return unavailable("observer_records_not_supplied");
  const files = observerFiles(src.observerDirectory);
  const bundle = evaluateObservationFiles({ runId: src.identity.runId, campaignId: src.identity.campaignId }, src.observerDirectory, src.maxHeartbeatGapMs, src.expectedObservation ?? null);
  if (bundle.limitMissing) return unavailable("heartbeat_gap_limit_not_set");
  const result = bundle.result;
  const digest = (file: string): string | null => { try { return sha256(readFileSync(file)); } catch { return null; } };
  return {
    state: "computed", outcome: result.outcome, reasons: dotted(result.reasons), passed: result.outcome === "PASS" && result.reasons.length === 0,
    material: { summary: JSON.parse(JSON.stringify(result.summary)), limitations: dotted(result.limitations), inputs: { canarySha256: digest(files.canaryFile), receiptsSha256: digest(files.receiptsFile), metaSha256: digest(files.metaFile), declarationSha256: digest(files.declarationFile) } },
  };
}
function recomputeProvenance(src: AuthoritySources): Recomputed {
  if (!src.retainedDirectory) return unavailable("retained_records_not_supplied");
  const report = verifyProvenance(src.packageDirectory, src.retainedDirectory);
  const l = report.levels;
  const passed = report.overall === "CONSISTENT_WITH_RECORDS" && l.byteIntegrity === "VERIFIED" && l.artifactCompleteness === "VERIFIED" && l.runBinding === "VERIFIED" && l.independentCorroboration === "CONSISTENT";
  return { state: "computed", outcome: report.overall, reasons: dotted(report.problems), passed, material: { levels: report.levels, claimedProducer: report.claimedProducer, claims: report.claims } };
}

/** Reads every authoritative input itself: the package, the generator report, the observer records and the retained provenance records. */
export function gatherAuthority(identity: M1Identity | null, sources: InputSources): Authority {
  const authority: Authority = { recomputed: {}, observed: {}, sources: {} };
  for (const name of COMPONENT_NAMES) {
    try { authority.observed[name] = observedInputs(name, sources); authority.sources[name] = evaluatorSources(name); } catch { /* left undefined: the component cannot be verified */ }
  }
  if (identity === null) return authority;
  const src: AuthoritySources = { ...sources, identity };
  const guard = (name: ComponentName, compute: (s: AuthoritySources) => Recomputed): void => { try { authority.recomputed[name] = compute(src); } catch { authority.recomputed[name] = unavailable("recomputation_failed"); } };
  guard("overlay", recomputeOverlay); guard("tally", recomputeTally); guard("receipts", recomputeReceipts); guard("observation", recomputeObservation); guard("provenance", recomputeProvenance);
  return authority;
}

/** Pure; never throws. A component PASSES only when the RECOMPUTED result passes AND the supplied result agrees with it in outcome, reasons and material claims. */
export function evaluateAcceptance(input: AcceptanceInput): AcceptanceResult {
  const components = Object.fromEntries(COMPONENT_NAMES.map((name) => [name, "ABSENT"])) as Record<ComponentName, ComponentStatus>;
  const finish = (outcome: AcceptanceOutcome, reasons: string[], provenanceLevels: Record<string, string> | null = null): AcceptanceResult =>
    ({ contract: ACCEPTANCE_CONTRACT, outcome, reasons: [...new Set(reasons)], identity: input?.packageIdentity ?? null, components, provenanceLevels, qualification: { reachable: false, blockers: QUALIFICATION_BLOCKERS } });
  try {
    if (input.packageIdentity === null) return finish("ERROR", ["m1.accept.package_identity_underivable", ...input.packageProblems.slice(0, 4).map((p) => `m1.accept.package.${p.replace(/[_:]/gu, ".")}`)]);
    const errors: string[] = []; const rejects: string[] = []; const incomplete: string[] = [];
    let provenanceLevels: Record<string, string> | null = null;
    const authority: Authority = input.authority ?? { recomputed: {}, observed: {}, sources: {} };
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
      // closed schema, then result provenance against the bytes read here: an identity match alone proves nothing
      const schema = schemaProblems(name, artifact, input.packageIdentity);
      if (schema.length > 0) { components[name] = "ERROR"; errors.push(...schema.map((p) => `m1.accept.${name}.schema.${p}`)); continue; }
      const recomputed = authority.recomputed[name];
      if (recomputed === undefined || recomputed.state === "unavailable") { components[name] = "ABSENT"; incomplete.push(`m1.accept.${name}.recomputation_inputs_unavailable`); continue; }
      const bound = provenanceProblems(name, artifact, authority.observed[name], authority.sources[name]);
      if (bound.length > 0) { components[name] = "ERROR"; errors.push(...bound.map((p) => `m1.accept.${name}.result_provenance.${p}`)); continue; }
      const supplied = suppliedView(name, artifact);
      if (supplied === null) { components[name] = "ERROR"; errors.push(`m1.accept.${name}.result_malformed`); continue; }
      if (!same({ outcome: supplied.outcome, reasons: supplied.reasons, material: supplied.material }, { outcome: recomputed.outcome, reasons: recomputed.reasons, material: recomputed.material })) {
        components[name] = "ERROR"; errors.push(`m1.accept.${name}.supplied_result_disagrees_with_recomputation`); continue;
      }
      components[name] = recomputed.passed ? "PASS" : "FAIL";
      if (!recomputed.passed) rejects.push(`m1.accept.${name}.not_passed`);
      if (name === "provenance" && isRecord(recomputed.material) && isRecord(recomputed.material.levels)) {
        const levels = recomputed.material.levels;
        provenanceLevels = Object.fromEntries(Object.entries(levels).filter(([, v]) => typeof v === "string")) as Record<string, string>;
        // the layers the prototype can never raise: any other claim is contradicted here
        if (provenanceLevels.authenticity !== "UNVERIFIED") { components[name] = "ERROR"; errors.push("m1.accept.provenance.overclaims_authenticity"); }
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

/** The result evidence runs to judge, plus the authoritative inputs acceptance reads ITSELF to recompute them (any not supplied makes its component INCOMPLETE). */
export type AcceptCli = { serverId: string; resultIds: Partial<Record<ComponentName, string>>; generatorReportPath?: string | null; observerDirectory?: string | null; retainedDirectory?: string | null };
/** Verifier-side settings that are NOT part of the run evidence (the CLI type above takes ids and input locations only). */
export type VerifierSettings = { maxHeartbeatGapMs?: number | null; /** the observation profile and committed observer identities, derived from a verified commitment; a function selects them per run (campaign). Absent: LOCAL_LOOPBACK. */ expectedObservation?: ExpectedObservation | null | ((serverId: string) => ExpectedObservation | null) };
export type AcceptOutcome = { result: AcceptanceResult; evidenceId: string };

/** The complete per-run evaluation, WITHOUT writing anything: re-derives the package identity, loads each supplied result and recomputes from the authoritative inputs. The campaign wrapper uses this same function. */
export function evaluateRunFromEvidence(cli: AcceptCli, root: string = EVIDENCE_ROOT, verifier: VerifierSettings = {}): { result: AcceptanceResult; packageDirectory: string; inputs: Record<string, string | null> } {
  const packageDirectory = resolveEvidenceDirectory(cli.serverId, root);
  const { identity, problems } = identityFromPackage(packageDirectory);
  const loaded: Partial<Record<ComponentName, LoadedComponent>> = {}; const inputs: Record<string, string | null> = {};
  for (const name of COMPONENT_NAMES) { const component = loadComponent(root, cli.resultIds[name], name); loaded[name] = component; inputs[`${name}Sha256`] = "sha256" in component && component.sha256 ? component.sha256 : null; }
  const sources: InputSources = { packageDirectory, generatorReportPath: cli.generatorReportPath ?? null, observerDirectory: cli.observerDirectory ?? null, retainedDirectory: cli.retainedDirectory ?? null, maxHeartbeatGapMs: verifier.maxHeartbeatGapMs ?? null, expectedObservation: typeof verifier.expectedObservation === "function" ? verifier.expectedObservation(cli.serverId) : (verifier.expectedObservation ?? null) };
  const authority = gatherAuthority(identity, sources);
  return { result: evaluateAcceptance({ packageIdentity: identity, packageProblems: problems, components: loaded, authority }), packageDirectory, inputs };
}

/** Re-derives the package identity, loads each supplied result and writes `m1-acceptance.json` as a NEW evidence run. */
export function m1AcceptRun(cli: AcceptCli, root: string = EVIDENCE_ROOT, now = new Date(), verifier: VerifierSettings = {}): AcceptOutcome {
  const { result, packageDirectory, inputs } = evaluateRunFromEvidence(cli, root, verifier);
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
