/**
 * M1 criterion 9 (tally versus ledger), offline and read-only.
 *
 *   tsx --conditions=react-server lab/defense/ba0-m1-tally-check.ts --server <server evidence run id>
 *
 * Reads one finalized, checksum-verified server evidence run: the plane's final telemetry tick (the outcome tally), the ledger journal (verified against the
 * digest recorded in accounting.json) and the external reducer's counters. It evaluates them with the pure evaluator and writes a NEW evidence run holding
 * `m1-tally-check.json`. It modifies no input, changes no defense decision and no instrumentation semantics, and adds no historical verdict category.
 * Partial or unreadable evidence is never accepted: missing tally => REJECT, unreadable/incomplete evidence => ERROR.
 *
 * Exit codes: 0 PASS, 1 REJECT, 2 REFUSED (bad arguments or unusable evidence directory), 4 ERROR.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory, verifyEvidenceDirectory } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { identityBlock } from "../m1/identity";
import { withResultProvenance } from "../m1/result-provenance";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "./field-thresholds";
import { FIELD_EXIT } from "./field-verdict";
import { evaluateTallyAgainstLedger, findDuplicateObjectKeys, tallyCheckWellFormed, type TallyCheckInput, type TallyCheckResult } from "./m1-tally-check";

export const TALLY_EXIT = Object.freeze({ pass: 0, reject: 1, refused: FIELD_EXIT.refused, error: FIELD_EXIT.error });
const JOURNAL_FILE = "ledger-journal-field.ndjson";

export type TallyCli = { serverId: string };
export type TallyOutcome = { exit: number; result: TallyCheckResult | null; evidenceId: string | null; refusal: string | null };

export function parseTallyArguments(argv: readonly string[]): TallyCli {
  if (argv.length !== 2 || argv[0] !== "--server" || !/^[A-Za-z0-9TZ-]{8,120}$/u.test(argv[1])) throw new Error("exactly --server <server evidence run id> is accepted");
  return { serverId: argv[1] };
}

export { MANDATORY_ARTIFACTS, verifyMandatoryInventory, type VerifiedInventory } from "../m1/inventory";
import { MANDATORY_ARTIFACTS, verifyMandatoryInventory } from "../m1/inventory";

const parseBytes = (data: Buffer | undefined): unknown => { if (data === undefined) return undefined; try { return JSON.parse(data.toString("utf8")); } catch { return undefined; } };
const DUPLICATE_KEY_CHECKED = MANDATORY_ARTIFACTS;

/** Gathers the evaluator's input from a finalized evidence directory. Anything unreadable or unverified becomes the matching null/flag, never a guess. */
export function gatherTallyInput(directory: string): TallyCheckInput {
  const inventory = verifyMandatoryInventory(directory);
  const readJson = (name: string): unknown => parseBytes(inventory.bytes.get(name));
  const telemetry = readJson("telemetry.json") as { ring?: { plane?: unknown } } | undefined;
  const ring = Array.isArray(telemetry?.ring?.plane) ? (telemetry!.ring!.plane as { final?: unknown; data?: { outcomes?: unknown } }[]) : [];
  const finals = ring.filter((tick) => tick !== null && typeof tick === "object" && tick.final === true);
  const tick = finals.length > 0 ? finals[finals.length - 1] : ring.length > 0 ? ring[ring.length - 1] : undefined;
  const externalDoc = readJson("external.json") as { counters?: unknown } | undefined;
  const accounting = readJson("accounting.json") as { anomalyTotal?: unknown; journal?: { journalSha256?: unknown; overflow?: unknown; lines?: unknown } | string } | undefined;

  let journalByKind: Record<string, number> | null = null;
  let journalIncomplete = false;
  const duplicateJournal: string[] = [];
  const journalPath = path.join(directory, JOURNAL_FILE);
  if (existsSync(journalPath)) {
    try {
      const text = readFileSync(journalPath, "utf8");
      const recorded = accounting?.journal;
      if (recorded === undefined || recorded === null || typeof recorded !== "object") journalIncomplete = true;
      else if (recorded.overflow !== false || recorded.journalSha256 !== createHash("sha256").update(text).digest("hex")) journalIncomplete = true;
      const counts: Record<string, number> = Object.create(null);
      let lines = 0;
      for (const line of text.split("\n")) {
        if (line.length === 0) continue;
        lines++;
        for (const entry of findDuplicateObjectKeys(line)) duplicateJournal.push(`${JOURNAL_FILE}:line${lines}${entry}`);
        const entry = JSON.parse(line) as { src?: unknown; k?: unknown };
        if (entry.src === "p" && typeof entry.k === "string") counts[entry.k] = (counts[entry.k] ?? 0) + 1;
      }
      if (typeof recorded === "object" && recorded !== null && recorded.lines !== lines) journalIncomplete = true;
      journalByKind = counts;
    } catch { journalByKind = null; }
  }
  // kind-ledger.json is MANDATORY for criterion 9: absent (or unverified: see the inventory) is passed on as undefined (-> REJECT / ERROR), present-but-unparseable as a malformed value (-> ERROR).
  const kindLedger = inventory.bytes.has("kind-ledger.json") ? (readJson("kind-ledger.json") ?? { unreadable: true }) : undefined;
  const processes = readJson("processes.json") as { plane?: unknown; boundary?: unknown; app?: unknown } | undefined;
  const planeFin = processes !== undefined && processes !== null && typeof processes.plane === "object" && processes.plane !== null ? processes.plane : undefined; // the string "no_fin" is not a fin
  const serverLevel = readJson("server-level.json");
  const core = readJson("core.json");
  const manifest = readJson("manifest.json");
  const level = serverLevel === undefined || core === undefined || manifest === undefined ? undefined : { serverLevel, core, manifest };
  const connections = readJson("connections.json");
  const duplicateKeys: string[] = [...duplicateJournal];
  for (const name of DUPLICATE_KEY_CHECKED) {
    const data = inventory.bytes.get(name);
    if (data !== undefined) for (const entry of findDuplicateObjectKeys(data.toString("utf8"))) duplicateKeys.push(`${name}${entry}`);
  }
  return {
    tally: tick === undefined ? { unreadable: true } : tick.data?.outcomes ?? null,
    tallyFromFinalTick: finals.length > 0,
    journalByKind, journalIncomplete,
    external: externalDoc?.counters ?? null,
    kindLedger, planeFin, level, duplicateKeys, connections, boundaryFin: processes?.boundary ?? undefined, appFin: processes?.app ?? undefined,
    inventoryProblems: inventory.problems, anomalyTotal: accounting?.anomalyTotal,
  };
}

export function m1TallyCheck(cli: TallyCli, root: string = EVIDENCE_ROOT, now = new Date()): TallyOutcome {
  const refuse = (reason: string): TallyOutcome => ({ exit: TALLY_EXIT.refused, result: null, evidenceId: null, refusal: reason });
  let directory: string;
  try { directory = resolveEvidenceDirectory(cli.serverId, root); } catch { return refuse("server evidence id is not a plain run id"); }
  if (!existsSync(path.join(directory, "SHA256SUMS"))) return refuse("server evidence is missing or not finalized");
  const malformedInventory = verifyMandatoryInventory(directory).problems.filter((problem) => problem.startsWith("SHA256SUMS:"));
  if (malformedInventory.length > 0) return refuse(`server evidence inventory is not canonical: ${malformedInventory.slice(0, 3).join(",")}`);
  const tampered = verifyEvidenceDirectory(directory);
  if (tampered.length > 0) return refuse(`server evidence failed its checksums: ${tampered.slice(0, 3).join(",")}`);

  let result = evaluateTallyAgainstLedger(gatherTallyInput(directory));
  if (!tallyCheckWellFormed(result)) result = { evaluated: false, outcome: "ERROR", reasons: ["m1.tally.evaluation_failed"], differences: [], ledgerSource: "none" };
  const evidence = new EvidenceRun("m1-tally-check", "m1-tally-check", now, root);
  evidence.addJsonArtifact("m1-tally-check.json", withResultProvenance("tally", {
    contract: "m1-tally-check-v1",
    scope: "M1 criterion 9: the plane's own outcome tally against the collector ledger (journal plus external reducer counters) for one finalized level; observation only",
    runId: cli.serverId,
    ...identityBlock(directory),
    tallyCheck: { evaluated: result.evaluated, outcome: result.outcome, reasons: result.reasons },
    differences: result.differences,
    ledgerSource: result.ledgerSource,
    claims: { defenseQualification: "not_claimed", notClaimed: ["pre-parser traffic and kernel drops are not seen by the tally", "events lost on the plane channel before numbering are outside every record"] },
  }, { packageDirectory: directory }, now));
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-tally-check",
    result: result.outcome === "PASS" ? "PASS" : result.outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: result.reasons.slice(0, 40),
    metrics: { overlayOutcome: result.outcome, evaluated: result.evaluated, networkActivity: false },
  });
  return { exit: result.outcome === "PASS" ? TALLY_EXIT.pass : result.outcome === "REJECT" ? TALLY_EXIT.reject : TALLY_EXIT.error, result, evidenceId: evidence.id, refusal: null };
}

async function main(argv: readonly string[]): Promise<number> {
  let cli: TallyCli;
  try { cli = parseTallyArguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return TALLY_EXIT.refused; }
  const outcome = m1TallyCheck(cli);
  if (outcome.refusal !== null) { console.error(`REFUSED  ${outcome.refusal}`); return outcome.exit; }
  console.log(`${outcome.result?.outcome}  M1 criterion 9 tally versus ledger (observation only)`);
  for (const reason of outcome.result?.reasons ?? []) console.log(`  - ${reason}`);
  for (const difference of outcome.result?.differences ?? []) console.log(`  diff ${difference.kind}: plane ${difference.plane}, ledger ${difference.ledger}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(TALLY_EXIT.error); });
}
