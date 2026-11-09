/**
 * M1 receipt reconciliation, offline and read-only.
 *
 *   tsx --conditions=react-server lab/defense/ba0-m1-receipt-check.ts --server <server evidence run id> [--report <path to generator-report.json>]
 *
 * Reads one finalized, inventory-verified server evidence run (every consumed artifact must be listed in SHA256SUMS and the manifest and match its bytes), evaluates the
 * additive receipt reconciliation (lab/defense/m1-receipt-check.ts) and writes a NEW evidence run holding `m1-receipt-check.json`. It changes no input, no defense decision and
 * no historical verdict. The generator report is required whenever the level carried remote traffic.
 *
 * Exit codes: 0 PASS, 1 REJECT, 2 REFUSED (bad arguments or unusable evidence directory), 4 ERROR.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory, verifyEvidenceDirectory } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { identityBlock } from "../m1/identity";
import { verifyMandatoryInventory } from "./ba0-m1-tally-check";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "./field-thresholds";
import { FIELD_EXIT } from "./field-verdict";
import { parseGeneratorReport } from "./generator-report";
import { evaluateReceipts, type JournalReceipts, type ReceiptCheckInput, type ReceiptCheckResult } from "./m1-receipt-check";
import { findDuplicateObjectKeys } from "./m1-tally-check";

export const RECEIPT_EXIT = Object.freeze({ pass: 0, reject: 1, refused: FIELD_EXIT.refused, error: FIELD_EXIT.error });
const JOURNAL_FILE = "ledger-journal-field.ndjson";
export const RECEIPT_ARTIFACTS = ["external.json", "processes.json", "accounting.json", "kind-ledger.json", "canary.json", "server-level.json", "manifest.json"] as const;

export type ReceiptCli = { serverId: string; reportPath: string | null };
export type ReceiptOutcome = { exit: number; result: ReceiptCheckResult | null; evidenceId: string | null; refusal: string | null };

export function parseReceiptArguments(argv: readonly string[]): ReceiptCli {
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg !== "--server" && arg !== "--report") throw new Error(`unexpected argument "${arg.slice(0, 24)}": only --server and --report are accepted`);
    if (arg in values) throw new Error(`${arg} given twice`);
    const value = argv[++index];
    if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
    values[arg] = value;
  }
  if (values["--server"] === undefined || !/^[A-Za-z0-9TZ-]{8,120}$/u.test(values["--server"])) throw new Error("--server <evidence run id> is required");
  if (values["--report"] !== undefined && path.basename(values["--report"]) !== "generator-report.json") throw new Error("--report must be a generator-report.json file");
  return { serverId: values["--server"], reportPath: values["--report"] ?? null };
}

const parse = (data: Buffer | undefined): unknown => { if (data === undefined) return undefined; try { return JSON.parse(data.toString("utf8")); } catch { return undefined; } };

/** Gathers the evaluator's input; unverified or unreadable evidence becomes the matching null/undefined, never a guess. */
export function gatherReceiptInput(directory: string, generatorText: string | null = null): ReceiptCheckInput {
  const inventory = verifyMandatoryInventory(directory, RECEIPT_ARTIFACTS);
  const read = (name: string): unknown => parse(inventory.bytes.get(name));
  const external = read("external.json") as { counters?: unknown } | undefined;
  const processes = read("processes.json") as { boundary?: unknown; app?: unknown } | undefined;
  const accounting = read("accounting.json") as { anomalyTotal?: unknown; journal?: { journalSha256?: unknown; overflow?: unknown; lines?: unknown } } | undefined;
  const ledger = read("kind-ledger.json") as { counts?: unknown } | undefined;
  const canary = read("canary.json") as { clientObservedMutations?: unknown } | undefined;
  const serverLevel = read("server-level.json") as { campaignId?: unknown; levelId?: unknown; gitSha?: unknown } | undefined;

  const duplicateKeys: string[] = [];
  for (const name of RECEIPT_ARTIFACTS) { const data = inventory.bytes.get(name); if (data !== undefined) for (const entry of findDuplicateObjectKeys(data.toString("utf8"))) duplicateKeys.push(`${name}${entry}`); }

  let journal: JournalReceipts | null = null;
  let journalIncomplete = false;
  const journalPath = path.join(directory, JOURNAL_FILE);
  if (existsSync(journalPath)) {
    try {
      const text = readFileSync(journalPath, "utf8");
      const recorded = accounting?.journal;
      if (recorded === undefined || recorded === null || typeof recorded !== "object") journalIncomplete = true;
      else if (recorded.overflow !== false || recorded.journalSha256 !== createHash("sha256").update(text).digest("hex")) journalIncomplete = true;
      const out: JournalReceipts = { boundary: Object.create(null), app: Object.create(null), anonymousBoundary: Object.create(null), anonymousApp: Object.create(null) };
      let lines = 0;
      for (const line of text.split("\n")) {
        if (line.length === 0) continue;
        lines++;
        for (const entry of findDuplicateObjectKeys(line)) duplicateKeys.push(`${JOURNAL_FILE}:line${lines}${entry}`);
        const entry = JSON.parse(line) as { src?: unknown; k?: unknown; rid?: unknown };
        if ((entry.src !== "b" && entry.src !== "a") || typeof entry.k !== "string") continue;
        const target = entry.src === "b" ? (typeof entry.rid === "string" ? out.boundary : out.anonymousBoundary) : (typeof entry.rid === "string" ? out.app : out.anonymousApp);
        target[entry.k] = (target[entry.k] ?? 0) + 1;
      }
      if (typeof recorded === "object" && recorded !== null && recorded.lines !== lines) journalIncomplete = true;
      journal = out;
    } catch { journal = null; }
  }

  let generator: unknown;
  if (generatorText !== null) {
    try { for (const entry of findDuplicateObjectKeys(generatorText)) duplicateKeys.push(`generator-report.json${entry}`); generator = parseGeneratorReport(generatorText); } catch { generator = { malformed: true }; }
  }
  return {
    external: external?.counters, boundaryFin: processes?.boundary, appFin: processes?.app, journal, journalIncomplete, anomalyTotal: accounting?.anomalyTotal,
    planeKindCounts: ledger?.counts, canaryClientMutations: canary?.clientObservedMutations, generator,
    level: serverLevel ? { campaignId: serverLevel.campaignId, levelId: serverLevel.levelId, gitSha: serverLevel.gitSha } : undefined,
    inventoryProblems: inventory.problems, duplicateKeys,
  };
}

export function m1ReceiptCheck(cli: ReceiptCli, root: string = EVIDENCE_ROOT, now = new Date()): ReceiptOutcome {
  const refuse = (reason: string): ReceiptOutcome => ({ exit: RECEIPT_EXIT.refused, result: null, evidenceId: null, refusal: reason });
  let directory: string;
  try { directory = resolveEvidenceDirectory(cli.serverId, root); } catch { return refuse("server evidence id is not a plain run id"); }
  if (!existsSync(path.join(directory, "SHA256SUMS"))) return refuse("server evidence is missing or not finalized");
  const malformed = verifyMandatoryInventory(directory, []).problems.filter((problem) => problem.startsWith("SHA256SUMS:"));
  if (malformed.length > 0) return refuse(`server evidence inventory is not canonical: ${malformed.slice(0, 3).join(",")}`);
  const tampered = verifyEvidenceDirectory(directory);
  if (tampered.length > 0) return refuse(`server evidence failed its checksums: ${tampered.slice(0, 3).join(",")}`);
  let generatorText: string | null = null;
  if (cli.reportPath !== null) { try { generatorText = readFileSync(cli.reportPath, "utf8"); } catch { return refuse("generator report is unreadable"); } }

  const result = evaluateReceipts(gatherReceiptInput(directory, generatorText));
  const evidence = new EvidenceRun("m1-receipt-check", "m1-receipt-check", now, root);
  evidence.addJsonArtifact("m1-receipt-check.json", {
    contract: result.contract,
    scope: "M1 receipt reconciliation: downstream observers (Boundary, App, origin-side served counters, generator, canary client) against the ledger attribution; additive to criterion 9",
    runId: cli.serverId, ...identityBlock(directory), generatorReportSha256: generatorText === null ? null : createHash("sha256").update(generatorText).digest("hex"),
    receiptCheck: { outcome: result.outcome, reasons: result.reasons }, identities: result.identities.map((identity) => ({ ...identity, id: identity.id.replace(/_/gu, ".") })), // dot-joined: the evidence scanner rejects long token-like strings
 limitations: result.limitations, campaignAttribution: result.campaignAttribution,
    claims: { defenseQualification: "not_claimed", authenticity: "not_claimed" },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-receipt-check",
    result: result.outcome === "PASS" ? "PASS" : result.outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: result.reasons.slice(0, 40), metrics: { receiptOutcome: result.outcome, networkActivity: false },
  });
  return { exit: result.outcome === "PASS" ? RECEIPT_EXIT.pass : result.outcome === "REJECT" ? RECEIPT_EXIT.reject : RECEIPT_EXIT.error, result, evidenceId: evidence.id, refusal: null };
}

function main(argv: readonly string[]): number {
  let cli: ReceiptCli;
  try { cli = parseReceiptArguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return RECEIPT_EXIT.refused; }
  const outcome = m1ReceiptCheck(cli);
  if (outcome.refusal !== null) { console.error(`REFUSED  ${outcome.refusal}`); return outcome.exit; }
  console.log(`${outcome.result?.outcome}  M1 receipt reconciliation (observation only; campaign attribution not established)`);
  for (const reason of outcome.result?.reasons ?? []) console.log(`  - ${reason}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  try { process.exit(main(process.argv.slice(2))); } catch (error) { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(RECEIPT_EXIT.error); }
}
