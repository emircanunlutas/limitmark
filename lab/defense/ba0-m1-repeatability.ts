/**
 * M1 criterion 7 (repeatability), offline and read-only.
 *
 *   tsx --conditions=react-server lab/defense/ba0-m1-repeatability.ts --server <run id> --report <generator-report.json> (x3, in this order per run)
 *
 * For each of exactly three runs it reads the finalized, checksum-verified server evidence and the generator report, recomputes the base decision with the
 * UNCHANGED `finalFrom` (pure), reads the shed reasons from `external.json`, and hands the extracted facts to the pure evaluator. It writes one new evidence run
 * holding `m1-repeatability.json`; it never modifies, re-signs or re-labels any input, and it introduces no historical verdict category.
 * A run whose evidence is missing, unreadable, tampered or malformed is not skipped: the whole evaluation is ERROR (never acceptance).
 *
 * Exit codes: 0 PASS, 1 REJECT, 2 REFUSED (bad arguments), 4 ERROR (evidence not evaluable).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory, verifyEvidenceDirectory } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { BA0_FIELD_V1, ba0FieldFingerprint, fieldLevel } from "./field-thresholds";
import { FIELD_EXIT } from "./field-verdict";
import { parseGeneratorReport } from "./generator-report";
import { M1_REPEATABILITY_RUNS, M1_SHED_SHARE_TOLERANCE_POINTS, evaluateRepeatability, repeatabilityWellFormed, type RepeatabilityResult, type RepeatabilityRun } from "./m1-repeatability";
import { SERVER_LEVEL_SCHEMA, finalFrom, type ServerLevelEvidence } from "./reconcile";

const sha256 = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
export const REPEAT_EXIT = Object.freeze({ pass: 0, reject: 1, refused: FIELD_EXIT.refused, error: FIELD_EXIT.error });

export type RepeatCli = { runs: { serverId: string; reportPath: string }[] };
export type RepeatOutcome = { exit: number; result: RepeatabilityResult | null; evidenceId: string | null; refusal: string | null };

/** Strict: exactly three (--server, --report) pairs, each --server immediately followed by its --report. */
export function parseRepeatArguments(argv: readonly string[]): RepeatCli {
  const runs: { serverId: string; reportPath: string }[] = [];
  if (argv.length !== M1_REPEATABILITY_RUNS * 4) throw new Error(`exactly ${M1_REPEATABILITY_RUNS} runs are required: --server <id> --report <generator-report.json> for each`);
  for (let index = 0; index < argv.length; index += 4) {
    const [a, serverId, b, reportPath] = argv.slice(index, index + 4);
    if (a !== "--server" || b !== "--report" || serverId === undefined || reportPath === undefined) throw new Error("each run is --server <run id> immediately followed by --report <path>");
    if (!/^[A-Za-z0-9TZ-]{8,120}$/u.test(serverId)) throw new Error("--server must be an evidence run id");
    if (path.basename(reportPath) !== "generator-report.json") throw new Error("--report must be a generator-report.json file");
    runs.push({ serverId, reportPath });
  }
  return { runs };
}

/** One run's facts, or null when anything about it cannot be read and verified. Never throws. */
export function extractRun(serverId: string, reportPath: string, root: string): RepeatabilityRun | null {
  try {
    const directory = resolveEvidenceDirectory(serverId, root);
    const serverFile = path.join(directory, "server-level.json");
    const externalFile = path.join(directory, "external.json");
    if (!existsSync(serverFile) || !existsSync(externalFile) || !existsSync(path.join(directory, "SHA256SUMS"))) return null;
    if (verifyEvidenceDirectory(directory).length > 0) return null;
    const server = JSON.parse(readFileSync(serverFile, "utf8")) as ServerLevelEvidence;
    if (server === null || typeof server !== "object" || server.schema !== SERVER_LEVEL_SCHEMA || server.window === null || server.window === undefined) return null;
    const report = parseGeneratorReport(readFileSync(reportPath, "utf8"));
    const field = fieldLevel(server.levelId)?.thresholds ?? BA0_FIELD_V1;
    const { decision } = finalFrom(server, report, field.generator);
    const external = JSON.parse(readFileSync(externalFile, "utf8")) as { counters?: { l2?: { shedByReason?: Record<string, number> } } };
    const shedReasonCounts = external.counters?.l2?.shedByReason;
    if (shedReasonCounts === undefined) return null;
    return {
      serverRunId: serverId, generatorRunId: report.runId, campaignId: server.campaignId, levelId: server.levelId, gitSha: server.gitSha, paramsFingerprintSha256: server.paramsFingerprintSha256,
      workloadFingerprintSha256: server.workloadFingerprintSha256, workers: server.workers, windowOpenedAt: server.window.openedAt, windowClosedAt: server.window.closedAt, baseVerdict: decision.verdict,
      shedReasonCounts, externalAccepted: server.reconcileInput.externalAccepted, status503Total: server.reconcileInput.status503.total,
    };
  } catch { return null; }
}

export function m1Repeatability(cli: RepeatCli, root: string = EVIDENCE_ROOT, now = new Date()): RepeatOutcome {
  const extracted = cli.runs.map((run) => extractRun(run.serverId, run.reportPath, root));
  let result = evaluateRepeatability(extracted);
  if (!repeatabilityWellFormed(result)) result = { evaluated: false, outcome: "ERROR", reasons: ["m1.repeat.evaluation_failed"], details: null };
  const evidence = new EvidenceRun("m1-repeatability", "m1-repeatability", now, root);
  evidence.addJsonArtifact("m1-repeatability.json", {
    contract: "m1-repeatability-v1",
    scope: "M1 criterion 7 over three finalized runs of the existing synthetic-origin fixture; it checks distinct executions with non-overlapping windows, not a freshly provisioned machine",
    toleranceShedSharePoints: M1_SHED_SHARE_TOLERANCE_POINTS,
    repeatability: { evaluated: result.evaluated, outcome: result.outcome, reasons: result.reasons },
    details: result.details,
    inputs: cli.runs.map((run, index) => ({ runId: run.serverId, extracted: extracted[index] !== null, reportSha256: (() => { try { return sha256(readFileSync(run.reportPath)); } catch { return "unreadable"; } })() })),
    claims: { defenseQualification: "not_claimed", notClaimed: ["freshly provisioned machine or empty caches: not provable from evidence", "criterion 8 and criterion 9: evaluated by their own tools"] },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-repeatability",
    result: result.outcome === "PASS" ? "PASS" : result.outcome === "REJECT" ? "FAIL" : "ERROR", resultReasons: result.reasons.slice(0, 40),
    metrics: { overlayOutcome: result.outcome, evaluated: result.evaluated, networkActivity: false },
  });
  return { exit: result.outcome === "PASS" ? REPEAT_EXIT.pass : result.outcome === "REJECT" ? REPEAT_EXIT.reject : REPEAT_EXIT.error, result, evidenceId: evidence.id, refusal: null };
}

async function main(argv: readonly string[]): Promise<number> {
  let cli: RepeatCli;
  try { cli = parseRepeatArguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return REPEAT_EXIT.refused; }
  const outcome = m1Repeatability(cli);
  console.log(`${outcome.result?.outcome ?? "REFUSED"}  M1 criterion 7 repeatability (three runs; no machine-freshness claim)`);
  for (const reason of outcome.result?.reasons ?? []) console.log(`  - ${reason}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(REPEAT_EXIT.error); });
}
