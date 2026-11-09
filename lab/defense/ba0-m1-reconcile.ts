/**
 * M1 status-contract overlay (criterion 8), offline. Additive: it runs AFTER, and independently of, the historical reconcile.
 *
 *   tsx --conditions=react-server lab/defense/ba0-m1-reconcile.ts --server <server evidence run id> --report <path to generator-report.json> [--final <final evidence run id>]
 *
 * It reads the same two inputs as `ba0-field-reconcile.ts`, recomputes the base decision with the UNCHANGED `finalFrom` (a pure function), evaluates
 * the status contract (m1-status-contract.ts) and writes a separate evidence run holding `m1-verdict.json`. It never reads or writes the historical
 * `final.json` except, with --final, to cross-check that the recomputed base verdict equals the recorded one (a mismatch is an ERROR, not a pass).
 * No network activity, no process is started, nothing the server enforced is changed, and no historical verdict category is introduced.
 *
 * Exit codes: 0 overlay PASS with a base VALID verdict (M1 status contract accepted), 1 overlay REJECT, 2 REFUSED (bad arguments or unusable input,
 * nothing evaluated, nothing accepted), 4 overlay ERROR (evidence present but not evaluable; never acceptance).
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory, verifyEvidenceDirectory } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { identityBlock } from "../m1/identity";
import { BA0_FIELD_V1, ba0FieldFingerprint, fieldLevel } from "./field-thresholds";
import { FIELD_EXIT } from "./field-verdict";
import { parseGeneratorReport, type GeneratorReport } from "./generator-report";
import { M1_ALLOWED_STATUS_LABEL, M1_STATUS_CONTRACT_ID, evaluateStatusOverlay, m1Accepted, overlayIsWellFormed, type StatusOverlay } from "./m1-status-contract";
import { SERVER_LEVEL_SCHEMA, finalFrom, type ServerLevelEvidence } from "./reconcile";

const sha256 = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");

export const M1_EXIT = Object.freeze({ pass: 0, reject: 1, refused: FIELD_EXIT.refused, error: FIELD_EXIT.error });
export const M1_NOT_CLAIMED = Object.freeze([
  "302/303 and 403/404 coverage: the reviewed fixture never produces them",
  "network, transport or origin-network behaviour",
  "anything about the real application: the origin is the synthetic stand-in",
  "criterion 7 repeatability and criterion 9 tally agreement: they are evaluated elsewhere",
]);

export type M1Cli = { serverId: string; reportPath: string; finalId: string | null };
export type M1Outcome = {
  exit: number;
  baseVerdict: string | null;
  overlay: StatusOverlay | null;
  accepted: boolean;
  reasons: string[];
  evidenceId: string | null;
};

/** Strict: --server and --report are required (a report is mandatory: without it the generator view is missing and the overlay cannot pass). */
export function parseM1Arguments(argv: readonly string[]): M1Cli {
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg !== "--server" && arg !== "--report" && arg !== "--final") throw new Error(`unexpected argument "${arg.slice(0, 24)}": only --server, --report and --final are accepted`);
    if (arg in values) throw new Error(`${arg} given twice`);
    const value = argv[++index];
    if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
    values[arg] = value;
  }
  if (values["--server"] === undefined) throw new Error("--server is required");
  if (values["--report"] === undefined) throw new Error("--report is required");
  for (const key of ["--server", "--final"]) if (values[key] !== undefined && !/^[A-Za-z0-9TZ-]{8,120}$/u.test(values[key])) throw new Error(`${key} must be an evidence run id`);
  if (path.basename(values["--report"]) !== "generator-report.json") throw new Error("--report must be a generator-report.json file");
  return { serverId: values["--server"], reportPath: values["--report"], finalId: values["--final"] ?? null };
}

export function m1Reconcile(cli: M1Cli, root: string = EVIDENCE_ROOT, now = new Date()): M1Outcome {
  const refuse = (reason: string): M1Outcome => ({ exit: M1_EXIT.refused, baseVerdict: null, overlay: null, accepted: false, reasons: [reason], evidenceId: null });
  let directory: string;
  try { directory = resolveEvidenceDirectory(cli.serverId, root); } catch { return refuse("server evidence id is not a plain run id"); }
  const serverFile = path.join(directory, "server-level.json");
  if (!existsSync(serverFile) || !existsSync(path.join(directory, "SHA256SUMS"))) return refuse("server evidence is missing or not finalized");
  const tampered = verifyEvidenceDirectory(directory);
  if (tampered.length > 0) return refuse(`server evidence failed its checksums: ${tampered.slice(0, 3).join(",")}`);
  let serverText: string;
  let server: ServerLevelEvidence;
  try { serverText = readFileSync(serverFile, "utf8"); server = JSON.parse(serverText) as ServerLevelEvidence; } catch { return refuse("server-level.json is not JSON"); }
  if (server === null || typeof server !== "object" || server.schema !== SERVER_LEVEL_SCHEMA) return refuse("server-level.json is not a level evidence this reconcile understands");

  let reportText: string;
  try { reportText = readFileSync(cli.reportPath, "utf8"); } catch { return refuse("generator report is unreadable"); }
  let report: GeneratorReport | null = null;
  let reportParsed = true;
  try { report = parseGeneratorReport(reportText); } catch { reportParsed = false; }

  // The base decision: the UNCHANGED historical path over the same two inputs. Failure to compute it is an overlay ERROR, never a pass.
  let baseVerdict: string | null = null;
  const baseReasons: string[] = [];
  try {
    if (report !== null) {
      const field = fieldLevel(server.levelId)?.thresholds ?? BA0_FIELD_V1;
      const { decision } = finalFrom(server, report, field.generator);
      baseVerdict = decision.verdict;
    }
  } catch { baseVerdict = null; }
  if (cli.finalId !== null) {
    try {
      const finalFile = path.join(resolveEvidenceDirectory(cli.finalId, root), "final.json");
      const recorded = (JSON.parse(readFileSync(finalFile, "utf8")) as { finalVerdict?: unknown }).finalVerdict;
      if (recorded !== baseVerdict) { baseVerdict = null; baseReasons.push("m1.base_verdict_cross_check_failed"); }
    } catch { baseVerdict = null; baseReasons.push("m1.base_verdict_cross_check_failed"); }
  }

  let overlay = evaluateStatusOverlay({
    baseVerdict, generatorStatuses: reportParsed ? report?.statuses : { malformed: "report" },
    serverStatusHistogram: server.reconcileInput?.statusHistogram, serverStatus503: server.reconcileInput?.status503,
  });
  if (baseReasons.length > 0) overlay = { evaluated: false, outcome: "ERROR", reasons: [...new Set([...overlay.reasons, ...baseReasons])] };
  // Defence in depth: an overlay that violates its own schema is never written as anything but ERROR.
  if (!overlayIsWellFormed(overlay)) overlay = { evaluated: false, outcome: "ERROR", reasons: ["m1.evaluation_failed"] };

  const accepted = m1Accepted(baseVerdict, overlay);
  const evidence = new EvidenceRun("m1-verdict", "m1-status-overlay", now, root);
  evidence.addJsonArtifact("m1-verdict.json", {
    contract: M1_STATUS_CONTRACT_ID,
    scope: "M1 status contract for the existing synthetic-origin fixture of the L1/L2 application plane; an overlay over, never a replacement of, the historical reconcile",
    ...identityBlock(directory),
    baseVerdict,
    statusOverlay: overlay,
    m1StatusContract: accepted ? "accepted" : "not_accepted",
    allowedStatuses: M1_ALLOWED_STATUS_LABEL,
    inputs: { server: { runId: cli.serverId, levelSha256: sha256(serverText) }, generator: { reportSha256: sha256(reportText) }, finalCrossChecked: cli.finalId !== null },
    claims: { defenseQualification: "not_claimed", notClaimed: [...M1_NOT_CLAIMED] },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "offline-m1-overlay",
    result: overlay.outcome === "PASS" ? "PASS" : overlay.outcome === "REJECT" ? "FAIL" : "ERROR",
    resultReasons: overlay.reasons.slice(0, 40),
    metrics: { baseVerdict, overlayOutcome: overlay.outcome, evaluated: overlay.evaluated, networkActivity: false },
  });
  const exit = overlay.outcome === "PASS" ? (accepted ? M1_EXIT.pass : M1_EXIT.reject) : overlay.outcome === "REJECT" ? M1_EXIT.reject : M1_EXIT.error;
  return { exit, baseVerdict, overlay, accepted, reasons: overlay.reasons, evidenceId: evidence.id };
}

async function main(argv: readonly string[]): Promise<number> {
  let cli: M1Cli;
  try { cli = parseM1Arguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return M1_EXIT.refused; }
  const outcome = m1Reconcile(cli);
  console.log(`${outcome.overlay?.outcome ?? "REFUSED"}  M1 status contract overlay (base verdict ${outcome.baseVerdict ?? "unknown"}; accepted=${outcome.accepted}; scope: existing synthetic-origin fixture only)`);
  for (const reason of outcome.reasons) console.log(`  - ${reason}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(M1_EXIT.error); });
}
