/**
 * BA0 FIELD LEVEL offline reconcile: the ONLY producer of a final verdict.
 *
 *   npm run lab:ba0:field:reconcile -- --server <server evidence run id> --report <path to generator-report.json>
 *
 * It reads (a) the server-side evidence of one level (verified against its SHA256SUMS) and (b) the generator report, compares them
 * (G1..G6, see reconcile.ts) and writes a small final evidence run. It performs no network activity, starts no process and changes nothing
 * the server enforced: the generator's numbers are evidence about the generator and can only ADD reasons.
 *
 * Final verdicts: EXTERNAL-L7-QUALIFICATION-VALID | INVALID | ABORTED.
 *
 *   VALID is scoped to the exact {commit, campaignId, levelId, N, parameter fingerprint, workload fingerprint} the two inputs share. It
 *   means: for this level, the server-side ledger accounted for every request that reached the Defense Plane ingress with no unexplained
 *   residual; hostile traffic that reached the application stayed within the predicted budget with no execution outside the proof chain; the
 *   independent canary completed every journey with no legitimate refusal; telemetry was complete; nothing but the reviewed plane listener was
 *   exposed on the host; and the generator's report agrees with the ledger and was not saturated. It does NOT mean DDoS resistance,
 *   capacity, bot detection, read-flood resistance, fairness, network or origin isolation, TLS behaviour, behaviour at any other level,
 *   protection of the real application, or production readiness.
 *
 * Exit codes: 0 VALID, 1 INVALID, 2 REFUSED (bad input), 3 ABORTED, 4 error.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory, verifyEvidenceDirectory } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { NOT_CLAIMED_FIELD, SCOPE_STATEMENT_FIELD } from "./field-evidence";
import { BA0_FIELD_V1, fieldLevel, ba0FieldFingerprint } from "./field-thresholds";
import { FIELD_EXIT, type FinalVerdict } from "./field-verdict";
import { parseGeneratorReport, type GeneratorReport } from "./generator-report";
import { SERVER_LEVEL_SCHEMA, finalFrom, type ReconcileResult, type ServerLevelEvidence } from "./reconcile";

const sha256 = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");

export type ReconcileOutcome = {
  exit: number;
  verdict: FinalVerdict | "REFUSED";
  reasons: string[];
  evidenceId: string | null;
  result: ReconcileResult | null;
};

export type ReconcileCli = { serverId: string; reportPath: string | null };

/** Strict: exactly --server (a run id) and --report (a file whose name is generator-report.json). */
export function parseReconcileArguments(argv: readonly string[]): ReconcileCli {
  const values: Record<string, string> = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg !== "--server" && arg !== "--report") throw new Error(`unexpected argument "${arg.slice(0, 24)}": only --server and --report are accepted`);
    if (arg in values) throw new Error(`${arg} given twice`);
    const value = argv[++index];
    if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
    values[arg] = value;
  }
  if (values["--server"] === undefined) throw new Error("--server is required");
  if (!/^[A-Za-z0-9TZ-]{8,120}$/.test(values["--server"])) throw new Error("--server must be an evidence run id");
  if (values["--report"] !== undefined && path.basename(values["--report"]) !== "generator-report.json") throw new Error("--report must be a generator-report.json file");
  return { serverId: values["--server"], reportPath: values["--report"] ?? null };
}

/** Reconciles one level. `root` is the evidence root (a seam for tests). */
export function reconcileLevel(cli: ReconcileCli, root: string = EVIDENCE_ROOT, now = new Date()): ReconcileOutcome {
  const refuse = (reason: string): ReconcileOutcome => ({ exit: FIELD_EXIT.refused, verdict: "REFUSED", reasons: [reason], evidenceId: null, result: null });
  let directory: string;
  try { directory = resolveEvidenceDirectory(cli.serverId, root); } catch { return refuse("server evidence id is not a plain run id"); }
  const serverFile = path.join(directory, "server-level.json");
  if (!existsSync(serverFile) || !existsSync(path.join(directory, "SHA256SUMS"))) return refuse("server evidence is missing or not finalized");
  const tampered = verifyEvidenceDirectory(directory);
  if (tampered.length > 0) return refuse(`server evidence failed its checksums: ${tampered.slice(0, 3).join(",")}`);
  let server: ServerLevelEvidence;
  try { server = JSON.parse(readFileSync(serverFile, "utf8")) as ServerLevelEvidence; } catch { return refuse("server-level.json is not JSON"); }
  if (server.schema !== SERVER_LEVEL_SCHEMA || server.reconcileInput === null || server.reconcileInput === undefined) return refuse("server-level.json is not a level evidence this reconcile understands");

  let report: GeneratorReport | null = null;
  let reportSha: string | null = null;
  const reasons: string[] = [];
  if (cli.reportPath !== null) {
    try {
      const text = readFileSync(cli.reportPath, "utf8");
      reportSha = sha256(text);
      report = parseGeneratorReport(text);
    } catch (error) { return refuse(`generator report unusable: ${evidenceSafeError(error)}`.slice(0, 160)); }
  }
  // N=1 evidence retains the historical reconciliation contract; the selected set supplies only limits and manifest identity.
  const field = fieldLevel(server.levelId)?.thresholds ?? BA0_FIELD_V1;
  const { decision, result } = finalFrom(server, report, field.generator);
  for (const reason of decision.reasons) reasons.push(`${reason.code}${reason.detail ? ` ${reason.detail}` : ""}`);

  const evidence = new EvidenceRun("field-final", "reconcile", now, root);
  evidence.addJsonArtifact("final.json", {
    scope: SCOPE_STATEMENT_FIELD,
    finalVerdict: decision.verdict, failureClass: decision.failureClass, reasons: decision.reasons.map((reason) => ({ code: reason.code, detail: reason.detail ?? null })),
    validScopedTo: {
      gitSha: server.gitSha, campaignId: server.campaignId, levelId: server.levelId, workers: server.workers,
      paramsFingerprintSha256: server.paramsFingerprintSha256, workloadFingerprintSha256: server.workloadFingerprintSha256,
    },
    // The run id key is the one long identifier the evidence scanner permits, under exactly this name.
    inputs: { server: { runId: cli.serverId, levelSha256: sha256(readFileSync(serverFile)) }, generator: { reportSha256: reportSha ?? "not_supplied" } },
    serverSide: { status: server.serverSide.status, failureClass: server.serverSide.failureClass },
    identities: result.identities, informational: result.informational,
    claims: { defenseQualification: "not_claimed", networkNonBypass: "not_measured", originNetworkIsolation: "not_measured", notClaimed: [...NOT_CLAIMED_FIELD] },
  });
  evidence.finalize({
    git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(field), engine: "offline-reconcile",
    result: decision.verdict === "EXTERNAL-L7-QUALIFICATION-VALID" ? "EXTERNAL-L7-QUALIFICATION-VALID" : decision.verdict === "INVALID" ? "INVALID" : "ABORTED",
    resultReasons: reasons.slice(0, 40).map((reason) => `field.${reason.replace(/[^A-Za-z0-9_. -]/g, "_")}`.slice(0, 200)),
    metrics: { finalVerdict: decision.verdict, failureClass: decision.failureClass, defenseQualification: "not_claimed", networkActivity: false },
  });
  const exit = decision.verdict === "EXTERNAL-L7-QUALIFICATION-VALID" ? FIELD_EXIT.complete : decision.verdict === "INVALID" ? FIELD_EXIT.invalid : FIELD_EXIT.aborted;
  return { exit, verdict: decision.verdict, reasons, evidenceId: evidence.id, result };
}

async function main(argv: readonly string[]): Promise<number> {
  let cli: ReconcileCli;
  try { cli = parseReconcileArguments(argv); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "bad arguments"}`); return FIELD_EXIT.refused; }
  const outcome = reconcileLevel(cli);
  console.log(`${outcome.verdict}  ba0 field level reconcile (DDoS resistance, capacity, network and origin isolation, and production readiness are NOT claimed; VALID is scoped to the exact level and campaign)`);
  for (const reason of outcome.reasons) console.log(`  - ${reason}`);
  for (const entry of outcome.result?.identities ?? []) console.log(`  ${entry.ok ? "ok  " : "FAIL"} ${entry.id}`);
  console.log(`evidence=${outcome.evidenceId ?? "none"}`);
  return outcome.exit;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(FIELD_EXIT.error); });
}
