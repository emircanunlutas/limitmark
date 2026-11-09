/**
 * M1 command line: thin, explicit-path entry points over the EXISTING evaluators. No decision is made here: every command calls the same function the library tests exercise
 * (`writeObservationResult`, `evaluateObservationFiles`, `writeProvenanceResult`, `m1AcceptRun`, `m1LocalCampaign`, `buildCommitment`, `verifySeal`). A supplied PASS artifact is never
 * trusted: acceptance and the campaign recompute from the authoritative inputs. Authoritative evidence is only read; commands that record a result write a NEW evidence run.
 *
 * Usage:  tsx lab/m1/cli.ts <command> [--flag value ...]      (also: npm run lab:m1 -- <command> ...)
 *   observe       --server ID --observer-dir DIR [--max-heartbeat-gap-ms N]
 *   completeness  --server ID --observer-dir DIR --max-heartbeat-gap-ms N            (check only; writes nothing)
 *   provenance    --server ID --retained-dir DIR
 *   accept        --server ID --generator-report FILE --observer-dir DIR --retained-dir DIR --max-heartbeat-gap-ms N
 *                 [--result overlay=ID --result tally=ID --result receipts=ID --result observation=ID --result provenance=ID] [--require-seal --commitment FILE]
 *   campaign      --runs-file FILE --max-heartbeat-gap-ms N [--require-seal]      (FILE: JSON array of run objects, see CampaignRunFile)
 *   commitment    --commitment FILE [--server ID]                                  (FILE: {"commitment": {...}, "digest": "<sha256>"})
 *   canary        --observer-dir DIR [--operational-action NAME ...] [--thresholds FILE]   (legitimate-user contract; 100 percent of journeys; latency only if thresholds are FIXED)
 *   thresholds    --file FILE                                                      (owner canary thresholds record: FIXED exits 0, UNSET 20, INVALID 10)
 *   preflight     --mode pilot|campaign --authorization FILE --tfvars FILE --cost FILE [--thresholds FILE] [--terraform-dir DIR] [--commit SHA]   (read-only go/no-go; PASS 0, INCOMPLETE 20, ERROR 30)
 *   pilot         --results FILE                                                   (evaluates a recorded infrastructure pilot result; never qualification)
 *   seal          --observer-dir DIR --destination DIR --server ID --commitment FILE
 *   verify-seal   --directory DIR --server ID --commitment FILE
 *   --evidence-root DIR   (all commands) the evidence root; defaults to the repository evidence root.
 * Exit codes: 0 positive (PASS, LOCALLY_CONSISTENT, LOCAL_REPEATABILITY_PASS, VALID, VERIFIED); 10 REJECT/INVALID/FAILED; 20 INCOMPLETE; 30 ERROR (malformed or unreadable); 64 usage error.
 * Output: one line of canonical JSON on stdout. `record` (the id of the evidence run just written) is the only non-deterministic field and is always last.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { EVIDENCE_ROOT, REPOSITORY_ROOT, canonicalJson, collectGitState, resolveEvidenceDirectory } from "../evidence/manifest";
import { COMPONENT_NAMES, evaluateRunFromEvidence, m1AcceptRun, type AcceptCli, type ComponentName } from "./acceptance";
import { m1LocalCampaign, type CampaignCli } from "./campaign";
import { buildCommitment, type CommitmentInput } from "./commitment";
import { identityFromPackage } from "./identity";
import { evaluateCanaryContract } from "./canary-contract";
import { evaluateLatencyAgainstThresholds, validateOwnerThresholds } from "./canary-thresholds";
import { evaluateObservationFiles } from "./observation-bundle";
import { writeObservationResult, writeProvenanceResult } from "./results";
import { verifySeal, verifySealSet, exportAndSeal } from "./seal";
import { evaluatePreflight, type GitProbe, type PreflightMode } from "./preflight";
import { evaluatePilotResults } from "./pilot";

export const EXIT = { POSITIVE: 0, REJECT: 10, INCOMPLETE: 20, ERROR: 30, USAGE: 64 } as const;
export type CliIo = { stdout: (line: string) => void; evidenceRoot?: string; now?: Date; /** test seam: the git state the preflight sees (default: the real repository) */ git?: () => GitProbe };
type Flags = Map<string, string[]>;

class UsageError extends Error {}
const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

function parseFlags(argv: readonly string[]): Flags {
  const flags: Flags = new Map();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) throw new UsageError(`unexpected argument ${arg}`);
    const name = arg.slice(2); const boolean = name === "require-seal";
    const value = boolean ? "true" : argv[++i];
    if (value === undefined || (!boolean && value.startsWith("--"))) throw new UsageError(`--${name} needs a value`);
    flags.set(name, [...(flags.get(name) ?? []), value]);
  }
  return flags;
}
const one = (flags: Flags, name: string, required = true): string | null => {
  const values = flags.get(name);
  if (values === undefined) { if (required) throw new UsageError(`--${name} is required`); return null; }
  if (values.length !== 1) throw new UsageError(`--${name} given more than once`);
  return values[0]!;
};
const directory = (flags: Flags, name: string): string => { const p = path.resolve(one(flags, name)!); return p; };
function gap(flags: Flags, required: boolean): number | null {
  const raw = one(flags, "max-heartbeat-gap-ms", required);
  if (raw === null) return null;
  const n = Number(raw);
  if (!/^[1-9][0-9]{0,8}$/u.test(raw) || !Number.isSafeInteger(n)) throw new UsageError("--max-heartbeat-gap-ms must be a positive integer");
  return n;
}
const allowedFlags: Record<string, readonly string[]> = {
  observe: ["server", "observer-dir", "max-heartbeat-gap-ms", "evidence-root"], completeness: ["server", "observer-dir", "max-heartbeat-gap-ms", "evidence-root"],
  provenance: ["server", "retained-dir", "evidence-root"],
  accept: ["server", "generator-report", "observer-dir", "retained-dir", "max-heartbeat-gap-ms", "result", "require-seal", "commitment", "evidence-root"],
  campaign: ["runs-file", "max-heartbeat-gap-ms", "require-seal", "evidence-root"], commitment: ["commitment", "server", "evidence-root"],
  canary: ["observer-dir", "operational-action", "thresholds", "evidence-root"], thresholds: ["file", "evidence-root"],
  preflight: ["mode", "authorization", "tfvars", "cost", "thresholds", "terraform-dir", "commit", "evidence-root"], pilot: ["results", "evidence-root"],
  seal: ["observer-dir", "destination", "server", "commitment", "evidence-root"], "verify-seal": ["directory", "server", "commitment", "evidence-root"],
};

type Emit = { command: string; outcome: string; exitCode: number; reasons: string[]; details?: Record<string, unknown>; record?: string | null };
const finish = (io: CliIo, e: Emit): number => {
  io.stdout(canonicalJson({ command: e.command, outcome: e.outcome, exitCode: e.exitCode, reasons: [...new Set(e.reasons)].sort(), details: e.details ?? {}, record: e.record ?? null }));
  return e.exitCode;
};
const fromOutcome = (outcome: string): number => {
  if (["PASS", "LOCALLY_CONSISTENT", "LOCAL_REPEATABILITY_PASS", "VALID", "VERIFIED", "CONSISTENT_WITH_RECORDS", "FRESH", "DISTINCT", "FIXED", "PILOT_PASS"].includes(outcome)) return EXIT.POSITIVE;
  if (["REJECT", "INVALID", "FAILED", "NOT_FRESH", "REPLAY"].includes(outcome)) return EXIT.REJECT;
  if (outcome === "INCOMPLETE" || outcome === "UNSET") return EXIT.INCOMPLETE;
  return EXIT.ERROR;
};

/** Canonical run identity of the SERVER package, derived from the package (never from a directory name or a supplied artifact). */
function packageIdentity(serverId: string, root: string) {
  let dir: string;
  try { dir = resolveEvidenceDirectory(serverId, root); } catch { return { identity: null, dir: null, problems: ["m1.cli.server_id_invalid"] }; }
  if (!existsSync(dir)) return { identity: null, dir, problems: ["m1.cli.server_package_absent"] };
  const { identity, problems } = identityFromPackage(dir);
  return { identity, dir, problems: identity === null ? [...problems, "m1.cli.identity_not_derivable"] : [] };
}

type CommitmentFile = { commitment: CommitmentInput; digest: string };
function readCommitment(file: string): { value: CommitmentFile | null; problems: string[] } {
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
    if (!isRecord(parsed) || !isRecord(parsed.commitment) || typeof parsed.digest !== "string") return { value: null, problems: ["m1.cli.commitment_file_malformed"] };
    return { value: parsed as unknown as CommitmentFile, problems: [] };
  } catch { return { value: null, problems: ["m1.cli.commitment_file_unreadable"] }; }
}
/** Rebuilds the commitment with the SAME builder and compares the digest; the file's own claim decides nothing. */
function checkCommitment(file: string, identity: { runId: string; campaignId: string; gitSha: string } | null): { digest: string | null; outcome: "VALID" | "INVALID" | "ERROR"; reasons: string[] } {
  const read = readCommitment(file);
  if (read.value === null) return { digest: null, outcome: "ERROR", reasons: read.problems };
  const input = { ...(read.value.commitment as CommitmentInput & { schema?: string }) };
  delete input.schema;
  const built = buildCommitment(input as CommitmentInput);
  const reasons = [...built.reasons];
  if (built.outcome !== "VALID") return { digest: null, outcome: "INVALID", reasons };
  if (built.digest !== read.value.digest) reasons.push("m1.cli.commitment_digest_mismatch");
  if (identity !== null) {
    if (built.commitment!.runId !== identity.runId) reasons.push("m1.cli.commitment_run_mismatch");
    if (built.commitment!.campaignId !== identity.campaignId) reasons.push("m1.cli.commitment_campaign_mismatch");
    if (built.commitment!.commit !== identity.gitSha) reasons.push("m1.cli.commitment_commit_mismatch");
  }
  return { digest: built.digest, outcome: reasons.length === 0 ? "VALID" : "INVALID", reasons };
}

function sealCheck(flagsDir: string, identity: { runId: string; campaignId: string; gitSha: string }, commitmentFile: string) {
  const commitment = checkCommitment(commitmentFile, identity);
  if (commitment.outcome !== "VALID" || commitment.digest === null) return { outcome: commitment.outcome === "ERROR" ? "ERROR" : "INVALID", reasons: commitment.reasons, seal: null as ReturnType<typeof verifySeal> | null };
  const seal = verifySeal(flagsDir, { runId: identity.runId, campaignId: identity.campaignId, commitmentDigest: commitment.digest });
  return { outcome: seal.outcome, reasons: seal.problems, seal };
}

export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const command = argv[0] ?? "";
  try {
    if (!(command in allowedFlags)) throw new UsageError(`unknown command ${JSON.stringify(command)}`);
    const flags = parseFlags(argv.slice(1));
    for (const name of flags.keys()) if (!allowedFlags[command]!.includes(name)) throw new UsageError(`--${name} is not a flag of ${command}`);
    const root = io.evidenceRoot ?? (one(flags, "evidence-root", false) !== null ? path.resolve(one(flags, "evidence-root", false)!) : EVIDENCE_ROOT);
    const now = io.now ?? new Date();

    if (command === "preflight") {
      const mode = one(flags, "mode")!; if (mode !== "pilot" && mode !== "campaign") throw new UsageError("--mode is pilot or campaign");
      const loadProblems: string[] = [];
      const load = (name: string): unknown => {
        const file = one(flags, name, false); if (file === null) return undefined;
        try { return JSON.parse(readFileSync(path.resolve(file), "utf8")) as unknown; } catch { loadProblems.push(`m1.preflight.${name}_unreadable_or_not_json`); return undefined; }
      };
      const authorization = load("authorization"); const tfvars = load("tfvars"); const cost = load("cost"); const thresholds = load("thresholds");
      const terraformDir = path.resolve(one(flags, "terraform-dir", false) ?? path.join(REPOSITORY_ROOT, "infra", "m1"));
      let terraform: Record<string, string> | null = null;
      try { terraform = {}; for (const name of readdirSync(terraformDir).filter((n) => n.endsWith(".tf")).sort()) terraform[name] = readFileSync(path.join(terraformDir, name), "utf8"); if (Object.keys(terraform).length === 0) terraform = null; } catch { terraform = null; }
      let git: GitProbe;
      if (io.git) git = io.git(); else { const g = collectGitState(); git = /^[0-9a-f]{40}$/u.test(g.gitSha) ? { sha: g.gitSha, trackedChanges: g.dirtyFileCount, untracked: g.untrackedFileCount } : null; }
      const verdict = evaluatePreflight({ mode: mode as PreflightMode, nowMs: now.getTime(), git, expectedCommit: one(flags, "commit", false), authorization, tfvars, cost, thresholds, loadProblems, terraform });
      return finish(io, { command, outcome: verdict.outcome, exitCode: fromOutcome(verdict.outcome), reasons: verdict.reasons, details: { mode, provisioned: false, checks: verdict.checks, digests: verdict.digests, limitations: verdict.limitations } });
    }
    if (command === "pilot") {
      let raw: unknown;
      try { raw = JSON.parse(readFileSync(directory(flags, "results"), "utf8")); } catch { return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.pilot_results_unreadable"] }); }
      const verdict = evaluatePilotResults(raw);
      return finish(io, { command, outcome: verdict.outcome, exitCode: fromOutcome(verdict.outcome), reasons: verdict.reasons, details: { checks: verdict.checks, qualification: "not_applicable" } });
    }
    if (command === "observe" || command === "completeness") {
      const serverId = one(flags, "server")!; const observerDir = directory(flags, "observer-dir"); const limit = gap(flags, command === "completeness");
      const id = packageIdentity(serverId, root);
      if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
      if (command === "completeness") {
        const bundle = evaluateObservationFiles({ runId: id.identity.runId, campaignId: id.identity.campaignId }, observerDir, limit);
        const completeness = bundle.completeness;
        const outcome = completeness === null ? "ERROR" : bundle.result.reasons.some((r) => r.startsWith("m1.complete.")) && completeness.outcome === "PASS" ? "REJECT" : completeness.outcome;
        return finish(io, { command, outcome, exitCode: fromOutcome(outcome), reasons: bundle.result.reasons.filter((r) => r.startsWith("m1.complete.")), details: { runId: id.identity.runId, limitSource: bundle.limitSource } });
      }
      const written = writeObservationResult(serverId, observerDir, root, now, limit);
      return finish(io, { command, outcome: written.result.outcome, exitCode: fromOutcome(written.result.outcome), reasons: written.result.reasons, details: { runId: id.identity.runId, summary: written.result.summary }, record: written.evidenceId });
    }
    if (command === "provenance") {
      const serverId = one(flags, "server")!; const retained = directory(flags, "retained-dir");
      const id = packageIdentity(serverId, root);
      if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
      const written = writeProvenanceResult(serverId, retained, root, now);
      return finish(io, { command, outcome: written.report.overall, exitCode: fromOutcome(written.report.overall), reasons: written.report.problems, details: { runId: id.identity.runId, levels: written.report.levels }, record: written.evidenceId });
    }
    if (command === "accept") {
      const serverId = one(flags, "server")!; const id = packageIdentity(serverId, root);
      if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
      const resultIds: Partial<Record<ComponentName, string>> = {};
      for (const pair of flags.get("result") ?? []) {
        const [name, value, ...rest] = pair.split("=");
        if (rest.length > 0 || value === undefined || !(COMPONENT_NAMES as readonly string[]).includes(name!) || (name as ComponentName) in resultIds) throw new UsageError(`--result ${pair} is not <component>=<evidence id>`);
        resultIds[name as ComponentName] = value;
      }
      const cli: AcceptCli = { serverId, resultIds, generatorReportPath: directory(flags, "generator-report"), observerDirectory: directory(flags, "observer-dir"), retainedDirectory: directory(flags, "retained-dir") };
      if (flags.has("require-seal")) {
        const commitmentFile = one(flags, "commitment")!;
        const checked = sealCheck(cli.observerDirectory!, id.identity, commitmentFile);
        if (checked.outcome !== "VERIFIED") return finish(io, { command, outcome: checked.outcome === "ERROR" ? "ERROR" : "REJECT", exitCode: checked.outcome === "ERROR" ? EXIT.ERROR : EXIT.REJECT, reasons: ["m1.cli.seal_not_verified", ...checked.reasons] });
      }
      const limit = gap(flags, true);
      const written = m1AcceptRun(cli, root, now, { maxHeartbeatGapMs: limit });
      return finish(io, { command, outcome: written.result.outcome, exitCode: fromOutcome(written.result.outcome), reasons: written.result.reasons, details: { runId: id.identity.runId, components: written.result.components, qualification: written.result.qualification.reachable }, record: written.evidenceId });
    }
    if (command === "campaign") {
      const limit = gap(flags, true);
      let raw: unknown;
      try { raw = JSON.parse(readFileSync(directory(flags, "runs-file"), "utf8")); } catch { return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.runs_file_unreadable"] }); }
      const runs = parseRunsFile(raw);
      if (runs === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.runs_file_malformed"] });
      if (flags.has("require-seal")) {
        const sealed: { runId: string; seal: NonNullable<ReturnType<typeof verifySeal>["seal"]>; sealSha256: string }[] = [];
        for (const run of runs) {
          const id = packageIdentity(run.serverId, root);
          if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: [...id.problems, `m1.cli.run.${run.serverId}`] });
          const checked = sealCheck(run.observerDirectory!, id.identity, run.commitmentFile!);
          if (checked.outcome !== "VERIFIED" || checked.seal === null || checked.seal.seal === null || checked.seal.sealSha256 === null) return finish(io, { command, outcome: checked.outcome === "ERROR" ? "ERROR" : "REJECT", exitCode: checked.outcome === "ERROR" ? EXIT.ERROR : EXIT.REJECT, reasons: ["m1.cli.seal_not_verified", `m1.cli.run.${run.serverId}`, ...checked.reasons] });
          sealed.push({ runId: id.identity.runId, seal: checked.seal.seal, sealSha256: checked.seal.sealSha256 });
        }
        const set = verifySealSet(sealed);
        if (set.outcome !== "DISTINCT") return finish(io, { command, outcome: "REJECT", exitCode: EXIT.REJECT, reasons: ["m1.cli.seal_set_not_distinct", ...set.problems] });
      }
      const written = m1LocalCampaign({ runs } as CampaignCli, root, now, { maxHeartbeatGapMs: limit });
      return finish(io, { command, outcome: written.result.outcome, exitCode: fromOutcome(written.result.outcome), reasons: written.result.reasons, details: { freshState: written.result.freshState, qualification: written.result.qualification.reachable }, record: written.evidenceId });
    }
    if (command === "thresholds") {
      let raw: unknown;
      try { raw = JSON.parse(readFileSync(directory(flags, "file"), "utf8")); } catch { return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.thresholds_unreadable"] }); }
      const status = validateOwnerThresholds(raw);
      const outcome = status.status === "INVALID" ? "INVALID" : status.status;
      return finish(io, { command, outcome, exitCode: fromOutcome(outcome), reasons: [...status.problems, ...status.missing.map((m) => `m1.thresholds.unset.${m}`)], details: { digest: status.digest } });
    }
    if (command === "canary") {
      let canary: unknown;
      try { canary = JSON.parse(readFileSync(path.join(directory(flags, "observer-dir"), "canary-results.json"), "utf8")); } catch { return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.canary_results_unreadable"] }); }
      const steps = isRecord(canary) ? canary.steps : undefined;
      const contract = evaluateCanaryContract({ steps, operationalActions: flags.get("operational-action") ?? [] });
      const reasons = [...contract.reasons, ...contract.openItems];
      let outcome = contract.outcome as string; const details: Record<string, unknown> = { journeys: contract.journeys, failures: contract.failures, latency: contract.latency, latencyThresholds: contract.latencyThresholds };
      const thresholdsFile = one(flags, "thresholds", false);
      if (thresholdsFile !== null) {
        let record: unknown;
        try { record = JSON.parse(readFileSync(path.resolve(thresholdsFile), "utf8")); } catch { return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.thresholds_unreadable"] }); }
        const latency = evaluateLatencyAgainstThresholds(contract, record);
        details.latencyEvaluation = latency.outcome; reasons.push(...latency.reasons);
        if (latency.outcome === "REJECT" && outcome === "PASS") outcome = "REJECT";
        if (latency.outcome === "NOT_EVALUATED" && outcome === "PASS") outcome = "INCOMPLETE";
      }
      return finish(io, { command, outcome, exitCode: fromOutcome(outcome), reasons, details });
    }
    if (command === "commitment") {
      const serverId = one(flags, "server", false); const id = serverId === null ? null : packageIdentity(serverId, root);
      if (id !== null && id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
      const checked = checkCommitment(directory(flags, "commitment"), id?.identity ?? null);
      return finish(io, { command, outcome: checked.outcome, exitCode: fromOutcome(checked.outcome), reasons: checked.reasons, details: { digest: checked.digest } });
    }
    if (command === "seal") {
      const id = packageIdentity(one(flags, "server")!, root);
      if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
      const commitment = checkCommitment(directory(flags, "commitment"), id.identity);
      if (commitment.outcome !== "VALID" || commitment.digest === null) return finish(io, { command, outcome: commitment.outcome, exitCode: fromOutcome(commitment.outcome), reasons: commitment.reasons });
      const sealed = exportAndSeal({ source: directory(flags, "observer-dir"), destination: directory(flags, "destination"), runId: id.identity.runId, campaignId: id.identity.campaignId, commitmentDigest: commitment.digest });
      const outcome = sealed.problems.length === 0 ? "VERIFIED" : "FAILED";
      return finish(io, { command, outcome, exitCode: fromOutcome(outcome), reasons: sealed.problems, details: { inventorySha256: sealed.seal.inventorySha256, files: sealed.seal.files.length, producerAuthentication: "none" } });
    }
    // verify-seal
    const id = packageIdentity(one(flags, "server")!, root);
    if (id.identity === null) return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: id.problems });
    const checked = sealCheck(directory(flags, "directory"), id.identity, directory(flags, "commitment"));
    return finish(io, { command, outcome: checked.outcome, exitCode: fromOutcome(checked.outcome), reasons: checked.reasons, details: { byteConsistencyOnly: true, producerAuthentication: "none", sealSha256: checked.seal?.sealSha256 ?? null } });
  } catch (error) {
    if (error instanceof UsageError) { io.stdout(canonicalJson({ command, outcome: "USAGE", exitCode: EXIT.USAGE, reasons: [error.message], details: {}, record: null })); return EXIT.USAGE; }
    return finish(io, { command, outcome: "ERROR", exitCode: EXIT.ERROR, reasons: ["m1.cli.unexpected_failure"] });
  }
}

type CampaignRunFile = { serverId: string; reportPath: string; observerDirectory: string; retainedDirectory: string; resultIds: Partial<Record<ComponentName, string>>; acceptanceId?: string; commitmentFile?: string };
function parseRunsFile(value: unknown): CampaignRunFile[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const runs: CampaignRunFile[] = [];
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.serverId !== "string" || typeof entry.reportPath !== "string" || typeof entry.observerDirectory !== "string" || typeof entry.retainedDirectory !== "string" || !isRecord(entry.resultIds)) return null;
    if (Object.keys(entry.resultIds).some((k) => !(COMPONENT_NAMES as readonly string[]).includes(k)) || Object.values(entry.resultIds).some((v) => typeof v !== "string")) return null;
    runs.push({ serverId: entry.serverId, reportPath: entry.reportPath, observerDirectory: entry.observerDirectory, retainedDirectory: entry.retainedDirectory, resultIds: entry.resultIds as CampaignRunFile["resultIds"],
      ...(typeof entry.acceptanceId === "string" ? { acceptanceId: entry.acceptanceId } : {}), ...(typeof entry.commitmentFile === "string" ? { commitmentFile: entry.commitmentFile } : {}) });
  }
  return runs;
}

// The recomputing evaluation without writing anything is also exposed for callers that only need a verdict.
export { evaluateRunFromEvidence, sha as _sha };

// Entry guard without `require`/`import.meta` (the repository import scan must be able to prove every module reference): run only when this very file is the script.
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  runCli(process.argv.slice(2), { stdout: (line) => process.stdout.write(`${line}\n`) }).then((code) => { process.exitCode = code; });
}
