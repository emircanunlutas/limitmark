/**
 * Evidence manifest writer. Output lives only under <repo>/artifacts/lab/evidence/<runId>/,
 * which is gitignored (`artifacts/` in .gitignore; asserted by tests/lab-evidence.test.ts).
 *
 * Every JSON artifact and the manifest itself pass `assertEvidenceSafe` before touching disk.
 * SHA-256 of every artifact and of manifest.json is written to SHA256SUMS.
 */
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { dockerServerVersionSync } from "../host/docker";
import { assertEvidenceSafe, sanitizeLog, verifyLogText, type SanitizedLog } from "./redact";
import { canonicalJson } from "../policy/thresholds";

export const REPOSITORY_ROOT = path.resolve(__dirname, "..", "..");
export const EVIDENCE_ROOT = path.join(REPOSITORY_ROOT, "artifacts", "lab", "evidence");

/**
 * BASELINE-VALID / INVALID are the only conclusions a BA0 Slice 1 run may reach; APP-NON-BYPASS-VALID / INVALID the only ones a Slice 2
 * run may. None is PASS: no defense qualification is claimed, and APP-NON-BYPASS-VALID says nothing about network or transport isolation.
 */
export type EvidenceResult = "PASS" | "FAIL" | "STOP" | "REFUSED" | "ERROR" | "BASELINE-VALID" | "APP-NON-BYPASS-VALID" | "INVALID";

export type EvidenceEnvironment = {
  os: string;
  kernelRelease: string;
  arch: string;
  nodeVersion: string;
  dockerVersion: string | null;
  postgresVersion: string | null;
  cpuCount: number;
  memoryMegabytes: number;
};

export type GitState = { gitSha: string; dirty: boolean; dirtyFileCount: number; untrackedFileCount: number };

export type EvidenceManifest = {
  schemaVersion: 1;
  runId: string;
  kind: string;
  git: GitState;
  environment: EvidenceEnvironment;
  /** `ownership` states what the lab ESTABLISHED about the destination: lab-process | lab-container-port | lab-container-netns | unproven; for a remote target it is `operator-asserted`, never a proof. */
  target: { id: string; class: string; scheme?: string; port?: number; ownership?: string } | null;
  workload: { id: string; phases: readonly unknown[] } | null;
  ceilings: Record<string, unknown> | null;
  thresholds: { id: string; version: number; sha256: string } | null;
  engine: string;
  startedAt: string;
  endedAt: string;
  result: EvidenceResult;
  resultReasons: string[];
  metrics: Record<string, unknown>;
  artifacts: { name: string; sha256: string; bytes: number }[];
};

function run(command: string, args: string[], timeoutMs = 10_000): string | null {
  try {
    return execFileSync(command, args, { cwd: REPOSITORY_ROOT, encoding: "utf8", timeout: timeoutMs, stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch { return null; }
}

export function collectGitState(): GitState {
  const sha = run("git", ["rev-parse", "HEAD"]) ?? "unknown";
  const status = run("git", ["status", "--porcelain=v1", "-uall"]);
  const lines = status ? status.split("\n").filter(Boolean) : [];
  const untracked = lines.filter((line) => line.startsWith("??")).length;
  return {
    gitSha: /^[0-9a-f]{40}$/.test(sha) ? sha : "0".repeat(40),
    dirty: status === null ? true : lines.length > 0,
    dirtyFileCount: lines.length - untracked,
    untrackedFileCount: untracked,
  };
}

function osName(): string {
  if (process.platform === "linux") {
    try {
      const match = /^PRETTY_NAME="?([^"\n]+)"?/m.exec(readFileSync("/etc/os-release", "utf8"));
      if (match) return match[1];
    } catch { /* fall through */ }
  }
  return `${os.type()} ${os.release()}`.slice(0, 100);
}

export function collectEnvironment(postgresVersion: string | null = null): EvidenceEnvironment {
  return {
    os: osName(),
    kernelRelease: os.release().slice(0, 100),
    arch: os.arch(),
    nodeVersion: process.version,
    // Through the same confinement as every other Docker call: a daemon the lab did not verify as local is never asked.
    dockerVersion: dockerServerVersionSync(),
    postgresVersion,
    cpuCount: os.cpus().length,
    memoryMegabytes: Math.round(os.totalmem() / 1_048_576),
  };
}

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function runId(label: string, now: Date): string {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const safe = label.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 40);
  return `${stamp}-${safe}-${randomBytes(3).toString("hex")}`;
}

/** The evidence directory must resolve under artifacts/lab/evidence (a gitignored path). */
export function resolveEvidenceDirectory(id: string, root = EVIDENCE_ROOT): string {
  const directory = path.resolve(root, id);
  const relative = path.relative(path.resolve(REPOSITORY_ROOT, "artifacts", "lab"), directory);
  if (!id || relative.startsWith("..") || path.isAbsolute(relative) || !/^[A-Za-z0-9TZ-]{8,120}$/.test(id)) {
    throw new Error("evidence directory must be a plain run id under artifacts/lab");
  }
  return directory;
}

export class EvidenceRun {
  readonly id: string;
  readonly directory: string;
  readonly startedAt: Date;
  private readonly artifacts: EvidenceManifest["artifacts"] = [];
  private finalized = false;

  constructor(readonly kind: string, label: string, now = new Date(), root = EVIDENCE_ROOT) {
    this.id = runId(label, now);
    this.directory = resolveEvidenceDirectory(this.id, root);
    this.startedAt = now;
    mkdirSync(this.directory, { recursive: true });
  }

  /** Writes a JSON artifact after the safety scan and records its hash. */
  addJsonArtifact(name: string, value: unknown): void {
    if (!/^[a-z0-9][a-z0-9.-]{0,60}\.json$/.test(name)) throw new Error("artifact name must be a plain .json file name");
    assertEvidenceSafe(value, `$artifact(${name})`);
    const text = `${JSON.stringify(value, null, 2)}\n`;
    writeFileSync(path.join(this.directory, name), text, { flag: "wx" });
    this.artifacts.push({ name, sha256: sha256Hex(text), bytes: Buffer.byteLength(text) });
  }

  finalize(fields: Omit<EvidenceManifest, "schemaVersion" | "runId" | "kind" | "startedAt" | "endedAt" | "artifacts"> & { endedAt?: Date }): EvidenceManifest {
    if (this.finalized) throw new Error("evidence run already finalized");
    const endedAt = fields.endedAt ?? new Date();
    const { endedAt: _ignored, ...rest } = fields;
    void _ignored;
    const manifest: EvidenceManifest = {
      schemaVersion: 1,
      runId: this.id,
      kind: this.kind,
      ...rest,
      startedAt: this.startedAt.toISOString(),
      endedAt: endedAt.toISOString(),
      artifacts: [...this.artifacts],
    };
    assertEvidenceSafe(manifest);
    const text = `${JSON.stringify(manifest, null, 2)}\n`;
    writeFileSync(path.join(this.directory, "manifest.json"), text, { flag: "wx" });
    const sums = [...this.artifacts.map((a) => `${a.sha256}  ${a.name}`), `${sha256Hex(text)}  manifest.json`].join("\n");
    writeFileSync(path.join(this.directory, "SHA256SUMS"), `${sums}\n`, { flag: "wx" });
    this.finalized = true;
    return manifest;
  }
}

/**
 * Persists raw child-process or container output, but never verbatim: home-directory prefixes are rewritten and every
 * line that breaks an evidence rule is replaced by a marker (see sanitizeLog). Returns what was withheld so the evidence
 * can state it. The file name must be a plain `.log` name; the directory is created if needed.
 */
export function writeSanitizedLog(directory: string, name: string, raw: string): SanitizedLog {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.log$/.test(name)) throw new Error("log name must be a plain .log file name");
  const sanitized = sanitizeLog(raw);
  // The bytes written are exactly the bytes verified: re-scan the final text with the same rules and refuse to write if anything is left.
  const leftover = verifyLogText(sanitized.text);
  if (leftover !== null) throw new Error(`sanitized log still breaks an evidence rule (${leftover}); nothing was written`);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, name), sanitized.text);
  return sanitized;
}

/** Re-computes every recorded hash; returns mismatching file names. */
export function verifyEvidenceDirectory(directory: string): string[] {
  const problems: string[] = [];
  const sums = readFileSync(path.join(directory, "SHA256SUMS"), "utf8").trim().split("\n");
  for (const line of sums) {
    const [hash, name] = line.split("  ");
    let actual = "";
    try { actual = sha256Hex(readFileSync(path.join(directory, name))); } catch { /* missing */ }
    if (actual !== hash) problems.push(name);
  }
  return problems;
}

export { canonicalJson };
