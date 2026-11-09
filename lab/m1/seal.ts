/**
 * Local sealing of an observer evidence directory (BYTE CONSISTENCY ONLY). Pure file I/O; no network, no key material, no retention lock.
 *
 * `exportAndSeal` copies the observer files into a NEW destination directory create-only (an existing file is never overwritten) and writes `SEAL.json` last: run and campaign
 * binding, the digest of the pre-run commitment, and the SHA-256 and size of every file. `verifySeal` recomputes all of it and reports a modified, missing, extra or substituted
 * file, a run/campaign/commitment mismatch and a malformed or self-inconsistent seal. `verifySealSet` compares the seals of several runs and reports replay (the same bytes or
 * seal reused by another run) and cross-run substitution.
 *
 * Cryptographic producer authentication is a SEPARATE question and is NOT answered here: the seal states `producerAuthentication: "none"` and `verified: false`. A sealed directory
 * proves the bytes did not change after sealing; it does not prove who produced them. In a remote campaign the independent custodian writes the seal and its digest into storage the
 * producer cannot overwrite; this module only defines and checks the content.
 */
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { canonicalJson } from "../evidence/manifest";

export const SEAL_SCHEMA = "m1-observer-seal-v1";
export const SEAL_FILE = "SEAL.json";
export const OBSERVER_FILES = ["canary-results.json", "origin-receipts.ndjson", "observation-meta.json", "collector-declaration.json"] as const;

export type SealedFile = { name: string; bytes: number; sha256: string };
export type Seal = {
  schema: typeof SEAL_SCHEMA; runId: string; campaignId: string; commitmentDigest: string; files: SealedFile[]; inventorySha256: string;
  producerAuthentication: "none"; verified: false;
};
export type SealVerification = { outcome: "VERIFIED" | "FAILED" | "ERROR"; problems: string[]; seal: Seal | null; sealSha256: string | null };

const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const HEX64 = /^[0-9a-f]{64}$/u;
const inventoryDigest = (files: readonly SealedFile[]): string => sha(canonicalJson(files));

/** Copies the observer files create-only into `destination` (which must not hold a seal yet) and writes the seal last. */
export function exportAndSeal(input: { source: string; destination: string; runId: string; campaignId: string; commitmentDigest: string }): { seal: Seal; problems: string[] } {
  const problems: string[] = [];
  if (!HEX64.test(input.commitmentDigest)) problems.push("m1.seal.commitment_digest_invalid");
  for (const name of OBSERVER_FILES) if (!existsSync(path.join(input.source, name))) problems.push(`m1.seal.source_missing.${name}`);
  if (existsSync(path.join(input.destination, SEAL_FILE))) problems.push("m1.seal.destination_already_sealed");
  const empty: Seal = { schema: SEAL_SCHEMA, runId: input.runId, campaignId: input.campaignId, commitmentDigest: input.commitmentDigest, files: [], inventorySha256: inventoryDigest([]), producerAuthentication: "none", verified: false };
  if (problems.length > 0) return { seal: empty, problems };
  mkdirSync(input.destination, { recursive: true });
  const files: SealedFile[] = [];
  for (const name of OBSERVER_FILES) {
    const target = path.join(input.destination, name);
    if (existsSync(target)) { problems.push(`m1.seal.destination_file_exists.${name}`); continue; }
    copyFileSync(path.join(input.source, name), target, 1 /* COPYFILE_EXCL: never overwrite */);
    const bytes = readFileSync(target);
    files.push({ name, bytes: bytes.length, sha256: sha(bytes) });
  }
  if (problems.length > 0) return { seal: empty, problems };
  const seal: Seal = { ...empty, files, inventorySha256: inventoryDigest(files) };
  writeFileSync(path.join(input.destination, SEAL_FILE), `${canonicalJson(seal)}\n`, { flag: "wx" });
  return { seal, problems: [] };
}

function parseSeal(value: unknown): Seal | null {
  if (!isRecord(value) || value.schema !== SEAL_SCHEMA || typeof value.runId !== "string" || typeof value.campaignId !== "string" || !HEX64.test(String(value.commitmentDigest)) || !HEX64.test(String(value.inventorySha256))) return null;
  if (value.producerAuthentication !== "none" || value.verified !== false || !Array.isArray(value.files)) return null;
  const files = value.files.map((f) => (isRecord(f) && typeof f.name === "string" && Number.isSafeInteger(f.bytes) && HEX64.test(String(f.sha256)) ? ({ name: f.name, bytes: f.bytes as number, sha256: f.sha256 as string }) : null));
  if (files.some((f) => f === null)) return null;
  return { ...(value as unknown as Seal), files: files as SealedFile[] };
}

/** Recomputes the seal from the bytes now on disk. `expected` pins the run, campaign and commitment the caller was told to expect. */
export function verifySeal(directory: string, expected: { runId: string; campaignId: string; commitmentDigest: string }): SealVerification {
  const file = path.join(directory, SEAL_FILE);
  if (!existsSync(file)) return { outcome: "FAILED", problems: ["m1.seal.absent"], seal: null, sealSha256: null };
  let bytes: Buffer; let seal: Seal | null;
  try { bytes = readFileSync(file); seal = parseSeal(JSON.parse(bytes.toString("utf8"))); } catch { return { outcome: "ERROR", problems: ["m1.seal.unreadable"], seal: null, sealSha256: null }; }
  if (seal === null) return { outcome: "ERROR", problems: ["m1.seal.malformed"], seal: null, sealSha256: null };
  const problems: string[] = [];
  if (seal.runId !== expected.runId) problems.push("m1.seal.run_mismatch");
  if (seal.campaignId !== expected.campaignId) problems.push("m1.seal.campaign_mismatch");
  if (seal.commitmentDigest !== expected.commitmentDigest) problems.push("m1.seal.commitment_mismatch");
  if (seal.inventorySha256 !== inventoryDigest(seal.files)) problems.push("m1.seal.inventory_digest_mismatch");
  const names = seal.files.map((f) => f.name);
  if (new Set(names).size !== names.length) problems.push("m1.seal.duplicate_file");
  for (const required of OBSERVER_FILES) if (!names.includes(required)) problems.push(`m1.seal.required_file_not_sealed.${required}`);
  for (const sealed of seal.files) {
    const target = path.join(directory, sealed.name);
    if (path.basename(sealed.name) !== sealed.name || !existsSync(target)) { problems.push(`m1.seal.file_missing.${path.basename(sealed.name)}`); continue; }
    const current = readFileSync(target);
    if (current.length !== sealed.bytes || sha(current) !== sealed.sha256) problems.push(`m1.seal.file_modified.${sealed.name}`);
  }
  for (const entry of readdirSync(directory)) if (entry !== SEAL_FILE && !names.includes(entry) && statSync(path.join(directory, entry)).isFile()) problems.push(`m1.seal.unsealed_file.${entry}`);
  return { outcome: problems.length === 0 ? "VERIFIED" : "FAILED", problems: [...new Set(problems)], seal, sealSha256: sha(bytes) };
}

/** Across the runs of one campaign: no seal, inventory or file content may be shared between runs (replay), and run ids must be distinct. */
export function verifySealSet(seals: readonly { runId: string; seal: Seal; sealSha256: string }[]): { outcome: "DISTINCT" | "REPLAY"; problems: string[] } {
  const problems: string[] = [];
  const dup = (values: string[]): boolean => new Set(values).size !== values.length;
  if (dup(seals.map((s) => s.runId))) problems.push("m1.seal.run_id_repeated");
  if (dup(seals.map((s) => s.sealSha256))) problems.push("m1.seal.replayed_seal");
  if (dup(seals.map((s) => s.seal.inventorySha256))) problems.push("m1.seal.replayed_inventory");
  if (dup(seals.map((s) => s.seal.commitmentDigest))) problems.push("m1.seal.commitment_shared_between_runs");
  for (const name of ["origin-receipts.ndjson", "canary-results.json", "collector-declaration.json"]) {
    const digests = seals.map((s) => s.seal.files.find((f) => f.name === name)?.sha256 ?? "");
    if (digests.some((d) => d !== "") && dup(digests.filter((d) => d !== ""))) problems.push(`m1.seal.${name}.content_reused_by_another_run`);
  }
  return { outcome: problems.length === 0 ? "DISTINCT" : "REPLAY", problems };
}
