import { open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { parseStrictJson } from "./lifecycle-submitter";
import { validateStagingLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";
import type { R2Credential } from "./r2-transport";

// Gate 6A: shared, hardened local-file I/O for the staging lifecycle
// transport manifest and R2 credential files. Factored out of
// scripts/authority-staging-submit.ts (which used this exact logic first)
// so the new Gate 6 IAM verification harness (scripts/gate6-credential-verify.ts)
// reuses the identical, single-reviewed code path rather than a second,
// potentially divergent copy of the same safety-relevant parsing.

export type StagingLifecycleTransportManifest = {
  accountId: string; requestBucket: string; resultBucket: string; operatorPublicKey: string; authorityId: string; policyEpoch: string;
};

export async function boundedFile(path: string, maximum: number): Promise<Uint8Array> {
  const file = await open(resolve(path), "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum) throw new Error("operator-input");
    const buffer = Buffer.alloc(maximum + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length !== stat.size) throw new Error("operator-input");
    return buffer.subarray(0, length);
  } finally { await file.close(); }
}

export function strictObject(bytes: Uint8Array): Record<string, unknown> {
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("operator-input");
  const value = parseStrictJson(source);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("operator-input");
  return value as Record<string, unknown>;
}

/** Loads and validates deployment/lifecycle-transport.staging.json: the one
 * fixed literal path, resolved through realpath() so a symlink at this exact
 * name pointing outside deployment/ (or at a differently placed file) is
 * refused rather than followed, exactly like the Gate 4B/5A rendered-config
 * pattern. Content is then validated with the reviewed
 * validateStagingLifecycleTransportManifest(..., false), which independently
 * refuses an unresolved template, a Production-shaped manifest, and any
 * unknown field. */
export async function loadStagingLifecycleTransportManifest(): Promise<StagingLifecycleTransportManifest> {
  let resolvedPath: string;
  try { resolvedPath = await realpath(resolve(process.cwd(), "deployment", "lifecycle-transport.staging.json")); }
  catch { throw new Error("operator-unavailable"); }
  if (dirname(resolvedPath) !== await realpath(join(process.cwd(), "deployment")) ||
      basename(resolvedPath) !== "lifecycle-transport.staging.json") throw new Error("operator-unavailable");
  let bytes: Uint8Array;
  try { bytes = await boundedFile(resolvedPath, 2_048); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  validateStagingLifecycleTransportManifest(value, false);
  return value as StagingLifecycleTransportManifest;
}

/** Loads one protected local R2 credential file: strict UTF-8 JSON without
 * BOM, at most 1,024 bytes, containing exactly the two nonempty string
 * members accessKeyId and secretAccessKey -- the same shape
 * scripts/gate6-credential-capture.ts writes. */
export async function readStagingR2Credential(path: string): Promise<R2Credential> {
  let bytes: Uint8Array;
  try { bytes = await boundedFile(path, 1_024); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  if (Object.keys(value).length !== 2 || typeof value.accessKeyId !== "string" || typeof value.secretAccessKey !== "string" ||
      !value.accessKeyId || !value.secretAccessKey) throw new Error("operator-input");
  return value as R2Credential;
}
