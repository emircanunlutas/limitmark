import { basename, dirname, join, resolve } from "node:path";
import { open, realpath } from "node:fs/promises";
import { validateLabLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";
import { TRUST_MANIFEST_MAX_BYTES, parseLabAuthorityResultTrustManifest, type AuthorityResultTrustManifest } from "../src/lib/authority-result-trust";
import type { R2Credential } from "./r2-transport";
import { boundedFile, strictObject } from "./staging-credential-io";

// Lab operator-side local file I/O. Fixed literal paths, resolved through realpath so a symlink pointing elsewhere is refused. The lab
// transport manifest and lab trust manifest have names of their own: a Production or staging manifest can never be loaded here, and the
// lab loaders can never load one of theirs (each content validator pins its own environment).

export const LAB_TRANSPORT_FILE = "lifecycle-transport.lab.json";
export const LAB_TRUST_FILE = "authority-result-trust.lab.json";
export type LabLifecycleTransportManifest = {
  accountId: string; requestBucket: string; resultBucket: string; operatorPublicKey: string; authorityId: string; policyEpoch: string;
};

async function fixedDeploymentFile(name: string): Promise<string> {
  const deployment = await realpath(join(process.cwd(), "deployment"));
  const resolvedPath = await realpath(resolve(deployment, name));
  if (dirname(resolvedPath) !== deployment || basename(resolvedPath) !== name) throw new Error("operator-unavailable");
  return resolvedPath;
}

export async function loadLabLifecycleTransportManifest(): Promise<LabLifecycleTransportManifest> {
  let bytes: Uint8Array;
  try { bytes = await boundedFile(await fixedDeploymentFile(LAB_TRANSPORT_FILE), 2_048); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  validateLabLifecycleTransportManifest(value, false);
  return value as LabLifecycleTransportManifest;
}

/** One protected local R2 credential file: strict UTF-8 JSON, at most 1,024 bytes, exactly the two nonempty string members
 * accessKeyId and secretAccessKey. The lab R2 tokens are minted per lab bucket; no other environment's token is accepted by R2 for them. */
export async function readLabR2Credential(path: string): Promise<R2Credential> {
  let bytes: Uint8Array;
  try { bytes = await boundedFile(path, 1_024); }
  catch { throw new Error("operator-unavailable"); }
  const value = strictObject(bytes);
  if (Object.keys(value).length !== 2 || typeof value.accessKeyId !== "string" || typeof value.secretAccessKey !== "string" ||
      !value.accessKeyId || !value.secretAccessKey) throw new Error("operator-input");
  return value as R2Credential;
}

export async function loadLabAuthorityResultTrustManifest(): Promise<AuthorityResultTrustManifest> {
  try {
    const file = await open(await fixedDeploymentFile(LAB_TRUST_FILE), "r");
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size < 1 || stat.size > TRUST_MANIFEST_MAX_BYTES) throw new Error("trust-size");
      const buffer = Buffer.alloc(stat.size + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length !== stat.size) throw new Error("trust-size");
      return await parseLabAuthorityResultTrustManifest(buffer.subarray(0, length));
    } finally { await file.close(); }
  } catch { throw new Error("operator-unavailable"); }
}
