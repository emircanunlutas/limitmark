import { open, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { TRUST_MANIFEST_MAX_BYTES, parseAuthorityResultTrustManifest, type AuthorityResultTrustManifest } from "../src/lib/authority-result-trust";

/**
 * Loads the PUBLIC Authority result trust manifest the operator readers verify against (R06 Slice 2C).
 *
 * The one fixed target is deployment/authority-result-trust.json: the provisioned instance of the tracked
 * deployment/authority-result-trust.template.json. It holds only public keys, fingerprints and validity windows. It is resolved through
 * realpath so a symlink at that name pointing elsewhere is refused. The unresolved template, a missing file, an oversize file or any
 * manifest the frozen parser rejects (placeholder values included) is "operator-unavailable": the caller reads nothing it cannot
 * verify and never falls back to an unsigned check. This module performs no network or provider access.
 */
export const AUTHORITY_RESULT_TRUST_FILE = "authority-result-trust.json";

export async function loadAuthorityResultTrustManifest(root: string = process.cwd()): Promise<AuthorityResultTrustManifest> {
  try {
    const deployment = await realpath(join(root, "deployment"));
    const resolvedPath = await realpath(resolve(deployment, AUTHORITY_RESULT_TRUST_FILE));
    if (dirname(resolvedPath) !== deployment || basename(resolvedPath) !== AUTHORITY_RESULT_TRUST_FILE) throw new Error("trust-path");
    const file = await open(resolvedPath, "r");
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
      return await parseAuthorityResultTrustManifest(buffer.subarray(0, length));
    } finally { await file.close(); }
  } catch { throw new Error("operator-unavailable"); }
}
