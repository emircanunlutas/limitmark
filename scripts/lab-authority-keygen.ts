import { createHash, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, openSync, closeSync, writeSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Offline generator for the two laboratory Ed25519 key pairs the reviewed initialization chain needs:
 *   operator     signs lifecycle commands (private half stays on the operator workstation only)
 *   attestation  signs the Authority's evidence (private half goes only into the admission Worker secret store)
 * Private keys are written ONLY to mode-0600 files in a new directory and are never printed. Public keys and SHA-256
 * fingerprints are printed. The two pairs are distinct by construction and verified distinct. Existing files are never overwritten.
 * Formats: private = canonical base64url RFC 8410 PKCS#8; public = canonical base64url raw 32 bytes; fingerprint = lowercase hex SHA-256 of the raw public key.
 */
const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

export function generateLabKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePkcs8 = b64url(privateKey.export({ format: "der", type: "pkcs8" }));
  const rawPublic = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  if (rawPublic.length !== 32) throw new Error("unexpected-public-key-length");
  return { privatePkcs8, publicKey: b64url(rawPublic), fingerprint: createHash("sha256").update(rawPublic).digest("hex") };
}

function writeSecretFile(path: string, value: string): void {
  if (existsSync(path)) throw new Error("refusing-to-overwrite");
  const descriptor = openSync(path, "wx", 0o600);
  try { writeSync(descriptor, value); } finally { closeSync(descriptor); }
}

function main(): void {
  const directory = process.argv[2];
  if (!directory) throw new Error("usage: lab-authority-keygen <new-private-directory-outside-the-repository>");
  const target = resolve(directory);
  if (target.startsWith(resolve(process.cwd()) + "\\") || target.startsWith(resolve(process.cwd()) + "/") || target === resolve(process.cwd())) throw new Error("directory-must-be-outside-the-repository");
  if (existsSync(target)) throw new Error("directory-must-not-exist");
  mkdirSync(target, { recursive: true, mode: 0o700 });
  const operator = generateLabKeyPair();
  const attestation = generateLabKeyPair();
  // The result-trust manifest must list a distinct staging-slot key. The laboratory has no staging Authority, so this pair exists only to
  // fill that slot: its private half is never written anywhere and is discarded with the process.
  const stagingSlot = generateLabKeyPair();
  if (new Set([operator.fingerprint, attestation.fingerprint, stagingSlot.fingerprint]).size !== 3) throw new Error("keys-not-distinct");
  writeSecretFile(resolve(target, "operator.private.b64url"), operator.privatePkcs8);
  writeSecretFile(resolve(target, "attestation.private.b64url"), attestation.privatePkcs8);
  process.stdout.write(`${JSON.stringify({
    operatorPublicKey: operator.publicKey, operatorFingerprint: operator.fingerprint,
    attestationPublicKey: attestation.publicKey, attestationFingerprint: attestation.fingerprint,
    stagingSlotPublicKey: stagingSlot.publicKey, stagingSlotFingerprint: stagingSlot.fingerprint,
    privateKeyFiles: ["operator.private.b64url", "attestation.private.b64url"], directory: target,
  }, null, 2)}\n`);
}

if (process.argv[1] && /lab-authority-keygen\.[cm]?[jt]s$/u.test(process.argv[1])) {
  try { main(); } catch (error) { process.stderr.write(`REFUSED: ${error instanceof Error ? error.message : "error"}\n`); process.exitCode = 2; }
}
