import { decodeCanonicalBase64url, encodeBase64url, toArrayBuffer } from "../../src/lib/ingress-protocol";
import {
  ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH,
  initializeAuthority,
  rotateAuthorityRelease,
  type AuthorityInitialization,
  type DurableStorageLike,
  type LifecycleReceipt,
} from "./authority";

export const AUTHORITY_OPERATOR_COMMAND_VERSION = "limitmark-authority-operator-v1";
export type AuthorityInitializationCommand = readonly [
  version: typeof AUTHORITY_OPERATOR_COMMAND_VERSION,
  operation: "initialize",
  environment: "production" | "staging",
  authorityId: typeof ADMISSION_AUTHORITY_ID,
  policyEpoch: typeof ADMISSION_POLICY_EPOCH,
  releaseId: string,
  releaseKeyId: string,
  issuedAtMs: number,
  confirmProduction: boolean,
];
export type AuthorityReleaseRotationCommand = readonly [
  version: typeof AUTHORITY_OPERATOR_COMMAND_VERSION,
  operation: "rotate-release",
  environment: "production",
  authorityId: typeof ADMISSION_AUTHORITY_ID,
  policyEpoch: typeof ADMISSION_POLICY_EPOCH,
  currentReleaseId: string,
  nextReleaseId: string,
  nextReleaseKeyId: string,
  activatesAtMs: number,
  previousRetiresAtMs: number,
  issuedAtMs: number,
  confirmProduction: true,
];
export type AuthorityOperatorCommand = AuthorityInitializationCommand | AuthorityReleaseRotationCommand;

const validRelease = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/u.test(value);
const validKeyId = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9_-]{1,64}$/u.test(value);
const validTime = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;

export function canonicalOperatorCommandBytes(command: AuthorityOperatorCommand): Uint8Array {
  if (!Array.isArray(command) || command[0] !== AUTHORITY_OPERATOR_COMMAND_VERSION || command[3] !== ADMISSION_AUTHORITY_ID ||
      command[4] !== ADMISSION_POLICY_EPOCH) throw new Error("operator-command");
  if (command[1] === "initialize") {
    if (command.length !== 9 || command[2] !== "staging" && command[2] !== "production" || !validRelease(command[5]) ||
        !validKeyId(command[6]) || !validTime(command[7]) || typeof command[8] !== "boolean" ||
        command[2] === "production" && command[8] !== true) throw new Error("operator-command");
  } else if (command[1] === "rotate-release") {
    if (command.length !== 12 || command[2] !== "production" || !validRelease(command[5]) || !validRelease(command[6]) ||
        command[5] === command[6] || !validKeyId(command[7]) || !validTime(command[8]) || !validTime(command[9]) ||
        !validTime(command[10]) || command[9] <= command[8] || command[9] - command[8] > 5 * 60_000 || command[11] !== true) {
      throw new Error("operator-command");
    }
  } else throw new Error("operator-command");
  return new TextEncoder().encode(JSON.stringify(command));
}

/** The same schema and canonical bytes used by signing and authority verification. */
export function validateAuthorityOperatorCommand(command: AuthorityOperatorCommand): void {
  canonicalOperatorCommandBytes(command);
}

export async function signAuthorityInitializationCommand(command: AuthorityInitializationCommand, privateKeyPkcs8: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", toArrayBuffer(decodeCanonicalBase64url(privateKeyPkcs8)), { name: "Ed25519" }, false, ["sign"]);
  return encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, toArrayBuffer(canonicalOperatorCommandBytes(command)))));
}

export async function signAuthorityReleaseRotationCommand(command: AuthorityReleaseRotationCommand, privateKeyPkcs8: string): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", toArrayBuffer(decodeCanonicalBase64url(privateKeyPkcs8)), { name: "Ed25519" }, false, ["sign"]);
  return encodeBase64url(new Uint8Array(await crypto.subtle.sign("Ed25519", key, toArrayBuffer(canonicalOperatorCommandBytes(command)))));
}

export async function verifyOperatorCommand(command: AuthorityOperatorCommand, signature: string, operatorPublicKey: string): Promise<void> {
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(operatorPublicKey, 32)), { name: "Ed25519" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("Ed25519", key, toArrayBuffer(decodeCanonicalBase64url(signature, 64)), toArrayBuffer(canonicalOperatorCommandBytes(command)));
  if (!valid) throw new Error("operator-signature");
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(bytes))),
    (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Domain-separated identity of the exact JSON.stringify signed-message bytes. */
export async function commandDigest(command: AuthorityOperatorCommand): Promise<string> {
  const domain = new TextEncoder().encode("limitmark-lifecycle-command-digest-v1\n");
  const message = canonicalOperatorCommandBytes(command);
  const bytes = new Uint8Array(domain.length + message.length);
  bytes.set(domain); bytes.set(message, domain.length);
  return sha256(bytes);
}

async function receiptBase(command: AuthorityOperatorCommand, operatorPublicKey: string): Promise<Omit<LifecycleReceipt, "sequence">> {
  const init = command[1] === "initialize";
  return { digest: await commandDigest(command), version: 1, operation: command[1], environment: command[2],
    authorityId: command[3], policyEpoch: command[4],
    keyFingerprint: await sha256(decodeCanonicalBase64url(operatorPublicKey, 32)), appliedMs: 0,
    currentReleaseId: command[5], nextReleaseId: init ? command[5] : command[6],
    nextKeyId: init ? command[6] : command[7], activatesMs: init ? command[7] : command[8],
    retiresMs: init ? null : command[9] };
}

export async function executeSignedAuthorityInitialization(storage: DurableStorageLike, command: AuthorityInitializationCommand, signature: string,
  operatorPublicKey: string, nowMs: number, expectedEnvironment: "production" | "staging" = "production",
  finalNow: () => number = () => nowMs): Promise<{ status: "initialized" | "already-initialized"; receipt?: LifecycleReceipt }> {
  if (command[2] !== expectedEnvironment) throw new Error("operator-environment");
  await verifyOperatorCommand(command, signature, operatorPublicKey);
  const receipt = await receiptBase(command, operatorPublicKey);
  const observed = finalNow();
  if (!Number.isSafeInteger(observed) || Math.abs(observed - command[7]) > 5 * 60_000) throw new Error("operator-command-freshness");
  const specification: AuthorityInitialization = { environment: command[2], authorityId: command[3], policyEpoch: command[4], releaseId: command[5],
    releaseKeyId: command[6], nowMs: command[7], confirmProduction: command[8] };
  return initializeAuthority(storage, specification, { ...receipt, appliedMs: observed });
}


export async function executeSignedAuthorityReleaseRotation(storage: DurableStorageLike, command: AuthorityReleaseRotationCommand, signature: string,
  operatorPublicKey: string, nowMs: number, expectedEnvironment: "production" | "staging" = "production",
  finalNow: () => number = () => nowMs): Promise<{ status: "rotated" | "already-rotated"; receipt?: LifecycleReceipt }> {
  if (command[2] !== expectedEnvironment) throw new Error("operator-environment");
  await verifyOperatorCommand(command, signature, operatorPublicKey);
  const receipt = await receiptBase(command, operatorPublicKey);
  const observed = finalNow();
  if (!Number.isSafeInteger(observed) || Math.abs(observed - command[10]) > 5 * 60_000 || Math.abs(observed - command[8]) > 5 * 60_000)
    throw new Error("operator-command-freshness");
  return rotateAuthorityRelease(storage, {
    authorityId: command[3], policyEpoch: command[4], currentReleaseId: command[5], nextReleaseId: command[6], nextKeyId: command[7],
    activatesAtMs: command[8], previousRetiresAtMs: command[9],
  }, { ...receipt, appliedMs: observed });
}
