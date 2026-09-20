import { decodeCanonicalBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  validateAuthorityOperatorCommand,
  verifyOperatorCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";
import type { LifecycleReceipt } from "../workers/admission-service/authority";

export const MAX_SEALED_ARTIFACT_BYTES = 4_096;
export type LifecycleOperation = "initialize" | "rotate-release";
export type SealedLifecycleArtifact = {
  command: AuthorityInitializationCommand | AuthorityReleaseRotationCommand;
  signature: string;
};
export type LifecycleResult =
  | { status: "initialized" | "already-initialized" | "rotated" | "already-rotated"; receipt?: LifecycleReceipt }
  | { status: "refused" }
  | { status: "unconfirmed"; instruction: "Inspect authoritative state before any retry; the mutation may have committed." };

/** Only these two calls can cross the private AdmissionServiceWorker binding. */
export type AdmissionLifecycleBinding = {
  initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string): Promise<{ status: "initialized" | "already-initialized"; receipt?: LifecycleReceipt } | { status: "refused" }>;
  rotateAuthorityReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string): Promise<{ status: "rotated" | "already-rotated"; receipt?: LifecycleReceipt } | { status: "refused" }>;
};

// The sealed format is deliberately narrower than general JSON. Each object key is
// checked before JSON.parse, so duplicate members cannot silently override data.
export function parseStrictJson(source: string): unknown {
  let index = 0;
  const fail = (): never => { throw new Error("invalid-sealed-artifact"); };
  const space = () => { while (/[ \t\r\n]/u.test(source[index] ?? "") && index < source.length) index += 1; };
  const string = (): string => {
    if (source[index] !== '"') fail();
    const start = index++;
    while (index < source.length) {
      const character = source[index++];
      if (character === '"') return JSON.parse(source.slice(start, index)) as string;
      if (character === "\\") index += 1;
      else if (character.charCodeAt(0) < 32) fail();
    }
    return fail();
  };
  const value = (): unknown => {
    space();
    if (source[index] === '"') return string();
    if (source[index] === "[") {
      index += 1; space();
      const array: unknown[] = [];
      if (source[index] === "]") { index += 1; return array; }
      for (;;) {
        array.push(value()); space();
        if (source[index] === "]") { index += 1; return array; }
        if (source[index++] !== ",") fail();
      }
    }
    if (source[index] === "{") {
      index += 1; space();
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      if (source[index] === "}") { index += 1; return object; }
      for (;;) {
        space(); const key = string(); space();
        if (source[index++] !== ":" || Object.hasOwn(object, key)) fail();
        object[key] = value(); space();
        if (source[index] === "}") { index += 1; return object; }
        if (source[index++] !== ",") fail();
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(source.slice(index));
    if (match === null) return fail();
    index += match[0].length;
    return JSON.parse(match[0]) as unknown;
  };
  const result = value(); space();
  if (index !== source.length) fail();
  return result;
}

export function parseSealedLifecycleArtifact(bytes: Uint8Array, operation: LifecycleOperation, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production"): SealedLifecycleArtifact {
  if (!bytes.length || bytes.byteLength > MAX_SEALED_ARTIFACT_BYTES || !Number.isSafeInteger(nowMs)) throw new Error("invalid-sealed-artifact");
  let value: unknown;
  try {
    const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (source.charCodeAt(0) === 0xfeff) throw new Error("bom");
    value = parseStrictJson(source);
  } catch { throw new Error("invalid-sealed-artifact"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid-sealed-artifact");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 2 || !Object.hasOwn(record, "command") || !Object.hasOwn(record, "signature") ||
      !Array.isArray(record.command) || typeof record.signature !== "string") throw new Error("invalid-sealed-artifact");
  const command = record.command as unknown as SealedLifecycleArtifact["command"];
  const expectedAuthorityId = expectedEnvironment === "staging" ? STAGING_ADMISSION_AUTHORITY_ID : ADMISSION_AUTHORITY_ID;
  if (command[0] !== AUTHORITY_OPERATOR_COMMAND_VERSION || command[1] !== operation || command[2] !== expectedEnvironment ||
      command[3] !== expectedAuthorityId || command[4] !== ADMISSION_POLICY_EPOCH) throw new Error("invalid-sealed-artifact");
  try {
    validateAuthorityOperatorCommand(command);
    decodeCanonicalBase64url(record.signature, 64);
  } catch { throw new Error("invalid-sealed-artifact"); }
  const issuedAtMs = operation === "initialize" ? (command as AuthorityInitializationCommand)[7] : (command as AuthorityReleaseRotationCommand)[10];
  if (Math.abs(nowMs - issuedAtMs) > 5 * 60_000 || operation === "rotate-release" &&
      Math.abs(nowMs - (command as AuthorityReleaseRotationCommand)[8]) > 5 * 60_000) throw new Error("invalid-sealed-artifact");
  return { command, signature: record.signature };
}

/** A provider-owned private executor supplies the pinned binding and public key. */
export async function submitSealedLifecycleArtifact(bytes: Uint8Array, operation: LifecycleOperation,
  admission: AdmissionLifecycleBinding, operatorPublicKey: string, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production"): Promise<LifecycleResult> {
  const artifact = parseSealedLifecycleArtifact(bytes, operation, nowMs, expectedEnvironment);
  await verifyOperatorCommand(artifact.command, artifact.signature, operatorPublicKey);
  try {
    const response = operation === "initialize"
      ? await admission.initializeAuthorityFromOperator(artifact.command as AuthorityInitializationCommand, artifact.signature)
      : await admission.rotateAuthorityReleaseFromOperator(artifact.command as AuthorityReleaseRotationCommand, artifact.signature);
    if (response.status === "refused" || operation === "initialize" && ["initialized", "already-initialized"].includes(response.status) ||
        operation === "rotate-release" && ["rotated", "already-rotated"].includes(response.status)) return response;
  } catch {
    // A transport exception can arrive after SQLite committed. Never retry here.
  }
  return { status: "unconfirmed", instruction: "Inspect authoritative state before any retry; the mutation may have committed." };
}
