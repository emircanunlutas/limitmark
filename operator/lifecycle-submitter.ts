import { decodeCanonicalBase64url } from "../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  expectedCommandReceipt,
  validateAuthorityOperatorCommand,
  verifyOperatorCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
  type CommandDerivedReceipt,
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

/** Invariant parse and canonicalization: strict JSON, exact envelope, pinned protocol/target and the exact command schema.
 * Nothing here depends on the current time, so the same logic serves submission and historical authentication.
 * `operation` undefined accepts either lifecycle operation (the command itself then names it). */
function parseSealedLifecycleArtifactInvariant(bytes: Uint8Array, operation: LifecycleOperation | undefined,
  expectedEnvironment: "production" | "staging"): SealedLifecycleArtifact {
  if (!bytes.length || bytes.byteLength > MAX_SEALED_ARTIFACT_BYTES) throw new Error("invalid-sealed-artifact");
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
  if (command[0] !== AUTHORITY_OPERATOR_COMMAND_VERSION || !(operation === undefined ? command[1] === "initialize" || command[1] === "rotate-release" : command[1] === operation) ||
      command[2] !== expectedEnvironment || command[3] !== expectedAuthorityId || command[4] !== ADMISSION_POLICY_EPOCH) throw new Error("invalid-sealed-artifact");
  try {
    validateAuthorityOperatorCommand(command);
    decodeCanonicalBase64url(record.signature, 64);
  } catch { throw new Error("invalid-sealed-artifact"); }
  return { command, signature: record.signature };
}

/** Submission eligibility only: "may this command be submitted now?" Never used for historical authentication. */
function assertSubmissionEligible(command: SealedLifecycleArtifact["command"], nowMs: number): void {
  if (!Number.isSafeInteger(nowMs)) throw new Error("invalid-sealed-artifact");
  const issuedAtMs = command[1] === "initialize" ? (command as AuthorityInitializationCommand)[7] : (command as AuthorityReleaseRotationCommand)[10];
  if (Math.abs(nowMs - issuedAtMs) > 5 * 60_000 || command[1] === "rotate-release" &&
      Math.abs(nowMs - (command as AuthorityReleaseRotationCommand)[8]) > 5 * 60_000) throw new Error("invalid-sealed-artifact");
}

export function parseSealedLifecycleArtifact(bytes: Uint8Array, operation: LifecycleOperation, nowMs = Date.now(),
  expectedEnvironment: "production" | "staging" = "production"): SealedLifecycleArtifact {
  if (!Number.isSafeInteger(nowMs)) throw new Error("invalid-sealed-artifact");
  const artifact = parseSealedLifecycleArtifactInvariant(bytes, operation, expectedEnvironment);
  assertSubmissionEligible(artifact.command, nowMs);
  return artifact;
}

/** A sealed artifact whose operator signature verified against a pinned public key. `expected` carries every
 * command-derived receipt field, including the operator-key fingerprint, and never `sequence`/`appliedMs`. */
export type AuthenticatedLifecycleCommand = SealedLifecycleArtifact & { digest: string; expected: CommandDerivedReceipt };

// The type above is structural: any object of that shape would typecheck. Authentication is therefore also recorded at RUNTIME in a
// module-private registry that only `authenticateSealedLifecycleArtifact` writes. A hand-built object, a spread/`Object.assign`
// copy, a JSON round trip, `Object.create(authenticated)` or a cast is never registered. Registered objects are deeply frozen so
// they cannot be altered after authentication. Consumers that must not trust a TypeScript type call `isAuthenticatedLifecycleCommand`.
const authenticatedCommands = new WeakSet<object>();

/** Runtime proof that `value` was returned by `authenticateSealedLifecycleArtifact` (operator signature verified). */
export function isAuthenticatedLifecycleCommand(value: unknown): value is AuthenticatedLifecycleCommand {
  return typeof value === "object" && value !== null && authenticatedCommands.has(value);
}

/** Historical authentication for result verification: the same invariant parser and signature logic as submission, but
 * with no freshness. It authenticates that the operator signed exactly this command; it does not make it submittable. */
export async function authenticateSealedLifecycleArtifact(bytes: Uint8Array, operatorPublicKey: string,
  options: { expectedOperation?: LifecycleOperation; expectedEnvironment?: "production" | "staging" } = {}): Promise<AuthenticatedLifecycleCommand> {
  const artifact = parseSealedLifecycleArtifactInvariant(bytes, options.expectedOperation, options.expectedEnvironment ?? "production");
  await verifyOperatorCommand(artifact.command, artifact.signature, operatorPublicKey);
  const expected = await expectedCommandReceipt(artifact.command, operatorPublicKey);
  const authenticated: AuthenticatedLifecycleCommand = Object.freeze({
    command: Object.freeze(artifact.command) as SealedLifecycleArtifact["command"], signature: artifact.signature,
    digest: expected.digest, expected: Object.freeze(expected) });
  authenticatedCommands.add(authenticated);
  return authenticated;
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
