import { createHash } from "node:crypto";
import { canonicalJson } from "./guard-ledger-export";
import { parseStrictJson } from "./lifecycle-submitter";
import { decodeCanonicalBase64url, toArrayBuffer } from "../src/lib/ingress-protocol";

/**
 * Two-person recovery DECISION RECORD, version 1 -- schema and VERIFIER only (Gate 11A preparation; DESIGN, not an authorized workflow).
 *
 * There is deliberately no signing helper, no CLI, no guard replacement and no persistence here: this module can only answer "is this record, as
 * presented, a valid two-person decision for exactly this situation?". A `valid: true` answer is a precondition for a future, separately authorized
 * recovery procedure; it is not authorization to run one.
 *
 * Document layout (strict JSON, duplicate keys refused, exact key sets, integers only, no BOM):
 *   { "body": <DecisionBody>, "approvals": [ <Approval>, <Approval> ] }
 * Canonicalization: `canonicalJson(body)` = keys sorted recursively, arrays in order, no insignificant whitespace (the same function that fixes the guard
 * ledger export bytes). Signed bytes for each approval = UTF-8( "limitmark-guard-recovery-decision-v1\n" + canonicalJson(body) + "\n" + keyId ).
 * Binding the keyId into the signed bytes means a signature cannot be re-attributed to another registered key even if the same private key were
 * (wrongly) registered twice. Signature = Ed25519, 64 bytes, canonical unpadded base64url.
 */
/** Approved design parameters for a stranded-initialization recovery (conservative proposal). Pure constants; the reference evidence judge is tests/support/recovery-evidence.ts. */
export const RECOVERY_TIMING = Object.freeze({
  commandLifetimeMs: 300_000,
  firstReconciliationAfterExpiryMs: 300_000,
  secondReconciliationAfterFirstMs: 60_000,
  decisionWithinAfterSecondMs: 300_000,
});
export const RECOVERY_DECISION_FORMAT = "limitmark-guard-recovery-decision-v1";
const DOMAIN = `${RECOVERY_DECISION_FORMAT}\n`;
/** Maximum validity of a record after creation (proposal; owner decision). */
export const RECOVERY_DECISION_MAX_LIFETIME_MS = 900_000;
export const RECOVERY_REASONS = Object.freeze(["STRANDED_INITIALIZATION_LATCH"] as const);

export type DecisionBody = {
  format: typeof RECOVERY_DECISION_FORMAT;
  decisionId: string;                     // 32 lowercase hex, unique per decision
  reason: (typeof RECOVERY_REASONS)[number];
  createdAtMs: number;
  expiresAtMs: number;
  target: { environment: "production"; accountId: string; authorityId: string; policyEpoch: string };
  guards: { original: string; proposed: string };
  initializationCommand: { digest: string; issuedAtMs: number };
  reconciliations: [{ nonce: string; observedAtMs: number; evidenceSha256: string }, { nonce: string; observedAtMs: number; evidenceSha256: string }];
  guardExportContentSha256: string;       // contentSha256 of the verified guard ledger export of the ORIGINAL guard
  evidenceBundleSha256: string;           // hash of the archived evidence bundle (export + both reconciliations + command artifact + this timing report)
  approverRegistrySha256: string;         // pins the exact registry version the signatures are judged against
};
export type Approval = { keyId: string; signature: string };
export type DecisionRecord = { body: DecisionBody; approvals: [Approval, Approval] };

export type ApproverKey = { keyId: string; person: string; publicKey: string; status: "active" | "retired" | "revoked"; notBeforeMs: number; notAfterMs: number | null };
export type ApproverRegistry = { version: number; keys: ApproverKey[] };

export type DecisionContext = {
  /** The reviewed registry, obtained out of band; its canonical hash must equal `body.approverRegistrySha256`. */
  registry: ApproverRegistry;
  /** Fingerprint-equivalent: the base64url public key of the LIFECYCLE operator. Approver keys must differ from it (separately authorized people). */
  lifecycleOperatorPublicKey: string;
  expected: { environment: "production"; accountId: string; authorityId: string; policyEpoch: string; originalGuard: string; strandedDigest: string; issuedAtMs: number };
  /** Reviewed generation allowlist (hard-coded and reviewed in code in any real workflow; supplied by the caller here). */
  guardAllowlist: readonly string[];
  /** Guard generations already used as a recovery target (including the original), and decisions already consumed. Persistence is the caller's. */
  consumed: { decisionIds: ReadonlySet<string>; guardGenerations: ReadonlySet<string>; strandedDigests: ReadonlySet<string> };
  nowMs: number;
  /** When given, each stored object must hash to the declared evidenceSha256 (order: first, second). */
  evidence?: { first: Uint8Array; second: Uint8Array };
};
export type DecisionVerdict = { valid: true; decisionId: string; people: [string, string]; keyIds: [string, string] } | { valid: false; failures: DecisionFailure[] };
export type DecisionFailure =
  | "document" | "format" | "schema" | "registry" | "registry-hash" | "approvals" | "same-key" | "same-person" | "key-not-authorized" | "key-is-operator-key" | "signature"
  | "target" | "guard-identity" | "guard-allowlist" | "guard-reused" | "command-binding" | "timing" | "lifetime" | "expired" | "not-yet-valid" | "replay" | "evidence-hash";

const hex = (length: number) => new RegExp(`^[a-f0-9]{${length}}$`, "u");
const sha256 = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");
const keysOf = (value: unknown, keys: readonly string[]): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const isTime = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
const identity = /^[A-Za-z0-9_.:-]{1,128}$/u;

export function registrySha256(registry: ApproverRegistry): string { return sha256(`limitmark-recovery-approver-registry-v1\n${canonicalJson(registry)}`); }
export function decisionSigningBytes(body: DecisionBody, keyId: string): Uint8Array { return new TextEncoder().encode(`${DOMAIN}${canonicalJson(body)}\n${keyId}`); }

function validBody(value: unknown): value is DecisionBody {
  if (!keysOf(value, ["format", "decisionId", "reason", "createdAtMs", "expiresAtMs", "target", "guards", "initializationCommand", "reconciliations", "guardExportContentSha256", "evidenceBundleSha256", "approverRegistrySha256"])) return false;
  const body = value as Record<string, unknown>;
  if (body.format !== RECOVERY_DECISION_FORMAT || typeof body.decisionId !== "string" || !hex(32).test(body.decisionId) || !(RECOVERY_REASONS as readonly unknown[]).includes(body.reason) ||
      !isTime(body.createdAtMs) || !isTime(body.expiresAtMs)) return false;
  if (!keysOf(body.target, ["environment", "accountId", "authorityId", "policyEpoch"]) || body.target.environment !== "production" || typeof body.target.accountId !== "string" || !hex(32).test(body.target.accountId) ||
      typeof body.target.authorityId !== "string" || !identity.test(body.target.authorityId) || typeof body.target.policyEpoch !== "string" || !identity.test(body.target.policyEpoch)) return false;
  if (!keysOf(body.guards, ["original", "proposed"]) || typeof body.guards.original !== "string" || !identity.test(body.guards.original) || typeof body.guards.proposed !== "string" || !identity.test(body.guards.proposed)) return false;
  if (!keysOf(body.initializationCommand, ["digest", "issuedAtMs"]) || typeof body.initializationCommand.digest !== "string" || !hex(64).test(body.initializationCommand.digest) || !isTime(body.initializationCommand.issuedAtMs)) return false;
  if (!Array.isArray(body.reconciliations) || body.reconciliations.length !== 2) return false;
  for (const entry of body.reconciliations) {
    if (!keysOf(entry, ["nonce", "observedAtMs", "evidenceSha256"]) || typeof entry.nonce !== "string" || !hex(32).test(entry.nonce) || !isTime(entry.observedAtMs) || typeof entry.evidenceSha256 !== "string" || !hex(64).test(entry.evidenceSha256)) return false;
  }
  return ["guardExportContentSha256", "evidenceBundleSha256", "approverRegistrySha256"].every((key) => typeof body[key] === "string" && hex(64).test(body[key] as string));
}

export function parseDecisionRecord(text: string): DecisionRecord | null {
  if (typeof text !== "string" || text.length === 0 || text.length > 16_384 || text.charCodeAt(0) === 0xfeff) return null;
  let parsed: unknown;
  try { parsed = parseStrictJson(text); } catch { return null; }
  if (!keysOf(parsed, ["body", "approvals"]) || !validBody(parsed.body) || !Array.isArray(parsed.approvals) || parsed.approvals.length !== 2) return null;
  for (const approval of parsed.approvals) {
    if (!keysOf(approval, ["keyId", "signature"]) || typeof approval.keyId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/u.test(approval.keyId) || typeof approval.signature !== "string") return null;
  }
  return parsed as unknown as DecisionRecord;
}

function validRegistry(registry: ApproverRegistry): boolean {
  if (!registry || !Number.isSafeInteger(registry.version) || registry.version < 1 || !Array.isArray(registry.keys) || registry.keys.length < 2 || registry.keys.length > 16) return false;
  const ids = new Set<string>(), publics = new Set<string>();
  for (const key of registry.keys) {
    if (!keysOf(key, ["keyId", "person", "publicKey", "status", "notBeforeMs", "notAfterMs"]) || typeof key.keyId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/u.test(key.keyId) ||
        typeof key.person !== "string" || !identity.test(key.person) || !["active", "retired", "revoked"].includes(key.status as string) || !isTime(key.notBeforeMs) ||
        !(key.notAfterMs === null || isTime(key.notAfterMs))) return false;
    try { decodeCanonicalBase64url(key.publicKey, 32); } catch { return false; }
    if (ids.has(key.keyId) || publics.has(key.publicKey)) return false;
    ids.add(key.keyId); publics.add(key.publicKey);
  }
  return true;
}

async function verifySignature(publicKey: string, signature: string, message: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(publicKey, 32)), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, toArrayBuffer(decodeCanonicalBase64url(signature, 64)), toArrayBuffer(message));
  } catch { return false; }
}

/** Every check runs and every failure is reported (no short-circuit that could hide a second problem); the answer is valid only with ZERO failures. */
export async function verifyRecoveryDecisionRecord(text: string, context: DecisionContext): Promise<DecisionVerdict> {
  const record = parseDecisionRecord(text);
  if (!record) return { valid: false, failures: ["document"] };
  const failures = new Set<DecisionFailure>();
  const { body, approvals } = record;
  const { expected } = context;
  if (!validRegistry(context.registry)) failures.add("registry");
  else if (registrySha256(context.registry) !== body.approverRegistrySha256) failures.add("registry-hash");
  if (body.target.environment !== expected.environment || body.target.accountId !== expected.accountId || body.target.authorityId !== expected.authorityId || body.target.policyEpoch !== expected.policyEpoch) failures.add("target");
  if (body.guards.original !== expected.originalGuard) failures.add("guard-identity");
  if (body.guards.proposed === body.guards.original || !context.guardAllowlist.includes(body.guards.proposed) || !context.guardAllowlist.includes(body.guards.original)) failures.add("guard-allowlist");
  if (context.consumed.guardGenerations.has(body.guards.proposed)) failures.add("guard-reused");
  if (body.initializationCommand.digest !== expected.strandedDigest || body.initializationCommand.issuedAtMs !== expected.issuedAtMs) failures.add("command-binding");
  // timing: the declared reconciliations obey the approved rules (the same constants the evidence judge uses)
  const expiry = body.initializationCommand.issuedAtMs + RECOVERY_TIMING.commandLifetimeMs;
  const [first, second] = body.reconciliations;
  if (first.nonce === second.nonce || first.evidenceSha256 === second.evidenceSha256 || first.observedAtMs < expiry + RECOVERY_TIMING.firstReconciliationAfterExpiryMs ||
      second.observedAtMs < first.observedAtMs + RECOVERY_TIMING.secondReconciliationAfterFirstMs || body.createdAtMs < second.observedAtMs ||
      body.createdAtMs - second.observedAtMs > RECOVERY_TIMING.decisionWithinAfterSecondMs) failures.add("timing");
  if (body.expiresAtMs <= body.createdAtMs || body.expiresAtMs - body.createdAtMs > RECOVERY_DECISION_MAX_LIFETIME_MS) failures.add("lifetime");
  if (context.nowMs < body.createdAtMs) failures.add("not-yet-valid");
  if (context.nowMs >= body.expiresAtMs) failures.add("expired");
  if (context.consumed.decisionIds.has(body.decisionId) || context.consumed.strandedDigests.has(body.initializationCommand.digest)) failures.add("replay");
  if (context.evidence) {
    if (sha256(context.evidence.first) !== first.evidenceSha256 || sha256(context.evidence.second) !== second.evidenceSha256) failures.add("evidence-hash");
  }
  // approvals: two different registered keys of two different people, both active at the decision time, neither the lifecycle operator key
  const [a, b] = approvals;
  if (a.keyId === b.keyId || a.signature === b.signature) failures.add("same-key");
  const verdictKeys: Array<ApproverKey | undefined> = [a, b].map((approval) => context.registry.keys?.find((key) => key.keyId === approval.keyId));
  const people: string[] = [];
  for (const [index, approval] of [a, b].entries()) {
    const key = verdictKeys[index];
    if (!key) { failures.add("key-not-authorized"); continue; }
    people.push(key.person);
    if (key.status !== "active" || key.notBeforeMs > body.createdAtMs || (key.notAfterMs !== null && body.createdAtMs >= key.notAfterMs)) failures.add("key-not-authorized");
    if (key.publicKey === context.lifecycleOperatorPublicKey) failures.add("key-is-operator-key");
    if (!await verifySignature(key.publicKey, approval.signature, decisionSigningBytes(body, approval.keyId))) failures.add("signature");
  }
  if (people.length === 2 && people[0] === people[1]) failures.add("same-person");
  if (failures.size > 0) return { valid: false, failures: [...failures] };
  return { valid: true, decisionId: body.decisionId, people: [people[0], people[1]], keyIds: [a.keyId, b.keyId] };
}
