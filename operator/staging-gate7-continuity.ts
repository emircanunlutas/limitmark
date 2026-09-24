import { LIVE_READONLY_OBSERVATION_FRESHNESS_MS } from "../deployment/lifecycle-private-contract";

// Gate 8 Phase 1A: the exact, committed Gate 7 continuity expectation for the
// permanently initialized live staging authority, and the pure validator a
// future reviewed read-only observation must satisfy. Values are copied from
// the operator-recorded Gate 7 evidence in PHASE5C_I3_PROVISIONING_RUNBOOK.md
// (tests/gate8-phase1a-continuity.test.ts checks them against that record and
// against the evidence-only STAGING_INITIALIZATION_LOCK, which this module
// deliberately does not import). Only public, non-secret identifiers appear:
// the operator key is represented solely by its SHA-256 public-key fingerprint.
//
// This module holds no enable/disable state. The live continuity transport is
// CLOSED / TOOLING REQUIRED: scripts/authority-staging-continuity-verify.ts
// refuses unconditionally, because positive workers.dev-subdomain verification
// (a precondition for the Wrangler preview transport) cannot currently be
// performed without a new provider credential or an unreviewed API client.

/** Full SHA-256 fingerprint of the Gate 7 staging operator Ed25519 public key. */
export const STAGING_GATE7_KEY_FINGERPRINT = "74f6e266c7cbdced42fffa944ee9eb397f48d1cdfd3b0b0e80817cc313073bd3";

export const STAGING_GATE7_CONTINUITY = Object.freeze({
  version: 1,
  environment: "staging",
  authorityId: "staging-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1",
  accountFingerprint: "0df3a690b3154513",
  initialized: true,
  coverage: "COMPLETE",
  status: "EXACT_RECEIPT",
  receipt: Object.freeze({
    digest: "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf",
    version: 1,
    operation: "initialize",
    environment: "staging",
    authorityId: "staging-public-inquiries-v1",
    policyEpoch: "phase5c-i1-epoch-1",
    keyFingerprint: STAGING_GATE7_KEY_FINGERPRINT,
    sequence: 1,
    appliedMs: 1790252041703,
    currentReleaseId: "staging-gate7-initial",
    nextReleaseId: "staging-gate7-initial",
    nextKeyId: "staging-gate7-key-1",
    activatesMs: 1790251978099,
    retiresMs: null,
  }),
  releases: Object.freeze([Object.freeze({
    release_id: "staging-gate7-initial",
    key_id: "staging-gate7-key-1",
    activated_ms: 1790251978099,
    retired_ms: null,
  })]),
} as const);

/** Same symmetric +/-300000ms bound as the reviewed Gate 4B observation contract. */
export const STAGING_CONTINUITY_OBSERVATION_FRESHNESS_MS = LIVE_READONLY_OBSERVATION_FRESHNESS_MS;

/** Fixed, non-secret refusal of the closed live continuity transport. */
export const STAGING_CONTINUITY_TRANSPORT_REFUSAL =
  "REFUSED: live staging continuity verification is CLOSED / TOOLING REQUIRED (Gate 8 Phase 1A). The Wrangler preview " +
  "transport can register a workers.dev subdomain when none exists and uploads a temporary preview Worker; positive " +
  "verification of a pre-existing subdomain cannot currently be performed without a new provider credential or an " +
  "unreviewed API client. Nothing was read or started and no provider was contacted.\n";

export type ContinuityRefusalCode = "snapshot-shape" | "snapshot-identity" | "snapshot-state" | "snapshot-receipt" |
  "snapshot-releases" | "observation-freshness";

export class ContinuityRefusal extends Error {
  constructor(readonly code: ContinuityRefusalCode) { super(code); this.name = "ContinuityRefusal"; }
}

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function matches(value: Record<string, unknown>, expected: Readonly<Record<string, unknown>>): boolean {
  return Object.keys(expected).every((key) => value[key] === expected[key]);
}

const expected = STAGING_GATE7_CONTINUITY;
const snapshotKeys = ["version", "environment", "authorityId", "policyEpoch", "observedAtMs", "initialized", "coverage", "status", "receipt", "releases"];

export type ContinuityEvidence = {
  status: "PASS"; proof: "live-initialized-continuity"; accountFingerprint: string; digest: string; releaseId: string;
  releaseKeyId: string; receiptSequence: number; keyFingerprintPrefix: string; observedAtMs: number;
};

/** Validates one inspectLifecycle(canonical digest) snapshot against the exact
 * Gate 7 state. Any missing, extra or mismatched field refuses with a closed
 * code; nothing is repaired, retried or broadened. Returns only the bounded,
 * redacted evidence line -- never the snapshot itself. */
export function validateGate7ContinuitySnapshot(value: unknown, nowMs: number = Date.now()): ContinuityEvidence {
  if (!exact(value, snapshotKeys)) throw new ContinuityRefusal("snapshot-shape");
  if (value.version !== expected.version || value.environment !== expected.environment ||
      value.authorityId !== expected.authorityId || value.policyEpoch !== expected.policyEpoch)
    throw new ContinuityRefusal("snapshot-identity");
  if (value.initialized !== expected.initialized || value.coverage !== expected.coverage || value.status !== expected.status)
    throw new ContinuityRefusal("snapshot-state");
  if (!exact(value.receipt, Object.keys(expected.receipt)) || !matches(value.receipt, expected.receipt))
    throw new ContinuityRefusal("snapshot-receipt");
  const releases = value.releases;
  if (!Array.isArray(releases) || releases.length !== expected.releases.length ||
      !releases.every((release, index) => exact(release, Object.keys(expected.releases[index])) &&
        matches(release, expected.releases[index])))
    throw new ContinuityRefusal("snapshot-releases");
  const observedAtMs = value.observedAtMs;
  if (typeof observedAtMs !== "number" || !Number.isSafeInteger(observedAtMs) || observedAtMs < 0 ||
      !Number.isSafeInteger(nowMs) || Math.abs(nowMs - observedAtMs) > STAGING_CONTINUITY_OBSERVATION_FRESHNESS_MS)
    throw new ContinuityRefusal("observation-freshness");
  return { status: "PASS", proof: "live-initialized-continuity", accountFingerprint: expected.accountFingerprint,
    digest: expected.receipt.digest, releaseId: expected.receipt.currentReleaseId, releaseKeyId: expected.receipt.nextKeyId,
    receiptSequence: expected.receipt.sequence, keyFingerprintPrefix: expected.receipt.keyFingerprint.slice(0, 16), observedAtMs };
}
