// Gate 8 Phase 0: permanent staging initialization lockout (operator CLI only;
// never imported by workers/). The live staging authority was initialized at
// Gate 7. A fresh, validly signed initialization for any new digest would pass
// the guard's pre-claim read, consume a claim and the singleton latch, and be
// refused by the authority as already initialized; no exact receipt can ever
// exist for that digest, so the latch would stay held permanently.
//
// The record below is reviewed evidence only. Enforcement never reads it:
// refuseClosedStagingInitialization() refuses unconditionally, and there is
// deliberately no unlock, setter, predicate, flag or environment override.

export const STAGING_INITIALIZATION_LOCK = Object.freeze({
  version: 1,
  state: "STAGING_INITIALIZED_PERMANENTLY_CLOSED",
  environment: "staging",
  authorityId: "staging-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1",
  gate: 7,
  recordedDate: "2026-09-24",
  evidenceCommit: "2216dcb",
  digest: "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf",
  releaseId: "staging-gate7-initial",
  releaseKeyId: "staging-gate7-key-1",
  receiptSequence: 1,
  settlement: "SETTLED",
  keyFingerprint: "74f6e266c7cbdced",
  accountFingerprint: "0df3a690b3154513",
} as const);

export const STAGING_INITIALIZATION_REFUSAL =
  "REFUSED: staging initialization is permanently closed (Gate 7 initialized; see the Gate 8 Phase 0 note in " +
  "PHASE5C_I3_PROVISIONING_RUNBOOK.md). No key, artifact, manifest or credential was read; nothing was signed; " +
  "no provider was contacted.\n";

/** Unconditional: no input, record value or environment can change this outcome. */
export function refuseClosedStagingInitialization(): never {
  process.stderr.write(STAGING_INITIALIZATION_REFUSAL);
  process.exit(2);
}
