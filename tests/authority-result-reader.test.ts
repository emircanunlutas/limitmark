import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  ATTESTATION_MAX_AGE_MS,
  attestationKeyFingerprint,
  type AttestationReceipt,
  type AttestationReleaseRow,
} from "../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest } from "../src/lib/authority-result-trust";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { isProductionAuthorityPositive, isStagingAuthorityPositive } from "../operator/authority-result-verifier";
import { readProductionAuthorityResult, readStagingAuthorityResult, type AuthorityReadOutcome } from "../operator/authority-result-reader";
import type { AuthenticatedLifecycleCommand } from "../operator/lifecycle-submitter";
import { STAGING_GATE7_CONTINUITY } from "../operator/staging-gate7-continuity";
import { unsignedDiagnostic } from "../operator/attested-relay";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { NONCE, OTHER_NONCE, fixturesAt, operatorKey, text, trustManifest, writer } from "./support/authority-result-fixtures";

// R06 Slice 2C: the active reader (Production and staging operator CLIs). Every positive requires a genuine Authority-signed envelope
// AND the independent evidence (Production: authenticated R07 command + 12-field equality; staging: Gate 7 pins). The stored
// object is hostile: nothing but the verified envelope bytes and caller-known expectations may decide anything.

const NOW = 1_800_000_000_000;
const fx = fixturesAt(NOW);
const { ISSUED, OBSERVED, authenticated, receiptFor, lifecycle, reconciliation } = fx;
const manifest = trustManifest;
const readProduction = async (kind: "lifecycle" | "reconciliation", digest: string, bytes: Uint8Array, command?: AuthenticatedLifecycleCommand,
  options: { nonce?: string; nowMs?: number } = {}): Promise<AuthorityReadOutcome> =>
  readProductionAuthorityResult({ kind, digest, ...(kind === "reconciliation" ? { nonce: options.nonce ?? NONCE } : {}), bytes, trustManifest: await manifest(),
    nowMs: options.nowMs ?? NOW, ...(command ? { authenticatedCommand: command } : {}) });
const readStaging = async (kind: "lifecycle" | "reconciliation", digest: string, bytes: Uint8Array, options: { nonce?: string; nowMs?: number } = {}): Promise<AuthorityReadOutcome> =>
  readStagingAuthorityResult({ kind, digest, ...(kind === "reconciliation" ? { nonce: options.nonce ?? NONCE } : {}), bytes, trustManifest: await manifest(), nowMs: options.nowMs ?? NOW });

function assertUnconfirmed(outcome: AuthorityReadOutcome, reason: string | RegExp, label: string) {
  assert.equal(outcome.status, "UNCONFIRMED", `${label}: ${JSON.stringify(outcome)}`);
  if (outcome.status !== "UNCONFIRMED") return;
  if (typeof reason === "string") assert.equal(outcome.reason, reason, label);
  else assert.match(outcome.reason, reason, label);
}

// ---------------------------------------------------------------------------------------------------------------------
// Production
// ---------------------------------------------------------------------------------------------------------------------
test("Production POSITIVE needs signed R06 AND an authenticated command; every positive carries the brand and the verified receipt", async () => {
  const operator = await operatorKey();
  for (const which of ["initialize", "rotate-release"] as const) {
    const command = await authenticated(operator, which);
    const receipt = receiptFor(command);
    for (const [kind, bytes] of [["lifecycle", await lifecycle("production", receipt)], ["reconciliation", await reconciliation("production", "EXACT_RECEIPT", receipt.digest, receipt)]] as const) {
      const positive = await readProduction(kind, receipt.digest, bytes, command);
      assert.equal(positive.status, "POSITIVE", `${which} ${kind}`);
      assert.equal((positive as { receipt: AttestationReceipt }).receipt.digest, command.digest);
      assert.equal(isProductionAuthorityPositive((positive as unknown as { composed: unknown }).composed), true, "the branded 2B composer result backs the outcome");
      assert.equal(Object.keys(positive).includes("composed"), false, "the brand is never serialized");
      assert.deepEqual(JSON.parse(JSON.stringify(positive)), { status: "POSITIVE", environment: "production", kind, digest: command.digest, observedAtMs: OBSERVED,
        signingKeyFingerprint: await writer("production"), receipt });
      // R06 alone is never positive
      const alone = await readProduction(kind, receipt.digest, bytes);
      assert.equal(alone.status, "VERIFIED_NON_POSITIVE", `${which} ${kind} without command`);
      assert.equal((alone as { observation: string }).observation, "COMMAND_CONTEXT_REQUIRED");
    }
  }
});

test("Production: signed negatives are reportable without a command, and a MISMATCHED optional command never erases them or vouches for a positive", async () => {
  const operator = await operatorKey();
  const command = await authenticated(operator, "initialize");
  const other = await authenticated(operator, "rotate-release");
  const digest = command.digest;
  for (const state of ["NOT_FOUND", "HISTORY_INCOMPLETE"] as const) {
    const bytes = await reconciliation("production", state, digest, null);
    const bare = await readProduction("reconciliation", digest, bytes);
    assert.deepEqual([bare.status, (bare as { observation: string }).observation, "commandContext" in bare], ["VERIFIED_NON_POSITIVE", state, false]);
    const matching = await readProduction("reconciliation", digest, bytes, command);
    assert.deepEqual([matching.status, (matching as { observation: string }).observation, "commandContext" in matching], ["VERIFIED_NON_POSITIVE", state, false]);
    const mismatched = await readProduction("reconciliation", digest, bytes, other);
    assert.deepEqual([mismatched.status, (mismatched as { observation: string }).observation, (mismatched as { commandContext?: string }).commandContext],
      ["VERIFIED_NON_POSITIVE", state, "MISMATCHED"], "the valid signed negative survives inconsistent optional context");
  }
  // a positive candidate with a mismatched command is NEVER positive and says why
  const receipt = receiptFor(command);
  for (const [kind, bytes] of [["lifecycle", await lifecycle("production", receipt)], ["reconciliation", await reconciliation("production", "EXACT_RECEIPT", digest, receipt)]] as const) {
    const outcome = await readProduction(kind, digest, bytes, other);
    assert.deepEqual([outcome.status, (outcome as { observation: string }).observation, (outcome as { commandContext?: string }).commandContext],
      ["VERIFIED_NON_POSITIVE", "COMMAND_CONTEXT_REQUIRED", "MISMATCHED"], kind);
  }
});

test("Production: all twelve command-derived fields are enforced against genuine signed evidence; Authority-assigned fields are not command-bound", async () => {
  const operator = await operatorKey();
  const command = await authenticated(operator, "rotate-release");
  const mutations: Partial<AttestationReceipt>[] = [
    { operation: "initialize" }, { environment: "staging" } as never, { authorityId: "other" }, { policyEpoch: "other" } as never, { operatorKeyFingerprint: "e".repeat(64) },
    { currentReleaseId: "release-x" }, { nextReleaseId: "release-x" }, { nextKeyId: "key-x" }, { activatesMs: command.expected.activatesMs + 1 },
    { retiresMs: (command.expected.retiresMs as number) + 1 }, { version: 2 } as never,
  ];
  let signedMutations = 0;
  for (const mutation of mutations) {
    const receipt = receiptFor(command, mutation);
    let bytes: Uint8Array;
    try { bytes = await lifecycle("production", receipt); } catch { continue; } // the frozen protocol itself refused to sign this statement
    signedMutations += 1;
    assertUnconfirmed(await readProduction("lifecycle", command.digest, bytes, command), /^(?:command-mismatch|attestation-.+|result-contract)$/u, JSON.stringify(mutation));
  }
  assert.ok(signedMutations >= 6, `exercised ${signedMutations} mutations that reach the composer`);
  // sequence / appliedMs are Authority-assigned: any valid value is accepted
  const positive = await readProduction("lifecycle", command.digest, await lifecycle("production", receiptFor(command, { sequence: 4_000, appliedMs: ISSUED + 1 })), command);
  assert.equal(positive.status, "POSITIVE");
  // a digest that is not the command's: the command does not match, so the candidate cannot be positive
  const synthetic = "5".repeat(64);
  const forged = await readProduction("lifecycle", synthetic, await lifecycle("production", receiptFor(command), OBSERVED, synthetic), command);
  assert.notEqual(forged.status, "POSITIVE");
});

test("hostile bytes never become positive: byte flips, truncation, re-serialization, wrappers, wrong digest/nonce/environment, staleness, unknown and retired keys", async () => {
  const operator = await operatorKey();
  const command = await authenticated(operator, "initialize");
  const receipt = receiptFor(command);
  const good = await lifecycle("production", receipt);
  assert.equal((await readProduction("lifecycle", command.digest, good, command)).status, "POSITIVE");
  const never = async (label: string, bytes: Uint8Array, kind: "lifecycle" | "reconciliation" = "lifecycle", options: { nonce?: string; nowMs?: number; digest?: string } = {}) => {
    const outcome = await readProduction(kind, options.digest ?? command.digest, bytes, command, options);
    assert.notEqual(outcome.status, "POSITIVE", label);
    assert.equal(outcome.status, "UNCONFIRMED", `${label}: ${JSON.stringify(outcome)}`);
  };
  // one flipped byte anywhere
  for (let index = 0; index < good.length; index += 7) { const mutated = good.slice(); mutated[index] ^= 0x01; await never(`flip byte ${index}`, mutated); }
  await never("truncated", good.slice(0, good.length - 1));
  await never("truncated half", good.slice(0, good.length >> 1));
  await never("empty", new Uint8Array(0));
  await never("appended byte", Uint8Array.from([...good, 0x0a]));
  const pretty = new TextEncoder().encode(JSON.stringify(JSON.parse(new TextDecoder().decode(good)), null, 2));
  await never("pretty-printed re-serialization", pretty);
  await never("reordered whitespace", new TextEncoder().encode(new TextDecoder().decode(good).replace(",", ", ")));
  // outer wrappers and legacy shapes are not evidence, whatever they claim
  const base64 = Buffer.from(good).toString("base64");
  for (const wrapper of [{ envelope: base64, status: "SUCCESS" }, { envelope: Array.from(good), status: "ALREADY_APPLIED", receipt }, { version: 1, digest: command.digest,
    environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: NOW, status: "SUCCESS", receipt }])
    await never(`wrapper ${Object.keys(wrapper).join(",")}`, text(wrapper));
  // another digest's genuinely signed envelope
  const otherCommand = await authenticated(operator, "initialize", "release-other");
  await never("other digest's envelope", await lifecycle("production", receiptFor(otherCommand)));
  // cross-environment: a staging-signed statement and a staging-labelled production statement
  await never("staging envelope for the same digest", await lifecycle("staging", { ...receipt, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID } as AttestationReceipt));
  // reconciliation nonce replaced / replayed against a new request
  const rec = await reconciliation("production", "EXACT_RECEIPT", command.digest, receipt, { nonce: OTHER_NONCE });
  await never("old nonce replayed against a new request", rec, "reconciliation", { nonce: NONCE });
  assert.equal((await readProduction("reconciliation", command.digest, rec, command, { nonce: OTHER_NONCE })).status, "POSITIVE", "the same bytes are valid only for their own nonce");
  // replay / freshness: an old valid envelope, a future one, and the exact boundaries
  await never("stale by one ms", good, "lifecycle", { nowMs: OBSERVED + ATTESTATION_MAX_AGE_MS + 1 });
  await never("future beyond skew", await lifecycle("production", receipt, NOW + 60_001), "lifecycle", { nowMs: NOW });
  assert.equal((await readProduction("lifecycle", command.digest, good, command, { nowMs: OBSERVED + ATTESTATION_MAX_AGE_MS })).status, "POSITIVE");
  assert.equal((await readProduction("lifecycle", command.digest, await lifecycle("production", receipt, NOW + 60_000), command)).status, "POSITIVE");
  // retired or unknown signer: the same genuinely signed bytes under a manifest where the writer key is retired / absent
  const fresh = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const freshPublic = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", fresh.publicKey)));
  const freshEntry = { keyFingerprint: await attestationKeyFingerprint(freshPublic), publicKey: freshPublic, status: "active", notBeforeMs: 1_700_000_000_000, notAfterMs: null };
  const variant = async (keys: (production: { keyFingerprint: string; publicKey: string; status: string; notBeforeMs: number; notAfterMs: number | null }) => unknown[]) => {
    const copy = JSON.parse(await readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8"));
    copy.environments[0].keys = keys(copy.environments[0].keys[0]);
    copy.environments[0].currentKeyFingerprint = freshEntry.keyFingerprint;
    return parseAuthorityResultTrustManifest(JSON.stringify(copy));
  };
  const unknownSigner = await variant(() => [freshEntry]);
  const retiredSigner = await variant((writerKey) => [freshEntry, { ...writerKey, status: "retired", notAfterMs: OBSERVED + 10 ** 9 }]);
  for (const [label, trustManifest] of [["unknown signer", unknownSigner], ["retired signer", retiredSigner]] as const) {
    const outcome = await readProductionAuthorityResult({ kind: "lifecycle", digest: command.digest, bytes: good, trustManifest, nowMs: NOW, authenticatedCommand: command });
    assertUnconfirmed(outcome, "attestation-key", label);
  }
});

test("Production: replay and reordering do not invent receipt/snapshot equality the frozen protocol avoids", async () => {
  const operator = await operatorKey();
  const command = await authenticated(operator, "initialize");
  const receipt = receiptFor(command);
  // a historical EXACT_RECEIPT whose CURRENT release snapshot has since moved on (a later rotation) is still the same command's evidence
  const newer: AttestationReleaseRow[] = [{ releaseId: receipt.nextReleaseId, keyId: receipt.nextKeyId, activatedMs: receipt.activatesMs, retiredMs: ISSUED + 100_000 },
    { releaseId: "release-later", keyId: "key-later", activatedMs: ISSUED + 50_000, retiredMs: null }];
  const historical = await reconciliation("production", "EXACT_RECEIPT", command.digest, receipt, { releases: newer });
  assert.equal((await readProduction("reconciliation", command.digest, historical, command)).status, "POSITIVE");
  // two reconciliation envelopes for different nonces delivered out of order: each is accepted only for its own nonce
  const first = await reconciliation("production", "NOT_FOUND", command.digest, null, { nonce: NONCE });
  const second = await reconciliation("production", "EXACT_RECEIPT", command.digest, receipt, { nonce: OTHER_NONCE });
  assert.equal((await readProduction("reconciliation", command.digest, second, command, { nonce: NONCE })).status, "UNCONFIRMED");
  assert.equal((await readProduction("reconciliation", command.digest, first, command, { nonce: OTHER_NONCE })).status, "UNCONFIRMED");
  assert.equal((await readProduction("reconciliation", command.digest, first, command, { nonce: NONCE })).status, "VERIFIED_NON_POSITIVE");
  assert.equal((await readProduction("reconciliation", command.digest, second, command, { nonce: OTHER_NONCE })).status, "POSITIVE");
});

test("unsigned legacy results are never positive, whatever they say; an explicit unsigned diagnostic is reported as such", async () => {
  const operator = await operatorKey();
  const command = await authenticated(operator, "initialize");
  const receipt = { ...command.expected, sequence: 1, appliedMs: NOW };
  const legacyBase = { version: 1, digest: command.digest, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: NOW };
  for (const body of [{ ...legacyBase, status: "SUCCESS", receipt }, { ...legacyBase, status: "ALREADY_APPLIED", receipt },
    { ...legacyBase, nonce: NONCE, status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [] }]) {
    for (const kind of ["lifecycle", "reconciliation"] as const) {
      const outcome = await readProduction(kind, command.digest, text(body), command);
      assert.equal(outcome.status, "UNCONFIRMED", `${kind} ${body.status}`);
      assert.equal(JSON.stringify(outcome).includes("POSITIVE"), false);
    }
  }
  const diagnostic = await readProduction("lifecycle", command.digest, text(unsignedDiagnostic(command.digest, "REFUSED", "x")), command);
  assert.deepEqual(diagnostic, { status: "UNCONFIRMED", environment: "production", kind: "lifecycle", digest: command.digest, reason: "no-signed-evidence", relayStatus: "REFUSED" });
  // junk, missing object bytes, malformed v2
  for (const junk of [new Uint8Array(0), new Uint8Array([1, 2, 3]), text({ statement: {}, signature: "AA" }), text({ statement: [], signature: 5 })])
    assert.equal((await readProduction("lifecycle", command.digest, junk, command)).status, "UNCONFIRMED");
  // a provenance-forged command is a programming error, not evidence
  const forged = { ...command };
  const genuine = await lifecycle("production", receiptFor(command));
  const trustManifest = await manifest();
  await assert.rejects(() => readProductionAuthorityResult({ kind: "lifecycle", digest: command.digest, bytes: genuine,
    trustManifest, nowMs: NOW, authenticatedCommand: forged as AuthenticatedLifecycleCommand }), /result-command-provenance/u);
});

// ---------------------------------------------------------------------------------------------------------------------
// Staging: signature AND the Gate 7 pins
// ---------------------------------------------------------------------------------------------------------------------
const GATE7_NOW = STAGING_GATE7_CONTINUITY.receipt.appliedMs + 10_000;
const { gate7Receipt, gate7Release } = fx;
const gate7Digest = STAGING_GATE7_CONTINUITY.receipt.digest;
const gate7Lifecycle = (over: Partial<AttestationReceipt> = {}, observedAtMs = GATE7_NOW - 1_000) => lifecycle("staging", gate7Receipt(over), observedAtMs, gate7Digest);

test("staging POSITIVE needs the signed staging statement AND every Gate 7 pin; unsigned old staging positives are non-positive", async () => {
  for (const [kind, bytes] of [["lifecycle", await gate7Lifecycle()],
    ["reconciliation", await reconciliation("staging", "EXACT_RECEIPT", gate7Digest, gate7Receipt(), { observedAtMs: GATE7_NOW - 1_000, releases: [gate7Release()] })]] as const) {
    const positive = await readStaging(kind, gate7Digest, bytes, { nowMs: GATE7_NOW });
    assert.equal(positive.status, "POSITIVE", kind);
    assert.equal(isStagingAuthorityPositive((positive as unknown as { composed: unknown }).composed), true);
  }
  // every Gate 7 pin, mutated in an otherwise genuine signed statement, is refused (the signature never replaces a pin)
  const mutations: Partial<AttestationReceipt>[] = [{ operatorKeyFingerprint: "e".repeat(64) }, { sequence: 2 }, { appliedMs: STAGING_GATE7_CONTINUITY.receipt.appliedMs + 1 },
    { currentReleaseId: "staging-other" }, { nextReleaseId: "staging-other" }, { nextKeyId: "staging-other-key" }, { activatesMs: STAGING_GATE7_CONTINUITY.receipt.activatesMs + 1 }, { operation: "rotate-release" }];
  for (const mutation of mutations) {
    let bytes: Uint8Array;
    try { bytes = await gate7Lifecycle(mutation); } catch { continue; }
    const outcome = await readStaging("lifecycle", gate7Digest, bytes, { nowMs: GATE7_NOW });
    assert.notEqual(outcome.status, "POSITIVE", JSON.stringify(mutation));
  }
  // a different (non-pinned) staging digest cannot be positive even though the Authority signed it
  const otherDigest = "7".repeat(64);
  assert.notEqual((await readStaging("lifecycle", otherDigest, await lifecycle("staging", gate7Receipt({ digest: otherDigest }), GATE7_NOW - 1_000, otherDigest), { nowMs: GATE7_NOW })).status, "POSITIVE");
  // (the canonical release row is also pinned by the composer; for a sequence-1 initialization the frozen statement validator already
  // refuses to sign any other snapshot, and tests/authority-result-verifier.test.ts exercises the pin itself.)
  // old unsigned staging objects
  const legacy = { version: 1, digest: gate7Digest, environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: GATE7_NOW };
  for (const kind of ["lifecycle", "reconciliation"] as const) {
    assert.equal((await readStaging(kind, gate7Digest, text({ ...legacy, nonce: NONCE, status: kind === "lifecycle" ? "SUCCESS" : "EXACT_RECEIPT", receipt: STAGING_GATE7_CONTINUITY.receipt,
      initialized: true, coverage: "COMPLETE", releases: STAGING_GATE7_CONTINUITY.releases }), { nowMs: GATE7_NOW })).status, "UNCONFIRMED", kind);
  }
});

test("staging: signed negatives are reportable; cross-environment, stale and nonce-replaced evidence is not positive", async () => {
  const negative = await reconciliation("staging", "NOT_FOUND", gate7Digest, null, { observedAtMs: GATE7_NOW - 1_000, releases: [gate7Release()] });
  const outcome = await readStaging("reconciliation", gate7Digest, negative, { nowMs: GATE7_NOW });
  assert.deepEqual([outcome.status, (outcome as { observation: string }).observation], ["VERIFIED_NON_POSITIVE", "NOT_FOUND"]);
  const incomplete = await reconciliation("staging", "HISTORY_INCOMPLETE", gate7Digest, null, { observedAtMs: GATE7_NOW - 1_000, releases: [gate7Release()] });
  assert.equal((await readStaging("reconciliation", gate7Digest, incomplete, { nowMs: GATE7_NOW })).status, "VERIFIED_NON_POSITIVE");
  const good = await gate7Lifecycle();
  // a Production-environment envelope presented to the staging reader, and the staging envelope presented to the Production reader
  const operator = await operatorKey();
  const productionCommand = await authenticated(operator, "initialize");
  assertUnconfirmed(await readStaging("lifecycle", productionCommand.digest, await lifecycle("production", receiptFor(productionCommand)), { nowMs: NOW }), "attestation-expectation", "production envelope at staging");
  assertUnconfirmed(await readProduction("lifecycle", gate7Digest, good, undefined, { nowMs: GATE7_NOW }), "attestation-expectation", "staging envelope at production");
  assertUnconfirmed(await readStaging("lifecycle", gate7Digest, good, { nowMs: GATE7_NOW - 1_000 + ATTESTATION_MAX_AGE_MS + 1_001 }), "attestation-stale", "stale");
  const rec = await reconciliation("staging", "EXACT_RECEIPT", gate7Digest, gate7Receipt(), { nonce: OTHER_NONCE, observedAtMs: GATE7_NOW - 1_000, releases: [gate7Release()] });
  assertUnconfirmed(await readStaging("reconciliation", gate7Digest, rec, { nonce: NONCE, nowMs: GATE7_NOW }), "attestation-expectation", "nonce replaced");
});
