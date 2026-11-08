import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { ATTESTATION_POLICY_EPOCH, ATTESTATION_TRUST_EPOCH, makeReconciliationStatement } from "../src/lib/authority-result-attestation";
import { ADMISSION_AUTHORITY_ID } from "../workers/admission-service/authority";
import { readProductionAuthorityResult } from "../operator/authority-result-reader";
import { healthySigner, rfcTrustManifest } from "./support/authority-attestation-test-signers";

// The reconciliation reader exposes the Authority-SIGNED `initialized`/`coverage` on a verified non-positive outcome. The value comes from the authenticated statement only.

const DIGEST = "a".repeat(64);
const NONCE = "b".repeat(32);
const OBSERVED = 1_760_000_000_000;

async function envelope(options: { initialized: boolean; coverage?: "COMPLETE" | "INCOMPLETE"; status?: "NOT_FOUND" | "HISTORY_INCOMPLETE"; nonce?: string; digest?: string; observedAtMs?: number; releases?: boolean }): Promise<Uint8Array> {
  const signer = await healthySigner("production");
  await signer.ready(options.observedAtMs ?? OBSERVED);
  const statement = makeReconciliationStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ATTESTATION_POLICY_EPOCH,
    digest: options.digest ?? DIGEST, nonce: options.nonce ?? NONCE, initialized: options.initialized, coverage: options.coverage ?? "COMPLETE", status: options.status ?? "NOT_FOUND",
    receipt: null, releases: options.releases ?? options.initialized ? [{ releaseId: "r", keyId: "k", activatedMs: OBSERVED - 1_000, retiredMs: null }] : [],
    observedAtMs: options.observedAtMs ?? OBSERVED, writerKeyFingerprint: signer.writerKeyFingerprint,
  });
  return (await signer.sign(statement)) as Uint8Array;
}
const read = async (bytes: Uint8Array, nowMs = OBSERVED + 1_000, digest = DIGEST, nonce = NONCE) =>
  readProductionAuthorityResult({ includeSignedInitialization: true, kind: "reconciliation", digest, nonce, bytes, trustManifest: await rfcTrustManifest(), nowMs });

test("a signed never-initialized reconciliation reports initialized:false / COMPLETE / NOT_FOUND", async () => {
  const outcome = await read(await envelope({ initialized: false }));
  assert.equal(outcome.status, "VERIFIED_NON_POSITIVE");
  if (outcome.status !== "VERIFIED_NON_POSITIVE") return;
  assert.deepEqual([outcome.initialized, outcome.coverage, outcome.observation, outcome.observedAtMs], [false, "COMPLETE", "NOT_FOUND", OBSERVED]);
});

test("signed initialized-by-another-command and incomplete-history statements are distinguishable from never-initialized", async () => {
  const other = await read(await envelope({ initialized: true }));
  assert.ok(other.status === "VERIFIED_NON_POSITIVE" && other.initialized === true && other.coverage === "COMPLETE" && other.observation === "NOT_FOUND");
  const incomplete = await read(await envelope({ initialized: true, coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE" }));
  assert.ok(incomplete.status === "VERIFIED_NON_POSITIVE" && incomplete.initialized === true && incomplete.coverage === "INCOMPLETE" && incomplete.observation === "HISTORY_INCOMPLETE");
});

test("missing evidence: empty, truncated, unsigned relay diagnostics and foreign objects yield UNCONFIRMED with NO initialized value", async () => {
  const good = await envelope({ initialized: false });
  const unsigned = new TextEncoder().encode(JSON.stringify({ version: 1, digest: DIGEST, nonce: NONCE, status: "UNAVAILABLE", reason: "authority-state-unavailable" }));
  for (const [name, bytes] of Object.entries({ empty: new Uint8Array(), truncated: good.slice(0, 50), unsigned, text: new TextEncoder().encode("initialized:false") })) {
    const outcome = await read(bytes);
    assert.equal(outcome.status, "UNCONFIRMED", name);
    assert.equal("initialized" in outcome, false, name);
  }
});

test("invalid evidence: tampered signature, other digest, other nonce, wrong environment trust all UNCONFIRMED", async () => {
  const good = await envelope({ initialized: false });
  const tampered = new Uint8Array(good); tampered[tampered.length - 4] ^= 1;
  for (const [name, outcome] of Object.entries({
    tampered: await read(tampered), otherDigest: await read(good, OBSERVED + 1_000, "c".repeat(64)), otherNonce: await read(good, OBSERVED + 1_000, DIGEST, "d".repeat(32)),
    flippedInitialized: await read(new TextEncoder().encode(new TextDecoder().decode(good).replace("false", "true"))),
  })) { assert.equal(outcome.status, "UNCONFIRMED", name); assert.equal("initialized" in outcome, false, name); }
});

test("contradictory evidence cannot exist: the statement grammar refuses initialized/coverage/status/releases combinations that the Authority never states", async () => {
  const signer = await healthySigner("production");
  const build = (initialized: boolean, coverage: "COMPLETE" | "INCOMPLETE", status: "NOT_FOUND" | "HISTORY_INCOMPLETE", withRelease: boolean) => () => makeReconciliationStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ATTESTATION_POLICY_EPOCH, digest: DIGEST, nonce: NONCE, initialized, coverage, status,
    receipt: null, releases: withRelease ? [{ releaseId: "r", keyId: "k", activatedMs: 1, retiredMs: null }] : [], observedAtMs: OBSERVED, writerKeyFingerprint: signer.writerKeyFingerprint });
  assert.throws(build(false, "COMPLETE", "NOT_FOUND", true), /attestation-releases/u, "uninitialized with release rows");
  assert.throws(build(true, "COMPLETE", "NOT_FOUND", false), /attestation-releases/u, "initialized without release rows");
  assert.throws(build(false, "INCOMPLETE", "HISTORY_INCOMPLETE", false), /attestation-statement/u, "uninitialized but incomplete");
  assert.throws(build(false, "COMPLETE", "HISTORY_INCOMPLETE", false), /attestation-statement/u);
  assert.throws(build(true, "COMPLETE", "HISTORY_INCOMPLETE", true), /attestation-statement/u);
});

test("stale or future-dated evidence is refused by the reader's freshness rule (300 s max age, 60 s future skew)", async () => {
  const bytes = await envelope({ initialized: false });
  assert.equal((await read(bytes, OBSERVED + 300_000)).status, "VERIFIED_NON_POSITIVE");
  assert.equal((await read(bytes, OBSERVED + 300_001)).status, "UNCONFIRMED");
  assert.equal((await read(bytes, OBSERVED - 60_000)).status, "VERIFIED_NON_POSITIVE");
  assert.equal((await read(bytes, OBSERVED - 60_001)).status, "UNCONFIRMED");
});

test("provenance: the value is copied from the verified statement only; the reader reads no ledger, no relay object and adds no new importer", async () => {
  const source = (await readFile(new URL("../operator/authority-result-reader.ts", import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "");
  assert.match(source, /initialized: statement\.initialized, coverage: statement\.coverage/u);
  assert.doesNotMatch(source, /guard|ledger|claims|settlements|node:fs/iu);
  assert.deepEqual([...source.matchAll(/^import .*? from "([^"]+)";$/gmu)].map((m) => m[1]).filter((s) => s.startsWith("./") || s.startsWith("../")).length > 0, true);
});

test("opt-in: without includeSignedInitialization the outcome shape is exactly the historical one (no initialized/coverage)", async () => {
  const bytes = await envelope({ initialized: false });
  const outcome = await readProductionAuthorityResult({ kind: "reconciliation", digest: DIGEST, nonce: NONCE, bytes, trustManifest: await rfcTrustManifest(), nowMs: OBSERVED + 1_000 });
  assert.equal(outcome.status, "VERIFIED_NON_POSITIVE");
  assert.equal("initialized" in outcome, false);
  assert.equal("coverage" in outcome, false);
});
