import assert from "node:assert/strict";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { ATTESTATION_POLICY_EPOCH, ATTESTATION_TRUST_EPOCH, makeReconciliationStatement } from "../src/lib/authority-result-attestation";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH } from "../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, executeSignedAuthorityInitialization, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../workers/admission-service/operator-command";
import { RECOVERY_TIMING, assessRecoveryEvidence, type RecoveryEvidenceInput } from "./support/recovery-evidence";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import { healthySigner, rfcTrustManifest } from "./support/authority-attestation-test-signers";

// Validation of the approved recovery timing parameters against the REAL Authority command layer, plus the pure evidence judge. Nothing here executes,
// prepares or authorizes a recovery.

const ISSUED = 1_760_000_000_000;
const EXPIRY = ISSUED + RECOVERY_TIMING.commandLifetimeMs;
const hex = (fill: string) => fill.repeat(32).slice(0, 32);
async function keys() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { privateKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}
const command = (issued = ISSUED): AuthorityInitializationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "r", "k", issued, true];
const tableCount = (storage: NodeSqliteDurableStorage) => Array.from(storage.sql.exec("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table'") as Iterable<{ count: number }>)[0].count;

test("Authority implementation: the last acceptable clock reading is EXACTLY issuedAtMs + 300 000; one millisecond later the command cannot commit, with zero storage effect", async () => {
  const operator = await keys();
  const signature = await signAuthorityInitializationCommand(command(), operator.privateKey);
  for (const [reading, accepted] of [[EXPIRY, true], [EXPIRY + 1, false], [ISSUED - 300_000, true], [ISSUED - 300_001, false], [EXPIRY + 3_600_000, false]] as const) {
    const storage = new NodeSqliteDurableStorage();
    try {
      const run = executeSignedAuthorityInitialization(storage, command(), signature, operator.publicKey, 0, "production", () => reading);
      if (accepted) assert.equal((await run).status, "initialized", String(reading));
      else {
        await assert.rejects(run, /operator-command-freshness/u, String(reading));
        assert.equal(tableCount(storage), 0, "a command refused for freshness creates no table and writes nothing");
      }
    } finally { storage.close(); }
  }
});

test("delayed completion: however long signature verification, signer preparation or the RPC hop takes, the freshness reading is taken AFTER them and decides", async () => {
  const operator = await keys();
  const signature = await signAuthorityInitializationCommand(command(), operator.privateKey);
  // Simulate an in-flight command whose Authority clock keeps advancing while it waits: the reading is the LAST thing before the transaction.
  let clock = EXPIRY - 5;
  const storage = new NodeSqliteDurableStorage();
  try {
    await assert.rejects(executeSignedAuthorityInitialization(storage, command(), signature, operator.publicKey, 0, "production", () => clock,
      async () => { clock = EXPIRY + 10; await new Promise((resolve) => setTimeout(resolve, 5)); }),   // preflight (signer preparation) crosses the expiry
    /operator-command-freshness/u);
    assert.equal(tableCount(storage), 0);
  } finally { storage.close(); }
  // Conversely a command that is still inside the window at the final reading commits: the evidence rules below therefore wait out the whole window.
  const inside = new NodeSqliteDurableStorage();
  try {
    let moving = EXPIRY - 100;
    const result = await executeSignedAuthorityInitialization(inside, command(), signature, operator.publicKey, 0, "production", () => moving, async () => { moving = EXPIRY; });
    assert.equal(result.status, "initialized");
    assert.equal(result.receipt?.appliedMs, EXPIRY, "appliedMs is the same final reading that passed freshness");
  } finally { inside.close(); }
});

// ----------------------------------------------------------------------------------------------------------------------- evidence judge

async function signedReconciliation(options: { digest: string; nonce: string; observedAtMs: number; initialized?: boolean; coverage?: "COMPLETE" | "INCOMPLETE"; status?: "NOT_FOUND" | "HISTORY_INCOMPLETE" | "EXACT_RECEIPT"; authorityId?: string; environment?: "production" | "staging" }): Promise<Uint8Array> {
  const signer = await healthySigner(options.environment ?? "production");
  await signer.ready(options.observedAtMs);
  const statement = makeReconciliationStatement({
    trustEpoch: ATTESTATION_TRUST_EPOCH, environment: options.environment ?? "production", authorityId: options.authorityId ?? ADMISSION_AUTHORITY_ID, policyEpoch: ATTESTATION_POLICY_EPOCH,
    digest: options.digest, nonce: options.nonce, initialized: options.initialized ?? false, coverage: options.coverage ?? "COMPLETE", status: options.status ?? "NOT_FOUND",
    receipt: null, releases: options.initialized ? [{ releaseId: "r", keyId: "k", activatedMs: ISSUED, retiredMs: null }] : [], observedAtMs: options.observedAtMs, writerKeyFingerprint: signer.writerKeyFingerprint,
  });
  return (await signer.sign(statement)) as Uint8Array;
}

async function baseInput(overrides: { first?: number; second?: number; decision?: number } = {}) {
  const digest = await commandDigest(command());
  const firstAt = overrides.first ?? EXPIRY + RECOVERY_TIMING.firstReconciliationAfterExpiryMs;
  const secondAt = overrides.second ?? firstAt + RECOVERY_TIMING.secondReconciliationAfterFirstMs;
  const decisionAt = overrides.decision ?? secondAt + 120_000;
  const input: RecoveryEvidenceInput = {
    strandedDigest: digest, issuedAtMs: ISSUED, trustManifest: await rfcTrustManifest(), decisionAtMs: decisionAt,
    first: { nonce: hex("a"), bytes: await signedReconciliation({ digest, nonce: hex("a"), observedAtMs: firstAt }), collectedAtMs: firstAt + 5_000 },
    second: { nonce: hex("b"), bytes: await signedReconciliation({ digest, nonce: hex("b"), observedAtMs: secondAt }), collectedAtMs: secondAt + 5_000 },
  };
  return { input, digest, firstAt, secondAt, decisionAt };
}

test("two fresh, fresh-nonce reconciliations at the approved offsets make the evidence requirements met (never a recovery by itself)", async () => {
  const { input, firstAt, secondAt } = await baseInput();
  const verdict = await assessRecoveryEvidence(input);
  assert.equal(verdict.eligible, true);
  if (verdict.eligible) assert.deepEqual([verdict.expiryMs, verdict.firstObservedAtMs, verdict.secondObservedAtMs], [EXPIRY, firstAt, secondAt]);
  // boundaries are inclusive exactly at the approved offsets and exclusive one millisecond short
  assert.equal((await assessRecoveryEvidence((await baseInput({ first: EXPIRY + 300_000 })).input)).eligible, true);
  const early = await baseInput({ first: EXPIRY + 299_999, second: EXPIRY + 299_999 + 60_000 });
  assert.deepEqual(await assessRecoveryEvidence(early.input), { eligible: false, blockers: ["first-too-early"] });
  const secondEarly = await baseInput({ second: EXPIRY + 300_000 + 59_999 });
  assert.deepEqual(await assessRecoveryEvidence(secondEarly.input), { eligible: false, blockers: ["second-too-early"] });
});

test("decision window: not before the second reconciliation, and at most 300 s after it", async () => {
  const base = await baseInput();
  assert.equal((await assessRecoveryEvidence({ ...base.input, decisionAtMs: base.secondAt + 300_000 })).eligible, true);
  const late = await assessRecoveryEvidence({ ...base.input, decisionAtMs: base.secondAt + 300_001 });
  assert.equal(late.eligible, false);
  assert.ok(!late.eligible && late.blockers.includes("signature-or-expectation") || !late.eligible && late.blockers.includes("decision-too-late"), JSON.stringify(late));
  const tooEarly = await assessRecoveryEvidence({ ...base.input, decisionAtMs: base.secondAt - 1 });
  assert.equal(tooEarly.eligible, false);
});

test("any unavailable, inconsistent, invalid or ambiguous evidence blocks: initialized, incomplete history, exact receipt, wrong identity, reused nonce, forged or foreign signature", async () => {
  const { input, digest, firstAt, secondAt } = await baseInput();
  const replaceSecond = async (options: Parameters<typeof signedReconciliation>[0], nonce = hex("b")) => ({ ...input, second: { ...input.second, nonce, bytes: await signedReconciliation(options) } });
  const blocked = async (candidate: RecoveryEvidenceInput) => { const verdict = await assessRecoveryEvidence(candidate); assert.equal(verdict.eligible, false, JSON.stringify(verdict)); return verdict.eligible ? [] : verdict.blockers; };
  assert.deepEqual(await blocked(await replaceSecond({ digest, nonce: hex("b"), observedAtMs: secondAt, initialized: true, status: "NOT_FOUND" })), ["initialized-or-incomplete", "receipt-or-release-present"]);
  assert.deepEqual(await blocked(await replaceSecond({ digest, nonce: hex("b"), observedAtMs: secondAt, initialized: true, coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE" })), ["initialized-or-incomplete", "receipt-or-release-present"]);
  assert.ok((await blocked(await replaceSecond({ digest: "f".repeat(64), nonce: hex("b"), observedAtMs: secondAt }))).includes("signature-or-expectation"), "another digest");
  assert.ok((await blocked(await replaceSecond({ digest, nonce: hex("c"), observedAtMs: secondAt }, hex("b")))).includes("signature-or-expectation"), "nonce bound in the signed statement differs from the caller's");
  assert.ok((await blocked(await replaceSecond({ digest, nonce: hex("b"), observedAtMs: secondAt, environment: "staging", authorityId: "staging-public-inquiries-v1" }))).includes("signature-or-expectation"), "staging statement");
  await assert.rejects(signedReconciliation({ digest, nonce: hex("b"), observedAtMs: secondAt, authorityId: "lab-public-inquiries-v1" }), /attestation-(?:signer-)?statement/u, "a statement for another authority cannot even be built or signed by the production signer");
  // the same stored object offered twice, or the same nonce twice
  assert.ok((await blocked({ ...input, second: { ...input.first } })).includes("nonce-reused"));
  assert.ok((await blocked({ ...input, second: { ...input.second, nonce: input.first.nonce } })).includes("nonce-reused"));
  // tampered / truncated / empty / non-signed bytes
  const tampered = new Uint8Array(input.second.bytes); tampered[tampered.length - 5] ^= 1;
  assert.ok((await blocked({ ...input, second: { ...input.second, bytes: tampered } })).includes("signature-or-expectation"));
  assert.ok((await blocked({ ...input, second: { ...input.second, bytes: input.second.bytes.slice(0, 40) } })).includes("signature-or-expectation"));
  assert.ok((await blocked({ ...input, second: { ...input.second, bytes: new TextEncoder().encode(JSON.stringify({ version: 1, digest, status: "UNAVAILABLE" })) } })).includes("signature-or-expectation"), "an unsigned relay diagnostic is never evidence");
  assert.deepEqual(await blocked({ ...input, second: { ...input.second, bytes: new Uint8Array() } }), ["input"]);
  assert.deepEqual(await blocked({ ...input, strandedDigest: "xyz" }), ["digest"]);
  assert.deepEqual(await blocked({ ...input, issuedAtMs: 1.5 }), ["input"]);
  // an old reconciliation taken before expiry can never be passed off as the first one
  const old = await baseInput({ first: ISSUED + 1_000, second: ISSUED + 61_000 });
  assert.ok((await blocked(old.input)).includes("first-too-early"));
  // reconciliations collected out of order, and order of observation inverted
  assert.ok((await blocked({ ...input, first: { ...input.first, collectedAtMs: input.second.collectedAtMs + 1_000 } })).includes("collection-order"));
  const swapped = await baseInput({ first: secondAt, second: firstAt });
  assert.ok((await blocked(swapped.input)).length > 0);
});

test("the judge is pure: it imports nothing that can sign, submit, claim or write, and exposes no recovery action", async () => {
  const { readFile } = await import("node:fs/promises");
  const source = (await readFile(new URL("./support/recovery-evidence.ts", import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "");
  assert.deepEqual([...source.matchAll(/^import .*? from "([^"]+)";$/gmu)].map((m) => m[1]).sort(),
    ["../../operator/authority-result-reader", "../../operator/recovery-decision-record", "../../workers/admission-service/authority"]);
  assert.doesNotMatch(source, /node:fs|node:child_process|fetch\(|sign\(|submit|claim|settle|replace|writeFile|initializeAuthority/u);
  assert.deepEqual([...source.matchAll(/^export (?:async )?(?:function|const) (\w+)/gmu)].map((m) => m[1]), ["assessRecoveryEvidence"]);
});
