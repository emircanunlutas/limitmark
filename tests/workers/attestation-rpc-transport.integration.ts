import assert from "node:assert/strict";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import type { Unstable_DevWorker } from "wrangler";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  commandDigest,
  expectedCommandReceipt,
  signAuthorityInitializationCommand,
  type AuthorityInitializationCommand,
} from "../../workers/admission-service/operator-command";
import { parseResultAttestationEnvelope } from "../../src/lib/authority-result-attestation";
import {
  parseAuthorityResultTrustManifest,
  verifyAuthoritySignedStatement,
  type ResultAttestationExpectations,
} from "../../src/lib/authority-result-trust";
import { encodeBase64url } from "../../src/lib/ingress-protocol";

// R06 PRE-2C transport gate. Proves, against a REAL local workerd (Durable Object RPC + WorkerEntrypoint RPC, real SQLite DO
// storage, real Slice 2A producer and RFC test signer), that an attested Authority result carrying the canonical R06 envelope as
// a native Uint8Array survives the RPC boundary byte-for-byte. The harness (workers/attestation-rpc-transport-harness.ts) is
// local-test-only. Nothing here activates Slice 2C.

const port = 8800;
const root = `http://127.0.0.1:${port}`;
const runtimeRoot = join(process.cwd(), ".wrangler", "tests", "attestation-rpc-transport");
const persistPath = join(runtimeRoot, "state");

type Role = "production" | "staging";
type Observed = {
  keys: string[]; status: string; relayDisposition?: string; reason?: string;
  envelope?: { isUint8Array: boolean; tag: string; byteLength: number; byteOffset: number; bufferByteLength: number; hex: string };
};
type CallReport = { hop1: Observed; final: Observed; finalIsPlainObject: boolean };

const bytesOf = (text: string) => new Uint8Array(Buffer.from(text, "hex"));

// Loose by design: this is the JSON the local harness reports back over plain HTTP.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Reported = Record<string, any>;
async function post(path: string, body: unknown): Promise<{ status: number; body: Reported }> {
  const response = await fetch(`${root}/__local-attestation-transport/${path}`, {
    method: "POST",
    signal: AbortSignal.timeout(20_000),
    headers: { "content-type": "application/json", "x-local-attestation-transport-test": "r06-pre2c" },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() as Reported };
}
async function call(role: Role, method: string, ...args: unknown[]): Promise<CallReport> {
  const result = await post("call", { role, method, args });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  return result.body as unknown as CallReport;
}
const retainedHex = async (role: Role) => (await post("retained", { role })).body.hex as string | null;

async function main() {
  await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  await mkdir(runtimeRoot, { recursive: true });
  process.env.XDG_CONFIG_HOME = join(runtimeRoot, "config");
  process.env.WRANGLER_SEND_METRICS = "false";

  // Existing frozen RFC 8032 test material only (TEST KEYS - NEVER PROVISION). The operator command key is an in-memory
  // ephemeral test key, exactly as in the existing workerd integration tests; nothing is written to disk.
  const goldenText = await readFile(join(process.cwd(), "tests", "fixtures", "authority-result-attestation-v2.golden.json"), "utf8");
  const rfcKeys = (JSON.parse(goldenText) as { keys: Record<Role, { privateKeyPkcs8: string; publicKey: string; fingerprint: string }> }).keys;
  const trust = await parseAuthorityResultTrustManifest(await readFile(join(process.cwd(), "tests", "fixtures", "authority-result-trust-v1.test.json"), "utf8"));
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const operatorPrivate = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const operatorPublic = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));

  const authorityId = (role: Role) => role === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID;
  const initialize = (role: Role): AuthorityInitializationCommand => role === "production"
    ? [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "dpl_transport", "transport-key", Date.now(), true]
    : [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "dpl_transport", "transport-key", Date.now(), false];
  const nonce = "0123456789abcdef0123456789abcdef";

  const verify = (bytes: Uint8Array, expectations: ResultAttestationExpectations) =>
    verifyAuthoritySignedStatement(bytes, expectations, trust, Date.now());

  let worker: Unstable_DevWorker | undefined;
  try {
    const { unstable_dev } = await import("wrangler");
    worker = await unstable_dev("workers/attestation-rpc-transport-harness.ts", {
      config: "wrangler.attestation-rpc-transport.local.jsonc",
      ip: "127.0.0.1",
      port,
      local: true,
      moduleRoot: process.cwd(),
      persistTo: persistPath,
      logLevel: "none",
      vars: {
        AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublic,
        ATTESTATION_TEST_KEYS: JSON.stringify(rfcKeys),
      },
      experimental: { showInteractiveDevSession: false, watch: false },
    });
    const health = await fetch(`${root}/health`, { signal: AbortSignal.timeout(10_000) });
    assert.deepEqual(await health.json(), { harness: "attestation-rpc-transport", bindings: ["AUTHORITY_PRODUCTION", "AUTHORITY_STAGING"], testOnly: true });

    for (const role of ["production", "staging"] as const) {
      const command = initialize(role);
      const signature = await signAuthorityInitializationCommand(command, operatorPrivate);
      const digest = await commandDigest(command);

      // 7. Non-ATTESTED discriminants survive: REFUSED (bad digest) and UNAVAILABLE (nothing durable yet), before any state exists.
      const refused = await call(role, "attestAppliedLifecycle", "not-a-digest");
      for (const view of [refused.hop1, refused.final]) {
        assert.deepEqual(view.keys, ["status"]);
        assert.equal(view.status, "REFUSED");
      }
      const unavailable = await call(role, "attestAppliedLifecycle", digest);
      for (const view of [unavailable.hop1, unavailable.final]) {
        assert.equal(view.status, "UNAVAILABLE");
        assert.equal(view.envelope, undefined);
        assert.deepEqual(view.keys.sort(), ["reason", "status"]);
        assert.match(view.reason ?? "", /^(receipt-not-found|authority-state-unavailable)$/u);
      }
      assert.equal(await retainedHex(role), null, "non-attested results retain no envelope");

      // 3-4. Positive round trip: ATTESTED/APPLIED with the signed canonical envelope as a native Uint8Array.
      const applied = await call(role, "initializeFromOperatorAttested", command, signature);
      assert.equal(applied.finalIsPlainObject, true);
      for (const view of [applied.hop1, applied.final]) {
        assert.deepEqual(view.keys.sort(), ["envelope", "relayDisposition", "status"]);
        assert.equal(view.status, "ATTESTED");
        assert.equal(view.relayDisposition, "APPLIED");
        const envelope = view.envelope!;
        assert.equal(envelope.isUint8Array, true, "envelope is still a Uint8Array after the RPC boundary (instanceof inside workerd)");
        assert.equal(envelope.tag, "[object Uint8Array]");
        assert.equal(envelope.byteOffset, 0);
        assert.equal(envelope.bufferByteLength, envelope.byteLength);
      }
      const authorityHex = await retainedHex(role);
      assert.ok(authorityHex, "Authority retained its own copy before returning");
      // Byte-for-byte against the Authority-side copy, compared after BOTH hops (DO RPC, then entrypoint RPC).
      assert.equal(applied.hop1.envelope!.hex, authorityHex);
      assert.equal(applied.final.envelope!.hex, authorityHex);
      assert.equal(applied.final.envelope!.byteLength, authorityHex.length / 2);

      // Strict parse + signature/trust verification, independently in this Node process on the transported bytes.
      const envelopeBytes = bytesOf(applied.final.envelope!.hex);
      const parsed = parseResultAttestationEnvelope(envelopeBytes);
      assert.equal(parsed.statement.kind, "lifecycle");
      const proof = await verify(envelopeBytes, { kind: "lifecycle", environment: role, authorityId: authorityId(role), policyEpoch: ADMISSION_POLICY_EPOCH, digest });
      assert.ok(proof.statement.kind === "lifecycle");
      assert.equal(proof.statement.outcome, "APPLIED");
      assert.equal(proof.statement.digest, digest);
      assert.equal(proof.signingKeyFingerprint, rfcKeys[role].fingerprint);
      const expected = await expectedCommandReceipt(command, operatorPublic);
      const { keyFingerprint: operatorKeyFingerprint, ...commandFields } = expected;
      for (const [field, value] of Object.entries({ ...commandFields, operatorKeyFingerprint })) assert.deepEqual((proof.statement.receipt as unknown as Record<string, unknown>)[field], value, field);
      assert.equal(proof.statement.receipt.sequence, 1);
      // The other environment's trust section does not accept these bytes.
      const other: Role = role === "production" ? "staging" : "production";
      await assert.rejects(verify(envelopeBytes, { kind: "lifecycle", environment: other, authorityId: authorityId(other), policyEpoch: ADMISSION_POLICY_EPOCH, digest }));

      // ALREADY_APPLIED: repeat of the same command keeps the other member of the positive union.
      const repeated = await call(role, "initializeFromOperatorAttested", command, signature);
      assert.equal(repeated.final.status, "ATTESTED");
      assert.equal(repeated.final.relayDisposition, "ALREADY_APPLIED");
      assert.equal(repeated.final.envelope!.isUint8Array, true);
      assert.equal(repeated.final.envelope!.hex, await retainedHex(role));

      // Read-only recovery and reconciliation envelopes (nonce/state survive; reconciliation has no relayDisposition member).
      const recovered = await call(role, "attestAppliedLifecycle", digest);
      assert.equal(recovered.final.status, "ATTESTED");
      assert.equal(recovered.final.relayDisposition, "ALREADY_APPLIED");
      assert.equal(recovered.final.envelope!.hex, await retainedHex(role));
      const recoveredProof = await verify(bytesOf(recovered.final.envelope!.hex), { kind: "lifecycle", environment: role, authorityId: authorityId(role), policyEpoch: ADMISSION_POLICY_EPOCH, digest });
      assert.deepEqual(recoveredProof.statement.kind === "lifecycle" && recoveredProof.statement.receipt, proof.statement.receipt, "signed receipt state survived unchanged");

      const reconciled = await call(role, "attestReconciliation", digest, nonce);
      for (const view of [reconciled.hop1, reconciled.final]) {
        assert.deepEqual(view.keys.sort(), ["envelope", "status"]);
        assert.equal(view.status, "ATTESTED");
        assert.equal(view.envelope!.isUint8Array, true);
      }
      assert.equal(reconciled.final.envelope!.hex, await retainedHex(role));
      const reconciledProof = await verify(bytesOf(reconciled.final.envelope!.hex), { kind: "reconciliation", environment: role, authorityId: authorityId(role), policyEpoch: ADMISSION_POLICY_EPOCH, digest, nonce });
      assert.ok(reconciledProof.statement.kind === "reconciliation");
      assert.equal(reconciledProof.statement.nonce, nonce, "signed nonce survived unchanged");
      assert.equal(reconciledProof.statement.status, "EXACT_RECEIPT");
      assert.equal(reconciledProof.statement.initialized, true);
      assert.deepEqual(reconciledProof.statement.receipt, proof.statement.receipt);
      const refusedNonce = await call(role, "attestReconciliation", digest, "NOT-A-NONCE");
      assert.deepEqual(refusedNonce.final.keys, ["status"]);
      assert.equal(refusedNonce.final.status, "REFUSED");

      // 4. Natural envelope byte range, then the binary echo probe over the same RPC mechanism.
      const natural = bytesOf(applied.final.envelope!.hex);
      const naturalDistinct = new Set(natural).size;
      const naturalHasZero = natural.includes(0);
      const naturalHasHigh = natural.some((byte) => byte >= 0x80);
      console.log(`  ${role}: canonical envelope ${natural.length} bytes, ${naturalDistinct} distinct values, has 0x00=${naturalHasZero}, has >=0x80=${naturalHasHigh}`);

      const probe = "00017f80feff";
      const echoed = await post("echo", { role, method: "probeEcho", hex: probe });
      assert.equal(echoed.status, 200);
      assert.deepEqual(echoed.body.result, { isUint8Array: true, tag: "[object Uint8Array]", byteLength: 6, byteOffset: 0, bufferByteLength: 6, hex: probe });
      assert.equal(echoed.body.sentLengthAfter, 6, "sent array was copied, not transferred/detached");
      const everyByte = Buffer.from(Array.from({ length: 256 }, (_, index) => index)).toString("hex");
      const all = await post("echo", { role, method: "probeEcho", hex: everyByte });
      assert.equal(all.body.result.hex, everyByte);
      assert.equal(all.body.result.byteLength, 256);
      const echoedResult = await post("echo", { role, method: "probeEchoResult", hex: probe });
      assert.deepEqual(echoedResult.body.result.keys, ["status", "relayDisposition", "envelope"]);
      assert.equal(echoedResult.body.result.status, "ATTESTED");
      assert.equal(echoedResult.body.result.relayDisposition, "APPLIED");
      assert.equal(echoedResult.body.result.envelope.isUint8Array, true);
      assert.equal(echoedResult.body.result.envelope.hex, probe);
      const view = await post("view", { role });
      // A subarray view keeps its viewed bytes; workerd also preserves the view's offset into the (whole) backing buffer. The
      // canonical envelope is asserted above to be a tight, offset-0 buffer, so no unrelated bytes ride along with it.
      assert.equal(view.body.isUint8Array, true);
      assert.equal(view.body.byteLength, 6);
      assert.equal(view.body.hex, probe);
      console.log(`  ${role}: subarray view crossed with byteOffset=${view.body.byteOffset}, bufferByteLength=${view.body.bufferByteLength}`);

      // 5. Copy / aliasing semantics.
      const alias = (await post("alias", { role, args: [digest] })).body;
      assert.deepEqual(alias, {
        sameBeforeMutation: true,
        receivedMutated: true,
        expectedCopyIntact: true,
        authorityUnchangedAfterReceiverMutation: true,
        retainedObjectMatches: true,
        authorityUnchangedAfterRetainedObjectMutation: true,
        secondFetchIntact: true,
        distinctBackingStores: true,
        sentIntactAfterCall: true,
        storedLength: 6,
        storedAfterSenderMutation: probe,
      });
      console.log(`  ${role}: ATTESTED/APPLIED, ALREADY_APPLIED, recovery, reconciliation, REFUSED, UNAVAILABLE, echo and aliasing checks PASS`);
    }
  } finally {
    try {
      if (worker) await worker.stop();
    } finally {
      await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
    }
  }
  console.log("Attestation RPC transport integration: PASS (real workerd DO RPC + entrypoint RPC; native Uint8Array envelope byte-identical for Production and staging)");
}

void main();
