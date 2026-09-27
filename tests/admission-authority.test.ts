import assert from "node:assert/strict";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import {
  ADMISSION_POLICY_EPOCH,
  ADMISSION_AUTHORITY_ID,
  PublicInquiryAdmissionAuthority,
  initializeAuthority,
  rotateAuthorityRelease,
  admissionPolicy,
  type ClaimPreInput,
} from "../workers/admission-service/authority";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";

const opaque = (length: number, seed: number) => {
  const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + seed) & 255);
  new DataView(bytes.buffer).setUint32(length - 4, seed >>> 0);
  return encodeBase64url(bytes);
};
const releaseId = "dpl_reviewed";
let sequence = 1;
function pre(now: number, changes: Partial<ClaimPreInput> = {}): ClaimPreInput {
  const current = sequence++;
  return { releaseId, clientPseudonym: opaque(32, current), requestBinding: opaque(32, current + 50), nonce: opaque(16, current + 100), issuedAtMs: now, ...changes };
}

function initialized(nowRef: { value: number }, options: ConstructorParameters<typeof PublicInquiryAdmissionAuthority>[1] = {}) {
  const storage = new NodeSqliteDurableStorage();
  const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => nowRef.value, ...options });
  initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId, releaseKeyId: "test-key", nowMs: nowRef.value, confirmProduction: false });
  return { authority, storage };
}

test("authority requires explicit initialization, exact epoch and active release", () => {
  const storage = new NodeSqliteDurableStorage();
  const missing = new PublicInquiryAdmissionAuthority({ storage }, { now: () => 1_000 });
  assert.equal(missing.claimPre(pre(1_000)).decision, "unavailable");
  initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId, releaseKeyId: "test-key", nowMs: 1_000, confirmProduction: false });
  assert.equal(missing.claimPre(pre(1_000, { releaseId: "wrong" })).decision, "unavailable");
  const wrongEpoch = new PublicInquiryAdmissionAuthority({ storage }, { now: () => 1_000, expectedPolicyEpoch: `${ADMISSION_POLICY_EPOCH}-wrong` });
  assert.equal(wrongEpoch.claimPre(pre(1_000)).decision, "unavailable");
  storage.close();
});

test("PRE atomically consumes client and global observations and same nonce has one execution owner", () => {
  const now = { value: 10_000 };
  const { authority, storage } = initialized(now);
  const input = pre(now.value);
  const first = authority.claimPre(input);
  assert.equal(first.decision, "allowed");
  assert.equal(authority.claimPre(input).decision, "replay");
  assert.equal(authority.claimPre(pre(now.value, { nonce: input.nonce })).decision, "replay");
  assert.equal(storage.count("observations"), 2);
  assert.equal(storage.count("nonces"), 1);
  // Re-instantiation over the same SQLite storage retains replay state.
  const restarted = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
  assert.equal(restarted.claimPre(input).decision, "replay");
  storage.close();
});

test("PRE client or global denial consumes neither rule and creates no nonce", () => {
  const now = { value: 20_000 };
  const { authority, storage } = initialized(now);
  const client = opaque(32, 230);
  for (let index = 0; index < admissionPolicy.pre.clientBurst.limit; index++) assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  const beforeClientDenial = storage.count("observations");
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  assert.equal(storage.count("observations"), beforeClientDenial);
  storage.close();

  const second = initialized(now);
  for (let index = 0; index < admissionPolicy.pre.global.limit; index++) assert.equal(second.authority.claimPre(pre(now.value)).decision, "allowed");
  const denied = pre(now.value);
  const beforeGlobalDenial = second.storage.count("nonces");
  assert.equal(second.authority.claimPre(denied).decision, "limited");
  assert.equal(second.storage.count("nonces"), beforeGlobalDenial);
  second.storage.close();
});

test("staggered PRE burst observations use a half-open rolling minute, not a fixed-minute reset", () => {
  const now = { value: 100_000 };
  const { authority, storage } = initialized(now);
  const client = opaque(32, 201);
  for (let index = 0; index < admissionPolicy.pre.clientBurst.limit; index++) {
    now.value = 100_000 + index;
    assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  }
  assert.equal(storage.count("observations"), admissionPolicy.pre.clientBurst.limit * 2);
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  now.value = 120_000; // A fixed-minute bucket would reset here.
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  now.value = 159_999;
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  now.value = 160_000;
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  now.value -= 1;
  assert.equal(authority.claimPre(pre(now.value)).decision, "unavailable");
  storage.close();
});

test("existing long-window history remains charged without resetting the policy epoch", () => {
  const now = { value: 100_000 };
  const { authority, storage } = initialized(now);
  const client = opaque(32, 202);
  // Synthetic history admitted by the former policy, older than the new minute but still within ten minutes.
  for (let index = 0; index < admissionPolicy.pre.client.limit; index++) {
    storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'pre','client',?,?)", `legacy-c-${index}`, client, 20_000);
    storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'pre','global','*',?)", `legacy-g-${index}`, 20_000);
  }
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  assert.equal(storage.count("nonces"), 0);
  assert.equal(Number((storage.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE stage='pre' AND scope='client' AND subject=?").get(client) as { count: number }).count), 30);
  now.value = 620_000;
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  storage.close();
});

test("paced grants reach thirty in ten minutes; the immediate next claim hits the short cap", () => {
  const now = { value: 100_000 };
  const { authority, storage } = initialized(now);
  const client = opaque(32, 203);
  for (let minute = 0; minute < 10; minute++) {
    now.value = 100_000 + minute * admissionPolicy.pre.clientBurst.windowMs;
    for (let attempt = 0; attempt < admissionPolicy.pre.clientBurst.limit; attempt++) {
      assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
    }
  }
  assert.equal(Number((storage.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE stage='pre' AND scope='client' AND subject=?").get(client) as { count: number }).count), admissionPolicy.pre.client.limit);
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "limited");
  now.value = 700_000;
  assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  storage.close();
});

test("POST is permit-bound, one-use, and consumes its pair only after a valid PRE", () => {
  const now = { value: 30_000 };
  const { authority, storage } = initialized(now);
  const input = pre(now.value);
  const admitted = authority.claimPre(input);
  assert.equal(admitted.decision, "allowed");
  if (admitted.decision !== "allowed") return;
  const post = { releaseId, clientPseudonym: input.clientPseudonym, requestBinding: input.requestBinding, nonce: input.nonce, permit: admitted.permit };
  assert.equal(authority.consumePost({ ...post, clientPseudonym: opaque(32, 8) }).decision, "unavailable");
  assert.equal(authority.consumePost({ ...post, requestBinding: opaque(32, 9) }).decision, "unavailable");
  assert.equal(authority.consumePost({ ...post, releaseId: "wrong" }).decision, "unavailable");
  assert.equal(authority.consumePost({ ...post, permit: opaque(32, 10) }).decision, "unavailable");
  assert.equal(authority.consumePost(post).decision, "allowed");
  assert.equal(authority.consumePost(post).decision, "replay");
  assert.equal(storage.count("observations"), 4);
  storage.close();
});

test("concurrent same-nonce claims have one winner and a lost PRE response cannot authorize replay", async () => {
  const now = { value: 35_000 };
  const { authority, storage } = initialized(now);
  const input = pre(now.value);
  // These synchronous calls are ordered within one process; this is not distributed workerd concurrency evidence.
  const results = await Promise.all([Promise.resolve().then(() => authority.claimPre(input)), Promise.resolve().then(() => authority.claimPre(input))]);
  assert.deepEqual(results.map((result) => result.decision).sort(), ["allowed", "replay"]);
  // Treat the allowed result as lost: a later duplicate still gets no permit.
  assert.equal(authority.claimPre(input).decision, "replay");
  assert.equal(storage.count("nonces"), 1);
  storage.close();
});

test("logical users sharing a pseudonym share its burst cap across releases and re-instantiation", () => {
  const now = { value: 1_000 };
  const { authority, storage } = initialized(now);
  assert.deepEqual(rotateAuthorityRelease(storage, { authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    currentReleaseId: releaseId, nextReleaseId: "dpl_next", nextKeyId: "next-key", activatesAtMs: 2_000, previousRetiresAtMs: 3_000 }), { status: "rotated" });
  now.value = 2_500;
  const sharedPseudonym = opaque(32, 800);
  for (const user of [1, 2]) {
    assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: sharedPseudonym, requestBinding: opaque(32, user + 900) })).decision, "allowed");
  }
  assert.equal(authority.claimPre(pre(now.value, { releaseId: "dpl_next", clientPseudonym: sharedPseudonym })).decision, "allowed");
  const restarted = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
  const denied = pre(now.value, { releaseId: "dpl_next", clientPseudonym: sharedPseudonym });
  const before = { observations: storage.count("observations"), nonces: storage.count("nonces") };
  assert.equal(restarted.claimPre(denied).decision, "limited");
  assert.deepEqual({ observations: storage.count("observations"), nonces: storage.count("nonces") }, before);
  storage.close();
});

test("POST client and global denials consume neither side and do not mark a permit consumed", () => {
  const now = { value: 37_000 };
  const { authority, storage } = initialized(now);
  const client = opaque(32, 700);
  for (let index = 0; index < 6; index++) {
    now.value = 37_000 + Math.floor(index / admissionPolicy.pre.clientBurst.limit) * admissionPolicy.pre.clientBurst.windowMs;
    const input = pre(now.value, { clientPseudonym: client });
    const result = authority.claimPre(input);
    assert.equal(result.decision, "allowed");
    if (result.decision !== "allowed") continue;
    const before = storage.count("observations");
    assert.equal(authority.consumePost({ ...input, permit: result.permit }).decision, index < 5 ? "allowed" : "limited");
    if (index === 5) assert.equal(storage.count("observations"), before);
  }
  storage.close();

  const global = initialized(now);
  const globalPending: Array<{ input: ClaimPreInput; permit: string }> = [];
  for (let index = 0; index < admissionPolicy.post.global.limit + 1; index++) {
    const input = pre(now.value);
    const result = global.authority.claimPre(input);
    assert.equal(result.decision, "allowed");
    if (result.decision === "allowed") globalPending.push({ input, permit: result.permit });
  }
  for (let index = 0; index < admissionPolicy.post.global.limit; index++) assert.equal(global.authority.consumePost({ ...globalPending[index].input, permit: globalPending[index].permit }).decision, "allowed");
  const beforeGlobal = global.storage.count("observations");
  assert.equal(global.authority.consumePost({ ...globalPending.at(-1)!.input, permit: globalPending.at(-1)!.permit }).decision, "limited");
  assert.equal(global.storage.count("observations"), beforeGlobal);
  global.storage.close();
});

test("expired permit, retained nonce, delayed cleanup and stale replay remain closed", () => {
  const now = { value: 40_000 };
  const { authority, storage } = initialized(now);
  const input = pre(now.value);
  const admitted = authority.claimPre(input);
  assert.equal(admitted.decision, "allowed");
  if (admitted.decision !== "allowed") return;
  now.value += 60_001;
  assert.equal(authority.consumePost({ ...input, permit: admitted.permit }).decision, "unavailable");
  assert.equal(authority.claimPre(input).decision, "unavailable");
  now.value = 40_000 + 120_001;
  assert.ok("deleted" in authority.cleanup());
  assert.equal(authority.claimPre(input).decision, "unavailable");
  storage.close();
});

test("mid-transaction failure rolls back both observations and nonce transition", () => {
  const now = { value: 50_000 };
  let fail = true;
  const { authority, storage } = initialized(now, { faultAfterObservation: () => { if (fail) throw new Error("synthetic-fault"); } });
  const input = pre(now.value);
  assert.equal(authority.claimPre(input).decision, "unavailable");
  assert.equal(storage.count("observations"), 0);
  assert.equal(storage.count("nonces"), 0);
  fail = false;
  assert.equal(authority.claimPre(input).decision, "allowed");
  storage.close();
});

test("one hundred clients can still exhaust global PRE without spending POST, then capacity recovers", () => {
  const now = { value: 100_000 };
  const { authority, storage } = initialized(now);
  for (let clientIndex = 0; clientIndex < 100; clientIndex++) {
    const client = opaque(32, clientIndex + 1);
    for (let count = 0; count < admissionPolicy.pre.clientBurst.limit; count++) assert.equal(authority.claimPre(pre(now.value, { clientPseudonym: client })).decision, "allowed");
  }
  assert.equal(storage.count("observations"), 600);
  assert.equal(authority.claimPre(pre(now.value)).decision, "limited");
  now.value += 59_999;
  assert.equal(authority.claimPre(pre(now.value)).decision, "limited");
  now.value += 1;
  assert.equal(authority.claimPre(pre(now.value)).decision, "allowed");
  storage.close();
});
