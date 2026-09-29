import assert from "node:assert/strict";
import test from "node:test";
import { executeVerifiedPublicInquiry } from "../src/lib/public-inquiry-flow.server";
import type { AdmissionClient } from "../src/lib/admission-client.server";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, PublicInquiryAdmissionAuthority, initializeAuthority,
} from "../workers/admission-service/authority";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";

const opaque = (length: number, seed: number) => {
  const bytes = new Uint8Array(length);
  new DataView(bytes.buffer).setUint32(length - 4, seed >>> 0);
  return encodeBase64url(bytes);
};

function form(): FormData {
  const value = new FormData();
  for (const [key, item] of Object.entries({ name: "Synthetic", email: "qa@example.test", service: "web", system: "Disposable",
    objective: "Review flow", environment: "staging", authority: "authorized", submissionToken: "s".repeat(43), "cf-turnstile-response": "challenge" })) value.set(key, item);
  return value;
}

test("ten rejected-challenge identities leave a fresh verified request admission capacity", async () => {
  const now = { value: 100_000 };
  const storage = new NodeSqliteDurableStorage();
  try {
    initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      releaseId: "dpl_reviewed", releaseKeyId: "test-key", nowMs: now.value, confirmProduction: false });
    const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
    let hostilePhase = true;
    let hostileGrants = 0;
    let postCalls = 0;
    const admission: AdmissionClient = {
      async claimPre(input) { const result = authority.claimPre(input); if (hostilePhase && result.decision === "allowed") hostileGrants++; return result; },
      async consumePost(input) { postCalls++; return authority.consumePost(input); },
    };
    let sequence = 1;
    let hostileVerifierCalls = 0;
    let freshVerifierCalls = 0;
    let repositoryCalls = 0;
    const ingress = (client: number) => {
      const id = sequence++;
      return { releaseId: "dpl_reviewed", keyId: "test-key", issuedAtMs: now.value, clientPseudonym: opaque(32, client),
        requestBinding: opaque(32, id + 1_000), nonce: opaque(16, id + 2_000) };
    };
    for (let client = 1; client <= 10; client++) {
      for (let attempt = 0; attempt < 30; attempt++) {
        const result = await executeVerifiedPublicInquiry({ form: form(), ingress: ingress(client), admission,
          turnstile: { async verify() { hostileVerifierCalls++; return "rejected"; } },
          repository: { async create() { repositoryCalls++; return { status: "created" as const }; } } });
        assert.equal(result.kind, "state");
      }
    }
    hostilePhase = false;
    const fresh = await executeVerifiedPublicInquiry({ form: form(), ingress: ingress(11), admission,
      turnstile: { async verify() { freshVerifierCalls++; return "verified"; } },
      repository: { async create() { repositoryCalls++; return { status: "created" as const }; } } });
    assert.deepEqual({ hostileGrants, hostileVerifierCalls, freshKind: fresh.kind, freshVerifierCalls, postCalls, repositoryCalls },
      { hostileGrants: 30, hostileVerifierCalls: 30, freshKind: "redirect", freshVerifierCalls: 1, postCalls: 1, repositoryCalls: 1 });
  } finally {
    storage.close();
  }
});

test("rejected, unavailable and thrown verification retain PRE charges without POST or repository work", async () => {
  const now = { value: 100_000 };
  const storage = new NodeSqliteDurableStorage();
  try {
    initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      releaseId: "dpl_reviewed", releaseKeyId: "test-key", nowMs: now.value, confirmProduction: false });
    const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
    let postCalls = 0;
    let repositoryCalls = 0;
    let verifierCalls = 0;
    const admission: AdmissionClient = {
      async claimPre(input) { return authority.claimPre(input); },
      async consumePost(input) { postCalls++; return authority.consumePost(input); },
    };
    for (let attempt = 0; attempt < 4; attempt++) {
      const ingress = { releaseId: "dpl_reviewed", keyId: "test-key", issuedAtMs: now.value, clientPseudonym: opaque(32, 90),
        requestBinding: opaque(32, attempt + 10), nonce: opaque(16, attempt + 20) };
      const result = await executeVerifiedPublicInquiry({ form: form(), ingress, admission,
        turnstile: { async verify() { verifierCalls++; if (attempt === 2) throw new Error("synthetic-verifier-fault");
          // The fourth attempt cannot reach "verified" while failed verification retains PRE; a refund would expose POST work.
          return attempt === 0 ? "rejected" : attempt === 1 ? "unavailable" : "verified"; } },
        repository: { async create() { repositoryCalls++; return { status: "created" as const }; } } });
      assert.equal(result.kind, "state");
    }
    assert.deepEqual({ verifierCalls, postCalls, repositoryCalls, observations: storage.count("observations") },
      { verifierCalls: 3, postCalls: 0, repositoryCalls: 0, observations: 6 });
  } finally {
    storage.close();
  }
});

test("verification resolving at permit expiry reaches POST denial without repository work", async () => {
  const now = { value: 100_000 };
  const storage = new NodeSqliteDurableStorage();
  try {
    initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      releaseId: "dpl_reviewed", releaseKeyId: "test-key", nowMs: now.value, confirmProduction: false });
    const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
    let started!: () => void;
    let resolveVerification!: (result: "verified") => void;
    const verificationStarted = new Promise<void>((resolve) => { started = resolve; });
    const verification = new Promise<"verified">((resolve) => { resolveVerification = resolve; });
    let postCalls = 0;
    let repositoryCalls = 0;
    const resultPromise = executeVerifiedPublicInquiry({ form: form(), ingress: { releaseId: "dpl_reviewed", keyId: "test-key",
      issuedAtMs: now.value, clientPseudonym: opaque(32, 91), requestBinding: opaque(32, 92), nonce: opaque(16, 93) },
    admission: { async claimPre(input) { return authority.claimPre(input); }, async consumePost(input) { postCalls++; return authority.consumePost(input); } },
    turnstile: { async verify() { started(); return verification; } },
    repository: { async create() { repositoryCalls++; return { status: "created" as const }; } } });
    await verificationStarted;
    now.value += 60_000;
    resolveVerification("verified");
    assert.equal((await resultPromise).kind, "state");
    assert.equal(postCalls, 1);
    assert.equal(repositoryCalls, 0);
    assert.equal(Number((storage.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE stage='post'").get() as { count: number }).count), 0);
  } finally {
    storage.close();
  }
});

test("repository failures do not refund POST charges", async () => {
  const now = { value: 100_000 };
  const storage = new NodeSqliteDurableStorage();
  try {
    initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      releaseId: "dpl_reviewed", releaseKeyId: "test-key", nowMs: now.value, confirmProduction: false });
    const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
    let repositoryCalls = 0;
    let verifierCalls = 0;
    let postCalls = 0;
    for (let attempt = 0; attempt < 6; attempt++) {
      now.value = 100_000 + Math.floor(attempt / 3) * 60_000;
      const ingress = { releaseId: "dpl_reviewed", keyId: "test-key", issuedAtMs: now.value, clientPseudonym: opaque(32, 94),
        requestBinding: opaque(32, attempt + 100), nonce: opaque(16, attempt + 200) };
      const result = await executeVerifiedPublicInquiry({ form: form(), ingress,
        admission: { async claimPre(input) { return authority.claimPre(input); }, async consumePost(input) { postCalls++; return authority.consumePost(input); } },
        turnstile: { async verify() { verifierCalls++; return "verified"; } },
        repository: { async create() { repositoryCalls++; throw new Error("synthetic-repository-fault"); } } });
      assert.equal(result.kind, "state");
    }
    assert.deepEqual({ verifierCalls, postCalls, repositoryCalls }, { verifierCalls: 6, postCalls: 6, repositoryCalls: 5 });
    assert.equal(Number((storage.database.prepare("SELECT COUNT(*) AS count FROM observations WHERE stage='post' AND scope='client'").get() as { count: number }).count), 5);
  } finally {
    storage.close();
  }
});
