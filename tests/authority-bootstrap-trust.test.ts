import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { attestationKeyFingerprint } from "../src/lib/authority-result-attestation";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, PublicInquiryAdmissionAuthority, STAGING_ADMISSION_AUTHORITY_ID, admissionPolicy,
} from "../workers/admission-service/authority";
import { AuthorityAttestationCoordinator, PRODUCTION_ATTESTATION_IDENTITY } from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand,
} from "../workers/admission-service/operator-command";
import { generateLabKeyPair } from "../scripts/lab-authority-keygen";

// Trust chain for the laboratory bootstrap: generated keys -> operator-signed command -> real attestation coordinator -> real authority storage -> data plane.
const RELEASE = "lab-deployment";
const KEY_ID = "lab-key";
const T0 = 1_800_000_000_000;
const command = (issued = T0, release = RELEASE, environment: "production" | "staging" = "production", authority: string = ADMISSION_AUTHORITY_ID): AuthorityInitializationCommand =>
  [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, authority as typeof ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, KEY_ID, issued, true];

async function rig() {
  const operator = generateLabKeyPair();
  const attestation = generateLabKeyPair();
  assert.notEqual(operator.fingerprint, attestation.fingerprint);
  assert.equal(await attestationKeyFingerprint(attestation.publicKey), attestation.fingerprint, "keygen fingerprint format matches the runtime's");
  const storage = new NodeSqliteDurableStorage();
  const clock = { value: T0 };
  const signer = createAuthorityAttestationSigner({ environment: "production", writerKeyFingerprint: attestation.fingerprint, privateKey: attestation.privatePkcs8, publicKey: attestation.publicKey });
  const coordinator = new AuthorityAttestationCoordinator(storage, PRODUCTION_ATTESTATION_IDENTITY, operator.publicKey, { signer, now: () => clock.value });
  const authority = () => new PublicInquiryAdmissionAuthority({ storage }, { now: () => clock.value });
  const rows = () => {
    try { return Array.from(storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM active_releases"))[0]?.c ?? 0; } catch { return 0; }
  };
  return { operator, attestation, storage, clock, coordinator, authority, rows };
}
const pre = (n: number) => ({ releaseId: RELEASE, clientPseudonym: encodeBase64url(new Uint8Array(32).fill(n)), requestBinding: encodeBase64url(new Uint8Array(32).fill(n + 1)),
  nonce: encodeBase64url(new Uint8Array(16).fill(n + 2)), issuedAtMs: T0 });

test("generated keys are accepted by the real operator verifier and attestation signer, and a valid operator signature initializes", async () => {
  const r = await rig();
  assert.equal(r.authority().claimPre(pre(1)).decision, "unavailable", "uninitialized authority fails closed");
  const good = command();
  const result = await r.coordinator.initialize(good, await signAuthorityInitializationCommand(good, r.operator.privatePkcs8));
  assert.equal(result.status, "ATTESTED");
  assert.equal(r.authority().claimPre(pre(1)).decision, "allowed");
});

test("wrong key, tampered command and malformed signature are refused with zero state change", async () => {
  const r = await rig();
  const stranger = generateLabKeyPair();
  const good = command();
  const forged = await signAuthorityInitializationCommand(good, stranger.privatePkcs8);
  const genuine = await signAuthorityInitializationCommand(good, r.operator.privatePkcs8);
  const tampered = command(T0, "other-release");
  for (const [cmd, sig] of [[good, forged], [tampered, genuine]] as const) {
    const out = await r.coordinator.initialize(cmd, sig);
    assert.equal(out.status, "REFUSED");
  }
  // A structurally malformed signature never reaches the authority through the reviewed chain (the sealed-artifact parser and the
  // executor reject it first); called directly the coordinator throws before any storage access instead of answering positively.
  assert.equal((await r.coordinator.initialize(good, "A".repeat(86))).status, "REFUSED", "well-formed but wrong signature");
  await assert.rejects(() => r.coordinator.initialize(good, "not-a-signature"));
  assert.equal(r.rows(), 0, "no release row was created");
  assert.equal(r.authority().claimPre(pre(1)).decision, "unavailable");
});

test("commands are bound to the production environment and authority identity", async () => {
  const r = await rig();
  for (const bad of [command(T0, RELEASE, "staging", STAGING_ADMISSION_AUTHORITY_ID), command(T0, RELEASE, "production", STAGING_ADMISSION_AUTHORITY_ID)]) {
    const signed = await signAuthorityInitializationCommand(bad, r.operator.privatePkcs8).catch(() => "A".repeat(86));
    assert.equal((await r.coordinator.initialize(bad, signed)).status, "REFUSED");
  }
  assert.equal(r.rows(), 0);
});

test("a stale or future-dated signed command is refused (5 minute window)", async () => {
  const r = await rig();
  for (const issued of [T0 - 5 * 60_000 - 1, T0 + 5 * 60_000 + 1]) {
    const c = command(issued);
    assert.equal((await r.coordinator.initialize(c, await signAuthorityInitializationCommand(c, r.operator.privatePkcs8))).status, "REFUSED");
  }
  assert.equal(r.rows(), 0);
});

test("replaying the same signed command is idempotent; a different signed command cannot reset an initialized authority", async () => {
  const r = await rig();
  const first = command();
  const sig = await signAuthorityInitializationCommand(first, r.operator.privatePkcs8);
  assert.equal((await r.coordinator.initialize(first, sig)).status, "ATTESTED");
  const replay = await r.coordinator.initialize(first, sig);
  assert.ok(replay.status === "ATTESTED" && replay.relayDisposition === "ALREADY_APPLIED");
  r.clock.value = T0 + 1_000;
  const other = command(T0 + 1_000, "another-release");
  assert.equal((await r.coordinator.initialize(other, await signAuthorityInitializationCommand(other, r.operator.privatePkcs8))).status, "REFUSED");
  assert.equal(r.rows(), 1);
  assert.equal(r.authority().claimPre({ ...pre(5), releaseId: "another-release", issuedAtMs: T0 + 1_000 }).decision, "unavailable");
  assert.equal(r.authority().claimPre({ ...pre(5), issuedAtMs: T0 + 1_000 }).decision, "allowed");
});

test("initialization does not weaken admission: replay, rate limits and unknown releases are still enforced", async () => {
  const r = await rig();
  const c = command();
  await r.coordinator.initialize(c, await signAuthorityInitializationCommand(c, r.operator.privatePkcs8));
  const first = pre(7);
  assert.equal(r.authority().claimPre(first).decision, "allowed");
  assert.equal(r.authority().claimPre(first).decision, "replay");
  assert.equal(r.authority().claimPre({ ...pre(8), releaseId: "unknown-release" }).decision, "unavailable");
  const burst = admissionPolicy.pre.clientBurst.limit;
  const decisions: string[] = [];
  for (let i = 0; i < burst + 1; i += 1) {
    decisions.push(r.authority().claimPre({ ...pre(9), nonce: encodeBase64url(Uint8Array.from({ length: 16 }, (_, j) => (i * 7 + j + 40) & 255)) }).decision);
  }
  assert.equal(decisions.at(-1), "limited");
});

test("a signer-less authority refuses initialization before touching storage (no unattested state)", async () => {
  const operator = generateLabKeyPair();
  const storage = new NodeSqliteDurableStorage();
  const coordinator = new AuthorityAttestationCoordinator(storage, PRODUCTION_ATTESTATION_IDENTITY, operator.publicKey, { now: () => T0 });
  const c = command();
  const out = await coordinator.initialize(c, await signAuthorityInitializationCommand(c, operator.privatePkcs8));
  assert.equal(out.status, "UNAVAILABLE");
  assert.equal(Array.from(storage.sql.exec("SELECT name FROM sqlite_master WHERE name='authority_meta'")).length, 0, "not even the schema was created");
});

test("the data plane does not depend on the control plane", () => {
  const authoritySource = readFileSync("workers/admission-service/authority.ts", "utf8").replace(/\/\/.*$/gmu, "");
  assert.equal(/from "\.\/(operator-command|authority-attestation)|lifecycle-mailbox|operator-lifecycle-executor/u.test(authoritySource), false);
  const index = readFileSync("workers/admission-service/index.ts", "utf8");
  const production = index.split("export class ProductionAdmissionAuthority")[1].split("export class AuthorityLifecycleOnly")[0];
  const claim = production.match(/async claimPre[\s\S]*?\n {2}\}/u)![0] + production.match(/async consumePost[\s\S]*?\n {2}\}/u)![0];
  assert.equal(/attestation|operator|signer/u.test(claim), false, "claim/consume touch only the core authority");
});

test("operator credentials stay separate from application and ingress credentials", () => {
  const matrix = JSON.parse(readFileSync("deployment/secret-matrix.json", "utf8")) as Record<string, unknown>;
  const policies: Array<[string, { requiredSecrets?: string[]; forbiddenSecrets?: string[] }]> = [];
  const collect = (value: unknown, name: string) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const record = value as Record<string, unknown>;
      if ("requiredSecrets" in record || "forbiddenSecrets" in record) policies.push([name, record as { requiredSecrets?: string[] }]);
      else for (const [key, child] of Object.entries(record)) collect(child, key);
    }
  };
  collect(matrix, "root");
  assert.ok(policies.length >= 4);
  for (const [name, policy] of policies) assert.equal((policy.requiredSecrets ?? []).includes("AUTHORITY_OPERATOR_PRIVATE_KEY"), false, name);
  for (const name of ["admissionService", "vercelApplication", "operatorExecutor", "lifecycleMailbox"]) {
    assert.ok(policies.find(([key]) => key === name)?.[1].forbiddenSecrets?.includes("AUTHORITY_OPERATOR_PRIVATE_KEY"), name);
  }
  assert.equal(/OPERATOR|ATTESTATION/u.test(readFileSync("deployment/terraform/cloud-lab/cloud-run.tf", "utf8")), false);
  assert.equal(/OPERATOR|ATTESTATION/u.test(readFileSync("workers/ingress-signer/laboratory-index.ts", "utf8")), false);
});

test("the key generator writes private keys only to new restricted files outside the repository and never prints them", () => {
  const base = mkdtempSync(join(tmpdir(), "lm-keygen-"));
  const target = join(base, "keys");
  const run = (directory: string) => spawnSync(process.execPath, ["--import", "tsx", "scripts/lab-authority-keygen.ts", directory], { encoding: "utf8" });
  try {
    const ok = run(target);
    assert.equal(ok.status, 0, ok.stderr);
    const printed = JSON.parse(ok.stdout) as Record<string, string>;
    const operatorPrivate = readFileSync(join(target, "operator.private.b64url"), "utf8");
    const attestationPrivate = readFileSync(join(target, "attestation.private.b64url"), "utf8");
    assert.notEqual(operatorPrivate, attestationPrivate);
    for (const secret of [operatorPrivate, attestationPrivate]) {
      assert.equal(ok.stdout.includes(secret) || ok.stderr.includes(secret), false);
      assert.match(secret, /^[A-Za-z0-9_-]{64}$/u);
    }
    if (process.platform !== "win32") assert.equal(statSync(join(target, "operator.private.b64url")).mode & 0o077, 0);
    assert.match(printed.operatorPublicKey, /^[A-Za-z0-9_-]{43}$/u);
    assert.equal(new Set([printed.operatorFingerprint, printed.attestationFingerprint, printed.stagingSlotFingerprint]).size, 3);
    assert.equal(readdirSync(target).length, 2, "only the two real private keys exist on disk");
    assert.equal(run(target).status, 2, "refuses an existing directory");
    assert.equal(run("tmp-inside-repo-keys").status, 2, "refuses a directory inside the repository");
    assert.equal(existsSync("tmp-inside-repo-keys"), false);
  } finally { rmSync(base, { recursive: true, force: true }); }
});
