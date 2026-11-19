import assert from "node:assert/strict";
import test from "node:test";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID, initializeAuthority, inspectLifecycleAuthority, type AuthorityInitialization,
} from "../workers/admission-service/authority";
import { AuthorityAttestationCoordinator, LAB_ATTESTATION_IDENTITY, PRODUCTION_ATTESTATION_IDENTITY } from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION, canonicalOperatorCommandBytes, executeSignedAuthorityInitialization, executeSignedAuthorityReleaseRotation, signAuthorityInitializationCommand, verifyOperatorCommand,
  type AuthorityInitializationCommand, type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";
import { generateLabKeyPair } from "../scripts/lab-authority-keygen";

// Direct negative tests for the lab environment added to workers/admission-service/authority.ts and operator-command.ts (migration review; test-only, no production file is modified).
// The existing lab-environment-isolation suite reaches these only through the attestation coordinator; here the two cores are called directly. Disposable in-memory SQLite and
// in-process keys only. Every refusal is also checked to leave NO release row behind.

const T0 = 1_800_000_000_000; const RELEASE = "lab-release-1"; const KEY_ID = "lab-release-key-1";
const view = (value: unknown): Record<string, unknown> => value as Record<string, unknown>;
const rows = (storage: NodeSqliteDurableStorage): number => { try { return Array.from(storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM active_releases"))[0]?.c ?? 0; } catch { return 0; } };
const spec = (change: Partial<AuthorityInitialization> = {}): AuthorityInitialization =>
  ({ environment: "lab", authorityId: LAB_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, releaseId: RELEASE, releaseKeyId: KEY_ID, nowMs: T0, confirmProduction: false, ...change }) as AuthorityInitialization;
const command = (environment: string, authority: string, confirm: boolean, issued = T0): AuthorityInitializationCommand =>
  [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, authority, ADMISSION_POLICY_EPOCH, RELEASE, KEY_ID, issued, confirm] as unknown as AuthorityInitializationCommand;

test("authority core: the lab specification is accepted only with the lab authority identity, the lab expectation and no production confirmation", () => {
  const ok = new NodeSqliteDurableStorage();
  assert.equal(initializeAuthority(ok, spec(), undefined, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }).status, "initialized");
  assert.equal(rows(ok), 1);
  const refusals: [string, Partial<AuthorityInitialization>, { expectedAuthorityId?: string; expectedPolicyEpoch?: string }][] = [
    ["lab environment naming the Production authority", { authorityId: ADMISSION_AUTHORITY_ID }, { expectedAuthorityId: ADMISSION_AUTHORITY_ID }],
    ["lab environment naming the staging authority", { authorityId: STAGING_ADMISSION_AUTHORITY_ID }, { expectedAuthorityId: STAGING_ADMISSION_AUTHORITY_ID }],
    ["lab specification against the default (Production) expectation", {}, {}],
    ["lab specification against the staging expectation", {}, { expectedAuthorityId: STAGING_ADMISSION_AUTHORITY_ID }],
    ["production environment naming the lab authority", { environment: "production", confirmProduction: true }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["staging environment naming the lab authority", { environment: "staging" }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["lab environment confirming production", { confirmProduction: true }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["lab confirmProduction not a boolean", { confirmProduction: undefined as unknown as boolean }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["case-variant environment", { environment: "Lab" as never }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["abbreviated environment", { environment: "prod" as never }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["missing environment", { environment: undefined as never }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["wrong policy epoch", { policyEpoch: "other-epoch" }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["invalid release id", { releaseId: "has space" }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
    ["negative time", { nowMs: -1 }, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID }],
  ];
  for (const [label, change, options] of refusals) {
    const storage = new NodeSqliteDurableStorage();
    assert.throws(() => initializeAuthority(storage, spec(change), undefined, options), /initialization-policy/u, label);
    assert.equal(rows(storage), 0, `${label}: nothing initialized`);
  }
});

test("authority core: an authority initialized for one environment cannot be re-initialized as another, and inspection never relabels a foreign authority as lab", () => {
  for (const [first, firstSpec, second] of [
    ["production", spec({ environment: "production", authorityId: ADMISSION_AUTHORITY_ID, confirmProduction: true }), LAB_ADMISSION_AUTHORITY_ID],
    ["staging", spec({ environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID }), LAB_ADMISSION_AUTHORITY_ID],
  ] as const) {
    const storage = new NodeSqliteDurableStorage();
    initializeAuthority(storage, firstSpec, undefined, { expectedAuthorityId: firstSpec.authorityId });
    assert.throws(() => initializeAuthority(storage, spec({ releaseId: "another" }), undefined, { expectedAuthorityId: second }), /./u, `${first} storage re-initialized as lab`);
    const seen = view(inspectLifecycleAuthority(storage, "a".repeat(64), T0, firstSpec.authorityId));
    assert.equal(seen.authorityId, firstSpec.authorityId);
    assert.equal(rows(storage), 1);
  }
  const lab = new NodeSqliteDurableStorage();
  initializeAuthority(lab, spec(), undefined, { expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID });
  assert.equal(view(inspectLifecycleAuthority(lab, "a".repeat(64), T0, LAB_ADMISSION_AUTHORITY_ID)).environment, "lab");
  // reading lab state with the Production or staging expectation does not answer as lab
  for (const expected of [ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID]) {
    let answered: Record<string, unknown> | undefined; let threw = false;
    try { answered = view(inspectLifecycleAuthority(lab, "a".repeat(64), T0, expected)); } catch { threw = true; }
    assert.ok(threw || (answered !== undefined && answered.environment !== "lab" && answered.initialized !== true), `expectation ${expected} must not read lab state as its own`);
  }
  // OBSERVATION (see the review document): an UNKNOWN authority id is labelled "production" in the not-found answer; the answer still echoes the unknown id, so a reader that compares authorityId is unaffected.
  const unknown = view(inspectLifecycleAuthority(new NodeSqliteDurableStorage(), "a".repeat(64), T0, "some-unknown-authority-v1"));
  assert.deepEqual([unknown.environment, unknown.authorityId, unknown.initialized], ["production", "some-unknown-authority-v1", false]);
});

test("attestation: a missing signer, or a signer bound to another environment, never produces an attested lab initialization", async () => {
  const operator = generateLabKeyPair(); const attestation = generateLabKeyPair();
  const cmd = command("lab", LAB_ADMISSION_AUTHORITY_ID, false);
  const signature = await signAuthorityInitializationCommand(cmd, operator.privatePkcs8);
  // no signer
  const noSigner = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), LAB_ATTESTATION_IDENTITY, operator.publicKey, { now: () => T0 });
  assert.notEqual((await noSigner.initialize(cmd, signature)).status, "ATTESTED");
  // a Production-bound signer inside a lab coordinator
  const wrongSigner = createAuthorityAttestationSigner({ environment: "production", writerKeyFingerprint: attestation.fingerprint, privateKey: attestation.privatePkcs8, publicKey: attestation.publicKey });
  const mismatched = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), LAB_ATTESTATION_IDENTITY, operator.publicKey, { signer: wrongSigner, now: () => T0 });
  assert.notEqual((await mismatched.initialize(cmd, signature)).status, "ATTESTED");
  // a lab command presented to a Production coordinator
  const production = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), PRODUCTION_ATTESTATION_IDENTITY, operator.publicKey, { now: () => T0 });
  assert.equal((await production.initialize(cmd, signature)).status, "REFUSED");
});

test("operator command: a lab command with confirmProduction=true is rejected, as is every environment/authority mismatch and every unknown environment", () => {
  assert.doesNotThrow(() => canonicalOperatorCommandBytes(command("lab", LAB_ADMISSION_AUTHORITY_ID, false)), "control");
  const bad: [string, AuthorityInitializationCommand][] = [
    ["lab + confirmProduction", command("lab", LAB_ADMISSION_AUTHORITY_ID, true)],
    ["lab naming the Production authority", command("lab", ADMISSION_AUTHORITY_ID, false)],
    ["lab naming the staging authority", command("lab", STAGING_ADMISSION_AUTHORITY_ID, false)],
    ["production naming the lab authority", command("production", LAB_ADMISSION_AUTHORITY_ID, true)],
    ["staging naming the lab authority", command("staging", LAB_ADMISSION_AUTHORITY_ID, false)],
    ["production without confirmation", command("production", ADMISSION_AUTHORITY_ID, false)],
    ["unknown environment", command("laboratory", LAB_ADMISSION_AUTHORITY_ID, false)],
    ["case-variant environment", command("Lab", LAB_ADMISSION_AUTHORITY_ID, false)],
    ["empty environment", command("", LAB_ADMISSION_AUTHORITY_ID, false)],
    ["non-boolean confirmation", [...command("lab", LAB_ADMISSION_AUTHORITY_ID, false).slice(0, 8), "false"] as unknown as AuthorityInitializationCommand],
    ["wrong field count", [...command("lab", LAB_ADMISSION_AUTHORITY_ID, false), "extra"] as unknown as AuthorityInitializationCommand],
  ];
  for (const [label, cmd] of bad) assert.throws(() => canonicalOperatorCommandBytes(cmd), /operator-command/u, label);
});

test("operator command: no lab command can reach a rotation, and rotation stays Production-only", async () => {
  const rotation = (environment: string, authority: string): AuthorityReleaseRotationCommand =>
    [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", environment, authority, ADMISSION_POLICY_EPOCH, RELEASE, "release-2", "key-2", T0, T0, T0] as unknown as AuthorityReleaseRotationCommand;
  for (const [environment, authority] of [["lab", LAB_ADMISSION_AUTHORITY_ID], ["staging", STAGING_ADMISSION_AUTHORITY_ID], ["lab", ADMISSION_AUTHORITY_ID], ["production", LAB_ADMISSION_AUTHORITY_ID]] as const)
    assert.throws(() => canonicalOperatorCommandBytes(rotation(environment, authority)), /operator-command/u, `${environment}/${authority}`);
  const operator = generateLabKeyPair(); const storage = new NodeSqliteDurableStorage();
  await assert.rejects(() => executeSignedAuthorityReleaseRotation(storage, rotation("lab", LAB_ADMISSION_AUTHORITY_ID), "A".repeat(86), operator.publicKey, T0, "lab" as never));
  assert.equal(rows(storage), 0);
});

test("operator execution: a lab command only runs as lab; the executor's expected environment, the signature and the key are all required; nothing is written on refusal", async () => {
  const operator = generateLabKeyPair(); const other = generateLabKeyPair();
  const cmd = command("lab", LAB_ADMISSION_AUTHORITY_ID, false);
  const signature = await signAuthorityInitializationCommand(cmd, operator.privatePkcs8);
  for (const expected of ["production", "staging"] as const) {
    const storage = new NodeSqliteDurableStorage();
    await assert.rejects(() => executeSignedAuthorityInitialization(storage, cmd, signature, operator.publicKey, T0, expected), /operator-environment/u, `lab command as ${expected}`);
    assert.equal(rows(storage), 0);
  }
  for (const [label, run] of [
    ["production command as lab", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, command("production", ADMISSION_AUTHORITY_ID, true), signature, operator.publicKey, T0, "lab")],
    ["staging command as lab", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, command("staging", STAGING_ADMISSION_AUTHORITY_ID, false), signature, operator.publicKey, T0, "lab")],
    ["missing signature", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, cmd, "", operator.publicKey, T0, "lab")],
    ["garbled signature", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, cmd, "not-a-signature", operator.publicKey, T0, "lab")],
    ["signature by another key", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, cmd, signature, other.publicKey, T0, "lab")],
    ["stale command", (s: NodeSqliteDurableStorage) => executeSignedAuthorityInitialization(s, cmd, signature, operator.publicKey, T0 + 6 * 60_000, "lab")],
  ] as const) {
    const storage = new NodeSqliteDurableStorage();
    await assert.rejects(() => run(storage), /./u, label);
    assert.equal(rows(storage), 0, `${label}: nothing initialized`);
  }
  // a valid lab signature cannot be re-targeted by editing the signed fields to Production
  const retargeted = command("production", ADMISSION_AUTHORITY_ID, true);
  await assert.rejects(() => verifyOperatorCommand(retargeted, signature, operator.publicKey));
  const storage = new NodeSqliteDurableStorage();
  assert.equal((await executeSignedAuthorityInitialization(storage, cmd, signature, operator.publicKey, T0, "lab")).status, "initialized");
  assert.equal(rows(storage), 1);
});
