import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { before, test } from "node:test";
import { build } from "esbuild";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "../operator/lifecycle-observation";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, initializeAuthority, inspectLifecycleAuthority,
  type DurableStorageLike } from "../workers/admission-service/authority";
import { AuthorityAttestationCoordinator, PRODUCTION_ATTESTATION_IDENTITY, STAGING_ATTESTATION_IDENTITY } from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner, type AuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { attestationReceiptFromLifecycleReceipt, encodeResultAttestationEnvelope, makeLifecycleStatement, parseResultAttestationEnvelope,
  signResultAttestation } from "../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest, verifyAuthoritySignedStatement, type ResultAttestationExpectations } from "../src/lib/authority-result-trust";
import { healthySigner, instrumentSigner, instrumentStorage, rfcKeys, rfcSignerConfig, scriptedClock, type SignerEvents } from "./support/authority-attestation-test-signers";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation, signAuthorityInitializationCommand, signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand, type AuthorityReleaseRotationCommand } from "../workers/admission-service/operator-command";

async function keys() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { privateKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
    publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}
const init = (issued = 1_000): AuthorityInitializationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production",
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "key-a", issued, true];
const rotate = (issued = 2_000): AuthorityReleaseRotationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production",
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b", 2_000, 3_000, issued, true];

test("canonical digest has stable domain-separated vector and includes issuance time", async () => {
  assert.equal(await commandDigest(init()), "a29951ac7bc8f4a784da4caf435a78d13377000219c9a09553b3c3437e66fedf");
  assert.equal(await commandDigest(rotate()), "2ef1a416b83bfae0970a0296a2d7bc728a7e4b297005eb46a61378bcedef9991");
  assert.notEqual(await commandDigest(init()), await commandDigest(init(1_001)));
  assert.notEqual(await commandDigest(rotate()), await commandDigest(rotate(2_001)));
});

test("signed state and exact receipt commit atomically; historical identity survives rotation", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const initial = init();
  const first = await executeSignedAuthorityInitialization(storage, initial,
    await signAuthorityInitializationCommand(initial, key.privateKey), key.publicKey, 1_001);
  assert.equal(first.status, "initialized");
  assert.equal(first.receipt?.digest, await commandDigest(initial));
  const rotation = rotate();
  const second = await executeSignedAuthorityReleaseRotation(storage, rotation,
    await signAuthorityReleaseRotationCommand(rotation, key.privateKey), key.publicKey, 2_001);
  assert.equal(second.status, "rotated");
  assert.equal(second.receipt?.sequence, 2);
  assert.deepEqual(inspectLifecycleAuthority(storage, first.receipt!.digest, 5_000).receipt, first.receipt);
  assert.equal(inspectLifecycleAuthority(storage, await commandDigest(rotate(2_001)), 5_000).status, "NOT_FOUND");
  const third: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production",
    ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-b", "release-c", "key-c", 800_000, 800_001, 800_000, true];
  await executeSignedAuthorityReleaseRotation(storage, third,
    await signAuthorityReleaseRotationCommand(third, key.privateKey), key.publicKey, 800_001);
  assert.equal(storage.database.prepare("SELECT release_id FROM active_releases WHERE release_id='release-a'").get(), undefined);
  assert.deepEqual(inspectLifecycleAuthority(storage, first.receipt!.digest, 810_000).receipt, first.receipt);
  storage.close();
});

test("receipt insertion failure rolls back lifecycle state", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const command = init();
  const proxy: DurableStorageLike = {
    sql: { exec: (query, ...args) => {
      if (query.startsWith("INSERT INTO lifecycle_receipts")) throw new Error("injected-receipt-failure");
      return storage.sql.exec(query, ...args);
    } },
    transactionSync: (callback) => storage.transactionSync(callback),
  };
  const signature = await signAuthorityInitializationCommand(command, key.privateKey);
  await assert.rejects(() => executeSignedAuthorityInitialization(proxy, command,
    signature, key.publicKey, 1_001));
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM authority_meta").get() as { count: number }).count, 0);
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM active_releases").get() as { count: number }).count, 0);
  storage.close();
});

test("rotation receipt failure and capacity exhaustion preserve old release and permanent history", async () => {
  const storage = new NodeSqliteDurableStorage();
  const key = await keys();
  const initial = init();
  await executeSignedAuthorityInitialization(storage, initial,
    await signAuthorityInitializationCommand(initial, key.privateKey), key.publicKey, 1_001);
  const rotation = rotate();
  const signature = await signAuthorityReleaseRotationCommand(rotation, key.privateKey);
  storage.database.exec("CREATE TRIGGER fail_rotation_receipt BEFORE INSERT ON lifecycle_receipts WHEN NEW.operation='rotate-release' BEGIN SELECT RAISE(ABORT, 'injected-receipt-failure'); END");
  await assert.rejects(() => executeSignedAuthorityReleaseRotation(storage, rotation, signature, key.publicKey, 2_001));
  assert.deepEqual(storage.database.prepare("SELECT release_id,retired_ms FROM active_releases").all().map((row) => ({ ...row })),
    [{ release_id: "release-a", retired_ms: null }]);
  storage.database.exec("DROP TRIGGER fail_rotation_receipt");
  const insert = storage.database.prepare("INSERT INTO lifecycle_receipts(digest,schema_version,operation,environment,authority_id,policy_epoch,key_fingerprint,sequence,applied_ms,current_release_id,next_release_id,next_key_id,activates_ms,retires_ms) VALUES(?,1,'rotate-release','production',?,?,?,?,?,'release-a','release-b','key-b',2000,3000)");
  for (let sequence = 2; sequence <= 4_095; sequence++) insert.run(sequence.toString(16).padStart(64, "0"), ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "f".repeat(64), sequence, 2_000);
  const boundary = await executeSignedAuthorityReleaseRotation(storage, rotation, signature, key.publicKey, 2_001);
  assert.equal(boundary.receipt?.sequence, 4_096, "new receipt row 4096 is accepted and committed with rotation");
  assert.equal((storage.database.prepare("SELECT retired_ms FROM active_releases WHERE release_id='release-a'").get() as
    { retired_ms: number }).retired_ms, 3_000);
  const next: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production",
    ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "release-b", "release-c", "key-c", 2_500, 3_500, 2_500, true];
  const queries: string[] = [];
  const instrumented: DurableStorageLike = { sql: { exec: (query, ...args) => {
    queries.push(query);
    return storage.sql.exec(query, ...args);
  } }, transactionSync: (callback) => storage.transactionSync(callback) };
  const nextSignature = await signAuthorityReleaseRotationCommand(next, key.privateKey);
  await assert.rejects(() => executeSignedAuthorityReleaseRotation(instrumented, next,
    nextSignature, key.publicKey, 2_501), /receipt-capacity/u);
  assert.equal(queries.some((query) => /^(?:INSERT INTO|UPDATE|DELETE FROM) active_releases/u.test(query)), false,
    "capacity refusal precedes every lifecycle release mutation SQL statement");
  assert.equal((await executeSignedAuthorityReleaseRotation(storage, rotation, signature, key.publicKey, 2_001)).receipt?.digest,
    boundary.receipt?.digest, "exact historical replay succeeds at full capacity");
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM lifecycle_receipts").get() as { count: number }).count, 4_096);
  storage.close();
});

test("read-only inspection executes SELECTs only, including never-initialized and incomplete legacy authority", async () => {
  const storage = new NodeSqliteDurableStorage();
  const queries: string[] = [];
  const proxy: DurableStorageLike = { sql: { exec: (query, ...args) => {
    queries.push(query);
    return storage.sql.exec(query, ...args);
  } }, transactionSync: (callback) => storage.transactionSync(callback),
  setAlarm: async () => { throw new Error("read-path-scheduled-alarm"); } };
  assert.equal(inspectLifecycleAuthority(proxy, "a".repeat(64)).status, "NOT_FOUND");
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='authority_meta'").get() as { count: number }).count, 0);
  const key = await keys();
  const command = init();
  const signed = await signAuthorityInitializationCommand(command, key.privateKey);
  const applied = await executeSignedAuthorityInitialization(storage, command, signed, key.publicKey, 1_001);
  storage.database.prepare("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES('old','pre','client','synthetic',1000)").run();
  storage.database.prepare("INSERT INTO nonces(nonce,release_id,client_id,request_binding,permit,claimed_ms,permit_expires_ms,retain_until_ms,post_consumed) VALUES('old','release-a','synthetic','synthetic','synthetic',1000,1001,1002,0)").run();
  const snapshot = () => ["authority_meta", "active_releases", "observations", "nonces", "lifecycle_receipts"]
    .map((table) => storage.database.prepare(`SELECT * FROM ${table}`).all().map((row) => ({ ...row })));
  const before = snapshot();
  queries.length = 0;
  assert.equal(inspectLifecycleAuthority(proxy, applied.receipt!.digest, 1_000_000).status, "EXACT_RECEIPT");
  assert.deepEqual(snapshot(), before);
  assert.ok(queries.every((query) => /^SELECT /u.test(query)));
  storage.close();

  const legacy = new NodeSqliteDurableStorage();
  const { initializeAuthority } = await import("../workers/admission-service/authority");
  initializeAuthority(legacy, { environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId: "release-a", releaseKeyId: "key-a", nowMs: 1_000, confirmProduction: true });
  assert.equal(inspectLifecycleAuthority(legacy, "a".repeat(64)).status, "HISTORY_INCOMPLETE");
  legacy.close();
});

test("unavailable authority inspection asserts no invented authority state", () => {
  const storage = new NodeSqliteDurableStorage();
  storage.database.exec("CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, last_now_ms INTEGER NOT NULL)");
  storage.database.exec("INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'wrong','wrong',0)");
  assert.deepEqual(inspectLifecycleAuthority(storage, "a".repeat(64)), UNAVAILABLE_AUTHORITY_OBSERVATION);
  storage.close();
});

// =====================================================================================================================
// R06 Slice 2A: inert Authority attestation producer. Real coordinator, real transactionSync (node:sqlite), real frozen
// protocol, RFC test keys only. Nothing here touches a relay, mailbox, observer, CLI, R2 object or provider.
// =====================================================================================================================
const T0 = 1_790_000_000_000;
type Role = "production" | "staging";
const identityOf = (role: Role) => role === "production" ? PRODUCTION_ATTESTATION_IDENTITY : STAGING_ATTESTATION_IDENTITY;
const authorityIdOf = (role: Role) => role === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID;
const initAt = (role: Role = "production", issued = T0, release = "release-a"): AuthorityInitializationCommand => role === "production"
  ? [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, "key-a", issued, true]
  : [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, "key-a", issued, false];
const rotateAt = (base = T0): AuthorityReleaseRotationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
  ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b", base + 1_000, base + 31_000, base + 500, true];

let manifestCache: Promise<{ text: string; manifest: Awaited<ReturnType<typeof parseAuthorityResultTrustManifest>> }> | undefined;
function trust() {
  manifestCache ??= readFile(new URL("./fixtures/authority-result-trust-v1.test.json", import.meta.url), "utf8")
    .then(async (text) => ({ text, manifest: await parseAuthorityResultTrustManifest(text) }));
  return manifestCache;
}
const lifecycleExpectation = (role: Role, digest: string): ResultAttestationExpectations =>
  ({ kind: "lifecycle", environment: role, authorityId: authorityIdOf(role), policyEpoch: ADMISSION_POLICY_EPOCH, digest });
const reconciliationExpectation = (role: Role, digest: string, nonce: string): ResultAttestationExpectations =>
  ({ kind: "reconciliation", environment: role, authorityId: authorityIdOf(role), policyEpoch: ADMISSION_POLICY_EPOCH, digest, nonce });
async function verified(bytes: Uint8Array, expectations: ResultAttestationExpectations, nowMs: number) {
  return verifyAuthoritySignedStatement(bytes, expectations, (await trust()).manifest, nowMs);
}
const NONCE = "0123456789abcdef0123456789abcdef";

const stateTables = ["authority_meta", "active_releases", "lifecycle_receipts", "lifecycle_receipt_coverage"];
function lifecycleState(storage: NodeSqliteDurableStorage) {
  return stateTables.map((table) => storage.database.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)
    ? storage.database.prepare(`SELECT * FROM ${table}`).all().map((row) => ({ ...row })) : null);
}
const tableCount = (storage: NodeSqliteDurableStorage) =>
  (storage.database.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table'").get() as { count: number }).count;
const receiptCount = (storage: NodeSqliteDurableStorage) =>
  (storage.database.prepare("SELECT COUNT(*) AS count FROM lifecycle_receipts").get() as { count: number }).count;

async function rig(role: Role, readings: number[], faults: { ready?: boolean; sign?: boolean } = {}, storage = new NodeSqliteDurableStorage()) {
  const events: SignerEvents = { log: [] };
  const operator = await keys();
  const clock = scriptedClock(...readings);
  const signer = instrumentSigner(await healthySigner(role), events, faults);
  const coordinator = new AuthorityAttestationCoordinator(instrumentStorage(storage, events), identityOf(role), operator.publicKey, { signer, now: clock.now });
  const coordinatorWith = (runtime: { signer?: AuthorityAttestationSigner; now?: () => number }) =>
    new AuthorityAttestationCoordinator(instrumentStorage(storage, events), identityOf(role), operator.publicKey, runtime);
  return { storage, events, operator, clock, signer, coordinator, coordinatorWith };
}
const firstIndex = (log: string[], prefix: string) => log.findIndex((entry) => entry.startsWith(prefix));
const selectOnly = (log: string[]) => log.filter((entry) => entry.startsWith("sql:")).every((entry) => entry.startsWith("sql:SELECT"));

test("Production initialize: signer ready before any storage statement, signing only after the transaction, Authority-clock observedAtMs", async () => {
  const { storage, events, operator, clock, coordinator } = await rig("production", [T0 - 20, T0, T0 + 50]);
  const command = initAt();
  const result = await coordinator.initialize(command, await signAuthorityInitializationCommand(command, operator.privateKey));
  assert.ok(result.status === "ATTESTED");
  assert.equal(result.relayDisposition, "APPLIED");
  assert.ok(result.envelope instanceof Uint8Array);
  // ordering: ready(preliminary time) < first SQL < tx:begin < tx:commit < sign
  assert.equal(events.log[0], `ready:${T0 - 20}`, "readiness is first after authentication: before any SQL, including schema creation");
  assert.ok(firstIndex(events.log, "sql:") > 0);
  assert.ok(firstIndex(events.log, "tx:begin") < firstIndex(events.log, "tx:commit") && firstIndex(events.log, "tx:commit") < events.log.indexOf("sign"));
  assert.equal(events.log.filter((entry) => entry === "sign").length, 1);
  // clock ownership: exactly three Authority reads: preliminary (readiness only), final (freshness = appliedMs), post-commit (observedAtMs)
  assert.deepEqual(clock.reads, [T0 - 20, T0, T0 + 50]);
  const digest = await commandDigest(command);
  const proof = await verified(result.envelope, lifecycleExpectation("production", digest), T0 + 1_000);
  assert.ok(proof.statement.kind === "lifecycle");
  assert.equal(proof.statement.observedAtMs, T0 + 50);
  assert.equal(proof.statement.receipt.appliedMs, T0);
  assert.equal(proof.statement.outcome, "APPLIED");
  // the attested receipt is exactly the durable receipt
  const durable = inspectLifecycleAuthority(storage, digest, T0 + 100).receipt!;
  assert.equal(durable.sequence, 1);
  assert.deepEqual(proof.statement.receipt, attestationReceiptFromLifecycleReceipt(durable));
  assert.equal(Buffer.from(result.envelope).toString("utf8").includes("ALREADY_APPLIED"), false, "relayDisposition never enters the envelope");
  storage.close();
});

test("exact replay attests the same stored receipt with fresh evidence and no second mutation", async () => {
  const first = await rig("production", [T0 - 20, T0, T0 + 50]);
  const command = initAt();
  const signature = await signAuthorityInitializationCommand(command, first.operator.privateKey);
  const initial = await first.coordinator.initialize(command, signature);
  assert.ok(initial.status === "ATTESTED");
  const before = lifecycleState(first.storage);
  const clock = scriptedClock(T0 + 990, T0 + 1_000, T0 + 1_100);
  const replay = await first.coordinatorWith({ signer: first.signer, now: clock.now }).initialize(command, signature);
  assert.ok(replay.status === "ATTESTED");
  assert.equal(replay.relayDisposition, "ALREADY_APPLIED");
  assert.deepEqual(lifecycleState(first.storage), before, "no duplicate mutation");
  assert.equal(receiptCount(first.storage), 1);
  const proof = await verified(replay.envelope, lifecycleExpectation("production", await commandDigest(command)), T0 + 1_200);
  assert.equal(proof.statement.observedAtMs, T0 + 1_100, "fresh observedAtMs");
  assert.ok(proof.statement.kind === "lifecycle");
  assert.equal(proof.statement.receipt.appliedMs, T0, "the stored receipt, not a new one");
  assert.notDeepEqual(Buffer.from(replay.envelope), Buffer.from(initial.envelope), "fresh evidence is a different signed statement");
  first.storage.close();
});

test("Production rotation: receipt commits before signing, sequence/state correct, exact replay without a second mutation", async () => {
  const { storage, events, operator, coordinator, coordinatorWith, signer } = await rig("production", [T0 - 20, T0, T0 + 10]);
  const initial = initAt();
  assert.ok((await coordinator.initialize(initial, await signAuthorityInitializationCommand(initial, operator.privateKey))).status === "ATTESTED");
  const rotation = rotateAt();
  const signature = await signAuthorityReleaseRotationCommand(rotation, operator.privateKey);
  events.log.length = 0;
  const rotated = await coordinatorWith({ signer, now: scriptedClock(T0 + 580, T0 + 600, T0 + 650).now }).rotate(rotation, signature);
  assert.ok(rotated.status === "ATTESTED");
  assert.equal(rotated.relayDisposition, "APPLIED");
  assert.equal(events.log[0], `ready:${T0 + 580}`);
  assert.ok(firstIndex(events.log, "tx:commit") < events.log.indexOf("sign"));
  const proof = await verified(rotated.envelope, lifecycleExpectation("production", await commandDigest(rotation)), T0 + 1_000);
  assert.ok(proof.statement.kind === "lifecycle");
  assert.equal(proof.statement.receipt.operation, "rotate-release");
  assert.equal(proof.statement.receipt.sequence, 2);
  assert.equal(proof.statement.receipt.appliedMs, T0 + 600);
  assert.equal(proof.statement.observedAtMs, T0 + 650);
  assert.deepEqual(storage.database.prepare("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY activated_ms").all().map((row) => ({ ...row })), [
    { release_id: "release-a", key_id: "key-a", activated_ms: T0, retired_ms: T0 + 31_000 },
    { release_id: "release-b", key_id: "key-b", activated_ms: T0 + 1_000, retired_ms: null }]);
  const before = lifecycleState(storage);
  const replay = await coordinatorWith({ signer, now: scriptedClock(T0 + 690, T0 + 700, T0 + 710).now }).rotate(rotation, signature);
  assert.ok(replay.status === "ATTESTED");
  assert.equal(replay.relayDisposition, "ALREADY_APPLIED");
  assert.deepEqual(lifecycleState(storage), before);
  assert.equal(receiptCount(storage), 2);
  storage.close();
});

test("staging has no rotation attestation path: the coordinator refuses with zero side effects", async () => {
  const { storage, events, operator, coordinator } = await rig("staging", [T0, T0 + 10]);
  const rotation = rotateAt();
  assert.deepEqual(await coordinator.rotate(rotation, await signAuthorityReleaseRotationCommand(rotation, operator.privateKey)), { status: "REFUSED" });
  assert.deepEqual(events.log, [], "no readiness, no SQL, no signing");
  assert.equal(tableCount(storage), 0);
  storage.close();
});

test("staging initialize signs with the staging key only; a Production signer cannot substitute and fails before mutation", async () => {
  const staging = await rig("staging", [T0 - 20, T0, T0 + 40]);
  const command = initAt("staging");
  const signature = await signAuthorityInitializationCommand(command, staging.operator.privateKey);
  const result = await staging.coordinator.initialize(command, signature);
  assert.ok(result.status === "ATTESTED");
  const proof = await verified(result.envelope, lifecycleExpectation("staging", await commandDigest(command)), T0 + 1_000);
  assert.equal(proof.signingKeyFingerprint, (await rfcKeys()).staging.fingerprint);
  assert.equal(proof.statement.environment, "staging");
  // cross-environment signer injection: refused before any readiness, SQL or signing
  const crossing = await rig("staging", [T0, T0 + 10]);
  const productionSigner = instrumentSigner(await healthySigner("production"), crossing.events);
  assert.deepEqual(await crossing.coordinatorWith({ signer: productionSigner, now: scriptedClock(T0, T0 + 10).now })
    .initialize(command, await signAuthorityInitializationCommand(command, crossing.operator.privateKey)), { status: "UNAVAILABLE", reason: "signer-mismatch" });
  assert.deepEqual(crossing.events.log, []);
  assert.equal(tableCount(crossing.storage), 0);
  // and the mirror: a staging signer in a Production coordinator
  const production = await rig("production", [T0, T0 + 10]);
  const stagingSigner = instrumentSigner(await healthySigner("staging"), production.events);
  const productionCommand = initAt();
  assert.deepEqual(await production.coordinatorWith({ signer: stagingSigner, now: scriptedClock(T0).now })
    .initialize(productionCommand, await signAuthorityInitializationCommand(productionCommand, production.operator.privateKey)), { status: "UNAVAILABLE", reason: "signer-mismatch" });
  assert.deepEqual(production.events.log, []);
  staging.storage.close(); crossing.storage.close(); production.storage.close();
});

test("Production and staging statements verify only under their own trust section/key", async () => {
  const production = await rig("production", [T0 - 20, T0, T0 + 20]);
  const staging = await rig("staging", [T0 - 20, T0, T0 + 20]);
  const productionCommand = initAt();
  const stagingCommand = initAt("staging");
  const productionResult = await production.coordinator.initialize(productionCommand, await signAuthorityInitializationCommand(productionCommand, production.operator.privateKey));
  const stagingResult = await staging.coordinator.initialize(stagingCommand, await signAuthorityInitializationCommand(stagingCommand, staging.operator.privateKey));
  assert.ok(productionResult.status === "ATTESTED" && stagingResult.status === "ATTESTED");
  const productionDigest = await commandDigest(productionCommand);
  const stagingDigest = await commandDigest(stagingCommand);
  await verified(productionResult.envelope, lifecycleExpectation("production", productionDigest), T0 + 1_000);
  await verified(stagingResult.envelope, lifecycleExpectation("staging", stagingDigest), T0 + 1_000);
  // each envelope under the other environment's expectations
  await assert.rejects(verified(productionResult.envelope, lifecycleExpectation("staging", productionDigest), T0 + 1_000), /attestation-expectation/u);
  await assert.rejects(verified(stagingResult.envelope, lifecycleExpectation("production", stagingDigest), T0 + 1_000), /attestation-expectation/u);
  // manifests with the two sections' keys swapped: neither statement finds its writer key in its own environment section
  const swapped = JSON.parse((await trust()).text) as { environments: { currentKeyFingerprint: string; keys: unknown[] }[] };
  [swapped.environments[0].keys, swapped.environments[1].keys] = [swapped.environments[1].keys, swapped.environments[0].keys];
  [swapped.environments[0].currentKeyFingerprint, swapped.environments[1].currentKeyFingerprint] =
    [swapped.environments[1].currentKeyFingerprint, swapped.environments[0].currentKeyFingerprint];
  const swappedManifest = await parseAuthorityResultTrustManifest(JSON.stringify(swapped));
  await assert.rejects(verifyAuthoritySignedStatement(productionResult.envelope, lifecycleExpectation("production", productionDigest), swappedManifest, T0 + 1_000), /attestation-key/u);
  await assert.rejects(verifyAuthoritySignedStatement(stagingResult.envelope, lifecycleExpectation("staging", stagingDigest), swappedManifest, T0 + 1_000), /attestation-key/u);
  production.storage.close(); staging.storage.close();
});

test("read-only APPLIED recovery signs the durable receipt, executes SELECTs only and mutates nothing", async () => {
  const { storage, events, operator, coordinator, coordinatorWith, signer } = await rig("production", [T0 - 20, T0, T0 + 10]);
  const command = initAt();
  assert.ok((await coordinator.initialize(command, await signAuthorityInitializationCommand(command, operator.privateKey))).status === "ATTESTED");
  const digest = await commandDigest(command);
  const before = lifecycleState(storage);
  const lastNow = () => (storage.database.prepare("SELECT last_now_ms FROM authority_meta").get() as { last_now_ms: number }).last_now_ms;
  const clockBefore = lastNow();
  events.log.length = 0;
  const recovered = await coordinatorWith({ signer, now: scriptedClock(T0 + 2_000, T0 + 2_050).now }).attestAppliedLifecycle(digest);
  assert.ok(recovered.status === "ATTESTED");
  assert.equal(recovered.relayDisposition, "ALREADY_APPLIED");
  assert.equal(events.log[0], `ready:${T0 + 2_000}`);
  assert.ok(selectOnly(events.log), "SELECT only");
  assert.equal(events.log.some((entry) => entry.startsWith("tx:")), false);
  assert.deepEqual(lifecycleState(storage), before);
  assert.equal(lastNow(), clockBefore, "stored clock untouched");
  const proof = await verified(recovered.envelope, lifecycleExpectation("production", digest), T0 + 2_100);
  assert.equal(proof.statement.observedAtMs, T0 + 2_050);
  assert.ok(proof.statement.kind === "lifecycle");
  assert.equal(proof.statement.receipt.appliedMs, T0);
  // non-positive states carry no receipt evidence
  assert.deepEqual(await coordinator.attestAppliedLifecycle("b".repeat(64)), { status: "UNAVAILABLE", reason: "receipt-not-found" });
  assert.deepEqual(await coordinator.attestAppliedLifecycle("not-a-digest"), { status: "REFUSED" });
  storage.close();

  const empty = await rig("production", [T0, T0 + 1]);
  assert.deepEqual(await empty.coordinator.attestAppliedLifecycle("a".repeat(64)), { status: "UNAVAILABLE", reason: "receipt-not-found" });
  assert.equal(tableCount(empty.storage), 0, "recovery never creates schema");
  const legacy = await rig("production", [T0, T0 + 1]);
  initializeAuthority(legacy.storage, { environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId: "release-a", releaseKeyId: "key-a", nowMs: T0, confirmProduction: true });
  assert.deepEqual(await legacy.coordinator.attestAppliedLifecycle("a".repeat(64)), { status: "UNAVAILABLE", reason: "history-incomplete" });
  empty.storage.close(); legacy.storage.close();
});

test("invalid digest/nonce are refused before signer readiness or any storage access", async () => {
  const { storage, events, coordinator } = await rig("production", [T0, T0 + 1]);
  for (const digest of ["", "A".repeat(64), "a".repeat(63), "a".repeat(65), "g".repeat(64)]) {
    assert.deepEqual(await coordinator.attestAppliedLifecycle(digest), { status: "REFUSED" });
    assert.deepEqual(await coordinator.attestReconciliation(digest, NONCE), { status: "REFUSED" });
  }
  for (const nonce of ["", "A".repeat(32), "a".repeat(31), "a".repeat(33), "z".repeat(32)]) {
    assert.deepEqual(await coordinator.attestReconciliation("a".repeat(64), nonce), { status: "REFUSED" });
  }
  assert.deepEqual(events.log, []);
  storage.close();
});

test("signed reconciliation: the Authority signs the nonce; EXACT_RECEIPT, NOT_FOUND (initialized and not), HISTORY_INCOMPLETE; canonical release rows", async () => {
  const { storage, events, operator, coordinator, coordinatorWith, signer } = await rig("production", [T0 - 20, T0, T0 + 10]);
  const reconcile = async (digest: string, nonce: string, readings: number[]) => {
    events.log.length = 0;
    const result = await coordinatorWith({ signer, now: scriptedClock(...readings).now }).attestReconciliation(digest, nonce);
    assert.ok(result.status === "ATTESTED", JSON.stringify(result));
    assert.equal(events.log[0], `ready:${readings[0]}`);
    assert.ok(selectOnly(events.log));
    return result.envelope;
  };
  // uninitialized NOT_FOUND
  const unknown = "c".repeat(64);
  let envelope = await reconcile(unknown, NONCE, [T0 + 100, T0 + 110]);
  let proof = await verified(envelope, reconciliationExpectation("production", unknown, NONCE), T0 + 200);
  assert.ok(proof.statement.kind === "reconciliation");
  assert.deepEqual([proof.statement.initialized, proof.statement.coverage, proof.statement.status, proof.statement.receipt, proof.statement.releases],
    [false, "COMPLETE", "NOT_FOUND", null, []]);
  assert.equal(proof.statement.nonce, NONCE);
  assert.equal(proof.statement.observedAtMs, T0 + 110);
  assert.equal(tableCount(storage), 0, "reconciling an uninitialized Authority creates nothing");

  const initial = initAt();
  assert.ok((await coordinator.initialize(initial, await signAuthorityInitializationCommand(initial, operator.privateKey))).status === "ATTESTED");
  const initialDigest = await commandDigest(initial);
  // EXACT_RECEIPT with one row
  envelope = await reconcile(initialDigest, NONCE, [T0 + 300, T0 + 310]);
  proof = await verified(envelope, reconciliationExpectation("production", initialDigest, NONCE), T0 + 400);
  assert.ok(proof.statement.kind === "reconciliation");
  assert.deepEqual([proof.statement.initialized, proof.statement.coverage, proof.statement.status], [true, "COMPLETE", "EXACT_RECEIPT"]);
  assert.deepEqual(proof.statement.releases, [{ releaseId: "release-a", keyId: "key-a", activatedMs: T0, retiredMs: null }]);
  assert.deepEqual(proof.statement.receipt, attestationReceiptFromLifecycleReceipt(inspectLifecycleAuthority(storage, initialDigest, T0).receipt!));
  // initialized NOT_FOUND
  envelope = await reconcile(unknown, NONCE, [T0 + 320, T0 + 330]);
  proof = await verified(envelope, reconciliationExpectation("production", unknown, NONCE), T0 + 400);
  assert.ok(proof.statement.kind === "reconciliation");
  assert.deepEqual([proof.statement.initialized, proof.statement.status, proof.statement.receipt], [true, "NOT_FOUND", null]);
  // after rotation the snapshot has two canonical rows while the historical receipt stays the initialization receipt
  const rotation = rotateAt();
  assert.ok((await coordinatorWith({ signer, now: scriptedClock(T0 + 590, T0 + 600, T0 + 610).now })
    .rotate(rotation, await signAuthorityReleaseRotationCommand(rotation, operator.privateKey))).status === "ATTESTED");
  envelope = await reconcile(initialDigest, NONCE, [T0 + 700, T0 + 710]);
  proof = await verified(envelope, reconciliationExpectation("production", initialDigest, NONCE), T0 + 800);
  assert.ok(proof.statement.kind === "reconciliation");
  assert.equal(proof.statement.status, "EXACT_RECEIPT");
  assert.equal(proof.statement.receipt?.operation, "initialize");
  assert.deepEqual(proof.statement.releases, [
    { releaseId: "release-a", keyId: "key-a", activatedMs: T0, retiredMs: T0 + 31_000 },
    { releaseId: "release-b", keyId: "key-b", activatedMs: T0 + 1_000, retiredMs: null }]);
  // the nonce is bound by the Authority's signature: a different expectation is refused and a replaced nonce breaks the signature
  await assert.rejects(verified(envelope, reconciliationExpectation("production", initialDigest, "f".repeat(32)), T0 + 800), /attestation-expectation/u);
  const original = Buffer.from(envelope).toString("utf8");
  const replaced = original.replace(NONCE, "f".repeat(32));
  assert.notEqual(replaced, original);
  await assert.rejects(verified(new TextEncoder().encode(replaced), reconciliationExpectation("production", initialDigest, "f".repeat(32)), T0 + 800), /attestation-signature/u);
  storage.close();

  // HISTORY_INCOMPLETE where source can produce it: legacy (receipt-less) initialization
  for (const role of ["production", "staging"] as const) {
    const legacy = await rig(role, [T0 + 100, T0 + 110]);
    initializeAuthority(legacy.storage, { environment: role, authorityId: authorityIdOf(role), policyEpoch: ADMISSION_POLICY_EPOCH,
      releaseId: "release-a", releaseKeyId: "key-a", nowMs: T0, confirmProduction: role === "production" },
    undefined, { expectedAuthorityId: authorityIdOf(role) });
    const result = await legacy.coordinator.attestReconciliation(unknown, NONCE);
    assert.ok(result.status === "ATTESTED");
    const incomplete = await verified(result.envelope, reconciliationExpectation(role, unknown, NONCE), T0 + 200);
    assert.ok(incomplete.statement.kind === "reconciliation");
    assert.deepEqual([incomplete.statement.initialized, incomplete.statement.coverage, incomplete.statement.status, incomplete.statement.receipt],
      [true, "INCOMPLETE", "HISTORY_INCOMPLETE", null]);
    legacy.storage.close();
  }
  // staging reconciliation of an uninitialized Authority
  const stagingEmpty = await rig("staging", [T0, T0 + 1]);
  const stagingResult = await stagingEmpty.coordinator.attestReconciliation(unknown, NONCE);
  assert.ok(stagingResult.status === "ATTESTED");
  await verified(stagingResult.envelope, reconciliationExpectation("staging", unknown, NONCE), T0 + 200);
  stagingEmpty.storage.close();
  // an unreadable Authority produces no statement at all
  const broken = await rig("production", [T0, T0 + 1]);
  broken.storage.database.exec("CREATE TABLE authority_meta(singleton INTEGER PRIMARY KEY, authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, last_now_ms INTEGER NOT NULL)");
  broken.storage.database.exec("INSERT INTO authority_meta VALUES(1,'wrong','wrong',0)");
  assert.deepEqual(await broken.coordinator.attestReconciliation(unknown, NONCE), { status: "UNAVAILABLE", reason: "authority-state-unavailable" });
  assert.equal(broken.events.log.includes("sign"), false);
  broken.storage.close();
});

test("MANDATORY post-commit failure: sign throws after the real transaction committed; result is AMBIGUOUS, never REFUSED; state is preserved and recoverable", async () => {
  const failing = await rig("production", [T0 - 20, T0, T0 + 50], { sign: true });
  const command = initAt();
  const signature = await signAuthorityInitializationCommand(command, failing.operator.privateKey);
  const result = await failing.coordinator.initialize(command, signature);
  assert.deepEqual(result, { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" });
  // ready succeeded (preliminary time), final freshness at T0, exactly one transaction committed, then sign was attempted once and threw
  assert.equal(failing.events.log[0], `ready:${T0 - 20}`);
  assert.ok(failing.events.log.indexOf(`ready:${T0 - 20}`) < failing.events.log.indexOf("tx:begin"));
  assert.deepEqual(failing.clock.reads, [T0 - 20, T0, T0 + 50], "ready -> final freshness (appliedMs) -> commit -> post-commit read -> sign failure");
  assert.equal(failing.events.log.filter((entry) => entry === "tx:commit").length, 1);
  assert.ok(failing.events.log.indexOf("tx:commit") < failing.events.log.indexOf("sign"));
  assert.equal(failing.events.log.filter((entry) => entry === "sign").length, 1);
  assert.equal(receiptCount(failing.storage), 1, "receipt remains durable");
  const durable = lifecycleState(failing.storage);
  // a later healthy signed reconciliation with a fresh nonce returns the exact receipt
  const digest = await commandDigest(command);
  const fresh = "1f".repeat(16);
  const reconciled = await failing.coordinatorWith({ signer: await healthySigner("production"), now: scriptedClock(T0 + 5_000, T0 + 5_010).now })
    .attestReconciliation(digest, fresh);
  assert.ok(reconciled.status === "ATTESTED");
  const proof = await verified(reconciled.envelope, reconciliationExpectation("production", digest, fresh), T0 + 5_100);
  assert.ok(proof.statement.kind === "reconciliation");
  assert.equal(proof.statement.status, "EXACT_RECEIPT");
  assert.equal(proof.statement.receipt?.digest, digest);
  assert.equal(proof.statement.receipt?.appliedMs, T0);
  assert.equal(proof.statement.receipt?.sequence, 1);
  assert.deepEqual(lifecycleState(failing.storage), durable, "failure and reconciliation changed nothing: sequence, count and releases identical");
  // the identical command retried with a healthy signer is the exact replay: same receipt, no second mutation
  const retried = await failing.coordinatorWith({ signer: await healthySigner("production"), now: scriptedClock(T0 + 5_990, T0 + 6_000, T0 + 6_010).now }).initialize(command, signature);
  assert.ok(retried.status === "ATTESTED");
  assert.equal(retried.relayDisposition, "ALREADY_APPLIED");
  assert.deepEqual(lifecycleState(failing.storage), durable);
  failing.storage.close();
});

test("post-commit failures of every kind stay AMBIGUOUS: invalid Authority clock, rotation sign failure", async () => {
  const clockFailure = await rig("production", [T0 - 20, T0, Number.NaN]);
  const command = initAt();
  const signature = await signAuthorityInitializationCommand(command, clockFailure.operator.privateKey);
  assert.deepEqual(await clockFailure.coordinator.initialize(command, signature), { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" });
  assert.equal(receiptCount(clockFailure.storage), 1);
  assert.equal(clockFailure.events.log.includes("sign"), false, "an invalid statement never reaches the signer");

  const rotationFailure = await rig("production", [T0 - 20, T0, T0 + 10]);
  const initial = initAt();
  assert.ok((await rotationFailure.coordinator.initialize(initial, await signAuthorityInitializationCommand(initial, rotationFailure.operator.privateKey))).status === "ATTESTED");
  const rotation = rotateAt();
  const signing = rotationFailure.coordinatorWith({ signer: instrumentSigner(await healthySigner("production"), rotationFailure.events, { sign: true }),
    now: scriptedClock(T0 + 590, T0 + 600, T0 + 610).now });
  assert.deepEqual(await signing.rotate(rotation, await signAuthorityReleaseRotationCommand(rotation, rotationFailure.operator.privateKey)),
    { status: "AMBIGUOUS", reason: "post-commit-attestation-failed" });
  assert.equal(receiptCount(rotationFailure.storage), 2);
  assert.equal((rotationFailure.storage.database.prepare("SELECT COUNT(*) AS count FROM active_releases").get() as { count: number }).count, 2);
  clockFailure.storage.close(); rotationFailure.storage.close();
});

test("a failing mutation transaction never signs and is neither attested nor ambiguous", async () => {
  const { storage, events, operator, signer } = await rig("production", [T0, T0 + 10]);
  const command = initAt();
  const signature = await signAuthorityInitializationCommand(command, operator.privateKey);
  const faulty: DurableStorageLike = { sql: { exec: (query, ...args) => {
    if (query.startsWith("INSERT INTO lifecycle_receipts")) throw new Error("injected-receipt-failure");
    return storage.sql.exec(query, ...args);
  } }, transactionSync: (callback) => storage.transactionSync(callback) };
  const coordinator = new AuthorityAttestationCoordinator(faulty, PRODUCTION_ATTESTATION_IDENTITY, operator.publicKey, { signer, now: scriptedClock(T0, T0 + 10).now });
  await assert.rejects(coordinator.initialize(command, signature), /injected-receipt-failure/u);
  assert.equal(events.log.includes("sign"), false);
  assert.equal((storage.database.prepare("SELECT COUNT(*) AS count FROM authority_meta").get() as { count: number }).count, 0, "rolled back");
  storage.close();
});

test("signer/configuration failures happen before the transaction, mutate nothing and are never REFUSED", async () => {
  const production = await rfcSignerConfig("production");
  const staging = await rfcSignerConfig("staging");
  const cases: { label: string; reason: string; signer?: AuthorityAttestationSigner; faults?: { ready?: boolean } }[] = [
    { label: "missing signer configuration", reason: "signer-unconfigured" },
    { label: "malformed test private key", reason: "signer-not-ready", signer: createAuthorityAttestationSigner({ ...production, privateKey: "not-a-key" }) },
    { label: "truncated private key", reason: "signer-not-ready", signer: createAuthorityAttestationSigner({ ...production, privateKey: production.privateKey.slice(0, -2) }) },
    { label: "wrong fingerprint pin", reason: "signer-not-ready", signer: createAuthorityAttestationSigner({ ...production, writerKeyFingerprint: staging.writerKeyFingerprint }) },
    { label: "public key of the other environment", reason: "signer-not-ready", signer: createAuthorityAttestationSigner({ ...production, publicKey: staging.publicKey }) },
    { label: "self-test failure (private key does not match the pinned public key)", reason: "signer-not-ready",
      signer: createAuthorityAttestationSigner({ ...production, privateKey: staging.privateKey }) },
    { label: "ready() rejects", reason: "signer-not-ready", signer: await healthySigner("production"), faults: { ready: true } },
  ];
  for (const entry of cases) {
    const events: SignerEvents = { log: [] };
    const storage = new NodeSqliteDurableStorage();
    const operator = await keys();
    const signer = entry.signer ? instrumentSigner(entry.signer, events, entry.faults) : undefined;
    const coordinator = new AuthorityAttestationCoordinator(instrumentStorage(storage, events), PRODUCTION_ATTESTATION_IDENTITY, operator.publicKey,
      { signer, now: scriptedClock(T0, T0 + 10).now });
    const command = initAt();
    const result = await coordinator.initialize(command, await signAuthorityInitializationCommand(command, operator.privateKey));
    assert.deepEqual(result, { status: "UNAVAILABLE", reason: entry.reason }, entry.label);
    assert.equal(events.log.some((item) => item.startsWith("sql:") || item.startsWith("tx:")), false, `${entry.label}: no storage statement, no transaction`);
    assert.equal(events.log.includes("sign"), false, entry.label);
    assert.equal(tableCount(storage), 0, `${entry.label}: no schema, receipt, release or lifecycle state`);
    // the same failure on the read paths yields no signed positive evidence and still touches no storage
    assert.equal((await coordinator.attestReconciliation("a".repeat(64), NONCE)).status, "UNAVAILABLE", entry.label);
    assert.equal((await coordinator.attestAppliedLifecycle("a".repeat(64))).status, "UNAVAILABLE", entry.label);
    assert.equal(events.log.some((item) => item.startsWith("sql:")), false, entry.label);
    storage.close();
  }
});

test("authentication refusals precede readiness; final freshness and state refusals follow it; all stay REFUSED", async () => {
  const { storage, events, operator, coordinator, coordinatorWith } = await rig("production", [T0, T0 + 10]);
  const command = initAt();
  // bad operator signature is refused before the signer is consulted, even with a broken signer
  const intruder = await keys();
  const broken = instrumentSigner(createAuthorityAttestationSigner({ ...await rfcSignerConfig("production"), privateKey: "bad" }), events);
  assert.deepEqual(await coordinatorWith({ signer: broken, now: scriptedClock(T0).now })
    .initialize(command, await signAuthorityInitializationCommand(command, intruder.privateKey)), { status: "REFUSED" });
  assert.deepEqual(events.log, []);
  // a stale command is refused by FINAL freshness, which now runs after readiness: readiness is the only thing that happened
  const stale = initAt("production", T0 - 6 * 60_000);
  assert.deepEqual(await coordinator.initialize(stale, await signAuthorityInitializationCommand(stale, operator.privateKey)), { status: "REFUSED" });
  assert.deepEqual(events.log, [`ready:${T0}`], "readiness only: no SQL, no transaction, no signing");
  assert.equal(tableCount(storage), 0);
  events.log.length = 0;
  // a command flagged for the other authority is refused
  const wrongEnvironment = initAt("staging");
  assert.deepEqual(await coordinator.initialize(wrongEnvironment, await signAuthorityInitializationCommand(wrongEnvironment, operator.privateKey)), { status: "REFUSED" });
  assert.deepEqual(events.log, []);
  // a genuine state conflict is REFUSED after readiness, with nothing signed and nothing changed
  assert.ok((await coordinator.initialize(command, await signAuthorityInitializationCommand(command, operator.privateKey))).status === "ATTESTED");
  const before = lifecycleState(storage);
  events.log.length = 0;
  const conflicting = initAt("production", T0, "release-other");
  assert.deepEqual(await coordinatorWith({ signer: instrumentSigner(await healthySigner("production"), events), now: scriptedClock(T0 + 20, T0 + 30).now })
    .initialize(conflicting, await signAuthorityInitializationCommand(conflicting, operator.privateKey)), { status: "REFUSED" });
  assert.deepEqual(lifecycleState(storage), before);
  const conflictLog: string[] = events.log as string[];
  assert.ok(conflictLog[0]?.startsWith("ready:"), "a state conflict is discovered after readiness");
  assert.equal(conflictLog.includes("sign"), false);
  storage.close();
});

// -- Freshness boundary: final freshness and appliedMs are taken AFTER signer readiness, with no await before the transaction --
/** Authority clock whose every read is logged into the shared event log. `onRead` runs at the exact read and may move the clock
 * for later reads or queue a microtask probe. */
function loggedClock(events: SignerEvents, start: number, onRead: (index: number, value: number, state: { t: number }) => void = () => {}) {
  const state = { t: start };
  const reads: number[] = [];
  return { state, reads, now: () => {
    const index = reads.length;
    const value = state.t;
    reads.push(value);
    events.log.push(`clock:${value}`);
    onRead(index, value, state);
    return value;
  } };
}
/** Real (instrumented) signer whose readiness is genuinely slow: ready() resolves on a later macrotask, after the Authority clock
 * has advanced. The wrapped signer's own readiness still runs. */
function slowReady(inner: AuthorityAttestationSigner, advance: () => void): AuthorityAttestationSigner {
  return Object.freeze({ ...inner, async ready(nowMs: number) {
    await inner.ready(nowMs);
    await new Promise<void>((resolve) => setImmediate(resolve));
    advance();
  } });
}
const WINDOW = 5 * 60_000;
const noStorageOrSigning = (log: string[]) => log.every((entry) => !entry.startsWith("sql:") && !entry.startsWith("tx:") && entry !== "sign");

test("slow signer readiness cannot carry a stale initialization command into mutation", async () => {
  const { storage, events, operator, coordinatorWith } = await rig("production", [T0]);
  const command = initAt();                       // issued T0: fresh at the preliminary readiness time
  const signature = await signAuthorityInitializationCommand(command, operator.privateKey);
  const clock = loggedClock(events, T0);
  const signer = slowReady(instrumentSigner(await healthySigner("production"), events), () => { clock.state.t += WINDOW + 1; });
  assert.deepEqual(await coordinatorWith({ signer, now: clock.now }).initialize(command, signature), { status: "REFUSED" });
  // exactly: preliminary read, readiness, FINAL read after readiness; then nothing at all
  assert.deepEqual(events.log, [`clock:${T0}`, `ready:${T0}`, `clock:${T0 + WINDOW + 1}`]);
  assert.ok(noStorageOrSigning(events.log), "zero SQL, no transaction, signer.sign never called");
  assert.equal(tableCount(storage), 0, "no schema or table was created");
  assert.deepEqual(lifecycleState(storage), [null, null, null, null], "no meta, release or receipt state");
  storage.close();

  // boundary control: delaying readiness by exactly the freshness window is still fresh, and that later reading is the appliedMs
  const control = await rig("production", [T0]);
  const controlClock = loggedClock(control.events, T0);
  const controlSigner = slowReady(instrumentSigner(await healthySigner("production"), control.events), () => { controlClock.state.t += WINDOW; });
  const accepted = await control.coordinatorWith({ signer: controlSigner, now: controlClock.now })
    .initialize(command, await signAuthorityInitializationCommand(command, control.operator.privateKey));
  assert.ok(accepted.status === "ATTESTED");
  assert.equal(inspectLifecycleAuthority(control.storage, await commandDigest(command), T0 + WINDOW).receipt!.appliedMs, T0 + WINDOW);
  control.storage.close();
});

test("slow signer readiness cannot carry a stale rotation into mutation: issuance freshness and activation eligibility are both re-evaluated", async () => {
  const { storage, events, operator, coordinator, coordinatorWith } = await rig("production", [T0 - 20, T0, T0 + 10]);
  const initial = initAt();
  assert.ok((await coordinator.initialize(initial, await signAuthorityInitializationCommand(initial, operator.privateKey))).status === "ATTESTED");
  const before = lifecycleState(storage);
  const attempt = async (rotation: AuthorityReleaseRotationCommand, start: number, delay: number) => {
    events.log.length = 0;
    const clock = loggedClock(events, start);
    const signer = slowReady(instrumentSigner(await healthySigner("production"), events), () => { clock.state.t += delay; });
    const result = await coordinatorWith({ signer, now: clock.now }).rotate(rotation, await signAuthorityReleaseRotationCommand(rotation, operator.privateKey));
    return { result, log: [...events.log] };
  };
  // (a) issuance freshness: issued T0+500, activates T0+1000; fresh at T0+600, stale after the delay (activation alone would still pass)
  const issuance = await attempt(rotateAt(), T0 + 600, WINDOW);
  assert.deepEqual(issuance.result, { status: "REFUSED" });
  assert.deepEqual(issuance.log, [`clock:${T0 + 600}`, `ready:${T0 + 600}`, `clock:${T0 + 600 + WINDOW}`]);
  assert.ok(Math.abs(T0 + 600 + WINDOW - (T0 + 1_000)) <= WINDOW, "activation alone would have been eligible");
  // (b) activation eligibility: issued T0+WINDOW (still fresh), activates T0+1000; eligible at T0+WINDOW, stale after +1500
  const activation: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "release-a", "release-b", "key-b", T0 + 1_000, T0 + 31_000, T0 + WINDOW, true];
  const eligibility = await attempt(activation, T0 + WINDOW, 1_500);
  assert.deepEqual(eligibility.result, { status: "REFUSED" });
  assert.deepEqual(eligibility.log, [`clock:${T0 + WINDOW}`, `ready:${T0 + WINDOW}`, `clock:${T0 + WINDOW + 1_500}`]);
  assert.ok(Math.abs(T0 + WINDOW + 1_500 - (T0 + WINDOW)) <= WINDOW, "issuance alone would have been fresh");
  for (const outcome of [issuance, eligibility]) assert.ok(noStorageOrSigning(outcome.log), "zero SQL, no transaction, no signing");
  assert.deepEqual(lifecycleState(storage), before, "no second receipt, no release row, no clock mutation");
  assert.equal(receiptCount(storage), 1);
  storage.close();
});

test("appliedMs is the post-readiness Authority reading used by final freshness, and nothing is awaited between that check and the transaction", async () => {
  for (const operation of ["initialize", "rotate"] as const) {
    const { storage, events, operator, coordinator, coordinatorWith } = await rig("production", [T0 - 20, T0, T0 + 10]);
    const initial = initAt();
    if (operation === "rotate") assert.ok((await coordinator.initialize(initial, await signAuthorityInitializationCommand(initial, operator.privateKey))).status === "ATTESTED");
    const base = operation === "initialize" ? T0 : T0 + 600;
    events.log.length = 0;
    // preliminary readiness time = base - 20; readiness advances the clock to `base`; the post-commit read is base + 50.
    // A microtask is queued at the FINAL read: if anything were awaited before the transaction it would run before tx:begin.
    const clock = loggedClock(events, base - 20, (index, _value, state) => {
      if (index === 1) { state.t = base + 50; queueMicrotask(() => events.log.push("microtask-after-final-read")); }
    });
    const signer = slowReady(instrumentSigner(await healthySigner("production"), events), () => { clock.state.t = base; });
    const command = operation === "initialize" ? initial : rotateAt();
    const signature = operation === "initialize" ? await signAuthorityInitializationCommand(initial, operator.privateKey)
      : await signAuthorityReleaseRotationCommand(rotateAt(), operator.privateKey);
    const result = await (operation === "initialize" ? coordinatorWith({ signer, now: clock.now }).initialize(initial, signature)
      : coordinatorWith({ signer, now: clock.now }).rotate(rotateAt(), signature));
    assert.ok(result.status === "ATTESTED", operation);
    // exactly three Authority reads: preliminary (readiness only), final (freshness AND appliedMs), post-commit (observedAtMs)
    assert.deepEqual(clock.reads, [base - 20, base, base + 50], operation);
    const log = events.log;
    const at = (entry: string) => log.indexOf(entry);
    assert.ok(at(`clock:${base - 20}`) < at(`ready:${base - 20}`) && at(`ready:${base - 20}`) < at(`clock:${base}`), "readiness precedes the final reading");
    assert.ok(at(`clock:${base}`) < log.findIndex((entry) => entry.startsWith("sql:")), "no storage before the final reading");
    const commit = at("tx:commit");
    const probe = at("microtask-after-final-read");
    assert.ok(probe > commit, `${operation}: the microtask only ran after the synchronous transaction, so no await sat between final freshness and mutation`);
    assert.ok(log.slice(at(`clock:${base}`) + 1, probe).every((entry) => entry.startsWith("sql:") || entry.startsWith("tx:")),
      `${operation}: between the final reading and the transaction there is only storage work, no signer or clock activity`);
    assert.ok(commit < at("sign") && at("sign") > at(`clock:${base + 50}`), "signing only after commit and the post-commit reading");
    // the stored receipt and the signed statement carry the post-readiness reading, never the preliminary one
    const digest = await commandDigest(command);
    const durable = inspectLifecycleAuthority(storage, digest, base + 100).receipt!;
    assert.equal(durable.appliedMs, base);
    assert.notEqual(durable.appliedMs, base - 20);
    const proof = await verified(result.envelope, lifecycleExpectation("production", digest), base + 200);
    assert.ok(proof.statement.kind === "lifecycle");
    assert.equal(proof.statement.receipt.appliedMs, base);
    assert.equal(proof.statement.observedAtMs, base + 50);
    storage.close();
  }
});

test("legacy executeSignedAuthority* path: no preflight is awaited, and nothing is awaited between final freshness and the transaction", async () => {
  const operator = await keys();
  for (const operation of ["initialize", "rotate"] as const) {
    const events: SignerEvents = { log: [] };
    const base = new NodeSqliteDurableStorage();
    const storage = instrumentStorage(base, events);
    if (operation === "rotate") {
      const initial = initAt();
      await executeSignedAuthorityInitialization(base, initial, await signAuthorityInitializationCommand(initial, operator.privateKey), operator.publicKey, T0, "production", () => T0);
    }
    const finalNow = () => { events.log.push("final-read"); queueMicrotask(() => events.log.push("microtask-after-final-read")); return operation === "initialize" ? T0 : T0 + 600; };
    const outcome = operation === "initialize"
      ? await executeSignedAuthorityInitialization(storage, initAt(), await signAuthorityInitializationCommand(initAt(), operator.privateKey), operator.publicKey, 0, "production", finalNow)
      : await executeSignedAuthorityReleaseRotation(storage, rotateAt(), await signAuthorityReleaseRotationCommand(rotateAt(), operator.privateKey), operator.publicKey, 0, "production", finalNow);
    assert.ok(outcome.status === "initialized" || outcome.status === "rotated");
    assert.equal(outcome.receipt?.appliedMs, operation === "initialize" ? T0 : T0 + 600);
    const log = events.log;
    assert.ok(log.indexOf("final-read") >= 0 && log.indexOf("microtask-after-final-read") > log.indexOf("tx:commit"), `${operation}: no await between final freshness and the transaction`);
    assert.ok(log.slice(log.indexOf("final-read") + 1, log.indexOf("microtask-after-final-read")).every((entry) => entry.startsWith("sql:") || entry.startsWith("tx:")));
    base.close();
  }
});

test("no fallback clock: the coordinator's command-layer clock default is NaN, which fails freshness closed and is never time zero", async () => {
  // source guard: the dummy `0` positional clock is gone from the coordinator
  const source = await readFile(new URL("../workers/admission-service/authority-attestation.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /operatorPublicKey, 0,/u);
  assert.match(source, /const NO_FALLBACK_CLOCK = Number\.NaN;/u);
  // behavior: with no finalNow supplied the NaN sentinel refuses even a command issued at time 0 (0 would have accepted it), with zero SQL
  const operator = await keys();
  for (const operation of ["initialize", "rotate"] as const) {
    const events: SignerEvents = { log: [] };
    const base = new NodeSqliteDurableStorage();
    const storage = instrumentStorage(base, events);
    const epoch0Init = initAt("production", 0);
    const epoch0Rotate = rotateAt(-500);               // issued 0, activates 500: valid schema, acceptable only to a zero clock
    await assert.rejects(operation === "initialize"
      ? executeSignedAuthorityInitialization(storage, epoch0Init, await signAuthorityInitializationCommand(epoch0Init, operator.privateKey), operator.publicKey, Number.NaN)
      : executeSignedAuthorityReleaseRotation(storage, epoch0Rotate, await signAuthorityReleaseRotationCommand(epoch0Rotate, operator.privateKey), operator.publicKey, Number.NaN),
    /operator-command-freshness/u);
    assert.deepEqual(events.log, [], `${operation}: zero SQL`);
    assert.equal(tableCount(base), 0);
    base.close();
  }
  // coordinator-level: an invalid Authority clock never reads as time zero
  const invalidFinal = await rig("production", [T0]);
  const command = initAt();
  assert.deepEqual(await invalidFinal.coordinatorWith({ signer: invalidFinal.signer, now: scriptedClock(T0, Number.NaN).now })
    .initialize(command, await signAuthorityInitializationCommand(command, invalidFinal.operator.privateKey)), { status: "REFUSED" });
  assert.ok(noStorageOrSigning(invalidFinal.events.log));
  assert.equal(tableCount(invalidFinal.storage), 0);
  const invalidPreliminary = await rig("production", [T0]);
  assert.deepEqual(await invalidPreliminary.coordinatorWith({ signer: invalidPreliminary.signer, now: scriptedClock(Number.NaN).now })
    .initialize(command, await signAuthorityInitializationCommand(command, invalidPreliminary.operator.privateKey)), { status: "UNAVAILABLE", reason: "authority-clock-invalid" });
  assert.deepEqual(invalidPreliminary.events.log, [], "no readiness, no storage, no signing");
  invalidFinal.storage.close(); invalidPreliminary.storage.close();
});

test("signer: frozen, pinned, no key text on any property, byte-identical to the frozen signer, strict about readiness and statements", async () => {
  const production = await healthySigner("production");
  const staging = await healthySigner("staging");
  const material = await rfcKeys();
  assert.ok(Object.isFrozen(production));
  assert.deepEqual(Object.keys(production).sort(), ["authorityId", "environment", "policyEpoch", "ready", "sign", "writerKeyFingerprint"]);
  assert.equal(production.writerKeyFingerprint, material.production.fingerprint);
  assert.equal(staging.authorityId, STAGING_ADMISSION_AUTHORITY_ID);
  assert.equal(JSON.stringify(production).includes(material.production.privateKeyPkcs8), false);
  const statement = makeLifecycleStatement({ trustEpoch: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    digest: "d".repeat(64), observedAtMs: T0 + 5, writerKeyFingerprint: production.writerKeyFingerprint,
    receipt: { digest: "d".repeat(64), version: 1, operation: "initialize", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, operatorKeyFingerprint: "e".repeat(64), sequence: 1, appliedMs: T0, currentReleaseId: "release-a",
      nextReleaseId: "release-a", nextKeyId: "key-a", activatesMs: T0, retiresMs: null } });
  await assert.rejects(production.sign(statement), /attestation-signer-not-ready/u, "sign before ready");
  await assert.rejects(production.ready(Number.NaN), /attestation-signer-not-ready/u);
  await assert.rejects(production.ready(-1), /attestation-signer-not-ready/u);
  await Promise.all([production.ready(T0), production.ready(T0)]);
  const bytes = await production.sign(statement);
  const frozen = encodeResultAttestationEnvelope(await signResultAttestation(statement, { privateKey: material.production.privateKeyPkcs8, publicKey: material.production.publicKey }));
  assert.deepEqual(Buffer.from(bytes), Buffer.from(frozen), "Ed25519 is deterministic: byte-identical to the frozen Slice-1 signer");
  assert.equal(parseResultAttestationEnvelope(bytes).statement.writerKeyFingerprint, production.writerKeyFingerprint);
  // not interchangeable: the staging signer refuses a Production statement; the Production signer refuses a foreign writer fingerprint
  await staging.ready(T0);
  await assert.rejects(staging.sign(statement), /attestation-signer-statement/u);
  await assert.rejects(production.sign({ ...statement, writerKeyFingerprint: material.staging.fingerprint }), /attestation-signer-statement/u);
  await assert.rejects(production.sign({ ...statement, digest: "nope" } as never), /attestation-statement/u);
  // configuration shape errors are synchronous and bounded
  assert.throws(() => createAuthorityAttestationSigner({ environment: "production", writerKeyFingerprint: "x", privateKey: "a", publicKey: "b" }), /attestation-signer-config/u);
  assert.throws(() => createAuthorityAttestationSigner({ environment: "dev" as never, writerKeyFingerprint: material.production.fingerprint, privateKey: "a", publicKey: "b" }), /attestation-signer-config/u);
  assert.throws(() => createAuthorityAttestationSigner({ environment: "production", writerKeyFingerprint: material.production.fingerprint, privateKey: 1 as never, publicKey: "b" }), /attestation-signer-config/u);
});

// -- Durable Object adapters: the REAL ProductionAdmissionAuthority / StagingAdmissionAuthority classes, bundled for node ----
type AdmissionIndex = typeof import("../workers/admission-service/index");
let admission: AdmissionIndex;
before(async () => {
  const bundled = await build({ entryPoints: [resolve("workers/admission-service/index.ts")], bundle: true, write: false,
    platform: "node", format: "esm", target: "node24", plugins: [{ name: "local-do-base", setup(api) {
      api.onResolve({ filter: /^cloudflare:workers$/ }, () => ({ path: "local-do-base", namespace: "test" }));
      api.onLoad({ filter: /.*/, namespace: "test" }, () => ({ contents: "export class DurableObject { constructor(state, env) { this.ctx = state; this.env = env; } } export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }", loader: "js" }));
    } }] });
  admission = await import(`data:text/javascript;base64,${Buffer.from(bundled.outputFiles[0].contents).toString("base64")}`) as AdmissionIndex;
});

test("DO adapters: attested methods are inert without a signer, active v1 methods are unchanged, and staging has no rotation attestation", async () => {
  const operator = await keys();
  const environment = { AUTHORITY_OPERATOR_PUBLIC_KEY: operator.publicKey } as never;
  const now = Date.now();
  const command = initAt("production", now);
  const signature = await signAuthorityInitializationCommand(command, operator.privateKey);

  // deployed posture: the Durable Object runtime never passes a signer, so every attested method is UNAVAILABLE and storage-free
  const bareStorage = new NodeSqliteDurableStorage();
  const bare = new admission.ProductionAdmissionAuthority({ storage: bareStorage } as never, environment);
  assert.deepEqual(await bare.initializeFromOperatorAttested(command, signature), { status: "UNAVAILABLE", reason: "signer-unconfigured" });
  assert.deepEqual(await bare.attestAppliedLifecycle("a".repeat(64)), { status: "UNAVAILABLE", reason: "signer-unconfigured" });
  assert.deepEqual(await bare.attestReconciliation("a".repeat(64), NONCE), { status: "UNAVAILABLE", reason: "signer-unconfigured" });
  assert.equal(tableCount(bareStorage), 0);
  // the active v1 method keeps its exact contract: status + receipt only, no envelope; replay is unchanged
  const legacy = await bare.initializeFromOperator(command, signature) as { status: string; receipt?: unknown };
  assert.equal(legacy.status, "initialized");
  assert.deepEqual(Object.keys(legacy).sort(), ["receipt", "status"]);
  assert.equal((await bare.initializeFromOperator(command, signature) as { status: string }).status, "already-initialized");
  assert.deepEqual(await bare.initializeFromOperatorAttested(command, signature), { status: "UNAVAILABLE", reason: "signer-unconfigured" });
  bareStorage.close();

  // injected runtime on the real Production class: initialize and rotate, verifying under the Production trust key
  const productionStorage = new NodeSqliteDurableStorage();
  const production = new admission.ProductionAdmissionAuthority({ storage: productionStorage } as never, environment,
    { signer: await healthySigner("production"), now: scriptedClock(now, now + 5).now });
  const attested = await production.initializeFromOperatorAttested(command, signature);
  assert.ok(attested.status === "ATTESTED" && attested.relayDisposition === "APPLIED");
  await verified(attested.envelope, lifecycleExpectation("production", await commandDigest(command)), now + 100);
  const rotation = rotateAt(now);
  const rotating = new admission.ProductionAdmissionAuthority({ storage: productionStorage } as never, environment,
    { signer: await healthySigner("production"), now: scriptedClock(now + 600, now + 610).now });
  const rotated = await rotating.rotateReleaseFromOperatorAttested(rotation, await signAuthorityReleaseRotationCommand(rotation, operator.privateKey));
  assert.ok(rotated.status === "ATTESTED" && rotated.relayDisposition === "APPLIED");
  await verified(rotated.envelope, lifecycleExpectation("production", await commandDigest(rotation)), now + 700);
  productionStorage.close();

  // the real staging class: initialize attests under the staging key; there is no rotation attestation method
  const stagingStorage = new NodeSqliteDurableStorage();
  const staging = new admission.StagingAdmissionAuthority({ storage: stagingStorage } as never, environment,
    { signer: await healthySigner("staging"), now: scriptedClock(now, now + 5).now });
  const stagingCommand = initAt("staging", now);
  const stagingResult = await staging.initializeFromOperatorAttested(stagingCommand, await signAuthorityInitializationCommand(stagingCommand, operator.privateKey));
  assert.ok(stagingResult.status === "ATTESTED");
  await verified(stagingResult.envelope, lifecycleExpectation("staging", await commandDigest(stagingCommand)), now + 100);
  assert.equal("rotateReleaseFromOperatorAttested" in staging, false);
  assert.deepEqual(await staging.rotateReleaseFromOperator(), { status: "refused" });
  stagingStorage.close();

  // a wrong-environment signer injected into the real Production class is refused before any storage access
  const crossStorage = new NodeSqliteDurableStorage();
  const crossed = new admission.ProductionAdmissionAuthority({ storage: crossStorage } as never, environment, { signer: await healthySigner("staging") });
  assert.deepEqual(await crossed.initializeFromOperatorAttested(command, signature), { status: "UNAVAILABLE", reason: "signer-mismatch" });
  assert.equal(tableCount(crossStorage), 0);
  crossStorage.close();

  // no service-binding entrypoint exposes any attested method
  for (const entrypoint of [admission.AdmissionServiceWorker, admission.AuthorityLifecycleOnly, admission.AuthorityLifecycleReadOnly,
    admission.StagingAuthorityLifecycleOnly, admission.StagingAuthorityLifecycleReadOnly]) {
    for (const method of ["initializeFromOperatorAttested", "rotateReleaseFromOperatorAttested", "attestAppliedLifecycle", "attestReconciliation",
      "initializeAuthorityFromOperatorAttested", "rotateAuthorityReleaseFromOperatorAttested"]) {
      assert.equal(method in entrypoint.prototype, false, `${entrypoint.name}.${method}`);
    }
  }
});
