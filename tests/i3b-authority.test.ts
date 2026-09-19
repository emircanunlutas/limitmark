import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "../operator/lifecycle-observation";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, inspectLifecycleAuthority, type DurableStorageLike } from "../workers/admission-service/authority";
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
