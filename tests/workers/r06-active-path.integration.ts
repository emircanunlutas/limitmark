import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { join, resolve, sep } from "node:path";
import { encodeResultAttestationEnvelope, parseResultAttestationEnvelope, attestationKeyFingerprint } from "../../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest, verifyAuthoritySignedStatement } from "../../src/lib/authority-result-trust";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { createAuthoritySchema, ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand, signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand, type AuthorityReleaseRotationCommand } from "../../workers/admission-service/operator-command";
import { readProductionAuthorityResult, readStagingAuthorityResult, type AuthorityReadOutcome } from "../../operator/authority-result-reader";
import { authenticateSealedLifecycleArtifact, type AuthenticatedLifecycleCommand } from "../../operator/lifecycle-submitter";
import { STAGING_GATE7_CONTINUITY } from "../../operator/staging-gate7-continuity";
import { SIGNED_RESULT_METADATA } from "../../workers/lifecycle-mailbox/wire";
import { rfcKeys, trustManifestText, trustManifest } from "../support/authority-result-fixtures";
import { createCliResultHarness } from "./support/i3b-cli-result-harness";
import { Rig, removeRuntime, type SignerMode } from "./support/r06-active-rig";

/**
 * R06 SLICE 2C -- the REAL activated chain on local workerd (see tests/workers/support/r06-active-rig.ts). Local resources only: no provider
 * contact, no remote Wrangler, no operational key (the Authority signs with the frozen RFC 8032 TEST vectors supplied through the same
 * binding names a deployment would use).
 *
 *  A  Production initialize  : sealed command -> mailbox -> guard -> executor -> Authority(signed APPLIED) -> R2 -> reader POSITIVE with the command
 *  B  Production rotate      : same, for rotate-release
 *  C  Staging                : real chain => signed, but NOT positive without the Gate 7 pins; Gate 7 canonical state => signed evidence + pins => POSITIVE
 *  D  Reconciliation         : caller nonce -> observer -> Authority attestReconciliation -> R2 -> reader checks that nonce
 *  E  Post-commit sign fault : AMBIGUOUS (never REFUSED), no duplicate mutation, recovery by signed reconciliation and by command replay
 *  F  Signer unavailable     : absent / malformed / wrong-environment / not-ready signer => UNAVAILABLE before any mutation, nothing positive
 *  G  Hostile storage        : every tampered, stale, swapped or unsigned stored object => never POSITIVE
 */
const root = process.cwd();
const testsRoot = resolve(root, ".wrangler", "tests");
const runtimeRoot = join(testsRoot, `r06-active-${process.pid}-${randomUUID()}`);
process.env.WRANGLER_SEND_METRICS = "false";
for (const name of Object.keys(process.env)) if (/^(CLOUDFLARE_|CF_)/iu.test(name)) delete process.env[name];

const text = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const NONCE = (character: string) => character.repeat(32);
const isSigned = (metadata: Record<string, string> | undefined) => metadata?.limitmarkResult === SIGNED_RESULT_METADATA.limitmarkResult;

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(testsRoot + sep), "runtime root is isolated under .wrangler/tests");
  const cli = await createCliResultHarness();
  const operator = { privateKey: cli.privateKey, publicKey: cli.publicKey };
  const manifest = await trustManifest();
  const live: Rig[] = [];
  const start = async (role: "production" | "staging", state: string, options: { signer?: SignerMode; dropAck?: boolean; operatorPublicKey?: string; admissionBindingOverrides?: Record<string, string | undefined> } = {}) => {
    const rig = await Rig.start({ role, operatorPublicKey: options.operatorPublicKey ?? operator.publicKey, runtimeRoot, state, signer: options.signer,
      dropAck: options.dropAck, admissionBindingOverrides: options.admissionBindingOverrides });
    live.push(rig);
    return rig;
  };
  const read = (kind: "lifecycle" | "reconciliation", digest: string, bytes: Uint8Array, command?: AuthenticatedLifecycleCommand, options: { nonce?: string; nowMs?: number; trust?: typeof manifest } = {}) =>
    readProductionAuthorityResult({ kind, digest, ...(kind === "reconciliation" ? { nonce: options.nonce ?? "" } : {}), bytes, trustManifest: options.trust ?? manifest,
      nowMs: options.nowMs ?? Date.now(), ...(command ? { authenticatedCommand: command } : {}) });
  const notPositive = (outcome: AuthorityReadOutcome, label: string) => {
    assert.notEqual(outcome.status, "POSITIVE", `FALSE POSITIVE: ${label}`);
    assert.ok(outcome.status === "UNCONFIRMED" || outcome.status === "VERIFIED_NON_POSITIVE", label);
  };
  const sealedInit = async (release: string, key: string, issuedAtMs = Date.now()) => {
    const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, key, issuedAtMs, true];
    const artifact = { command, signature: await signAuthorityInitializationCommand(command, operator.privateKey) };
    const bytes = text(artifact);
    return { command, artifact, bytes, digest: await commandDigest(command), authenticated: await authenticateSealedLifecycleArtifact(bytes, operator.publicKey) };
  };
  try {
    await Rig.bundle(runtimeRoot, "production");
    await Rig.bundle(runtimeRoot, "staging");

    // ====================================================================================================================================
    // A + B + D : Production active path
    // ====================================================================================================================================
    const prod = await start("production", "prod-main");
    const A = await sealedInit("r06-current", "r06-key");
    await prod.put("initialize.json", A.artifact);
    await prod.scheduled("mailbox");
    assert.deepEqual(await prod.counts(), [1, 1], "one executor dispatch and one Authority mutation");
    assert.equal((await prod.authoritySql("SELECT * FROM lifecycle_receipts")).length, 1);
    assert.deepEqual(await prod.guardSql("SELECT digest,status FROM claims"), [{ digest: A.digest, status: "SUCCESS" }], "relay-local ledger note");
    const lifecycleA = await prod.result(`lifecycle/${A.digest}.json`);
    assert.ok(lifecycleA, "the signed result was stored");
    assert.ok(isSigned(await prod.resultMetadata(`lifecycle/${A.digest}.json`)), "stored as signed-envelope bytes (non-authoritative marker)");
    // The stored object IS the Authority's canonical envelope: strict-parse + canonical re-encode round-trips to the same bytes, so no relay hop
    // re-serialized, wrapped, annotated or otherwise altered it.
    assert.deepEqual(encodeResultAttestationEnvelope(parseResultAttestationEnvelope(lifecycleA)), lifecycleA);
    const verifiedA = await verifyAuthoritySignedStatement(lifecycleA, { kind: "lifecycle", environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, digest: A.digest }, manifest, Date.now());
    assert.equal(verifiedA.statement.kind === "lifecycle" && verifiedA.statement.writerKeyFingerprint, (await rfcKeys()).production.fingerprint, "signed by the Production writer key only");
    const positiveA = await read("lifecycle", A.digest, lifecycleA, A.authenticated);
    assert.equal(positiveA.status, "POSITIVE", JSON.stringify(positiveA));
    assert.equal((positiveA as { receipt: { digest: string } }).receipt.digest, A.digest);
    const withoutCommand = await read("lifecycle", A.digest, lifecycleA);
    assert.deepEqual([withoutCommand.status, (withoutCommand as { observation: string }).observation], ["VERIFIED_NON_POSITIVE", "COMMAND_CONTEXT_REQUIRED"], "R06 alone is never Production positive");
    // the actual CLI over the actual stored bytes
    const cliA = await cli.run(lifecycleA, "lifecycle", A.digest, undefined, A.bytes);
    assert.equal(cliA.exitCode, 0, `${cliA.stderr}${cliA.stdout}`);
    assert.equal((JSON.parse(cliA.stdout) as { status: string }).status, "POSITIVE");
    assert.equal((await cli.run(lifecycleA, "lifecycle", A.digest)).exitCode, 3, "no command => non-positive CLI exit");

    // D: reconciliation nonce flow through the real observer
    const nonceD = NONCE("d");
    const beforeReads = await prod.authorityTables();
    const reconciliationD = await prod.reconcile(A.digest, nonceD);
    assert.ok(reconciliationD);
    assert.deepEqual(encodeResultAttestationEnvelope(parseResultAttestationEnvelope(reconciliationD)), reconciliationD, "observer relayed the exact canonical bytes");
    const positiveD = await read("reconciliation", A.digest, reconciliationD, A.authenticated, { nonce: nonceD });
    assert.equal(positiveD.status, "POSITIVE", JSON.stringify(positiveD));
    notPositive(await read("reconciliation", A.digest, reconciliationD, A.authenticated, { nonce: NONCE("e") }), "reconciliation envelope read with another nonce");
    assert.deepEqual(await prod.authorityTables(), beforeReads, "signed reconciliation is read-only");
    assert.deepEqual(await prod.counts(), [1, 1], "reconciliation dispatched nothing");
    const synthetic = "5".repeat(64);
    const notFound = await prod.reconcile(synthetic, NONCE("f"));
    const notFoundOutcome = await read("reconciliation", synthetic, notFound!, undefined, { nonce: NONCE("f") });
    assert.deepEqual([notFoundOutcome.status, (notFoundOutcome as { observation: string }).observation], ["VERIFIED_NON_POSITIVE", "NOT_FOUND"]);

    // B: Production rotation. A signed APPLIED does NOT bypass settlement: the supervisor latch stays held until settlement observes the exact receipt.
    assert.equal((await prod.guardSql("SELECT * FROM latch")).length, 1, "signed APPLIED did not release the latch");
    assert.equal(await prod.settle(A.digest, NONCE("1")), true, "settlement stays independent: exact receipt releases only the latch");
    assert.equal((await prod.guardSql("SELECT * FROM latch")).length, 0);
    const activatesAtMs = Date.now() + 1_000;
    const rotation: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH,
      "r06-current", "r06-next", "r06-next-key", activatesAtMs, activatesAtMs + 30_000, Date.now(), true];
    const rotationArtifact = { command: rotation, signature: await signAuthorityReleaseRotationCommand(rotation, operator.privateKey) };
    const rotationBytes = text(rotationArtifact);
    const rotationDigest = await commandDigest(rotation);
    await prod.put("rotate-release.json", rotationArtifact);
    await prod.scheduled("mailbox");
    assert.deepEqual(await prod.counts(), [2, 2]);
    assert.equal((await prod.authoritySql("SELECT * FROM lifecycle_receipts")).length, 2);
    const lifecycleB = await prod.result(`lifecycle/${rotationDigest}.json`);
    assert.ok(lifecycleB);
    const rotationCommand = await authenticateSealedLifecycleArtifact(rotationBytes, operator.publicKey);
    const positiveB = await read("lifecycle", rotationDigest, lifecycleB, rotationCommand);
    assert.equal(positiveB.status, "POSITIVE", JSON.stringify(positiveB));
    assert.equal((positiveB as { receipt: { operation: string } }).receipt.operation, "rotate-release");
    assert.equal((await cli.run(lifecycleB, "lifecycle", rotationDigest, undefined, rotationBytes)).exitCode, 0);
    // the init envelope cannot vouch for the rotation and vice versa
    notPositive(await read("lifecycle", rotationDigest, lifecycleA, rotationCommand), "init envelope for the rotation digest");
    notPositive(await read("lifecycle", A.digest, lifecycleB, A.authenticated), "rotation envelope for the init digest");

    // ====================================================================================================================================
    // C : staging
    // ====================================================================================================================================
    const stagingOperator = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const stagingOperatorPublic = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", stagingOperator.publicKey)));
    const stagingOperatorPrivate = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", stagingOperator.privateKey)));
    const stag = await start("staging", "stag-main", { operatorPublicKey: stagingOperatorPublic });
    const stagingCommand: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH,
      "i3b-current", "staging-key", Date.now(), false];
    const stagingDigest = await commandDigest(stagingCommand);
    await stag.put("initialize.json", { command: stagingCommand, signature: await signAuthorityInitializationCommand(stagingCommand, stagingOperatorPrivate) });
    await stag.scheduled("mailbox");
    assert.deepEqual(await stag.counts(), [1, 1]);
    const stagingLifecycle = await stag.result(`lifecycle/${stagingDigest}.json`);
    assert.ok(stagingLifecycle);
    const stagingVerified = await verifyAuthoritySignedStatement(stagingLifecycle, { kind: "lifecycle", environment: "staging", authorityId: STAGING_ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, digest: stagingDigest }, manifest, Date.now());
    assert.equal(stagingVerified.statement.kind === "lifecycle" && stagingVerified.statement.writerKeyFingerprint, (await rfcKeys()).staging.fingerprint, "signed by the STAGING writer key");
    const stagingOutcome = await readStagingAuthorityResult({ kind: "lifecycle", digest: stagingDigest, bytes: stagingLifecycle, trustManifest: manifest, nowMs: Date.now() });
    assert.deepEqual([stagingOutcome.status, (stagingOutcome as { reason: string }).reason], ["UNCONFIRMED", "result-contract"], "a valid staging signature alone is not staging positive: the Gate 7 pins also bind");
    // staging rotation stays impossible on the active path
    await stag.put("rotate-release.json", { command: ["garbage"], signature: "x" });
    await stag.scheduled("mailbox");
    assert.equal((await stag.guardSql("SELECT * FROM claims")).length, 1, "no rotation claim");

    // Gate 7 canonical state: the live staging Authority's committed state, seeded into a fresh local staging Authority
    const gate7 = await start("staging", "stag-gate7", { operatorPublicKey: stagingOperatorPublic });
    const ddl: string[] = [];
    createAuthoritySchema({ sql: { exec: (query: string) => { ddl.push(query); return []; } }, transactionSync: <T>(callback: () => T) => callback() });
    for (const statement of ddl) await gate7.authoritySql(statement);
    const g = STAGING_GATE7_CONTINUITY.receipt;
    await gate7.authoritySql(`INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'${g.authorityId}','${g.policyEpoch}',${g.appliedMs})`);
    await gate7.authoritySql(`INSERT INTO active_releases(release_id,key_id,activated_ms,retired_ms) VALUES('${g.currentReleaseId}','${g.nextKeyId}',${g.activatesMs},NULL)`);
    await gate7.authoritySql("INSERT INTO lifecycle_receipt_coverage(singleton,complete) VALUES(1,1)");
    await gate7.authoritySql(`INSERT INTO lifecycle_receipts(digest,schema_version,operation,environment,authority_id,policy_epoch,key_fingerprint,sequence,applied_ms,current_release_id,next_release_id,next_key_id,activates_ms,retires_ms) VALUES('${g.digest}',1,'${g.operation}','${g.environment}','${g.authorityId}','${g.policyEpoch}','${g.keyFingerprint}',${g.sequence},${g.appliedMs},'${g.currentReleaseId}','${g.nextReleaseId}','${g.nextKeyId}',${g.activatesMs},NULL)`);
    const gate7Nonce = NONCE("7");
    const gate7Bytes = await gate7.reconcile(g.digest, gate7Nonce);
    assert.ok(gate7Bytes);
    const gate7Outcome = await readStagingAuthorityResult({ kind: "reconciliation", digest: g.digest, nonce: gate7Nonce, bytes: gate7Bytes, trustManifest: manifest, nowMs: Date.now() });
    assert.equal(gate7Outcome.status, "POSITIVE", JSON.stringify(gate7Outcome));
    assert.equal((gate7Outcome as { receipt: { operatorKeyFingerprint: string } }).receipt.operatorKeyFingerprint, STAGING_GATE7_CONTINUITY.receipt.keyFingerprint);
    // a staging statement is never Production evidence, and a Production statement is never staging evidence
    notPositive(await read("reconciliation", g.digest, gate7Bytes, undefined, { nonce: gate7Nonce }), "staging envelope read by the Production reader");
    notPositive(await readStagingAuthorityResult({ kind: "lifecycle", digest: A.digest, bytes: lifecycleA, trustManifest: manifest, nowMs: Date.now() }), "Production envelope read by the staging reader");

    // ====================================================================================================================================
    // E : AMBIGUOUS post-commit signing failure
    // ====================================================================================================================================
    const ambiguous = await start("production", "prod-ambiguous");
    await ambiguous.fault("sign");
    const E = await sealedInit("e-current", "e-key");
    await ambiguous.put("initialize.json", E.artifact);
    await ambiguous.scheduled("mailbox");
    assert.deepEqual(await ambiguous.counts(), [1, 1]);
    assert.equal((await ambiguous.authoritySql("SELECT * FROM lifecycle_receipts")).length, 1, "the transaction committed and was NOT rolled back");
    assert.deepEqual(await ambiguous.guardSql("SELECT status FROM claims"), [{ status: "UNCONFIRMED" }], "never recorded as REFUSED");
    const ambiguousResult = await ambiguous.result(`lifecycle/${E.digest}.json`);
    assert.ok(ambiguousResult, "an explicit unsigned diagnostic was stored");
    assert.equal(isSigned(await ambiguous.resultMetadata(`lifecycle/${E.digest}.json`)), false);
    const diagnostic = JSON.parse(new TextDecoder().decode(ambiguousResult)) as { status: string; reason: string };
    assert.deepEqual([diagnostic.status, diagnostic.reason], ["UNCONFIRMED", "attestation-ambiguous"]);
    assert.deepEqual(await read("lifecycle", E.digest, ambiguousResult, E.authenticated), { status: "UNCONFIRMED", environment: "production", kind: "lifecycle", digest: E.digest,
      reason: "no-signed-evidence", relayStatus: "UNCONFIRMED" });
    assert.equal((await cli.run(ambiguousResult, "lifecycle", E.digest, undefined, E.bytes)).exitCode, 3, "caller sees a non-positive exit");
    // signing still failing: the replay's signed read is UNAVAILABLE (not a refusal, not a mutation); nothing new is stored or dispatched
    await ambiguous.scheduled("mailbox");
    assert.deepEqual(await ambiguous.counts(), [1, 1], "no duplicate mutation while signing is down");
    assert.equal(isSigned(await ambiguous.resultMetadata(`lifecycle/${E.digest}.json`)), false);
    assert.equal((await ambiguous.reconcile(E.digest, NONCE("2")))?.length !== undefined, true);
    const stillDown = await ambiguous.result(`reconciliation/${NONCE("2")}.json`);
    assert.equal((await read("reconciliation", E.digest, stillDown!, E.authenticated, { nonce: NONCE("2") })).status, "UNCONFIRMED", "no signed evidence while signing is down");
    // recovery 1: a fresh-nonce signed reconciliation
    await ambiguous.fault("none");
    const recovered = await ambiguous.reconcile(E.digest, NONCE("3"));
    assert.equal((await read("reconciliation", E.digest, recovered!, E.authenticated, { nonce: NONCE("3") })).status, "POSITIVE", "signed EXACT_RECEIPT recovers the ambiguous commit");
    // recovery 2: the command replay gets signed APPLIED evidence WITHOUT mutating again
    await ambiguous.scheduled("mailbox");
    assert.deepEqual(await ambiguous.counts(), [1, 1], "replay performed no second mutation");
    assert.equal((await ambiguous.authoritySql("SELECT * FROM lifecycle_receipts")).length, 1);
    assert.ok(isSigned(await ambiguous.resultMetadata(`lifecycle/${E.digest}.json`)), "the signed result replaced the unsigned diagnostic");
    const replayed = await ambiguous.result(`lifecycle/${E.digest}.json`);
    assert.equal((await read("lifecycle", E.digest, replayed!, E.authenticated)).status, "POSITIVE");
    assert.equal((await cli.run(replayed!, "lifecycle", E.digest, undefined, E.bytes)).exitCode, 0);

    // ====================================================================================================================================
    // F : signer unavailable BEFORE any mutation (through the active path)
    // ====================================================================================================================================
    const unavailableCases: Array<{ role: "production" | "staging"; mode: SignerMode | "not-ready"; label: string }> = [
      { role: "production", mode: "absent", label: "Production, no signer binding (no test-key fallback)" },
      { role: "production", mode: "malformed-fingerprint", label: "Production, malformed fingerprint pin" },
      { role: "production", mode: "other-environment", label: "Production using the STAGING signer" },
      { role: "production", mode: "both-environments", label: "Production holding both environments' signer material" },
      { role: "staging", mode: "other-environment", label: "staging using the PRODUCTION signer" },
      { role: "production", mode: "not-ready", label: "Production, signer present but not ready" },
    ];
    let caseIndex = 0;
    for (const entry of unavailableCases) {
      const rig = await start(entry.role, `unavailable-${caseIndex++}`, { signer: entry.mode === "not-ready" ? "rfc" : entry.mode,
        operatorPublicKey: entry.role === "production" ? operator.publicKey : stagingOperatorPublic });
      if (entry.mode === "not-ready") await rig.fault("ready");
      const command: AuthorityInitializationCommand = entry.role === "production"
        ? [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "u-current", "u-key", Date.now(), true]
        : [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "u-current", "u-key", Date.now(), false];
      const signature = await signAuthorityInitializationCommand(command, entry.role === "production" ? operator.privateKey : stagingOperatorPrivate);
      const digest = await commandDigest(command);
      const tablesBefore = await rig.authorityTables();
      await rig.put("initialize.json", { command, signature });
      await rig.scheduled("mailbox");
      assert.deepEqual(await rig.counts(), [0, 0], `${entry.label}: the guard's signed probe stops it before any claim or dispatch`);
      assert.equal((await rig.guardSql("SELECT * FROM claims")).length, 0, `${entry.label}: no claim consumed`);
      assert.equal((await rig.guardSql("SELECT * FROM latch")).length, 0, `${entry.label}: no latch held`);
      assert.equal(await rig.result(`lifecycle/${digest}.json`), null, `${entry.label}: no result (and no manufactured REFUSED)`);
      assert.deepEqual(await rig.authorityTables(), tablesBefore, `${entry.label}: no receipt, release or meta mutation`);
      // the Authority's own answer, seen through the real executor + service-binding hops (bypassing the guard)
      const direct = await (await rig.mf.getWorker("driver")).fetch("http://localhost/executor-initialize", { method: "POST", body: JSON.stringify({ command, signature }) });
      const directBody = await direct.json() as { status: string; reason?: string };
      assert.equal(directBody.status, "UNAVAILABLE", `${entry.label}: ${JSON.stringify(directBody)}`);
      assert.deepEqual(await rig.authorityTables(), tablesBefore, `${entry.label}: the direct attempt mutated nothing`);
      // reconciliation without a signer is an unsigned diagnostic, never signed and never positive
      const reconciled = await rig.reconcile(digest, NONCE("9"));
      assert.ok(reconciled);
      assert.equal(new TextDecoder().decode(reconciled).includes('"statement"'), false, `${entry.label}: nothing signed`);
      assert.equal((JSON.parse(new TextDecoder().decode(reconciled)) as { status: string }).status, "UNAVAILABLE");
      await rig.dispose(); live.splice(live.indexOf(rig), 1);
    }

    // ====================================================================================================================================
    // F2 : CLAIM-BURN REGRESSION. A HEALTHY signer beside an invalid runtime-secret configuration. The mutation entrypoint fails the
    //      runtime-secret gate deterministically, so before the read-only gate the signed pre-claim probe answered "receipt-not-found",
    //      the guard consumed the claim + latch, and the mutation then failed: a permanent wedge. The read-only entrypoints now fail the
    //      SAME gate, so the probe is UNAVAILABLE and nothing is consumed. (A signer failure strictly AFTER a successful probe is a
    //      different, narrow, transient residual that this deterministic check does not claim to remove.)
    // ====================================================================================================================================
    const configCases: Array<{ role: "production" | "staging"; overrides: Record<string, string | undefined>; label: string }> = [
      { role: "production", overrides: { ADMISSION_CURRENT_RPC_KEY: undefined }, label: "Production: required ADMISSION_CURRENT_RPC_KEY missing" },
      { role: "production", overrides: { ADMISSION_RELEASE_RPC_KEY: "forbidden" }, label: "Production: forbidden ADMISSION_RELEASE_RPC_KEY present" },
      { role: "staging", overrides: { ADMISSION_CURRENT_RPC_KEY: undefined }, label: "staging: required ADMISSION_CURRENT_RPC_KEY missing" },
      { role: "staging", overrides: { AUTHORITY_OPERATOR_PRIVATE_KEY: "forbidden" }, label: "staging: forbidden operator private key present" },
    ];
    let configIndex = 0;
    for (const entry of configCases) {
      const rig = await start(entry.role, `config-mismatch-${configIndex++}`, { admissionBindingOverrides: entry.overrides,
        operatorPublicKey: entry.role === "production" ? operator.publicKey : stagingOperatorPublic });
      const command: AuthorityInitializationCommand = entry.role === "production"
        ? [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "c-current", "c-key", Date.now(), true]
        : [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "c-current", "c-key", Date.now(), false];
      const signature = await signAuthorityInitializationCommand(command, entry.role === "production" ? operator.privateKey : stagingOperatorPrivate);
      const digest = await commandDigest(command);
      const tablesBefore = await rig.authorityTables();
      // the signer itself is healthy: only the runtime-secret gate differs from the passing active path
      await rig.put("initialize.json", { command, signature });
      await rig.scheduled("mailbox");
      assert.deepEqual(await rig.counts(), [0, 0], `${entry.label}: no executor dispatch, no Authority mutation`);
      assert.equal((await rig.guardSql("SELECT * FROM claims")).length, 0, `${entry.label}: ZERO claim consumption`);
      assert.equal((await rig.guardSql("SELECT * FROM latch")).length, 0, `${entry.label}: ZERO latch acquisition`);
      assert.equal(await rig.result(`lifecycle/${digest}.json`), null, `${entry.label}: no result evidence (no manufactured REFUSED)`);
      assert.deepEqual(await rig.authorityTables(), tablesBefore, `${entry.label}: no Authority lifecycle mutation`);
      // the precondition of the old wedge: the mutation entrypoint itself fails the same gate, so a claim consumed for it could never complete
      const direct = await (await rig.mf.getWorker("driver")).fetch("http://localhost/executor-initialize", { method: "POST", body: JSON.stringify({ command, signature }) });
      assert.notEqual(((await direct.json()) as { status?: string }).status, "ATTESTED", `${entry.label}: the mutation entrypoint is not positive either`);
      assert.deepEqual(await rig.authorityTables(), tablesBefore, `${entry.label}: the direct attempt mutated nothing`);
      // the probe's own answer through the real read-only entrypoint hop is the explicit non-positive UNAVAILABLE
      const probe = await (await rig.mf.getWorker("driver")).fetch("http://localhost/reader-attest-applied", { method: "POST", body: JSON.stringify({ digest }) });
      assert.deepEqual(await probe.json(), { status: "UNAVAILABLE", reason: "runtime-config-invalid" }, entry.label);
      // reconciliation through the same entrypoint is gated too: unsigned non-positive diagnostic, nothing signed
      const reconciled = await rig.reconcile(digest, NONCE("8"));
      assert.ok(reconciled);
      assert.equal(new TextDecoder().decode(reconciled).includes('"statement"'), false, `${entry.label}: nothing signed`);
      assert.equal((JSON.parse(new TextDecoder().decode(reconciled)) as { status: string }).status, "UNAVAILABLE");
      assert.deepEqual(await rig.authorityTables(), tablesBefore, `${entry.label}: reads touched no Authority state`);
      await rig.dispose(); live.splice(live.indexOf(rig), 1);
    }

    // ====================================================================================================================================
    // G : hostile / stale storage (real R2 round trips; the reader trusts nothing but verified bytes + caller expectations)
    // ====================================================================================================================================
    const keyA = `lifecycle/${A.digest}.json`;
    const baseline = await prod.result(keyA);
    assert.ok(baseline);
    const roundTrip = async (label: string, bytes: Uint8Array | string, options: { command?: AuthenticatedLifecycleCommand | "none"; nowMs?: number; trust?: typeof manifest; metadata?: Record<string, string> } = {}) => {
      await prod.putResult(keyA, bytes, options.metadata);
      const stored = await prod.result(keyA);
      assert.ok(stored, label);
      const outcome = await read("lifecycle", A.digest, stored, options.command === "none" ? undefined : options.command ?? A.authenticated, { nowMs: options.nowMs, trust: options.trust });
      notPositive(outcome, label);
      const run = await cli.run(stored, "lifecycle", A.digest, undefined, A.bytes);
      // (the CLI always pairs the CORRECT command and uses the real clock and trust file, so only the cases that vary neither are comparable)
      if (options.nowMs === undefined && options.trust === undefined && options.command === undefined) assert.notEqual(run.exitCode, 0, `${label}: CLI must not exit 0`);
      return outcome;
    };
    // genuine bytes are positive; this proves every rejection below is caused by the tampering, not by the rig
    await prod.putResult(keyA, baseline);
    assert.equal((await read("lifecycle", A.digest, (await prod.result(keyA))!, A.authenticated)).status, "POSITIVE");
    const flipped = baseline.slice(); flipped[Math.floor(flipped.length / 2)] ^= 0x01;
    await roundTrip("one flipped byte", flipped);
    await roundTrip("truncated", baseline.slice(0, baseline.length - 2));
    await roundTrip("appended newline", Uint8Array.from([...baseline, 0x0a]));
    await roundTrip("pretty-printed re-serialization", JSON.stringify(JSON.parse(new TextDecoder().decode(baseline)), null, 2));
    await roundTrip("another digest's genuine signed envelope (the rotation's)", lifecycleB);
    await roundTrip("staging's genuine signed envelope", stagingLifecycle);
    await roundTrip("genuine envelope paired with the WRONG caller command", baseline, { command: rotationCommand });
    await roundTrip("valid envelope, replayed after the freshness window", baseline, { nowMs: Date.now() + 301_000 });
    await roundTrip("valid envelope, observed in the future", baseline, { nowMs: Date.now() - 120_000 });
    // retired / unknown signer
    const spare = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const sparePublic = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", spare.publicKey)));
    const manifestVariant = async (production: (writer: Record<string, unknown>, fresh: Record<string, unknown>) => unknown[]) => {
      const copy = JSON.parse(await trustManifestText());
      const fresh = { keyFingerprint: await attestationKeyFingerprint(sparePublic), publicKey: sparePublic, status: "active", notBeforeMs: 1_700_000_000_000, notAfterMs: null };
      copy.environments[0].keys = production(copy.environments[0].keys[0], fresh);
      copy.environments[0].currentKeyFingerprint = fresh.keyFingerprint;
      return parseAuthorityResultTrustManifest(JSON.stringify(copy));
    };
    await roundTrip("signer retired in the trust manifest", baseline, { trust: await manifestVariant((writer, fresh) => [fresh, { ...writer, status: "retired", notAfterMs: Date.now() + 10 ** 9 }]) });
    await roundTrip("signer unknown to the trust manifest", baseline, { trust: await manifestVariant((_writer, fresh) => [fresh]) });
    // unsigned / malformed / junk / legacy objects
    const legacy = { version: 1, digest: A.digest, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: Date.now() };
    const receipt = { ...A.authenticated.expected, sequence: 1, appliedMs: Date.now() };
    for (const [label, body] of [["legacy unsigned SUCCESS", { ...legacy, status: "SUCCESS", receipt }], ["legacy unsigned ALREADY_APPLIED", { ...legacy, status: "ALREADY_APPLIED", receipt }],
      ["legacy unsigned EXACT_RECEIPT", { ...legacy, nonce: NONCE("a"), status: "EXACT_RECEIPT", initialized: true, coverage: "COMPLETE", receipt, releases: [] }],
      ["malformed v2", { statement: [2, 1], signature: "AAAA" }], ["envelope wrapped by outer SUCCESS metadata", { status: "SUCCESS", envelope: Buffer.from(baseline).toString("base64"), receipt }],
      ["junk", "not json at all"]] as const) await roundTrip(label, typeof body === "string" ? body : JSON.stringify(body));
    await roundTrip("empty object", new Uint8Array(0));
    // outer metadata can neither create nor override signed semantics: a forged marker on junk is not positive, and the genuine bytes stay what they are
    await roundTrip("junk carrying a forged 'signed' marker", "junk", { metadata: { ...SIGNED_RESULT_METADATA, status: "SUCCESS" } });
    await prod.putResult(keyA, baseline, { limitmarkResult: "forged", status: "SUCCESS", receipt: "{}" });
    assert.equal((await read("lifecycle", A.digest, (await prod.result(keyA))!, A.authenticated)).status, "POSITIVE", "outer metadata changes nothing about verified bytes");
    // a missing object is UNCONFIRMED at the CLI
    await (await prod.mf.getR2Bucket("RESULT_BUCKET", "mailbox")).delete(keyA);
    assert.equal(await prod.result(keyA), null);
    // storage that was rewritten with stale-but-genuine evidence under the signed marker stays UNCONFIRMED (a DoS at most), and the relay is idempotent over it
    const stale = baseline;
    await prod.putResult(keyA, stale, { ...SIGNED_RESULT_METADATA });
    await prod.scheduled("mailbox");
    assert.deepEqual(await prod.counts(), [2, 2], "re-running the mailbox over hostile storage dispatches nothing");
    assert.equal((await read("lifecycle", A.digest, (await prod.result(keyA))!, A.authenticated, { nowMs: Date.now() + 400_000 })).status, "UNCONFIRMED");
    // reconciliation: nonce replaced, old nonce replayed, another nonce's envelope stored under this nonce, staging/Production swaps
    const replaceKey = `reconciliation/${NONCE("a")}.json`;
    await prod.putResult(replaceKey, reconciliationD!);
    notPositive(await read("reconciliation", A.digest, (await prod.result(replaceKey))!, A.authenticated, { nonce: NONCE("a") }), "another nonce's genuine envelope stored under this nonce");
    await prod.putResult(replaceKey, gate7Bytes);
    notPositive(await read("reconciliation", A.digest, (await prod.result(replaceKey))!, A.authenticated, { nonce: NONCE("a") }), "staging reconciliation envelope stored under a Production key");
    // the hostile storage tests never mutated Authority state
    assert.equal((await prod.authoritySql("SELECT * FROM lifecycle_receipts")).length, 2);

    console.log("R06 Slice 2C real-workerd active path: PASS (Production initialize/rotate signed APPLIED + command composition, Gate 7 staging continuity, signed reconciliation nonce flow, " +
      "AMBIGUOUS post-commit recovery without duplicate mutation, signer-unavailable pre-mutation (absent/malformed/wrong-environment/not-ready), hostile and stale storage never positive)");
  } finally {
    for (const rig of live) await rig.dispose().catch(() => undefined);
    await cli.dispose();
    await removeRuntime(runtimeRoot);
  }
}
void main().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
