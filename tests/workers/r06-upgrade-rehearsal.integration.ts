import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, createAuthoritySchema } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand, type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";
import { ATTESTATION_SIGNER_BINDINGS } from "../../workers/admission-service/authority-attestation-config";
import { SIGNED_RESULT_METADATA } from "../../workers/lifecycle-mailbox/wire";
import { readStagingAuthorityResult, type AuthorityReadOutcome } from "../../operator/authority-result-reader";
import { STAGING_GATE7_CONTINUITY } from "../../operator/staging-gate7-continuity";
import { rfcSignerBindings } from "../support/authority-attestation-test-signers";
import { trustManifest } from "../support/authority-result-fixtures";
import { GATE7_ERA_COMMIT, UpgradeRig, bundleRevision, extractRevision, removeRuntime, type Versions } from "./support/r06-upgrade-rig";

/**
 * R06 ACTIVATION -- UPGRADE REHEARSAL (T7), on local workerd. Local resources only: no provider, no Wrangler provider execution, no remote
 * binding, no operational key (the Authority signs with the frozen RFC 8032 TEST vectors through the real binding names).
 *
 * It rehearses, over PERSISTED storage, the exact ordering of the R06 activation design:
 *
 *   (S0) every Worker at the Gate 7-era revision, seeded with the Gate 7 canonical committed state
 *   (S1) admission -> HEAD, signer-less           (old observer/mailbox/executor still work; nothing committed changes)
 *   (S2) observer  -> HEAD against signer-less admission (unsigned UNAVAILABLE diagnostic; nothing positive; nothing committed)
 *   (S3) partial attestation secret sets          (fingerprint; fingerprint+public; private alone) => still no signer
 *   (S4) full signer                              (signed reconciliation => POSITIVE with the Gate 7 pins; synthetic digest => signed NOT_FOUND)
 *   (S5) old observer against the activated admission (unsigned, readable by nobody as positive)
 *   (S6) HEAD observer against OLD admission, then admission upgraded (the slot stays free and the SAME request then succeeds)
 *   (S7-S9) the standing stray-initialization hazard: identical at every mixed state, never worse, never touching Authority state
 *
 * Throughout: the whole Authority Durable Object state and the whole dispatch-guard Durable Object state are compared byte-for-byte with
 * the seeded baseline after every step. Nothing in this script can initialize, rotate, reset or re-arm anything it is not explicitly
 * testing as a refused/unconfirmed stray (and those run only in disposable local state, never in the shared baseline state).
 */
const root = process.cwd();
const testsRoot = resolve(root, ".wrangler", "tests");
const runtimeRoot = join(testsRoot, `r06-upgrade-${process.pid}-${randomUUID()}`);
const oldTree = join(runtimeRoot, "old-tree");
process.env.WRANGLER_SEND_METRICS = "false";
for (const name of Object.keys(process.env)) if (/^(CLOUDFLARE_|CF_)/iu.test(name)) delete process.env[name];

const allOld: Versions = { admission: "old", mailbox: "old", observer: "old", executor: "old" };
const allHead: Versions = { admission: "head", mailbox: "head", observer: "head", executor: "head" };
/** One unique 32-hex nonce per label (persisted R2 state would otherwise short-circuit a reused reconciliation slot). */
const nonces = new Map<string, string>();
const NONCE = (label: string): string => {
  let value = nonces.get(label);
  if (value === undefined) { value = (nonces.size + 1).toString(16).padStart(32, "0"); nonces.set(label, value); }
  return value;
};
const ZERO_DIGEST = "0".repeat(64);
const g = STAGING_GATE7_CONTINUITY.receipt;
const names = ATTESTATION_SIGNER_BINDINGS.staging;
const isSigned = (metadata: Record<string, string> | undefined) => metadata?.limitmarkResult === SIGNED_RESULT_METADATA.limitmarkResult;
const json = (bytes: Uint8Array | null) => JSON.parse(new TextDecoder().decode(bytes!)) as Record<string, unknown>;

function ddlFrom(source: string, pattern: RegExp): string[] { return [...source.matchAll(pattern)].map((match) => match[1]); }

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(testsRoot + sep), "runtime root is isolated under .wrangler/tests");
  const live: UpgradeRig[] = [];
  try {
    // ======================================================================================================================================
    // Setup: the Gate 7-era sources from git history, and HEAD from the working tree
    // ======================================================================================================================================
    await extractRevision(GATE7_ERA_COMMIT, oldTree);
    await bundleRevision("old", oldTree, runtimeRoot);
    await bundleRevision("head", root, runtimeRoot);

    // ---- the rehearsal is only meaningful if "old" really is the pre-R06 code and "head" really is R06: prove it from the bundles ----
    const bundle = (version: string, worker: string) => readFile(join(runtimeRoot, `${version}-${worker}.mjs`), "utf8");
    const [oldAdmission, headAdmission, oldObserver, headObserver, oldGuard, headGuard] = await Promise.all([
      bundle("old", "admission"), bundle("head", "admission"), bundle("old", "observer"), bundle("head", "observer"), bundle("old", "mailbox"), bundle("head", "mailbox")]);
    assert.ok(oldAdmission.includes("initializeAuthorityFromOperator") && !oldAdmission.includes("attestReconciliation") && !oldAdmission.includes("initializeAuthorityFromOperatorAttested"), "old admission is pre-R06");
    assert.ok(headAdmission.includes("attestReconciliation") && headAdmission.includes("initializeAuthorityFromOperatorAttested") && headAdmission.includes("inspectLifecycle"), "HEAD admission is R06 and keeps the unsigned supervisory read");
    assert.ok(!oldAdmission.includes("AUTHORITY_STAGING_ATTESTATION"), "old admission never reads the signer bindings");
    assert.ok(oldObserver.includes("inspectLifecycle") && !oldObserver.includes("attestReconciliation"), "old observer is pre-R06");
    assert.ok(headObserver.includes("attestReconciliation") && headObserver.includes("r06-signed-envelope-v2"), "HEAD observer is R06");
    assert.ok(!oldGuard.includes("attestAppliedLifecycle") && headGuard.includes("attestAppliedLifecycle"), "old guard has no signed pre-claim probe; HEAD guard does");

    // ---- storage schema equivalence: the DDL the old and HEAD code execute is identical (the "NO MIGRATION" evidence, in code) ----
    const headAuthorityDdl: string[] = [];
    createAuthoritySchema({ sql: { exec: (query: string) => { headAuthorityDdl.push(query); return []; } }, transactionSync: <T>(callback: () => T) => callback() });
    const oldAuthorityDdl = ddlFrom(await readFile(join(oldTree, "workers", "admission-service", "authority.ts"), "utf8"), /storage\.sql\.exec\("(CREATE [^"]*)"\)/gu);
    assert.equal(headAuthorityDdl.length, 8, "the Authority schema is 6 tables + 2 indexes");
    assert.deepEqual(oldAuthorityDdl, headAuthorityDdl, "old and HEAD Authority DDL are identical, statement for statement");
    const guardPattern = /this\.#ledger\.sql\.exec\("(CREATE [^"]*)"\)/gu;
    const oldGuardDdl = ddlFrom(await readFile(join(oldTree, "workers", "lifecycle-mailbox", "staging-dispatch-guard.ts"), "utf8"), guardPattern);
    const headGuardDdl = ddlFrom(await readFile(join(root, "workers", "lifecycle-mailbox", "staging-dispatch-guard.ts"), "utf8"), guardPattern);
    assert.equal(headGuardDdl.length, 3, "the guard schema is claims + latch + settlements");
    assert.deepEqual(oldGuardDdl, headGuardDdl, "old and HEAD guard DDL are identical, statement for statement");

    // ---- keys: a synthetic staging operator (used only for stray-initialization artifacts) and the frozen RFC test attestation signer ----
    const operator = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const operatorPublic = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", operator.publicKey)));
    const operatorPrivate = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", operator.privateKey)));
    const fullSigner = await rfcSignerBindings("staging");
    const manifest = await trustManifest();

    const start = async (state: string, versions: Versions, signerBindings: Record<string, string> = {}) => {
      const rig = await UpgradeRig.start({ runtimeRoot, state, versions, operatorPublicKey: operatorPublic, signerBindings });
      live.push(rig);
      return rig;
    };
    const stop = async (rig: UpgradeRig) => { await rig.dispose(); live.splice(live.indexOf(rig), 1); };
    const staging = (kind: "reconciliation" | "lifecycle", digest: string, bytes: Uint8Array, nonce?: string): Promise<AuthorityReadOutcome> =>
      readStagingAuthorityResult({ kind, digest, ...(nonce ? { nonce } : {}), bytes, trustManifest: manifest, nowMs: Date.now() } as Parameters<typeof readStagingAuthorityResult>[0]);

    /** Seeds the Gate 7 canonical committed state exactly as the old code wrote it: Authority rows and the guard's claim/settlement rows. */
    const seedGate7 = async (rig: UpgradeRig) => {
      for (const statement of headAuthorityDdl) await rig.authoritySql(statement);
      await rig.authoritySql(`INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,'${g.authorityId}','${g.policyEpoch}',${g.appliedMs})`);
      await rig.authoritySql(`INSERT INTO active_releases(release_id,key_id,activated_ms,retired_ms) VALUES('${g.currentReleaseId}','${g.nextKeyId}',${g.activatesMs},NULL)`);
      await rig.authoritySql("INSERT INTO lifecycle_receipt_coverage(singleton,complete) VALUES(1,1)");
      await rig.authoritySql(`INSERT INTO lifecycle_receipts(digest,schema_version,operation,environment,authority_id,policy_epoch,key_fingerprint,sequence,applied_ms,current_release_id,next_release_id,next_key_id,activates_ms,retires_ms) VALUES('${g.digest}',1,'${g.operation}','${g.environment}','${g.authorityId}','${g.policyEpoch}','${g.keyFingerprint}',${g.sequence},${g.appliedMs},'${g.currentReleaseId}','${g.nextReleaseId}','${g.nextKeyId}',${g.activatesMs},NULL)`);
      // Touching the guard constructs its Durable Object (creating its tables); an unknown digest settles to false and changes nothing.
      assert.equal((await rig.settle(ZERO_DIGEST, NONCE("1"))).settled, false);
      await rig.guardSql(`INSERT INTO claims(digest,operation,status) VALUES('${g.digest}','initialize','SUCCESS')`);
      await rig.guardSql(`INSERT INTO settlements(digest,version,status,sequence,settled_ms) VALUES('${g.digest}',1,'SETTLED',1,1790253000000)`);
    };

    // ======================================================================================================================================
    // S0 : every Worker at the Gate 7-era revision
    // ======================================================================================================================================
    const s0 = await start("main", allOld);
    await seedGate7(s0);
    const T0 = await s0.authorityState();
    const G0 = await s0.guardState();
    assert.deepEqual(Object.keys(T0).sort(), ["active_releases", "authority_meta", "lifecycle_receipt_coverage", "lifecycle_receipts", "nonces", "observations"],
      "the Authority state is exactly the six tables");
    assert.equal((T0.lifecycle_receipts as unknown[]).length, 1);
    assert.deepEqual(Object.keys(G0).sort(), ["claims", "latch", "settlements"]);
    const unchanged = async (rig: UpgradeRig, label: string) => {
      assert.deepEqual(await rig.authorityState(), T0, `${label}: the Authority state is byte-for-byte the seeded baseline`);
      assert.deepEqual(await rig.guardState(), G0, `${label}: the guard state is byte-for-byte the seeded baseline`);
    };

    assert.equal((await s0.settle(g.digest, NONCE("2"))).settled, true, "S0: duplicate settlement of the Gate 7 digest stays SETTLED");
    const oldBytes = await s0.reconcile(g.digest, NONCE("a"));
    assert.ok(oldBytes);
    const oldSnapshot = json(oldBytes);
    assert.equal(oldSnapshot.status, "EXACT_RECEIPT", "S0: the deployed-era observer writes an UNSIGNED full snapshot");
    assert.equal((oldSnapshot.receipt as { digest: string }).digest, g.digest);
    assert.equal(isSigned(await s0.resultMetadata(`reconciliation/${NONCE("a")}.json`)), false);
    assert.notEqual((await staging("reconciliation", g.digest, oldBytes, NONCE("a"))).status, "POSITIVE",
      "S0: HEAD read-result can never accept the deployed-era unsigned object (the review's premise, proven)");
    await unchanged(s0, "S0");
    await stop(s0);

    // ======================================================================================================================================
    // S1 : admission -> HEAD (signer-less); observer, mailbox, executor still at the Gate 7-era revision
    // ======================================================================================================================================
    const s1 = await start("main", { ...allOld, admission: "head" });
    await unchanged(s1, "S1 on first start over the persisted state");
    assert.equal((await s1.settle(g.digest, NONCE("3"))).settled, true, "S1: the OLD mailbox still settles through HEAD admission (inspectLifecycle is retained and ungated)");
    const s1Bytes = await s1.reconcile(g.digest, NONCE("b"));
    assert.equal(json(s1Bytes).status, "EXACT_RECEIPT", "S1: the OLD observer still observes through HEAD admission");
    assert.equal(isSigned(await s1.resultMetadata(`reconciliation/${NONCE("b")}.json`)), false);
    await unchanged(s1, "S1");
    await stop(s1);

    // ======================================================================================================================================
    // S2 : observer -> HEAD against the signer-less HEAD admission
    // ======================================================================================================================================
    const s2 = await start("main", { ...allOld, admission: "head", observer: "head" });
    const s2Bytes = await s2.reconcile(g.digest, NONCE("c"));
    assert.ok(s2Bytes);
    assert.deepEqual(json(s2Bytes), { version: 1, digest: g.digest, nonce: NONCE("c"), status: "UNAVAILABLE", reason: "signer-unconfigured" },
      "S2: a signer-less Authority yields an explicit unsigned, never-positive diagnostic");
    assert.equal(isSigned(await s2.resultMetadata(`reconciliation/${NONCE("c")}.json`)), false);
    const s2Read = await staging("reconciliation", g.digest, s2Bytes, NONCE("c"));
    assert.equal(s2Read.status, "UNCONFIRMED");
    assert.equal((s2Read as { relayStatus?: string }).relayStatus, "UNAVAILABLE");
    assert.equal((await s2.settle(g.digest, NONCE("4"))).settled, true, "S2: settlement unaffected");
    await unchanged(s2, "S2");
    await stop(s2);

    // ======================================================================================================================================
    // S3 : partial attestation secret sets (the wrapper's order: fingerprint, public key, private key last)
    // ======================================================================================================================================
    const partials: Array<[string, Record<string, string>]> = [
      ["fingerprint only", { [names.writerKeyFingerprint]: fullSigner[names.writerKeyFingerprint] }],
      ["fingerprint + public key", { [names.writerKeyFingerprint]: fullSigner[names.writerKeyFingerprint], [names.publicKey]: fullSigner[names.publicKey] }],
      ["private key alone", { [names.privateKey]: fullSigner[names.privateKey] }],
    ];
    let partialIndex = 0;
    for (const [label, bindings] of partials) {
      partialIndex += 1;
      const rig = await start("main", { ...allOld, admission: "head", observer: "head" }, bindings);
      const nonce = NONCE(`partial-${partialIndex}`);
      const bytes = await rig.reconcile(g.digest, nonce);
      assert.deepEqual(json(bytes), { version: 1, digest: g.digest, nonce, status: "UNAVAILABLE", reason: "signer-unconfigured" }, `S3 (${label}): no signer`);
      assert.equal(isSigned(await rig.resultMetadata(`reconciliation/${nonce}.json`)), false, `S3 (${label})`);
      await unchanged(rig, `S3 (${label})`);
      await stop(rig);
    }

    // ======================================================================================================================================
    // S4 : the full signer (RFC test vectors under the real staging binding names); observer HEAD; mailbox/executor still OLD
    // ======================================================================================================================================
    const s4 = await start("main", { ...allOld, admission: "head", observer: "head" }, fullSigner);
    const gate7Bytes = await s4.reconcile(g.digest, NONCE("e"));
    assert.ok(gate7Bytes);
    assert.equal(isSigned(await s4.resultMetadata(`reconciliation/${NONCE("e")}.json`)), true, "S4: the exact signed envelope bytes are stored with the signed marker");
    const gate7Outcome = await staging("reconciliation", g.digest, gate7Bytes, NONCE("e"));
    assert.equal(gate7Outcome.status, "POSITIVE", `S4: signed reconciliation of the Gate 7 digest is POSITIVE with the Gate 7 pins: ${JSON.stringify(gate7Outcome)}`);
    assert.equal((gate7Outcome as { receipt: { operatorKeyFingerprint: string } }).receipt.operatorKeyFingerprint, g.keyFingerprint);
    const syntheticBytes = await s4.reconcile("b".repeat(64), NONCE("f"));
    assert.ok(syntheticBytes);
    const syntheticOutcome = await staging("reconciliation", "b".repeat(64), syntheticBytes, NONCE("f"));
    assert.equal(syntheticOutcome.status, "VERIFIED_NON_POSITIVE", "S4: a synthetic never-signed digest is a signed NOT_FOUND, never positive");
    assert.match(JSON.stringify(syntheticOutcome), /NOT_FOUND/u);
    assert.equal((await s4.settle(g.digest, NONCE("5"))).settled, true, "S4: the OLD mailbox settles duplicate through the activated admission");
    assert.equal((await s4.settle("c".repeat(64), NONCE("6"))).settled, false, "S4: an unclaimed digest settles false");
    // a signed envelope is bound to its caller nonce: replayed under another nonce it is not accepted
    assert.notEqual((await staging("reconciliation", g.digest, gate7Bytes, NONCE("9"))).status, "POSITIVE", "S4: another nonce's genuine envelope is never positive");
    await unchanged(s4, "S4");
    await stop(s4);

    // ======================================================================================================================================
    // S5 : the OLD observer against the ACTIVATED admission: works, but its output is never positive
    // ======================================================================================================================================
    const s5 = await start("main", { ...allOld, admission: "head" }, fullSigner);
    const s5Bytes = await s5.reconcile(g.digest, NONCE("7"));
    assert.equal(json(s5Bytes).status, "EXACT_RECEIPT");
    assert.equal(isSigned(await s5.resultMetadata(`reconciliation/${NONCE("7")}.json`)), false);
    assert.notEqual((await staging("reconciliation", g.digest, s5Bytes!, NONCE("7"))).status, "POSITIVE");
    await unchanged(s5, "S5");
    await stop(s5);

    // ======================================================================================================================================
    // S6 : HEAD observer against the OLD admission, then admission upgraded: the slot stays free and the SAME request then succeeds
    // ======================================================================================================================================
    const s6a = await start("main", { ...allOld, observer: "head" });
    assert.equal(await s6a.reconcile(g.digest, NONCE("8")), null, "S6: an old admission has no attested read; the HEAD observer stores nothing (the throw is swallowed)");
    await unchanged(s6a, "S6a");
    await stop(s6a);
    const s6b = await start("main", { ...allOld, admission: "head", observer: "head" }, fullSigner);
    assert.equal(await s6b.result(`reconciliation/${NONCE("8")}.json`), null, "S6: still nothing stored (no phantom nonce consumed)");
    await s6b.scheduled("observer");
    const recovered = await s6b.result(`reconciliation/${NONCE("8")}.json`);
    assert.ok(recovered, "S6: after the upgrade the same request.reconcile.json is served");
    assert.equal((await staging("reconciliation", g.digest, recovered, NONCE("8"))).status, "POSITIVE");
    await unchanged(s6b, "S6b");
    await stop(s6b);

    // ======================================================================================================================================
    // S7-S9 : the STANDING stray-initialization hazard, characterized at three mixed states. Each runs in its own disposable local state,
    // seeded with the same Gate 7 baseline, and none of them may ever change Authority state.
    // ======================================================================================================================================
    const stray = async () => {
      const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH,
        "r06-stray-release", "r06-stray-key", Date.now(), false];
      return { artifact: { command, signature: await signAuthorityInitializationCommand(command, operatorPrivate) }, digest: await commandDigest(command) };
    };
    const claimsOf = async (rig: UpgradeRig) => (await rig.guardSql("SELECT digest,status FROM claims ORDER BY digest")) as Array<{ digest: string; status: string }>;

    // S7: OLD mailbox + OLD executor against HEAD admission: the guard consumes the digest and latches (exactly as it does today); the
    // executor's removed unsigned method cannot reach the Authority. Hazard identical to the baseline hazard; Authority untouched.
    const s7 = await start("stray-old-mailbox", { ...allOld, admission: "head" }, fullSigner);
    await seedGate7(s7);
    const T7 = await s7.authorityState();
    const strayA = await stray();
    await s7.put("initialize.json", strayA.artifact);
    await s7.scheduled("mailbox");
    assert.deepEqual((await claimsOf(s7)).filter((row) => row.digest === strayA.digest), [{ digest: strayA.digest, status: "UNCONFIRMED" }], "S7: claimed, outcome UNCONFIRMED");
    assert.deepEqual(await s7.guardSql("SELECT digest FROM latch"), [{ digest: strayA.digest }], "S7: the standing hazard: the latch is held");
    assert.deepEqual(await s7.authorityState(), T7, "S7: Authority state untouched");
    assert.equal(isSigned(await s7.resultMetadata(`lifecycle/${strayA.digest}.json`)), false);
    await stop(s7);

    // S8: HEAD mailbox + HEAD executor against a SIGNER-LESS HEAD admission: the signed pre-claim probe fails closed BEFORE any claim.
    const s8 = await start("stray-head-signerless", allHead);
    await seedGate7(s8);
    const T8 = await s8.authorityState();
    const G8 = await s8.guardState();
    const strayB = await stray();
    await s8.put("initialize.json", strayB.artifact);
    await s8.scheduled("mailbox");
    assert.deepEqual(await s8.guardState(), G8, "S8: no claim, no latch: a signer-less Authority is a strictly safer posture than the deployed-era chain");
    assert.deepEqual(await s8.authorityState(), T8, "S8: Authority state untouched");
    assert.equal(await s8.result(`lifecycle/${strayB.digest}.json`), null, "S8: nothing published for an UNAVAILABLE pre-claim outcome");
    await stop(s8);

    // S9: fully activated HEAD chain with a signer: the standing hazard persists unchanged (claim consumed, REFUSED, latch held); Authority untouched.
    const s9 = await start("stray-head-signer", allHead, fullSigner);
    await seedGate7(s9);
    const T9 = await s9.authorityState();
    const strayC = await stray();
    await s9.put("initialize.json", strayC.artifact);
    await s9.scheduled("mailbox");
    assert.deepEqual((await claimsOf(s9)).filter((row) => row.digest === strayC.digest), [{ digest: strayC.digest, status: "REFUSED" }], "S9: the initialized Authority refuses; the claim is consumed");
    assert.deepEqual(await s9.guardSql("SELECT digest FROM latch"), [{ digest: strayC.digest }], "S9: the standing hazard is unchanged by activation (never worse, never better)");
    assert.deepEqual(await s9.authorityState(), T9, "S9: Authority state untouched");
    await stop(s9);

    console.log("R06 upgrade rehearsal: PASS (identical old/HEAD Authority and guard DDL; persisted Gate 7 state byte-for-byte unchanged through every step of the activation order; " +
      "old observer/mailbox work against HEAD admission; HEAD observer against signer-less, partial-secret and old admission never positive and the slot stays free; " +
      "full signer: signed reconciliation POSITIVE with the Gate 7 pins, synthetic digest signed NOT_FOUND, duplicate settlement SETTLED; " +
      "standing stray-initialization hazard identical at every mixed state and signer-less HEAD fails closed before any claim)");
  } finally {
    for (const rig of live) await rig.dispose().catch(() => undefined);
    await removeRuntime(runtimeRoot);
  }
}
void main().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
