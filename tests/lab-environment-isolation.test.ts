import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";
import {
  ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, PublicInquiryAdmissionAuthority, STAGING_ADMISSION_AUTHORITY_ID,
  inspectLifecycleAuthority,
} from "../workers/admission-service/authority";
import {
  AuthorityAttestationCoordinator, LAB_ATTESTATION_IDENTITY, PRODUCTION_ATTESTATION_IDENTITY, STAGING_ATTESTATION_IDENTITY,
} from "../workers/admission-service/authority-attestation";
import { createAuthorityAttestationSigner } from "../workers/admission-service/authority-attestation-signer";
import { authorityAttestationRuntimeFromEnvironment } from "../workers/admission-service/authority-attestation-config";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, type AuthorityInitializationCommand,
} from "../workers/admission-service/operator-command";
import { authenticateSealedLifecycleArtifact } from "../operator/lifecycle-submitter";
import { readLabAuthorityResult } from "../operator/lab-authority-result";
import { readProductionAuthorityResult, readStagingAuthorityResult } from "../operator/authority-result-reader";
import { parseAuthorityResultTrustManifest, parseLabAuthorityResultTrustManifest } from "../src/lib/authority-result-trust";
import {
  LAB_RESOURCES, validateLabAdmissionServiceConfig, validateLabEnvironmentGate, validateLabLifecycleMailboxConfig,
  validateLabLifecycleObserverConfig, validateLabLifecycleTransportManifest, validateLifecycleEnvironmentGates, validateLifecycleMailboxConfig,
  validateLifecycleObserverConfig, validateLifecycleTransportManifest, validateStagingAdmissionServiceConfig, validateStagingLifecycleMailboxConfig,
  validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";
import {
  validateLabOperatorExecutorTemplate, validateOperatorExecutorTemplate, validateRenderedLabOperatorExecutorConfig,
  validateRenderedOperatorExecutorConfig, validateRenderedStagingOperatorExecutorConfig, validateStagingOperatorExecutorTemplate,
} from "../deployment/operator-executor-contract";
import { validateRuntimeSecrets } from "../deployment/secret-policy";
import { generateLabKeyPair } from "../scripts/lab-authority-keygen";

// Lab is a third, strictly isolated environment. These tests prove the isolation properties, not merely the happy path.
const T0 = 1_800_000_000_000;
const RELEASE = "lab-release-1";
const KEY_ID = "lab-release-key-1";
type Env = "production" | "staging" | "lab";
const AUTHORITY: Record<Env, string> = { production: ADMISSION_AUTHORITY_ID, staging: STAGING_ADMISSION_AUTHORITY_ID, lab: LAB_ADMISSION_AUTHORITY_ID };
const IDENTITY = { production: PRODUCTION_ATTESTATION_IDENTITY, staging: STAGING_ATTESTATION_IDENTITY, lab: LAB_ATTESTATION_IDENTITY } as const;
const command = (environment: Env, issued = T0, release = RELEASE, authority: string = AUTHORITY[environment], confirm = environment === "production"): AuthorityInitializationCommand =>
  [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, authority as typeof ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, release, KEY_ID, issued, confirm];
const strip = (text: string): string => text.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
const json = (path: string) => JSON.parse(strip(readFileSync(path, "utf8")));
const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

function rig(environment: Env) {
  const operator = generateLabKeyPair();
  const attestation = generateLabKeyPair();
  const storage = new NodeSqliteDurableStorage();
  const clock = { value: T0 };
  const signer = createAuthorityAttestationSigner({ environment, writerKeyFingerprint: attestation.fingerprint, privateKey: attestation.privatePkcs8, publicKey: attestation.publicKey });
  const coordinator = new AuthorityAttestationCoordinator(storage, IDENTITY[environment], operator.publicKey, { signer, now: () => clock.value });
  const authority = () => new PublicInquiryAdmissionAuthority({ storage }, { now: () => clock.value, expectedAuthorityId: AUTHORITY[environment], expectedPolicyEpoch: ADMISSION_POLICY_EPOCH });
  const releaseRows = () => {
    try { return Array.from(storage.sql.exec<{ c: number }>("SELECT COUNT(*) AS c FROM active_releases"))[0]?.c ?? 0; } catch { return 0; }
  };
  return { operator, attestation, storage, clock, coordinator, authority, releaseRows };
}
const pre = (n: number, issued = T0) => ({ releaseId: RELEASE, clientPseudonym: encodeBase64url(new Uint8Array(32).fill(n)),
  requestBinding: encodeBase64url(new Uint8Array(32).fill(n + 1)), nonce: encodeBase64url(new Uint8Array(16).fill(n + 2)), issuedAtMs: issued });
const sealed = (cmd: AuthorityInitializationCommand, signature: string): Uint8Array => new TextEncoder().encode(JSON.stringify({ command: cmd, signature }));

function trustSection(environment: Env, key: { publicKey: string; fingerprint: string }) {
  return { environment, authorityId: AUTHORITY[environment], policyEpoch: ADMISSION_POLICY_EPOCH, currentKeyFingerprint: key.fingerprint,
    keys: [{ keyFingerprint: key.fingerprint, publicKey: key.publicKey, status: "active", notBeforeMs: T0 - 1_000, notAfterMs: null }] };
}
const manifestText = (...sections: ReturnType<typeof trustSection>[]): string =>
  JSON.stringify({ manifestVersion: 1, attestationVersion: 2, trustEpoch: 1, environments: sections });

async function initialized(environment: Env) {
  const r = rig(environment);
  const cmd = command(environment);
  const signature = await signAuthorityInitializationCommand(cmd, r.operator.privatePkcs8);
  const out = await r.coordinator.initialize(cmd, signature);
  assert.equal(out.status, "ATTESTED");
  if (out.status !== "ATTESTED") throw new Error("not attested");
  const digest = (await authenticateSealedLifecycleArtifact(sealed(cmd, signature), r.operator.publicKey, { expectedEnvironment: environment })).digest;
  return { ...r, cmd, signature, envelope: out.envelope, digest };
}

// ---- 1/2. staging and production are isolated from lab (and lab from them) -------------------------------------------------------
const templates = {
  production: { mailbox: "deployment/lifecycle-mailbox.template.jsonc", observer: "deployment/lifecycle-observer.template.jsonc",
    executor: "deployment/operator-lifecycle-executor.template.jsonc", transport: "deployment/lifecycle-transport.production.template.json" },
  staging: { mailbox: "deployment/lifecycle-mailbox.staging.template.jsonc", observer: "deployment/lifecycle-observer.staging.template.jsonc",
    executor: "deployment/operator-lifecycle-executor.staging.template.jsonc", transport: "deployment/lifecycle-transport.staging.template.json",
    admission: "deployment/admission-service.staging.template.jsonc" },
  lab: { mailbox: "deployment/lifecycle-mailbox.lab.template.jsonc", observer: "deployment/lifecycle-observer.lab.template.jsonc",
    executor: "deployment/operator-lifecycle-executor.lab.template.jsonc", transport: "deployment/lifecycle-transport.lab.template.json",
    admission: "deployment/admission-service.lab.template.jsonc" },
} as const;

test("the lab templates satisfy ONLY the lab validators; every lab validator rejects the Production and staging templates", () => {
  const lab = Object.fromEntries(Object.entries(templates.lab).map(([k, p]) => [k, json(p)]));
  validateLabLifecycleMailboxConfig(lab.mailbox, true);
  validateLabLifecycleObserverConfig(lab.observer, true);
  validateLabOperatorExecutorTemplate(lab.executor);
  validateLabLifecycleTransportManifest(lab.transport, true);
  validateLabAdmissionServiceConfig(lab.admission, true);
  // lab validators reject every Production and staging counterpart
  for (const env of ["production", "staging"] as const) {
    const t = templates[env];
    assert.throws(() => validateLabLifecycleMailboxConfig(json(t.mailbox), true), env);
    assert.throws(() => validateLabLifecycleObserverConfig(json(t.observer), true), env);
    assert.throws(() => validateLabOperatorExecutorTemplate(json(t.executor)), env);
    assert.throws(() => validateLabLifecycleTransportManifest(json(t.transport), true), env);
  }
  assert.throws(() => validateLabAdmissionServiceConfig(json(templates.staging.admission), true));
});

test("staging and Production validators reject every lab template (no cross-environment acceptance, in both directions)", () => {
  const lab = Object.fromEntries(Object.entries(templates.lab).map(([k, p]) => [k, json(p)]));
  assert.throws(() => validateStagingLifecycleMailboxConfig(lab.mailbox, true));
  assert.throws(() => validateStagingLifecycleObserverConfig(lab.observer, true));
  assert.throws(() => validateStagingOperatorExecutorTemplate(lab.executor));
  assert.throws(() => validateStagingLifecycleTransportManifest(lab.transport, true));
  assert.throws(() => validateStagingAdmissionServiceConfig(lab.admission, true));
  assert.throws(() => validateLifecycleMailboxConfig(lab.mailbox, true));
  assert.throws(() => validateLifecycleObserverConfig(lab.observer, true));
  assert.throws(() => validateOperatorExecutorTemplate(lab.executor));
  assert.throws(() => validateLifecycleTransportManifest(lab.transport, true));
  // and a RENDERED lab executor config is not a rendered Production or staging executor config
  const rendered = clone(lab.executor);
  rendered.account_id = "a".repeat(32);
  rendered.main = "../workers/lab-operator-lifecycle-executor.ts";
  rendered.vars = { AUTHORITY_OPERATOR_PUBLIC_KEY: encodeBase64url(new Uint8Array(32).fill(7)), OPERATOR_EXECUTOR_ENVIRONMENT: "lab" };
  validateRenderedLabOperatorExecutorConfig(rendered);
  assert.throws(() => validateRenderedOperatorExecutorConfig(rendered));
  assert.throws(() => validateRenderedStagingOperatorExecutorConfig(rendered));
});

test("no wildcard or look-alike environment identity is accepted: names, hostnames, DO classes and environment values are exact", () => {
  const mailbox = json(templates.lab.mailbox);
  for (const bad of ["limitmark-lifecycle-mailbox-lab2", "limitmark-lifecycle-mailbox-*", "limitmark-lifecycle-mailbox-labx", "limitmark-lifecycle-mailbox-dev", "limitmark-lifecycle-mailbox-production"]) {
    const m = clone(mailbox); m.name = bad;
    assert.throws(() => validateLabLifecycleMailboxConfig(m, true), bad);
  }
  for (const bad of ["dev", "lab2", "*", "Lab", "production", "staging", ""]) {
    const m = clone(mailbox); m.vars.LIFECYCLE_ENVIRONMENT = bad;
    assert.throws(() => validateLabLifecycleMailboxConfig(m, true), `LIFECYCLE_ENVIRONMENT=${bad}`);
  }
  for (const bad of ["lab.limitmark.com", "*.limitmark.com", "lab-admission.limitmark.com.evil.test", "admission.limitmark.com", "limitmark.com"]) {
    const a = json(templates.lab.admission); a.routes = [{ pattern: bad, custom_domain: true }];
    assert.throws(() => validateLabAdmissionServiceConfig(a, true), `route ${bad}`);
  }
  const wildcardRoute = json(templates.lab.admission); wildcardRoute.routes = [{ pattern: "lab-admission.limitmark.com/*", zone_name: "limitmark.com" }];
  assert.throws(() => validateLabAdmissionServiceConfig(wildcardRoute, true));
  const productionClass = json(templates.lab.admission); productionClass.durable_objects.bindings[0].class_name = "ProductionAdmissionAuthority";
  assert.throws(() => validateLabAdmissionServiceConfig(productionClass, true));
  const stagingClass = json(templates.lab.admission); stagingClass.durable_objects.bindings[0].class_name = "StagingAdmissionAuthority";
  assert.throws(() => validateLabAdmissionServiceConfig(stagingClass, true));
  const twoBindings = json(templates.lab.admission); twoBindings.durable_objects.bindings.push({ name: "OTHER", class_name: "ProductionAdmissionAuthority" });
  assert.throws(() => validateLabAdmissionServiceConfig(twoBindings, true));
  const extraKey = json(templates.lab.admission); extraKey.services = [{ binding: "X", service: "limitmark-admission-service-production" }];
  assert.throws(() => validateLabAdmissionServiceConfig(extraKey, true));
  // a lab mailbox bound to the Production executor/reader/bucket is refused
  const prodExecutor = clone(mailbox); prodExecutor.services[0].service = "limitmark-authority-operator-executor-production";
  assert.throws(() => validateLabLifecycleMailboxConfig(prodExecutor, true));
  const prodReader = clone(mailbox); prodReader.services[1].service = "limitmark-admission-service-production";
  assert.throws(() => validateLabLifecycleMailboxConfig(prodReader, true));
  const prodBucket = clone(mailbox); prodBucket.r2_buckets[0].bucket_name = "limitmark-lifecycle-requests-production";
  assert.throws(() => validateLabLifecycleMailboxConfig(prodBucket, true));
  const stagingBucket = clone(mailbox); stagingBucket.r2_buckets[1].bucket_name = "limitmark-lifecycle-results-staging";
  assert.throws(() => validateLabLifecycleMailboxConfig(stagingBucket, true));
});

test("lab templates reference no Production or staging resource, and the environment gates keep every environment closed and disjoint", () => {
  for (const path of Object.values(templates.lab)) assert.doesNotMatch(readFileSync(path, "utf8"), /production|staging/iu, path);
  const gates = json("deployment/lifecycle-environment-gates.json");
  validateLifecycleEnvironmentGates(gates);
  // Production provisioning is NOT implied by the existence of lab: every environment stays closed.
  assert.equal(gates.production.provisioningOpen, false);
  assert.equal(gates.staging.provisioningOpen, false);
  assert.equal(gates.lab.provisioningOpen, false);
  assert.equal(gates.lab.productionProvisioningImplied, false);
  assert.equal(gates.lab.isolatedFromProduction, true);
  assert.equal(gates.crossEnvironmentKeyReuseAllowed, false);
  assert.equal(gates.crossEnvironmentCredentialReuseAllowed, false);
  assert.equal(gates.crossEnvironmentNamespaceReuseAllowed, false);
  const fields = ["requestBucket", "resultBucket", "mailboxWorker", "observerWorker", "guardObject", "executorWorker", "admissionWorker", "authorityObject"];
  const identities = (["production", "staging", "lab"] as const).flatMap((env) => fields.map((field) => gates[env][field] as string));
  assert.equal(new Set(identities).size, identities.length, "no resource identity is shared between environments");
  for (const field of fields) assert.match(gates.lab[field], /lab/u, field);
  // tampering is rejected
  for (const mutate of [
    (g: typeof gates) => { g.production.provisioningOpen = true; },
    (g: typeof gates) => { g.lab.provisioningOpen = true; },
    (g: typeof gates) => { g.lab.productionProvisioningImplied = true; },
    (g: typeof gates) => { g.lab.requestBucket = g.production.requestBucket; },
    (g: typeof gates) => { g.lab.authorityObject = g.staging.authorityObject; },
    (g: typeof gates) => { g.lab.publicHostname = "*.limitmark.com"; },
    (g: typeof gates) => { g.lab.admissionHostname = "limitmark.com"; },
    (g: typeof gates) => { delete g.lab; },
    (g: typeof gates) => { g.dev = clone(g.lab); },
    (g: typeof gates) => { g.lab.extra = true; },
    (g: typeof gates) => { g.crossEnvironmentCredentialReuseAllowed = true; },
  ]) { const g = clone(gates); mutate(g); assert.throws(() => validateLifecycleEnvironmentGates(g)); }
  assert.throws(() => validateLabEnvironmentGate({ ...gates.lab, rotationImplemented: true }));
  assert.equal(LAB_RESOURCES.publicHostname, "lab.limitmark.com");
});

// ---- 3. lab cannot impersonate production (or staging), and vice versa ----------------------------------------------------------
test("lab-signed evidence is not accepted by the Production or staging reader, and Production/staging evidence is not accepted by the lab reader", async () => {
  const lab = await initialized("lab");
  const production = await initialized("production");
  const staging = await initialized("staging");
  const labTrust = await parseLabAuthorityResultTrustManifest(manifestText(trustSection("lab", lab.attestation)));
  const prodTrust = await parseAuthorityResultTrustManifest(manifestText(trustSection("production", production.attestation), trustSection("staging", staging.attestation)));
  const now = T0 + 1_000;
  // the genuine paths work (control for the negatives below)
  const labCommand = await authenticateSealedLifecycleArtifact(sealed(lab.cmd, lab.signature), lab.operator.publicKey, { expectedEnvironment: "lab" });
  const ok = await readLabAuthorityResult({ kind: "lifecycle", digest: lab.digest, bytes: lab.envelope, trustManifest: labTrust, nowMs: now, authenticatedCommand: labCommand });
  assert.equal(ok.status, "POSITIVE");
  assert.equal(ok.environment, "lab");
  // lab evidence presented to the Production and staging readers: never positive
  const asProduction = await readProductionAuthorityResult({ kind: "lifecycle", digest: lab.digest, bytes: lab.envelope, trustManifest: prodTrust, nowMs: now });
  assert.notEqual(asProduction.status, "POSITIVE");
  const asStaging = await readStagingAuthorityResult({ kind: "lifecycle", digest: lab.digest, bytes: lab.envelope, trustManifest: prodTrust, nowMs: now });
  assert.notEqual(asStaging.status, "POSITIVE");
  // even if the lab key were (wrongly) listed as the Production key, the statement still names environment=lab and is refused
  const impersonation = await parseAuthorityResultTrustManifest(manifestText(trustSection("production", lab.attestation), trustSection("staging", staging.attestation)));
  assert.notEqual((await readProductionAuthorityResult({ kind: "lifecycle", digest: lab.digest, bytes: lab.envelope, trustManifest: impersonation, nowMs: now })).status, "POSITIVE");
  // Production and staging evidence presented to the lab reader: never positive (even with the matching command)
  for (const other of [production, staging]) {
    const otherEnv = other === production ? "production" : "staging";
    const otherCommand = await authenticateSealedLifecycleArtifact(sealed(other.cmd, other.signature), other.operator.publicKey, { expectedEnvironment: otherEnv });
    const outcome = await readLabAuthorityResult({ kind: "lifecycle", digest: other.digest, bytes: other.envelope, trustManifest: labTrust, nowMs: now, authenticatedCommand: otherCommand });
    assert.notEqual(outcome.status, "POSITIVE", otherEnv);
  }
  // a lab trust manifest listing the Production key does not make Production evidence lab evidence
  const labListingProductionKey = await parseLabAuthorityResultTrustManifest(manifestText(trustSection("lab", production.attestation)));
  assert.notEqual((await readLabAuthorityResult({ kind: "lifecycle", digest: production.digest, bytes: production.envelope, trustManifest: labListingProductionKey, nowMs: now })).status, "POSITIVE");
});

test("trust manifests are environment-exact: the lab manifest and the Production/staging manifest cannot stand in for each other", async () => {
  const [a, b, c] = [generateLabKeyPair(), generateLabKeyPair(), generateLabKeyPair()];
  const labOnly = manifestText(trustSection("lab", a));
  const twoSection = manifestText(trustSection("production", b), trustSection("staging", c));
  await parseLabAuthorityResultTrustManifest(labOnly);
  await parseAuthorityResultTrustManifest(twoSection);
  await assert.rejects(parseAuthorityResultTrustManifest(labOnly));
  await assert.rejects(parseLabAuthorityResultTrustManifest(twoSection));
  await assert.rejects(parseLabAuthorityResultTrustManifest(manifestText(trustSection("lab", a), trustSection("production", b))));
  // the same key in two environments is refused outright
  await assert.rejects(parseAuthorityResultTrustManifest(manifestText(trustSection("production", b), trustSection("staging", b))));
  // the lab section must name the lab authority
  await assert.rejects(parseLabAuthorityResultTrustManifest(manifestText({ ...trustSection("lab", a), authorityId: ADMISSION_AUTHORITY_ID })));
  const template = readFileSync("deployment/authority-result-trust.lab.template.json", "utf8");
  await assert.rejects(parseLabAuthorityResultTrustManifest(template), "the lab trust template is shape-only and never parses");
  assert.doesNotMatch(template, /production|staging/iu);
});

// ---- 4. lab initialization cannot initialize another authority ------------------------------------------------------------------
test("a lab-signed initialization cannot initialize the Production or staging authority, and no other environment's command initializes lab", async () => {
  for (const target of ["production", "staging"] as const) {
    const victim = rig(target);
    const attacker = generateLabKeyPair(); // the lab operator key
    // (a) lab command signed with the lab operator key, delivered to the other environment's authority
    const labCmd = command("lab");
    assert.equal((await victim.coordinator.initialize(labCmd, await signAuthorityInitializationCommand(labCmd, attacker.privatePkcs8))).status, "REFUSED", `${target}: foreign operator key`);
    // (b) even when the victim's own operator key signed it, a lab-flavoured command does not match the victim's identity
    assert.equal((await victim.coordinator.initialize(labCmd, await signAuthorityInitializationCommand(labCmd, victim.operator.privatePkcs8))).status, "REFUSED", `${target}: lab command, own key`);
    // (c) a command naming the target environment but the lab authority id (and the reverse)
    for (const mixed of [command(target, T0, RELEASE, LAB_ADMISSION_AUTHORITY_ID, target === "production"), command("lab", T0, RELEASE, AUTHORITY[target], false)]) {
      const signed = await signAuthorityInitializationCommand(mixed, victim.operator.privatePkcs8).catch(() => "A".repeat(86));
      assert.equal((await victim.coordinator.initialize(mixed, signed)).status, "REFUSED");
    }
    assert.equal(victim.releaseRows(), 0, `${target}: no release row created`);
    assert.equal(victim.authority().claimPre(pre(1)).decision, "unavailable", `${target}: still uninitialized`);
  }
  const lab = rig("lab");
  for (const foreign of [command("production"), command("staging"), command("production", T0, RELEASE, LAB_ADMISSION_AUTHORITY_ID, true),
    command("lab", T0, RELEASE, ADMISSION_AUTHORITY_ID), command("lab", T0, RELEASE, LAB_ADMISSION_AUTHORITY_ID, true)]) {
    const signed = await signAuthorityInitializationCommand(foreign, lab.operator.privatePkcs8).catch(() => "A".repeat(86));
    assert.equal((await lab.coordinator.initialize(foreign, signed)).status, "REFUSED", JSON.stringify(foreign.slice(2, 4)));
  }
  assert.equal(lab.releaseRows(), 0);
  assert.equal(lab.authority().claimPre(pre(1)).decision, "unavailable");
  // the lab authority id is bound both ways in the core: an environment other than lab cannot carry it and the lab command carries no production confirmation
  const good = command("lab");
  assert.equal((await lab.coordinator.initialize(good, await signAuthorityInitializationCommand(good, lab.operator.privatePkcs8))).status, "ATTESTED");
  assert.equal(lab.releaseRows(), 1);
});

test("lab initialization is immutable: replay is idempotent, a different command cannot re-initialize, stale/future commands are refused", async () => {
  const r = rig("lab");
  for (const issued of [T0 - 5 * 60_000 - 1, T0 + 5 * 60_000 + 1]) {
    const c = command("lab", issued);
    assert.equal((await r.coordinator.initialize(c, await signAuthorityInitializationCommand(c, r.operator.privatePkcs8))).status, "REFUSED");
  }
  const first = command("lab");
  const sig = await signAuthorityInitializationCommand(first, r.operator.privatePkcs8);
  assert.equal((await r.coordinator.initialize(first, sig)).status, "ATTESTED");
  const replay = await r.coordinator.initialize(first, sig);
  assert.ok(replay.status === "ATTESTED" && replay.relayDisposition === "ALREADY_APPLIED");
  r.clock.value = T0 + 1_000;
  const other = command("lab", T0 + 1_000, "another-release");
  assert.equal((await r.coordinator.initialize(other, await signAuthorityInitializationCommand(other, r.operator.privatePkcs8))).status, "REFUSED");
  assert.equal(r.releaseRows(), 1);
  const wrongKey = generateLabKeyPair();
  assert.equal((await r.coordinator.initialize(first, await signAuthorityInitializationCommand(first, wrongKey.privatePkcs8))).status, "REFUSED", "a replay signed by another key is not accepted");
  assert.equal(r.releaseRows(), 1);
});

// ---- 5. lab credentials are not reusable in staging/production ----------------------------------------------------------------------
test("a lab operator key or lab attestation key is useless in Production and staging (and the reverse)", async () => {
  const lab = await initialized("lab");
  const production = rig("production");
  const staging = rig("staging");
  // the lab operator key cannot authorize anything on the other authorities (the verifier is pinned to each authority's own public key)
  const prodCmd = command("production");
  const stgCmd = command("staging");
  assert.equal((await production.coordinator.initialize(prodCmd, await signAuthorityInitializationCommand(prodCmd, lab.operator.privatePkcs8))).status, "REFUSED");
  assert.equal((await staging.coordinator.initialize(stgCmd, await signAuthorityInitializationCommand(stgCmd, lab.operator.privatePkcs8))).status, "REFUSED");
  // a lab attestation key cannot become the Production or staging signer: the signer is bound to its own environment and pinned fingerprint
  for (const environment of ["production", "staging"] as const) {
    const coordinator = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), IDENTITY[environment], lab.operator.publicKey, {
      signer: createAuthorityAttestationSigner({ environment: "lab", writerKeyFingerprint: lab.attestation.fingerprint, privateKey: lab.attestation.privatePkcs8, publicKey: lab.attestation.publicKey }),
      now: () => T0 });
    const cmd = command(environment);
    const out = await coordinator.initialize(cmd, await signAuthorityInitializationCommand(cmd, lab.operator.privatePkcs8));
    assert.notEqual(out.status, "ATTESTED", `${environment}: a lab-environment signer must not attest ${environment}`);
  }
  // a lab signer whose pinned fingerprint does not match its key never attests
  const mismatched = new AuthorityAttestationCoordinator(new NodeSqliteDurableStorage(), LAB_ATTESTATION_IDENTITY, lab.operator.publicKey, {
    signer: createAuthorityAttestationSigner({ environment: "lab", writerKeyFingerprint: "0".repeat(64), privateKey: lab.attestation.privatePkcs8, publicKey: lab.attestation.publicKey }),
    now: () => T0 });
  const labCmd = command("lab");
  assert.notEqual((await mismatched.initialize(labCmd, await signAuthorityInitializationCommand(labCmd, lab.operator.privatePkcs8))).status, "ATTESTED");
});

test("signer bindings are per environment: any other environment's binding leaves an Authority without a signer", () => {
  const key = generateLabKeyPair();
  const bindings = (env: Env) => {
    const tag = env === "production" ? "" : `${env.toUpperCase()}_`;
    return { [`AUTHORITY_${tag}ATTESTATION_PRIVATE_KEY`]: key.privatePkcs8, [`AUTHORITY_${tag}ATTESTATION_PUBLIC_KEY`]: key.publicKey,
      [`AUTHORITY_${tag}ATTESTATION_KEY_FINGERPRINT`]: key.fingerprint };
  };
  for (const env of ["production", "staging", "lab"] as const) {
    const own = authorityAttestationRuntimeFromEnvironment(env, bindings(env) as never);
    assert.ok("signer" in own && own.signer, `${env}: own bindings configure a signer`);
    for (const other of ["production", "staging", "lab"] as const) {
      if (other === env) continue;
      assert.deepEqual(authorityAttestationRuntimeFromEnvironment(env, bindings(other) as never), {}, `${env} ignores ${other}'s bindings`);
      assert.deepEqual(authorityAttestationRuntimeFromEnvironment(env, { ...bindings(env), ...bindings(other) } as never), {}, `${env} with a stray ${other} binding has no signer`);
    }
  }
});

test("runtime secret policy forbids lab credentials in every non-signer runtime and rejects a credential shared across environments", () => {
  const matrix = json("deployment/secret-matrix.json");
  assert.ok(matrix.collisionSensitive.includes("AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY"));
  for (const [name, policy] of Object.entries(matrix.runtimes as Record<string, { forbiddenSecrets: string[] }>)) {
    assert.ok(policy.forbiddenSecrets.includes("AUTHORITY_LAB_OPERATOR_PRIVATE_KEY"), `${name} forbids the lab operator private key`);
    if (name !== "admissionService") assert.ok(policy.forbiddenSecrets.includes("AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY"), `${name} forbids the lab attestation private key`);
  }
  const base = { ADMISSION_CURRENT_RPC_KEY: "rpc-key-lab", AUTHORITY_OPERATOR_PUBLIC_KEY: "operator-public", AUTHORITY: {} };
  assert.equal(validateRuntimeSecrets("admissionService", base), true);
  assert.equal(validateRuntimeSecrets("admissionService", { ...base, AUTHORITY_LAB_OPERATOR_PRIVATE_KEY: "x" }), false, "operator private key never reaches the admission Worker");
  assert.equal(validateRuntimeSecrets("operatorExecutor", { AUTHORITY_OPERATOR_PUBLIC_KEY: "k", ADMISSION_SERVICE: {}, AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: "x" }), false);
  assert.equal(validateRuntimeSecrets("lifecycleMailbox", { AUTHORITY_OPERATOR_PUBLIC_KEY: "k", REQUEST_BUCKET: {}, RESULT_BUCKET: {}, DISPATCH_GUARD: {},
    LIFECYCLE_EXECUTOR: {}, LIFECYCLE_READER: {}, AUTHORITY_LAB_OPERATOR_PRIVATE_KEY: "x" }), false);
  assert.equal(validateRuntimeSecrets("vercelApplication", { AUTHORITY_LAB_OPERATOR_PRIVATE_KEY: "x" }, false), false);
  // one value used as both the lab and the Production/staging attestation key is a collision
  const shared = { ...base, AUTHORITY_ATTESTATION_PRIVATE_KEY: "same", AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: "same" };
  assert.equal(validateRuntimeSecrets("admissionService", shared), false);
  assert.equal(validateRuntimeSecrets("admissionService", { ...shared, AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: "different" }), true);
  assert.equal(validateRuntimeSecrets("admissionService", { ...base, ADMISSION_CURRENT_RPC_KEY: "same", AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: "same" }), false, "RPC key must differ from the lab attestation key");
});

// ---- 6. lab replay protection; lab control plane vs data plane ------------------------------------------------------------------------
test("lab admission enforces replay protection and rate limits after initialization", async () => {
  const lab = await initialized("lab");
  const authority = lab.authority();
  assert.equal(authority.claimPre(pre(7)).decision, "allowed");
  assert.equal(authority.claimPre(pre(7)).decision, "replay", "the same nonce is a replay");
  assert.equal(lab.authority().claimPre(pre(7)).decision, "replay", "replay state is durable across authority instances");
  assert.equal(authority.claimPre({ ...pre(8), releaseId: "unknown-release" }).decision, "unavailable");
  const other = encodeBase64url(new Uint8Array(32).fill(99));
  assert.equal(authority.claimPre({ ...pre(9), clientPseudonym: other, issuedAtMs: T0 - 31_000 }).decision !== "allowed", true, "an aged claim is not admitted");
});

test("the Production-default data-plane core cannot serve lab state, and the lab Durable Object pins the lab identity", async () => {
  const lab = await initialized("lab");
  const productionCore = new PublicInquiryAdmissionAuthority({ storage: lab.storage }, { now: () => T0 });
  assert.equal(productionCore.claimPre(pre(30)).decision, "unavailable", "lab state is not servable under the Production identity");
  const stagingCore = new PublicInquiryAdmissionAuthority({ storage: lab.storage }, { now: () => T0, expectedAuthorityId: STAGING_ADMISSION_AUTHORITY_ID });
  assert.equal(stagingCore.claimPre(pre(30)).decision, "unavailable");
  assert.equal(lab.authority().claimPre(pre(30)).decision, "allowed");
  const index = readFileSync("workers/admission-service/index.ts", "utf8");
  const labBlock = index.split("export class LabAdmissionAuthority")[1].split("export class LabAuthorityLifecycleOnly")[0];
  assert.match(labBlock, /new PublicInquiryAdmissionAuthority\(\{ storage: this\.durableStorage \},\s*\{ expectedAuthorityId: LAB_ADMISSION_AUTHORITY_ID, expectedPolicyEpoch: ADMISSION_POLICY_EPOCH \}\)/u);
});

test("lab authority state is lab-only: inspection answers the lab identity and never the Production or staging identity", async () => {
  const lab = await initialized("lab");
  const snapshot = inspectLifecycleAuthority(lab.storage, lab.digest, T0, LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH) as Record<string, unknown>;
  assert.equal(snapshot.environment, "lab");
  assert.equal(snapshot.authorityId, LAB_ADMISSION_AUTHORITY_ID);
  assert.equal(snapshot.status, "EXACT_RECEIPT");
  // asking the lab storage as the Production or staging identity never yields an exact receipt, and never claims to be lab
  for (const id of [ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID]) {
    const view = inspectLifecycleAuthority(lab.storage, lab.digest, T0, id, ADMISSION_POLICY_EPOCH) as Record<string, unknown>;
    assert.notEqual(view.environment, "lab", id);
    assert.notEqual(view.status, "EXACT_RECEIPT", id);
  }
});

test("a lab control-plane failure (no signer, bad signature, refused command) does not disable lab admission", async () => {
  const lab = await initialized("lab");
  assert.equal(lab.authority().claimPre(pre(20)).decision, "allowed");
  // the signer disappears: the attested reads are UNAVAILABLE, but the data plane is independent of the control plane
  const signerless = new AuthorityAttestationCoordinator(lab.storage, LAB_ATTESTATION_IDENTITY, lab.operator.publicKey, { now: () => T0 });
  assert.equal((await signerless.attestAppliedLifecycle(lab.digest)).status, "UNAVAILABLE");
  const bad = command("lab", T0, "x");
  assert.equal((await lab.coordinator.initialize(bad, "A".repeat(86))).status, "REFUSED");
  await assert.rejects(() => lab.coordinator.initialize(bad, "not-a-signature"));
  assert.equal(lab.authority().claimPre(pre(21)).decision, "allowed", "admission continues after control-plane failures");
  assert.equal(lab.authority().claimPre(pre(20)).decision, "replay", "and replay protection is intact");
  // structural: the lab claim/consume path touches only the core authority, never the attestation/operator machinery
  const index = readFileSync("workers/admission-service/index.ts", "utf8");
  const labBlock = index.split("export class LabAdmissionAuthority")[1].split("export class LabAuthorityLifecycleOnly")[0];
  const claim = labBlock.match(/async claimPre[^\n]*/u)![0] + labBlock.match(/async consumePost[^\n]*/u)![0];
  assert.equal(/attestation|operator|signer/iu.test(claim), false);
  // the mailbox, executor, guard and observer are not imported by the admission data plane
  const authoritySource = readFileSync("workers/admission-service/authority.ts", "utf8").replace(/\/\/.*$/gmu, "");
  assert.equal(/lifecycle-mailbox|operator-lifecycle-executor|lab-operator-lifecycle-executor/u.test(authoritySource), false);
});

// ---- 7. structural separation of lab code ---------------------------------------------------------------------------------------------
test("lab code never names the Production or staging authority, bucket, guard or Worker identity", () => {
  const labFiles = ["workers/lab-operator-lifecycle-executor.ts", "workers/lab-lifecycle-observer.ts", "workers/lifecycle-mailbox/lab-index.ts",
    "workers/lifecycle-mailbox/lab-processor.ts", "workers/lifecycle-mailbox/lab-dispatch-guard.ts", "workers/admission-service/lab-index.ts",
    "operator/lab-authority-result.ts", "operator/lab-operator-io.ts", "scripts/authority-lab-initialize.ts", "scripts/authority-lab-submit.ts"];
  for (const file of labFiles) {
    const text = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
    assert.equal(/(?<![A-Z_])ADMISSION_AUTHORITY_ID|STAGING_ADMISSION_AUTHORITY_ID|production-public-inquiries|staging-public-inquiries/u.test(text), false, `${file} names another authority`);
    assert.equal(/limitmark-[a-z-]+-(?:production|staging)|"production"|"staging"|Staging[A-Z]|Production[A-Z]/u.test(text), false, `${file} names another environment`);
  }
  const index = readFileSync("workers/admission-service/index.ts", "utf8");
  const labSection = index.slice(index.indexOf("// Laboratory capability"));
  assert.equal(/(?<![A-Z_])ADMISSION_AUTHORITY_ID|STAGING_ADMISSION_AUTHORITY_ID|PRODUCTION_ATTESTATION_IDENTITY|STAGING_ATTESTATION_IDENTITY|"production"|"staging"/u.test(
    labSection.replace(/\/\/.*$/gmu, "").replace(/\/\*[\s\S]*?\*\//gu, "")), false, "the lab section of the admission Worker addresses only the lab identity");
  // the Production and staging classes and entrypoints never address the lab identity
  const pieces = [
    index.slice(index.indexOf("export class ProductionAdmissionAuthority"), index.indexOf("const runtimeSecretsValid")),
    index.slice(index.indexOf("export class AdmissionServiceWorker"), index.indexOf("/** Lab public admission fetch")),
    index.slice(index.indexOf("/** The executor binds only these two methods"), index.indexOf("// Laboratory capability")),
  ];
  for (const piece of pieces) {
    assert.ok(piece.length > 200);
    assert.equal(/LAB_|\bLab[A-Z]|\blab\b/u.test(piece.replace(/\/\/.*$/gmu, "").replace(/\/\*[\s\S]*?\*\//gu, "")), false, "Production and staging classes do not reference lab");
  }
  // the lab admission entry exports only lab-pinned classes
  const entry = readFileSync("workers/admission-service/lab-index.ts", "utf8");
  assert.equal(/ProductionAdmissionAuthority|StagingAdmissionAuthority|AuthorityLifecycleOnly(?!\b)/u.test(entry.replace(/LabAuthorityLifecycleOnly/gu, "")), false);
});

test("lab rotation is not implemented anywhere: no rotate artifact, handler, script or executor method exists", () => {
  for (const file of ["workers/lifecycle-mailbox/lab-processor.ts", "workers/lifecycle-mailbox/lab-index.ts", "workers/lab-operator-lifecycle-executor.ts", "scripts/authority-lab-submit.ts"])
    assert.equal(/rotate-release\.json|submitRotationArtifact|processRotation/u.test(readFileSync(file, "utf8").replace(/\/\/.*$/gmu, "").replace(/\/\*[\s\S]*?\*\//gu, "")), false, file);
  const pkg = readFileSync("package.json", "utf8");
  assert.equal(/authority:lab:[a-z:-]*rotate/u.test(pkg), false);
  const gates = json("deployment/lifecycle-environment-gates.json");
  assert.equal(gates.lab.rotationImplemented, false);
});

test("lab package scripts and ignore rules keep rendered lab material out of the repository", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { scripts: Record<string, string> };
  const labScripts = Object.entries(pkg.scripts).filter(([name]) => name.startsWith("authority:lab:"));
  assert.ok(labScripts.length >= 5);
  for (const [name, script] of labScripts) assert.match(script, /authority-lab-(?:initialize|submit)\.ts/u, name);
  const ignore = readFileSync("deployment/.gitignore", "utf8").split("\n");
  for (const name of ["lifecycle-transport.lab.json", "authority-result-trust.lab.json", "lifecycle-mailbox.lab.jsonc", "lifecycle-observer.lab.jsonc",
    "operator-lifecycle-executor.lab.jsonc", "admission-service.lab.jsonc"]) assert.ok(ignore.includes(name), name);
  // the tracked templates are NOT ignored by those rules
  for (const name of ["lifecycle-mailbox.lab.template.jsonc", "authority-result-trust.lab.template.json"]) assert.equal(ignore.includes(name), false, name);
});
