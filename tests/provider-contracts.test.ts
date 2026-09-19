import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";
import { validateRuntimeSecrets, validateVercelProjectContract } from "../deployment/secret-policy";
import { importActiveIngressSigningKeys, parseIngressSigningKeyRollout } from "../src/lib/ingress-key-rollout";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { getPublicSubmissionConfiguration } from "../src/lib/public-submission-config";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, PublicInquiryAdmissionAuthority, initializeAuthority, rotateAuthorityRelease } from "../workers/admission-service/authority";
import {
  AUTHORITY_OPERATOR_COMMAND_VERSION,
  executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation,
  signAuthorityInitializationCommand,
  signAuthorityReleaseRotationCommand,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "../workers/admission-service/operator-command";
import { NodeSqliteDurableStorage } from "./support/sqlite-do-storage";

const readJson = async (name: string) => JSON.parse(await readFile(new URL(`../deployment/${name}`, import.meta.url), "utf8")) as Record<string, unknown>;

async function readTree(root: URL): Promise<string> {
  const entries = await readdir(root, { withFileTypes: true });
  return (await Promise.all(entries.map(async (entry) => entry.isDirectory()
    ? readTree(new URL(`${entry.name}/`, root))
    : readFile(new URL(entry.name, root), "utf8")))).join("\n");
}

test("Production Worker templates disable alternate entrypoints and own disjoint routes/bindings", async () => {
  const signer = await readJson("public-signer.template.jsonc");
  const gateway = await readJson("admin-gateway.template.jsonc");
  const admission = await readJson("admission-service.template.jsonc");
  for (const config of [signer, gateway, admission]) {
    assert.equal(config.workers_dev, false); assert.equal(config.preview_urls, false);
    assert.equal(config.compatibility_date, "2026-09-13"); assert.match(String(config.name), /-production$/u);
    assert.match(JSON.stringify(config), /__REQUIRED_/u);
  }
  const patterns = [signer, gateway, admission].flatMap((config) => (config.routes as Array<{ pattern: string }>).map((route) => route.pattern));
  assert.equal(new Set(patterns).size, patterns.length);
  assert.deepEqual((signer.durable_objects as undefined), undefined);
  assert.deepEqual((gateway.durable_objects as undefined), undefined);
  assert.deepEqual((admission.durable_objects as { bindings: Array<{ name: string }> }).bindings.map((binding) => binding.name), ["AUTHORITY"]);
  assert.deepEqual(Object.keys(signer.vars as object).sort(), ["INGRESS_AUDIENCE", "INGRESS_SIGNING_KEY_ID", "VERCEL_DEPLOYMENT_ID"]);
  assert.deepEqual(Object.keys(gateway.vars as object).sort(), ["ADMIN_ALLOWED_EMAIL", "CLOUDFLARE_ACCESS_AUD", "CLOUDFLARE_ACCESS_TEAM_DOMAIN", "VERCEL_ADMIN_UPSTREAM_ORIGIN"]);
  assert.doesNotMatch(JSON.stringify(signer), /VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET|CLOUDFLARE_ACCESS/u);
  assert.doesNotMatch(JSON.stringify(gateway), /INGRESS_SIGNING_PRIVATE_KEY|INGRESS_IDENTITY_HMAC_KEY|VERCEL_AUTOMATION_BYPASS_SECRET|AUTHORITY/u);
  assert.doesNotMatch(JSON.stringify(admission), /VERCEL_(?:ADMIN_)?AUTOMATION_BYPASS_SECRET/u);
});

test("runtime secret matrix rejects forbidden placement and credential reuse", () => {
  const signer = { INGRESS_SIGNING_PRIVATE_KEY: "sign", INGRESS_IDENTITY_HMAC_KEY: "identity", PUBLIC_ORIGIN_SECRET: "origin", VERCEL_AUTOMATION_BYPASS_SECRET: "bypass" };
  assert.equal(validateRuntimeSecrets("publicSigner", signer), true);
  assert.equal(validateRuntimeSecrets("publicSigner", { ...signer, DATABASE_URL: "database" }), false);
  assert.equal(validateRuntimeSecrets("publicSigner", { ...signer, PUBLIC_ORIGIN_SECRET: "bypass" }), false);
  assert.equal(validateRuntimeSecrets("adminGateway", { VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "admin" }), true);
  assert.equal(validateRuntimeSecrets("adminGateway", { VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "admin", PUBLIC_ORIGIN_SECRET: "origin" }), false);
  assert.equal(validateRuntimeSecrets("adminGateway", { VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "admin", AUTHORITY: {} }), false);
  assert.equal(validateRuntimeSecrets("admissionService", { ADMISSION_CURRENT_RPC_KEY: "rpc", AUTHORITY_OPERATOR_PUBLIC_KEY: "public", AUTHORITY: {} }), true);
  assert.equal(validateRuntimeSecrets("admissionService", { ADMISSION_CURRENT_RPC_KEY: "rpc", AUTHORITY_OPERATOR_PUBLIC_KEY: "public", AUTHORITY: {},
    VERCEL_AUTOMATION_BYPASS_SECRET: "public-bypass" }), false);
  assert.equal(validateRuntimeSecrets("previewApplication", { DATABASE_URL: "production" }), false);
  assert.equal(validateRuntimeSecrets("previewApplication", { AUTHORITY: {} }), false);
  assert.equal(validateRuntimeSecrets("previewApplication", { AUTHORITY_OPERATOR_PRIVATE_KEY: "offline" }), false);
  assert.equal(validateRuntimeSecrets("vercelApplication", { VERCEL_DEPLOYMENT_ID: "dpl", VERCEL_PROJECT_ID: "prj" }, false), true);
  assert.equal(validateRuntimeSecrets("vercelApplication", { VERCEL_DEPLOYMENT_ID: "dpl", VERCEL_PROJECT_ID: "prj",
    VERCEL_AUTOMATION_BYPASS_SECRET: "platform-injected-public-ingress-secret" }, false), true);
  assert.equal(validateRuntimeSecrets("vercelApplication", { VERCEL_DEPLOYMENT_ID: "dpl", VERCEL_PROJECT_ID: "prj",
    VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "forbidden-admin-secret" }, false), false);
});

test("one shared Production project P and separate Preview project Q form the accepted topology", async () => {
  const contract = await readJson("vercel-project-contract.json");
  assert.equal(validateVercelProjectContract(contract), true);
  const production = contract.productionApplicationProject as Record<string, unknown>;
  const preview = contract.previewApplicationProject as Record<string, unknown>;
  const shared = contract.sharedRequirements as Record<string, unknown>;
  const targets = production.gatewayTargets as Record<string, Record<string, unknown>>;
  const bypass = production.bypassCredentials as Record<string, Record<string, unknown>>;
  assert.equal(production.projectRef, "P");
  assert.deepEqual(production.applicationRoutes, ["public", "admin"]);
  assert.equal(production.systemEnvironmentVariableAccess, "enabled");
  assert.deepEqual(production.productionBoundary, { VERCEL: "1", VERCEL_ENV: "production" });
  assert.equal(targets.publicSigner.projectRef, "P");
  assert.equal(targets.adminGateway.projectRef, "P");
  assert.equal(preview.projectRef, "Q");
  assert.equal(preview.mustDifferFromProjectRef, "P");
  assert.equal(bypass.public.contractId, "B-public");
  assert.equal(bypass.public.selectedForSystemEnvironmentExposure, true);
  assert.equal(bypass.admin.contractId, "B-admin");
  assert.equal(bypass.admin.ordinaryApplicationEnvironmentConfiguration, "forbidden");
  assert.equal(bypass.admin.applicationRequestTimeObservation, "possible");
  assert.notEqual(bypass.public.contractId, bypass.admin.contractId);
  assert.equal(shared.productionAndPreviewProjectIdsMustDiffer, true);
  assert.equal(shared.publicAndAdminBypassCredentialsMustDiffer, true);
  assert.equal(shared.staticChecksAreRuntimeSecrecyProof, false);
  assert.equal(shared.realSettingsChangeAuthorized, false);

  const equalProject = structuredClone(contract) as Record<string, Record<string, unknown>>;
  equalProject.previewApplicationProject.expectedProjectId = production.expectedProjectId;
  assert.equal(validateVercelProjectContract(equalProject), false);
  const wrongTarget = structuredClone(contract) as Record<string, Record<string, unknown>>;
  ((wrongTarget.productionApplicationProject.gatewayTargets as Record<string, Record<string, unknown>>).adminGateway).projectRef = "Q";
  assert.equal(validateVercelProjectContract(wrongTarget), false);
  const sameBypass = structuredClone(contract) as Record<string, Record<string, unknown>>;
  ((sameBypass.productionApplicationProject.bypassCredentials as Record<string, Record<string, unknown>>).admin).contractId = "B-public";
  assert.equal(validateVercelProjectContract(sameBypass), false);
});

test("Preview and bypass-only configurations remain closed", async () => {
  const contract = await readJson("vercel-project-contract.json");
  const forbidden = (contract.previewApplicationProject as { forbiddenProductionConfiguration: string[] }).forbiddenProductionConfiguration;
  for (const name of ["DATABASE_URL", "ADMISSION_RELEASE_RPC_KEY", "VERCEL_AUTOMATION_BYPASS_SECRET", "VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET",
    "INGRESS_SIGNING_PRIVATE_KEY", "INGRESS_IDENTITY_HMAC_KEY", "PUBLIC_ORIGIN_SECRET", "TURNSTILE_SECRET_KEY", "RESEND_API_KEY",
    "AUTHORITY_OPERATOR_PRIVATE_KEY", "AUTHORITY"]) assert.ok(forbidden.includes(name));
  for (const name of ["DATABASE_URL", "ADMISSION_RELEASE_RPC_KEY", "VERCEL_AUTOMATION_BYPASS_SECRET", "VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET",
    "INGRESS_SIGNING_PRIVATE_KEY", "INGRESS_IDENTITY_HMAC_KEY", "PUBLIC_ORIGIN_SECRET", "TURNSTILE_SECRET_KEY", "RESEND_API_KEY",
    "AUTHORITY_OPERATOR_PRIVATE_KEY", "AUTHORITY"])
    assert.equal(validateRuntimeSecrets("previewApplication", { [name]: name === "AUTHORITY" ? {} : "production-value" }, false), false);
  assert.deepEqual(getPublicSubmissionConfiguration({ VERCEL_AUTOMATION_BYPASS_SECRET: "B-public" } as never, ["cloudflare-do"]),
    { enabled: false, reason: "persistence" });
  assert.deepEqual(getPublicSubmissionConfiguration({ VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET: "B-admin" } as never, ["cloudflare-do"]),
    { enabled: false, reason: "persistence" });
});

test("browser/static checks catch configuration regressions without claiming runtime secrecy", async () => {
  const browserSource = await readTree(new URL("../src/app/", import.meta.url));
  const nextConfig = await readFile(new URL("../next.config.ts", import.meta.url), "utf8");
  const exampleEnvironment = await readFile(new URL("../.env.example", import.meta.url), "utf8");
  assert.doesNotMatch(`${browserSource}\n${nextConfig}`, /NEXT_PUBLIC_[A-Z0-9_]*BYPASS|BYPASS_SENTINEL/u);
  assert.doesNotMatch(exampleEnvironment, /^(?:VERCEL_AUTOMATION_BYPASS_SECRET|VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET)=/mu);
});

test("signed operator initialization succeeds once, is safely idempotent, and never resets", async () => {
  const storage = new NodeSqliteDurableStorage();
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const command: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "dpl_current", "release-current", 1_000, true];
  const signature = await signAuthorityInitializationCommand(command, privateKey);
  const first = await executeSignedAuthorityInitialization(storage, command, signature, publicKey, 1_001);
  assert.equal(first.status, "initialized");
  assert.ok(first.receipt);
  const repeat = await executeSignedAuthorityInitialization(storage, command, signature, publicKey, 1_001);
  assert.equal(repeat.status, "already-initialized");
  assert.deepEqual(repeat.receipt, first.receipt);
  const changed = [...command] as unknown as AuthorityInitializationCommand;
  (changed as unknown as string[])[5] = "dpl_changed";
  const changedSignature = await signAuthorityInitializationCommand(changed, privateKey);
  await assert.rejects(() => executeSignedAuthorityInitialization(storage, changed, changedSignature, publicKey, 1_001));
  assert.throws(() => initializeAuthority(storage, { environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, releaseId: "dpl_other", releaseKeyId: "other", nowMs: 1_000, confirmProduction: false }));
  storage.close();

  for (const specification of [
    { environment: "preview", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH },
    { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: "wrong-epoch" },
  ]) {
    const invalidStorage = new NodeSqliteDurableStorage();
    assert.throws(() => initializeAuthority(invalidStorage, { ...specification, releaseId: "dpl_current", releaseKeyId: "release-current",
      nowMs: 1_000, confirmProduction: false } as never));
    invalidStorage.close();
  }
});

test("release lifecycle keeps quota state and denies a retired release", () => {
  const storage = new NodeSqliteDurableStorage();
  const now = { value: 1_000 };
  const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
  initializeAuthority(storage, { environment: "staging", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    releaseId: "dpl_current", releaseKeyId: "key-current", nowMs: now.value, confirmProduction: false });
  assert.deepEqual(rotateAuthorityRelease(storage, { authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    currentReleaseId: "dpl_current", nextReleaseId: "dpl_next", nextKeyId: "key-next", activatesAtMs: 2_000, previousRetiresAtMs: 3_000 }), { status: "rotated" });
  const input = (releaseId: string, fill: number) => ({ releaseId, clientPseudonym: encodeBase64url(new Uint8Array(32).fill(fill)),
    requestBinding: encodeBase64url(new Uint8Array(32).fill(fill + 1)), nonce: encodeBase64url(new Uint8Array(16).fill(fill + 2)), issuedAtMs: now.value });
  now.value = 2_500;
  assert.equal(authority.claimPre(input("dpl_current", 1)).decision, "allowed");
  assert.equal(authority.claimPre(input("dpl_next", 5)).decision, "allowed");
  const observations = storage.count("observations");
  now.value = 3_000;
  assert.equal(authority.claimPre(input("dpl_current", 9)).decision, "unavailable");
  assert.equal(authority.claimPre(input("dpl_next", 13)).decision, "allowed");
  assert.ok(storage.count("observations") > observations);
  storage.close();
});

test("signed Production rotation is idempotent, preserves history and rejects conflicts", async () => {
  const storage = new NodeSqliteDurableStorage();
  const now = { value: 1_000 };
  const authority = new PublicInquiryAdmissionAuthority({ storage }, { now: () => now.value });
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const init: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "dpl_current", "key-current", now.value, true];
  await executeSignedAuthorityInitialization(storage, init, await signAuthorityInitializationCommand(init, privateKey), publicKey, now.value);
  const input = { releaseId: "dpl_current", clientPseudonym: encodeBase64url(new Uint8Array(32).fill(1)),
    requestBinding: encodeBase64url(new Uint8Array(32).fill(2)), nonce: encodeBase64url(new Uint8Array(16).fill(3)), issuedAtMs: now.value };
  assert.equal(authority.claimPre(input).decision, "allowed");
  const before = { observations: storage.count("observations"), nonces: storage.count("nonces") };
  const command: AuthorityReleaseRotationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "production", ADMISSION_AUTHORITY_ID,
    ADMISSION_POLICY_EPOCH, "dpl_current", "dpl_next", "key-next", 2_000, 3_000, 2_000, true];
  const signature = await signAuthorityReleaseRotationCommand(command, privateKey);
  const rotated = await executeSignedAuthorityReleaseRotation(storage, command, signature, publicKey, 2_001);
  assert.equal(rotated.status, "rotated");
  assert.ok(rotated.receipt);
  now.value = 2_500;
  assert.equal(authority.claimPre({ ...input, issuedAtMs: now.value }).decision, "replay");
  const repeated = await executeSignedAuthorityReleaseRotation(storage, command, signature, publicKey, 2_500);
  assert.equal(repeated.status, "already-rotated");
  assert.deepEqual(repeated.receipt, rotated.receipt);
  assert.deepEqual({ observations: storage.count("observations"), nonces: storage.count("nonces") }, before);

  const conflict = [...command] as unknown as AuthorityReleaseRotationCommand;
  (conflict as unknown as string[])[7] = "key-conflict";
  await assert.rejects(async () => executeSignedAuthorityReleaseRotation(storage, conflict,
    await signAuthorityReleaseRotationCommand(conflict, privateKey), publicKey, 2_500));
  assert.deepEqual({ observations: storage.count("observations"), nonces: storage.count("nonces") }, before);
  now.value = 3_000;
  assert.equal(authority.claimPre({ ...input, nonce: encodeBase64url(new Uint8Array(16).fill(4)), issuedAtMs: now.value }).decision, "unavailable");
  storage.close();
});

test("Ed25519 verifier accepts only the bounded current/next rollout window", async () => {
  const first = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const second = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = async (key: CryptoKey) => encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
  const rollout = JSON.stringify([
    { role: "current", keyId: "current", publicKey: await raw(first.publicKey), activatesAtMs: 1_000, retiresAtMs: 2_500 },
    { role: "next", keyId: "next", publicKey: await raw(second.publicKey), activatesAtMs: 2_000 },
  ]);
  assert.equal(parseIngressSigningKeyRollout(rollout)?.length, 2);
  assert.deepEqual([...await importActiveIngressSigningKeys(rollout, 1_500).then((keys) => keys.keys())], ["current"]);
  assert.deepEqual([...await importActiveIngressSigningKeys(rollout, 2_250).then((keys) => keys.keys())], ["current", "next"]);
  assert.deepEqual([...await importActiveIngressSigningKeys(rollout, 2_500).then((keys) => keys.keys())], ["next"]);
  assert.equal(parseIngressSigningKeyRollout(JSON.stringify([...JSON.parse(rollout), { role: "next", keyId: "third", publicKey: await raw(second.publicKey), activatesAtMs: 2_100 }])), null);
});

test("production authority class has no public HTTP initialization path", async () => {
  const source = await readFile(new URL("../workers/admission-service/index.ts", import.meta.url), "utf8");
  assert.match(source, /class ProductionAdmissionAuthority extends DurableObject/u);
  assert.doesNotMatch(source, /class ProductionAdmissionAuthority extends PublicInquiryAdmissionAuthority/u);
  assert.match(source, /class AdmissionServiceWorker extends WorkerEntrypoint/u);
  assert.doesNotMatch(source, /(?:url\.pathname|request\.url)[^\n]*(?:initialize|rotate|reset)|\/(?:initialize|rotate|reset)/u);
});
