import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import type { DurableObjectState } from "@cloudflare/workers-types";
import { importAdmissionRpcKey } from "../../src/lib/admission-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, inspectLifecycleAuthority, PublicInquiryAdmissionAuthority, type DurableStorageLike } from "./authority";
import type { AuthorityInitializationCommand, AuthorityReleaseRotationCommand } from "./operator-command";
import {
  AuthorityAttestationCoordinator,
  PRODUCTION_ATTESTATION_IDENTITY,
  STAGING_ATTESTATION_IDENTITY,
  type AttestedLifecycleResult,
  type AttestedReconciliationResult,
  type AttestedRecoveryResult,
  type AuthorityAttestationRuntime,
} from "./authority-attestation";
import { authorityAttestationRuntimeFromEnvironment } from "./authority-attestation-config";
import { createVercelOidcVerifier, type VercelOidcPolicy } from "./auth";
import { createAdmissionService, type AdmissionServiceRelease } from "./service";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

export { PublicInquiryAdmissionAuthority } from "./authority";
export { createAdmissionService } from "./service";
export { createVercelOidcVerifier } from "./auth";

type AuthorityStub = {
  initializeFromOperatorAttested(command: AuthorityInitializationCommand, signature: string): Promise<AttestedLifecycleResult>;
  rotateReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string): Promise<AttestedLifecycleResult>;
  attestAppliedLifecycle(digest: string): Promise<AttestedRecoveryResult>;
  attestReconciliation(digest: string, nonce: string): Promise<AttestedReconciliationResult>;
  claimPre(input: Parameters<PublicInquiryAdmissionAuthority["claimPre"]>[0]): Promise<ReturnType<PublicInquiryAdmissionAuthority["claimPre"]>>;
  consumePost(input: Parameters<PublicInquiryAdmissionAuthority["consumePost"]>[0]): Promise<ReturnType<PublicInquiryAdmissionAuthority["consumePost"]>>;
  inspectLifecycle(digest: string): Promise<ReturnType<typeof inspectLifecycleAuthority>>;
};
type AuthorityNamespace = { getByName(name: string): AuthorityStub };

export type AdmissionServiceEnvironment = {
  AUTHORITY: AuthorityNamespace;
  VERCEL_OIDC_ISSUER: string; VERCEL_OIDC_AUDIENCE: string; VERCEL_OIDC_SUBJECT: string;
  VERCEL_OWNER_ID: string; VERCEL_PROJECT_ID: string;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  ADMISSION_CURRENT_RELEASE_ID: string; ADMISSION_CURRENT_KEY_ID: string; ADMISSION_CURRENT_RPC_KEY: string; ADMISSION_CURRENT_ACTIVATED_AT_MS: string;
  ADMISSION_PREVIOUS_RELEASE_ID?: string; ADMISSION_PREVIOUS_KEY_ID?: string; ADMISSION_PREVIOUS_RPC_KEY?: string;
  ADMISSION_PREVIOUS_ACTIVATED_AT_MS?: string; ADMISSION_PREVIOUS_RETIRE_AT_MS?: string;
  /** R06 signer bindings (secret channel). Each Authority class reads only its own environment's names; see authority-attestation-config.ts. */
  AUTHORITY_ATTESTATION_PRIVATE_KEY?: string; AUTHORITY_ATTESTATION_PUBLIC_KEY?: string; AUTHORITY_ATTESTATION_KEY_FINGERPRINT?: string;
  AUTHORITY_STAGING_ATTESTATION_PRIVATE_KEY?: string; AUTHORITY_STAGING_ATTESTATION_PUBLIC_KEY?: string; AUTHORITY_STAGING_ATTESTATION_KEY_FINGERPRINT?: string;
};

/** Production RPC adapter. Business/state-machine logic remains in the reviewed
 * core; this class exists only to attach that core to Cloudflare's DO runtime.
 * Lifecycle mutation is signed-result ONLY (R06 Slice 2C): there is no unsigned lifecycle mutation method on this class. */
export class ProductionAdmissionAuthority extends DurableObject<AdmissionServiceEnvironment> {
  private readonly operatorPublicKey: string;
  private readonly authority: PublicInquiryAdmissionAuthority;
  private readonly durableStorage: DurableStorageLike;
  private readonly attestation: AuthorityAttestationCoordinator;
  /** `attestationRuntime` (signer + Authority clock) is a construction seam for tests. The Durable Object runtime never
   * passes it: the signer then comes ONLY from this environment's production signer bindings, and an absent or malformed binding
   * leaves no signer, so every attested method answers UNAVAILABLE/signer-unconfigured before touching storage. */
  constructor(state: DurableObjectState, environment: AdmissionServiceEnvironment, attestationRuntime?: AuthorityAttestationRuntime) {
    super(state, environment);
    // Cloudflare's generic SQL cursor type is narrower than the core's testable
    // structural seam, while exposing the same exec/transactionSync operations.
    this.durableStorage = state.storage as unknown as DurableStorageLike;
    this.authority = new PublicInquiryAdmissionAuthority({ storage: this.durableStorage });
    this.operatorPublicKey = environment.AUTHORITY_OPERATOR_PUBLIC_KEY;
    this.attestation = new AuthorityAttestationCoordinator(this.durableStorage, PRODUCTION_ATTESTATION_IDENTITY, this.operatorPublicKey,
      attestationRuntime ?? authorityAttestationRuntimeFromEnvironment("production", environment));
  }

  /** Signed APPLIED envelope for the operator-authenticated initialization command. */
  async initializeFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    return this.attestation.initialize(command, signature);
  }

  async rotateReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string) {
    return this.attestation.rotate(command, signature);
  }

  /** Read-only fresh signed APPLIED evidence for an already-durable receipt. */
  async attestAppliedLifecycle(digest: string) {
    return this.attestation.attestAppliedLifecycle(digest);
  }

  /** Authority-signed reconciliation; the nonce is inside the signed statement. */
  async attestReconciliation(digest: string, nonce: string) {
    return this.attestation.attestReconciliation(digest, nonce);
  }

  async inspectLifecycle(digest: string) {
    return inspectLifecycleAuthority(this.durableStorage, digest);
  }

  async claimPre(input: Parameters<PublicInquiryAdmissionAuthority["claimPre"]>[0]) {
    return this.authority.claimPre(input);
  }

  async consumePost(input: Parameters<PublicInquiryAdmissionAuthority["consumePost"]>[0]) {
    return this.authority.consumePost(input);
  }

  override async alarm(): Promise<void> {
    await this.authority.alarm();
  }
}

/** The ONE runtime-secret gate for every admission entrypoint, mutating and read-only (the `admissionService` policy of
 * deployment/secret-matrix.json; the Production and staging admission Workers are both validated against it). */
const runtimeSecretsValid = (environment: AdmissionServiceEnvironment): boolean =>
  validateRuntimeSecrets("admissionService", environment as unknown as Record<string, unknown>);
/** Read-only attested entrypoints answer this (never a throw, never "receipt-not-found") when the gate fails, before the Authority is
 * reached. The pre-claim probe then stops a dispatch whose mutation entrypoint would deterministically fail the same gate AFTER a
 * claim was consumed. */
const RUNTIME_CONFIG_UNAVAILABLE = { status: "UNAVAILABLE", reason: "runtime-config-invalid" } as const;

let handlerPromise: Promise<(request: Request) => Promise<Response>> | undefined;
async function configure(environment: AdmissionServiceEnvironment) {
  const policy: VercelOidcPolicy = { issuer: environment.VERCEL_OIDC_ISSUER, audience: environment.VERCEL_OIDC_AUDIENCE,
    subject: environment.VERCEL_OIDC_SUBJECT, ownerId: environment.VERCEL_OWNER_ID, projectId: environment.VERCEL_PROJECT_ID };
  const releases: AdmissionServiceRelease[] = [{ role: "current", releaseId: environment.ADMISSION_CURRENT_RELEASE_ID,
    keyId: environment.ADMISSION_CURRENT_KEY_ID, rpcKey: await importAdmissionRpcKey(environment.ADMISSION_CURRENT_RPC_KEY),
    activatedAtMs: Number(environment.ADMISSION_CURRENT_ACTIVATED_AT_MS) }];
  const previousValues = [environment.ADMISSION_PREVIOUS_RELEASE_ID, environment.ADMISSION_PREVIOUS_KEY_ID, environment.ADMISSION_PREVIOUS_RPC_KEY,
    environment.ADMISSION_PREVIOUS_ACTIVATED_AT_MS, environment.ADMISSION_PREVIOUS_RETIRE_AT_MS];
  if (previousValues.some((value) => value !== undefined)) {
    if (previousValues.some((value) => value === undefined)) throw new Error("partial-previous-release");
    releases.push({ role: "previous", releaseId: previousValues[0]!, keyId: previousValues[1]!, rpcKey: await importAdmissionRpcKey(previousValues[2]!),
      activatedAtMs: Number(previousValues[3]), retireAtMs: Number(previousValues[4]) });
  }
  const authority = environment.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID);
  return createAdmissionService({ releases, oidcPolicy: policy, oidcVerifier: createVercelOidcVerifier(policy), authority });
}

export class AdmissionServiceWorker extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override async fetch(request: Request): Promise<Response> {
    try {
      if (!runtimeSecretsValid(this.env)) throw new Error("admission-secret-policy");
      handlerPromise ??= configure(this.env); return await (await handlerPromise)(request);
    }
    catch { return Response.json({ decision: "unavailable" }, { status: 503 }); }
  }
}

/** The executor binds only these two methods; public fetch has no dispatch path. Results are Authority-signed envelopes
 * (ATTESTED), refusals, or explicit non-positive UNAVAILABLE/AMBIGUOUS: never an unsigned positive. */
export class AuthorityLifecycleOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    if (!runtimeSecretsValid(this.env)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).initializeFromOperatorAttested(command, signature);
  }
  async rotateAuthorityReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string) {
    if (!runtimeSecretsValid(this.env)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).rotateReleaseFromOperatorAttested(command, signature);
  }
}

/** Narrow read capability: one fixed authority, SELECT-only. `inspectLifecycle` is the unsigned supervisory read used by guard
 * settlement and the Gate 4 continuity verifier; it is deliberately NOT gated. `attestAppliedLifecycle` / `attestReconciliation`
 * return Authority-signed envelopes and pass the same runtime-secret gate as the mutation entrypoints before the Authority is reached. */
export class AuthorityLifecycleReadOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async inspectLifecycle(digest: string) {
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).inspectLifecycle(digest);
  }
  async attestAppliedLifecycle(digest: string): Promise<AttestedRecoveryResult | typeof RUNTIME_CONFIG_UNAVAILABLE> {
    if (!runtimeSecretsValid(this.env)) return RUNTIME_CONFIG_UNAVAILABLE;
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).attestAppliedLifecycle(digest);
  }
  async attestReconciliation(digest: string, nonce: string): Promise<AttestedReconciliationResult | typeof RUNTIME_CONFIG_UNAVAILABLE> {
    if (!runtimeSecretsValid(this.env)) return RUNTIME_CONFIG_UNAVAILABLE;
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).attestReconciliation(digest, nonce);
  }
}

// ---------------------------------------------------------------------------
// Gate 2 staging capability. This is a physically separate Durable Object
// identity (STAGING_ADMISSION_AUTHORITY_ID), deployed as a separate rendered
// staging admission Worker binding a separate AUTHORITY namespace/object. It
// is never reachable from the Production entrypoints above and vice versa:
// AuthorityLifecycleOnly always resolves ADMISSION_AUTHORITY_ID, never the
// staging identity, and this DO's initializeFromOperator always requires
// expectedEnvironment "staging" (rejecting a Production-flagged artifact).
// Staging rotation is intentionally NOT IMPLEMENTED (Gate 9 — CLOSED): the
// rotate method below never parses, verifies or dispatches anything.
// ---------------------------------------------------------------------------

/** Staging RPC adapter, structurally identical to ProductionAdmissionAuthority
 * except for its pinned authority identity and permanently closed rotation. */
export class StagingAdmissionAuthority extends DurableObject<AdmissionServiceEnvironment> {
  private readonly operatorPublicKey: string;
  private readonly durableStorage: DurableStorageLike;
  private readonly attestation: AuthorityAttestationCoordinator;
  /** See ProductionAdmissionAuthority: `attestationRuntime` is a test seam; the deployed signer comes only from the STAGING
   * signer bindings (distinct names from Production's) and is absent when they are absent or malformed. */
  constructor(state: DurableObjectState, environment: AdmissionServiceEnvironment, attestationRuntime?: AuthorityAttestationRuntime) {
    super(state, environment);
    this.durableStorage = state.storage as unknown as DurableStorageLike;
    this.operatorPublicKey = environment.AUTHORITY_OPERATOR_PUBLIC_KEY;
    this.attestation = new AuthorityAttestationCoordinator(this.durableStorage, STAGING_ATTESTATION_IDENTITY, this.operatorPublicKey,
      attestationRuntime ?? authorityAttestationRuntimeFromEnvironment("staging", environment));
  }

  /** Staging-keyed signed APPLIED envelope. Staging has NO rotation attestation method at all. */
  async initializeFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    return this.attestation.initialize(command, signature);
  }

  async attestAppliedLifecycle(digest: string) {
    return this.attestation.attestAppliedLifecycle(digest);
  }

  async attestReconciliation(digest: string, nonce: string) {
    return this.attestation.attestReconciliation(digest, nonce);
  }

  /** STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED. No parsing, signature
   * verification or storage access occurs; every call fails closed. */
  async rotateReleaseFromOperator(): Promise<{ status: "refused" }> {
    return { status: "refused" };
  }

  async inspectLifecycle(digest: string) {
    return inspectLifecycleAuthority(this.durableStorage, digest, Date.now(), STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH);
  }
}

/** Staging executor binds only this entrypoint; it exposes the same lifecycle-only
 * surface as AuthorityLifecycleOnly, pinned to the distinct staging authority. */
export class StagingAuthorityLifecycleOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    if (!runtimeSecretsValid(this.env)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).initializeFromOperatorAttested(command, signature);
  }
  /** STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED. */
  async rotateAuthorityReleaseFromOperator(): Promise<{ status: "refused" }> {
    return { status: "refused" };
  }
}

/** Narrow staging read capability: one fixed staging authority, SELECT-only (see AuthorityLifecycleReadOnly). */
export class StagingAuthorityLifecycleReadOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async inspectLifecycle(digest: string) {
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).inspectLifecycle(digest);
  }
  async attestAppliedLifecycle(digest: string): Promise<AttestedRecoveryResult | typeof RUNTIME_CONFIG_UNAVAILABLE> {
    if (!runtimeSecretsValid(this.env)) return RUNTIME_CONFIG_UNAVAILABLE;
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).attestAppliedLifecycle(digest);
  }
  async attestReconciliation(digest: string, nonce: string): Promise<AttestedReconciliationResult | typeof RUNTIME_CONFIG_UNAVAILABLE> {
    if (!runtimeSecretsValid(this.env)) return RUNTIME_CONFIG_UNAVAILABLE;
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).attestReconciliation(digest, nonce);
  }
}

export default AdmissionServiceWorker;
