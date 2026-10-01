import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import type { DurableObjectState } from "@cloudflare/workers-types";
import { importAdmissionRpcKey } from "../../src/lib/admission-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID, inspectLifecycleAuthority, PublicInquiryAdmissionAuthority, type DurableStorageLike } from "./authority";
import {
  executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation,
  isLifecycleRefusal,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "./operator-command";
import {
  AuthorityAttestationCoordinator,
  PRODUCTION_ATTESTATION_IDENTITY,
  STAGING_ATTESTATION_IDENTITY,
  type AuthorityAttestationRuntime,
} from "./authority-attestation";
import { createVercelOidcVerifier, type VercelOidcPolicy } from "./auth";
import { createAdmissionService, type AdmissionServiceRelease } from "./service";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

export { PublicInquiryAdmissionAuthority } from "./authority";
export { createAdmissionService } from "./service";
export { createVercelOidcVerifier } from "./auth";

type AuthorityStub = {
  initializeFromOperator(command: AuthorityInitializationCommand, signature: string): Promise<{ status: "initialized" | "already-initialized" | "refused" }>;
  rotateReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string): Promise<{ status: "rotated" | "already-rotated" | "refused" }>;
  claimPre(input: Parameters<PublicInquiryAdmissionAuthority["claimPre"]>[0]): Promise<ReturnType<PublicInquiryAdmissionAuthority["claimPre"]>>;
  consumePost(input: Parameters<PublicInquiryAdmissionAuthority["consumePost"]>[0]): Promise<ReturnType<PublicInquiryAdmissionAuthority["consumePost"]>>;
  inspectLifecycle(digest: string): Promise<ReturnType<typeof inspectLifecycleAuthority>>;
};
type AuthorityNamespace = { getByName(name: string): AuthorityStub };

async function withLifecycleRefusal<T>(operation: () => Promise<T>): Promise<T | { status: "refused" }> {
  try { return await operation(); }
  catch (error) {
    if (isLifecycleRefusal(error)) return { status: "refused" };
    throw error;
  }
}

export type AdmissionServiceEnvironment = {
  AUTHORITY: AuthorityNamespace;
  VERCEL_OIDC_ISSUER: string; VERCEL_OIDC_AUDIENCE: string; VERCEL_OIDC_SUBJECT: string;
  VERCEL_OWNER_ID: string; VERCEL_PROJECT_ID: string;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  ADMISSION_CURRENT_RELEASE_ID: string; ADMISSION_CURRENT_KEY_ID: string; ADMISSION_CURRENT_RPC_KEY: string; ADMISSION_CURRENT_ACTIVATED_AT_MS: string;
  ADMISSION_PREVIOUS_RELEASE_ID?: string; ADMISSION_PREVIOUS_KEY_ID?: string; ADMISSION_PREVIOUS_RPC_KEY?: string;
  ADMISSION_PREVIOUS_ACTIVATED_AT_MS?: string; ADMISSION_PREVIOUS_RETIRE_AT_MS?: string;
};

/** Production RPC adapter. Business/state-machine logic remains in the reviewed
 * core; this class exists only to attach that core to Cloudflare's DO runtime. */
export class ProductionAdmissionAuthority extends DurableObject<AdmissionServiceEnvironment> {
  private readonly operatorPublicKey: string;
  private readonly authority: PublicInquiryAdmissionAuthority;
  private readonly durableStorage: DurableStorageLike;
  private readonly attestation: AuthorityAttestationCoordinator;
  /** `attestationRuntime` (signer + Authority clock) is a construction seam for tests. The Durable Object runtime never
   * passes it, and Slice 2A deliberately configures no signer from the environment, so in a deployed Authority every attested
   * method below answers UNAVAILABLE/signer-unconfigured before touching storage. */
  constructor(state: DurableObjectState, environment: AdmissionServiceEnvironment, attestationRuntime?: AuthorityAttestationRuntime) {
    super(state, environment);
    // Cloudflare's generic SQL cursor type is narrower than the core's testable
    // structural seam, while exposing the same exec/transactionSync operations.
    this.durableStorage = state.storage as unknown as DurableStorageLike;
    this.authority = new PublicInquiryAdmissionAuthority({ storage: this.durableStorage });
    this.operatorPublicKey = environment.AUTHORITY_OPERATOR_PUBLIC_KEY;
    this.attestation = new AuthorityAttestationCoordinator(this.durableStorage, PRODUCTION_ATTESTATION_IDENTITY, this.operatorPublicKey, attestationRuntime);
  }

  async initializeFromOperator(command: AuthorityInitializationCommand, signature: string) {
    return withLifecycleRefusal(() => executeSignedAuthorityInitialization(this.durableStorage, command, signature, this.operatorPublicKey, Date.now(), "production", Date.now));
  }

  /** R06 Slice 2A (inert): same command, signed APPLIED envelope. Not bound to any entrypoint or caller yet. */
  async initializeFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    return this.attestation.initialize(command, signature);
  }

  /** R06 Slice 2A (inert). */
  async rotateReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string) {
    return this.attestation.rotate(command, signature);
  }

  /** R06 Slice 2A (inert): read-only fresh signed APPLIED evidence for an already-durable receipt. */
  async attestAppliedLifecycle(digest: string) {
    return this.attestation.attestAppliedLifecycle(digest);
  }

  /** R06 Slice 2A (inert): Authority-signed reconciliation; the nonce is inside the signed statement. */
  async attestReconciliation(digest: string, nonce: string) {
    return this.attestation.attestReconciliation(digest, nonce);
  }

  async rotateReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string) {
    return withLifecycleRefusal(() => executeSignedAuthorityReleaseRotation(this.durableStorage, command, signature, this.operatorPublicKey, Date.now(), "production", Date.now));
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
      if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
      handlerPromise ??= configure(this.env); return await (await handlerPromise)(request);
    }
    catch { return Response.json({ decision: "unavailable" }, { status: 503 }); }
  }

  /** Operator service-binding RPC only; public fetch never dispatches here. */
  async initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string) {
    if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).initializeFromOperator(command, signature);
  }

  /** Operator service-binding RPC only; preserves the one fixed authority ID. */
  async rotateAuthorityReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string) {
    if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).rotateReleaseFromOperator(command, signature);
  }
}

/** The executor binds only these two methods; public fetch has no dispatch path. */
export class AuthorityLifecycleOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string) {
    if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).initializeFromOperator(command, signature);
  }
  async rotateAuthorityReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string) {
    if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).rotateReleaseFromOperator(command, signature);
  }
}

/** Narrow read capability: one fixed authority, one digest SELECT. */
export class AuthorityLifecycleReadOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async inspectLifecycle(digest: string) {
    return this.env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).inspectLifecycle(digest);
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
  /** See ProductionAdmissionAuthority: `attestationRuntime` is a test seam; none is configured from the environment. */
  constructor(state: DurableObjectState, environment: AdmissionServiceEnvironment, attestationRuntime?: AuthorityAttestationRuntime) {
    super(state, environment);
    this.durableStorage = state.storage as unknown as DurableStorageLike;
    this.operatorPublicKey = environment.AUTHORITY_OPERATOR_PUBLIC_KEY;
    this.attestation = new AuthorityAttestationCoordinator(this.durableStorage, STAGING_ATTESTATION_IDENTITY, this.operatorPublicKey, attestationRuntime);
  }

  async initializeFromOperator(command: AuthorityInitializationCommand, signature: string) {
    return withLifecycleRefusal(() => executeSignedAuthorityInitialization(this.durableStorage, command, signature, this.operatorPublicKey, Date.now(), "staging", Date.now));
  }

  /** R06 Slice 2A (inert): staging-keyed signed APPLIED envelope. Staging has NO rotation attestation method at all. */
  async initializeFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    return this.attestation.initialize(command, signature);
  }

  /** R06 Slice 2A (inert). */
  async attestAppliedLifecycle(digest: string) {
    return this.attestation.attestAppliedLifecycle(digest);
  }

  /** R06 Slice 2A (inert). */
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
  async initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string) {
    if (!validateRuntimeSecrets("admissionService", this.env as unknown as Record<string, unknown>)) throw new Error("admission-secret-policy");
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).initializeFromOperator(command, signature);
  }
  /** STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED. */
  async rotateAuthorityReleaseFromOperator(): Promise<{ status: "refused" }> {
    return { status: "refused" };
  }
}

/** Narrow staging read capability: one fixed staging authority, one digest SELECT. */
export class StagingAuthorityLifecycleReadOnly extends WorkerEntrypoint<AdmissionServiceEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async inspectLifecycle(digest: string) {
    return this.env.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID).inspectLifecycle(digest);
  }
}

export default AdmissionServiceWorker;
