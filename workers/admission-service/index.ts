import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import type { DurableObjectState } from "@cloudflare/workers-types";
import { importAdmissionRpcKey } from "../../src/lib/admission-protocol";
import { ADMISSION_AUTHORITY_ID, PublicInquiryAdmissionAuthority, type DurableStorageLike } from "./authority";
import {
  executeSignedAuthorityInitialization,
  executeSignedAuthorityReleaseRotation,
  type AuthorityInitializationCommand,
  type AuthorityReleaseRotationCommand,
} from "./operator-command";
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
};
type AuthorityNamespace = { getByName(name: string): AuthorityStub };

const lifecycleRefusals = new Set(["operator-command", "operator-signature", "operator-command-freshness", "initialization-policy",
  "authority-already-initialized", "release-rotation-policy", "authority-mismatch", "release-already-exists", "release-retention", "release-state"]);

async function withLifecycleRefusal<T>(operation: () => Promise<T>): Promise<T | { status: "refused" }> {
  try { return await operation(); }
  catch (error) {
    if (error instanceof Error && lifecycleRefusals.has(error.message)) return { status: "refused" };
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
  constructor(state: DurableObjectState, environment: AdmissionServiceEnvironment) {
    super(state, environment);
    // Cloudflare's generic SQL cursor type is narrower than the core's testable
    // structural seam, while exposing the same exec/transactionSync operations.
    this.durableStorage = state.storage as unknown as DurableStorageLike;
    this.authority = new PublicInquiryAdmissionAuthority({ storage: this.durableStorage });
    this.operatorPublicKey = environment.AUTHORITY_OPERATOR_PUBLIC_KEY;
  }

  async initializeFromOperator(command: AuthorityInitializationCommand, signature: string) {
    return withLifecycleRefusal(() => executeSignedAuthorityInitialization(this.durableStorage, command, signature, this.operatorPublicKey, Date.now()));
  }

  async rotateReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string) {
    return withLifecycleRefusal(() => executeSignedAuthorityReleaseRotation(this.durableStorage, command, signature, this.operatorPublicKey, Date.now()));
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

export default AdmissionServiceWorker;
