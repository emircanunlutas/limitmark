import { WorkerEntrypoint } from "cloudflare:workers";
import { MAX_SEALED_ARTIFACT_BYTES, submitSealedLifecycleArtifact, type AdmissionLifecycleBinding } from "../operator/lifecycle-submitter";
import { validateRuntimeSecrets } from "../deployment/secret-policy";

// The bound entrypoint (StagingAuthorityLifecycleOnly) exposes both methods;
// rotateAuthorityReleaseFromOperator always refuses (Gate 9 — CLOSED). This
// executor itself never calls it: submitInitializationArtifact is the only
// method exported below.
type StagingExecutorEnvironment = {
  ADMISSION_SERVICE: AdmissionLifecycleBinding;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  OPERATOR_EXECUTOR_ENVIRONMENT: string;
};

/** Gate 2 staging capability. Private service-binding RPC seam; no public
 * dispatch. There is deliberately no `submitRotationArtifact` method at all
 * (STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED): the RPC surface
 * itself does not expose it, so even a misconfigured caller fails closed with
 * "no such method" rather than reaching any lifecycle logic. */
export class StagingOperatorLifecycleExecutor extends WorkerEntrypoint<StagingExecutorEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }

  async submitInitializationArtifact(sealedJson: string) {
    if (this.env.OPERATOR_EXECUTOR_ENVIRONMENT !== "staging" || !validateRuntimeSecrets("operatorExecutor", this.env as unknown as Record<string, unknown>)) throw new Error("invalid-executor-environment");
    return submitSealedLifecycleArtifact(encodeBounded(sealedJson), "initialize", this.env.ADMISSION_SERVICE, this.env.AUTHORITY_OPERATOR_PUBLIC_KEY, Date.now(), "staging");
  }
}

function encodeBounded(value: string): Uint8Array {
  if (typeof value !== "string" || value.length > MAX_SEALED_ARTIFACT_BYTES) throw new Error("invalid-sealed-artifact");
  return new TextEncoder().encode(value);
}

export default StagingOperatorLifecycleExecutor;
