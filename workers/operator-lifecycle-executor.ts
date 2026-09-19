import { WorkerEntrypoint } from "cloudflare:workers";
import { MAX_SEALED_ARTIFACT_BYTES, submitSealedLifecycleArtifact, type AdmissionLifecycleBinding } from "../operator/lifecycle-submitter";
import { validateRuntimeSecrets } from "../deployment/secret-policy";

type ExecutorEnvironment = {
  ADMISSION_SERVICE: AdmissionLifecycleBinding;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  OPERATOR_EXECUTOR_ENVIRONMENT: string;
};

/** Private service-binding RPC seam. There is deliberately no public dispatch. */
export class OperatorLifecycleExecutor extends WorkerEntrypoint<ExecutorEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }

  async submitInitializationArtifact(sealedJson: string) {
    if (this.env.OPERATOR_EXECUTOR_ENVIRONMENT !== "production" || !validateRuntimeSecrets("operatorExecutor", this.env as unknown as Record<string, unknown>)) throw new Error("invalid-executor-environment");
    return submitSealedLifecycleArtifact(encodeBounded(sealedJson), "initialize", this.env.ADMISSION_SERVICE, this.env.AUTHORITY_OPERATOR_PUBLIC_KEY);
  }

  async submitRotationArtifact(sealedJson: string) {
    if (this.env.OPERATOR_EXECUTOR_ENVIRONMENT !== "production" || !validateRuntimeSecrets("operatorExecutor", this.env as unknown as Record<string, unknown>)) throw new Error("invalid-executor-environment");
    return submitSealedLifecycleArtifact(encodeBounded(sealedJson), "rotate-release", this.env.ADMISSION_SERVICE, this.env.AUTHORITY_OPERATOR_PUBLIC_KEY);
  }
}

function encodeBounded(value: string): Uint8Array {
  if (typeof value !== "string" || value.length > MAX_SEALED_ARTIFACT_BYTES) throw new Error("invalid-sealed-artifact");
  return new TextEncoder().encode(value);
}

export default OperatorLifecycleExecutor;
