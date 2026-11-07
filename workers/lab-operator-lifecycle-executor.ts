import { WorkerEntrypoint } from "cloudflare:workers";
import { MAX_SEALED_ARTIFACT_BYTES, submitSealedLifecycleArtifact, type LabAdmissionLifecycleBinding } from "../operator/lifecycle-submitter";
import { validateRuntimeSecrets } from "../deployment/secret-policy";

// The bound entrypoint (LabAuthorityLifecycleOnly) exposes the attested initialization method and a
// rotation stub that always refuses (Gate 9 — CLOSED). This executor binds and calls only initialization:
// submitInitializationArtifact is the only method exported below.
type LabExecutorEnvironment = {
  ADMISSION_SERVICE: LabAdmissionLifecycleBinding;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  OPERATOR_EXECUTOR_ENVIRONMENT: string;
};

/** Lab (third environment) capability. Private service-binding RPC seam; no public
 * dispatch. There is deliberately no `submitRotationArtifact` method at all
 * (LAB ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED): the RPC surface
 * itself does not expose it, so even a misconfigured caller fails closed with
 * "no such method" rather than reaching any lifecycle logic. */
export class LabOperatorLifecycleExecutor extends WorkerEntrypoint<LabExecutorEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }

  async submitInitializationArtifact(sealedJson: string) {
    if (this.env.OPERATOR_EXECUTOR_ENVIRONMENT !== "lab" || !validateRuntimeSecrets("operatorExecutor", this.env as unknown as Record<string, unknown>)) throw new Error("invalid-executor-environment");
    return submitSealedLifecycleArtifact(encodeBounded(sealedJson), "initialize", this.env.ADMISSION_SERVICE, this.env.AUTHORITY_OPERATOR_PUBLIC_KEY, Date.now(), "lab");
  }
}

function encodeBounded(value: string): Uint8Array {
  if (typeof value !== "string" || value.length > MAX_SEALED_ARTIFACT_BYTES) throw new Error("invalid-sealed-artifact");
  return new TextEncoder().encode(value);
}

export default LabOperatorLifecycleExecutor;
