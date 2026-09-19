import { WorkerEntrypoint } from "cloudflare:workers";
import type { AuthorityInitializationCommand, AuthorityReleaseRotationCommand } from "../../../workers/admission-service/operator-command";
import type { AdmissionLifecycleBinding } from "../../../operator/lifecycle-submitter";

type Environment = { ADMISSION: AdmissionLifecycleBinding };
let count = 0;

/** Local-only binding proxy; measures entry into the final admission adapter. */
export class CountingAdmission extends WorkerEntrypoint<Environment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  getDispatchCount(): number { return count; }
  async initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string) {
    count++;
    return this.env.ADMISSION.initializeAuthorityFromOperator(command, signature);
  }
  async rotateAuthorityReleaseFromOperator(command: AuthorityReleaseRotationCommand, signature: string) {
    count++;
    return this.env.ADMISSION.rotateAuthorityReleaseFromOperator(command, signature);
  }
}
export default CountingAdmission;
