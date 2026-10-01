import { WorkerEntrypoint } from "cloudflare:workers";
import type { AuthorityInitializationCommand, AuthorityReleaseRotationCommand } from "../../../workers/admission-service/operator-command";

type Environment = {
  ADMISSION_SERVICE: {
    initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string): Promise<unknown>;
    rotateAuthorityReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string): Promise<unknown>;
  };
};

let dispatchCount = 0;
let dropNextAcknowledgement = true;

// Test-only service-binding hop. It throws only after the real admission RPC resolves.
export class OperatorAckLossProxy extends WorkerEntrypoint<Environment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }

  getDispatchCount(): number { return dispatchCount; }

  async initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string) {
    dispatchCount += 1;
    const result = await this.env.ADMISSION_SERVICE.initializeAuthorityFromOperatorAttested(command, signature);
    if (dropNextAcknowledgement) {
      dropNextAcknowledgement = false;
      throw new Error("test-acknowledgement-lost-after-commit");
    }
    return result;
  }

  async rotateAuthorityReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string) {
    dispatchCount += 1;
    return this.env.ADMISSION_SERVICE.rotateAuthorityReleaseFromOperatorAttested(command, signature);
  }
}

export default OperatorAckLossProxy;
