import { WorkerEntrypoint } from "cloudflare:workers";

type Executor = { submitInitializationArtifact(sealed: string): Promise<unknown>; submitRotationArtifact(sealed: string): Promise<unknown> };
type Environment = { EXECUTOR: Executor; DROP_ACK: string; FAIL_BEFORE: string };
let count = 0;
export class CountingExecutor extends WorkerEntrypoint<Environment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  getDispatchCount(): number { return count; }
  async submitInitializationArtifact(sealed: string) {
    count++;
    if (this.env.FAIL_BEFORE === "true") throw new Error("injected-consumed-before-call");
    const result = await this.env.EXECUTOR.submitInitializationArtifact(sealed);
    if (this.env.DROP_ACK === "true") throw new Error("injected-lost-ack");
    return result;
  }
  async submitRotationArtifact(sealed: string) {
    count++;
    if (this.env.FAIL_BEFORE === "true") throw new Error("injected-consumed-before-call");
    const result = await this.env.EXECUTOR.submitRotationArtifact(sealed);
    if (this.env.DROP_ACK === "true") throw new Error("injected-lost-ack");
    return result;
  }
}
export default CountingExecutor;
