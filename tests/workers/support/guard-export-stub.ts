import { WorkerEntrypoint } from "cloudflare:workers";

// Inert stand-in for the executor and the read-only Authority entrypoint in the guard-export integration. Any call is a test failure signal:
// the export path must never reach either binding. It records nothing; a call simply throws a recognizable error and counts via a global.
let calls = 0;
export class Inert extends WorkerEntrypoint {
  override fetch(): Response { return Response.json({ calls }); }
  async submitInitializationArtifact(): Promise<never> { calls += 1; throw new Error("inert-called"); }
  async submitRotationArtifact(): Promise<never> { calls += 1; throw new Error("inert-called"); }
  async inspectLifecycle(): Promise<never> { calls += 1; throw new Error("inert-called"); }
  async attestAppliedLifecycle(): Promise<never> { calls += 1; throw new Error("inert-called"); }
  async attestReconciliation(): Promise<never> { calls += 1; throw new Error("inert-called"); }
  async getCalls(): Promise<number> { return calls; }
}
export default { fetch(): Response { return Response.json({ calls }); } };
