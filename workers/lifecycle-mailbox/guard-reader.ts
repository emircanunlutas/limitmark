import { WorkerEntrypoint } from "cloudflare:workers";
import { GUARD_OBJECT_NAME } from "./dispatch-guard";
import type { GuardExportOutcome } from "./guard-export";

/**
 * Read-only service entrypoint over the dispatch guard. A caller holding a service binding to THIS entrypoint can invoke exactly one method,
 * `exportLedger`; it cannot reach `processInitialization`, `processRotation` or `settle`, and it holds no Durable Object, executor or R2 binding of
 * its own beyond what this Worker already has. The guard authenticates the operator-signed request itself, so this class adds no authorization
 * semantics: it only narrows the callable surface (the same pattern as AuthorityLifecycleReadOnly).
 */
export type GuardReaderEnvironment = {
  DISPATCH_GUARD: { getByName(name: string): { exportLedger(envelopeJson: string): Promise<GuardExportOutcome> } };
};

export class LifecycleGuardReadOnly extends WorkerEntrypoint<GuardReaderEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  async exportLedger(envelopeJson: string): Promise<GuardExportOutcome> {
    return this.env.DISPATCH_GUARD.getByName(GUARD_OBJECT_NAME).exportLedger(envelopeJson);
  }
}
