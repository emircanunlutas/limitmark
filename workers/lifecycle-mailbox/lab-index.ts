import type { ScheduledEvent } from "@cloudflare/workers-types";
import { processLabSettlement, processLabInitializationSlot, type LabMailboxEnvironment } from "./lab-processor";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

/** Lab (third environment) mailbox. Fixed slots only; no "rotate-release.json" handler
 * exists (LAB ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED). */
const labLifecycleMailbox = {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(_event: ScheduledEvent, env: LabMailboxEnvironment): Promise<void> {
    if (!validateRuntimeSecrets("lifecycleMailbox", env as unknown as Record<string, unknown>)) return;
    for (const action of [() => processLabSettlement(env), () => processLabInitializationSlot(env)]) {
      try { await action(); } catch { /* Delayed polling does not retry a lifecycle RPC. */ }
    }
  },
};

export default labLifecycleMailbox;

export { LabLifecycleDispatchGuard } from "./lab-dispatch-guard";
