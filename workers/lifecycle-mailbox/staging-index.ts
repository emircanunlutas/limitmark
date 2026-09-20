import type { ScheduledEvent } from "@cloudflare/workers-types";
import { processStagingSettlement, processStagingInitializationSlot, type StagingMailboxEnvironment } from "./staging-processor";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

/** Gate 2 staging mailbox. Fixed slots only; no "rotate-release.json" handler
 * exists (STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED). */
const stagingLifecycleMailbox = {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(_event: ScheduledEvent, env: StagingMailboxEnvironment): Promise<void> {
    if (!validateRuntimeSecrets("lifecycleMailbox", env as unknown as Record<string, unknown>)) return;
    for (const action of [() => processStagingSettlement(env), () => processStagingInitializationSlot(env)]) {
      try { await action(); } catch { /* Delayed polling does not retry a lifecycle RPC. */ }
    }
  },
};

export default stagingLifecycleMailbox;

export { StagingLifecycleDispatchGuard } from "./staging-dispatch-guard";
