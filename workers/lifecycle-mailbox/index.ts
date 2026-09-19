import type { ScheduledEvent } from "@cloudflare/workers-types";
import { processSettlement, processSlot, type MailboxEnvironment } from "./processor";
import { validateRuntimeSecrets } from "../../deployment/secret-policy";

/** Fixed slots only. Each scheduled event can be delivered repeatedly. */
const lifecycleMailbox = {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(_event: ScheduledEvent, env: MailboxEnvironment): Promise<void> {
    if (!validateRuntimeSecrets("lifecycleMailbox", env as unknown as Record<string, unknown>)) return;
    for (const action of [() => processSettlement(env), () => processSlot(env, "initialize.json"), () => processSlot(env, "rotate-release.json")]) {
      try { await action(); } catch { /* Delayed polling does not retry a lifecycle RPC. */ }
    }
  },
};

export default lifecycleMailbox;

export { LifecycleDispatchGuard } from "./dispatch-guard";
