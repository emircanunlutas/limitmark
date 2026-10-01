import { boundedResult, parseControl, publishSignedEnvelope, readBounded } from "./lifecycle-mailbox/wire";
import type { R2Bucket, ScheduledEvent } from "@cloudflare/workers-types";
import { validateRuntimeSecrets } from "../deployment/secret-policy";
import { normalizeReconciliationRelayResult, unsignedDiagnostic } from "../operator/attested-relay";

export type StagingObserverEnvironment = {
  REQUEST_BUCKET: R2Bucket;
  RESULT_BUCKET: R2Bucket;
  /** The staging Authority-signed reconciliation capability. The observer holds no unsigned read and constructs no Authority semantics. */
  LIFECYCLE_READER: { attestReconciliation(digest: string, nonce: string): Promise<unknown> };
};

/** A DUMB RELAY. It forwards the caller's exact digest and nonce to the Authority and stores the signed envelope bytes the
 * Authority returns, untouched. It never builds initialized/coverage/status/receipt/releases/observedAtMs: those are signed
 * Authority semantics. Without signed evidence it stores only an explicit unsigned, never-positive diagnostic. */
export async function observeStagingReconciliation(env: StagingObserverEnvironment): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get("reconcile.json"), 1_024);
  if (!bytes) return;
  const control = parseControl(bytes);
  const key = `reconciliation/${control.nonce}.json`;
  if (await env.RESULT_BUCKET.head(key)) return;
  const answer = normalizeReconciliationRelayResult(await env.LIFECYCLE_READER.attestReconciliation(control.digest, control.nonce));
  if (answer.status === "ATTESTED") { await publishSignedEnvelope(env.RESULT_BUCKET, key, answer.envelope); return; }
  const diagnostic = unsignedDiagnostic(control.digest, answer.status === "UNCONFIRMED" ? "UNCONFIRMED" : answer.status,
    answer.status === "UNAVAILABLE" ? answer.reason : undefined, control.nonce);
  const written = await env.RESULT_BUCKET.put(key, boundedResult(diagnostic));
  if (!written || typeof written !== "object" || written.key !== key)
    throw new Error("reconciliation-publication-unconfirmed");
}

const stagingLifecycleObserver = {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(_event: ScheduledEvent, env: StagingObserverEnvironment): Promise<void> {
    if (!validateRuntimeSecrets("lifecycleObserver", env as unknown as Record<string, unknown>)) return;
    try { await observeStagingReconciliation(env); }
    catch { /* Read-only observation may be requested again with a new nonce. */ }
  },
};

export default stagingLifecycleObserver;
