import { boundedResult, parseControl, readBounded } from "./lifecycle-mailbox/wire";
import type { R2Bucket, ScheduledEvent } from "@cloudflare/workers-types";
import { validateRuntimeSecrets } from "../deployment/secret-policy";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "../operator/lifecycle-observation";

export type StagingObserverEnvironment = {
  REQUEST_BUCKET: R2Bucket;
  RESULT_BUCKET: R2Bucket;
  LIFECYCLE_READER: { inspectLifecycle(digest: string): Promise<object> };
};

/** Reconstructs a nonce-scoped result using only the staging authority read capability. */
export async function observeStagingReconciliation(env: StagingObserverEnvironment): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get("reconcile.json"), 1_024);
  if (!bytes) return;
  const control = parseControl(bytes);
  const key = `reconciliation/${control.nonce}.json`;
  if (await env.RESULT_BUCKET.head(key)) return;
  const snapshot = await env.LIFECYCLE_READER.inspectLifecycle(control.digest);
  const observed = (snapshot as { status?: unknown }).status === UNAVAILABLE_AUTHORITY_OBSERVATION.status
    ? { version: 1, digest: control.digest, nonce: control.nonce, status: "UNAVAILABLE", environment: "staging",
      authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now() }
    : { version: 1, digest: control.digest, nonce: control.nonce, ...snapshot };
  const written = await env.RESULT_BUCKET.put(key, boundedResult(observed));
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
