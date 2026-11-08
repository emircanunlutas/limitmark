import { boundedResult, parseControl, publishSignedEnvelope, readBounded } from "./lifecycle-mailbox/wire";
import type { R2Bucket, ScheduledEvent } from "@cloudflare/workers-types";
import { validateRuntimeSecrets } from "../deployment/secret-policy";
import { normalizeReconciliationRelayResult, unsignedDiagnostic } from "../operator/attested-relay";

export type LabObserverEnvironment = {
  REQUEST_BUCKET: R2Bucket;
  RESULT_BUCKET: R2Bucket;
  /** The lab Authority-signed reconciliation capability. The observer holds no unsigned read and constructs no Authority semantics. */
  LIFECYCLE_READER: { attestReconciliation(digest: string, nonce: string): Promise<unknown> };
  /** Required lab marker (deployment var). Anything but the exact string "lab" is refused before any storage access. */
  LIFECYCLE_OBSERVER_ENVIRONMENT?: unknown;
};

/** The marker is declarative (a Worker cannot read its own bucket names): it stops a lab bundle from running under a configuration that does not declare the lab environment. The Authority's own authorization is the decisive boundary. */
export const labObserverEnvironmentValid = (env: { LIFECYCLE_OBSERVER_ENVIRONMENT?: unknown }): boolean => env.LIFECYCLE_OBSERVER_ENVIRONMENT === "lab";

/** A DUMB RELAY. It forwards the caller's exact digest and nonce to the Authority and stores the signed envelope bytes the
 * Authority returns, untouched. It never builds initialized/coverage/status/receipt/releases/observedAtMs: those are signed
 * Authority semantics. Without signed evidence it stores only an explicit unsigned, never-positive diagnostic. */
export async function observeLabReconciliation(env: LabObserverEnvironment): Promise<void> {
  if (!labObserverEnvironmentValid(env)) throw new Error("invalid-observer-environment"); // before any bucket or Authority access
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

const labLifecycleObserver = {
  fetch(): Response { return new Response(null, { status: 404 }); },
  async scheduled(_event: ScheduledEvent, env: LabObserverEnvironment): Promise<void> {
    if (!labObserverEnvironmentValid(env) || !validateRuntimeSecrets("lifecycleObserver", env as unknown as Record<string, unknown>)) return;
    try { await observeLabReconciliation(env); }
    catch { /* Read-only observation may be requested again with a new nonce. */ }
  },
};

export default labLifecycleObserver;
