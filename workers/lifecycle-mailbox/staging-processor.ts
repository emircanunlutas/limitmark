import type { R2Bucket } from "@cloudflare/workers-types";
import type { GuardOutcome } from "./dispatch-guard";
import { boundedResult, parseControl, readBounded } from "./wire";

// Gate 2 staging capability. Only "initialize.json" is ever read here — there
// is deliberately no staging "rotate-release.json" handling anywhere in this
// file (STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED): even a
// misdelivered rotate artifact in the staging request bucket is never read.

export type StagingGuardStub = {
  processInitialization(artifact: string): Promise<GuardOutcome>;
  settle(digest: string): Promise<{ version: 1; settled: boolean }>;
};
export type StagingMailboxEnvironment = {
  REQUEST_BUCKET: R2Bucket;
  RESULT_BUCKET: R2Bucket;
  DISPATCH_GUARD: { getByName(name: string): StagingGuardStub };
};

export async function publishStaging(bucket: R2Bucket, key: string, value: object): Promise<void> {
  if (await bucket.head(key)) return;
  const written = await bucket.put(key, boundedResult(value));
  if (!written || typeof written !== "object" || written.key !== key)
    throw new Error("result-publication-unconfirmed");
}

export async function processStagingInitializationSlot(env: StagingMailboxEnvironment): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get("initialize.json"), 4_096);
  if (!bytes) return;
  const artifact = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (artifact.charCodeAt(0) === 0xfeff) return;
  const guard = env.DISPATCH_GUARD.getByName("staging-lifecycle-dispatch-v1");
  const outcome = await guard.processInitialization(artifact);
  if (outcome.status !== "UNAVAILABLE" && outcome.reason !== "consumed" && /^[a-f0-9]{64}$/u.test(outcome.digest))
    await publishStaging(env.RESULT_BUCKET, `lifecycle/${outcome.digest}.json`, { ...outcome, environment: "staging",
      authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now() });
}

export async function processStagingSettlement(env: StagingMailboxEnvironment): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get("settle.json"), 1_024);
  if (!bytes) return;
  const control = parseControl(bytes);
  const outcome = await env.DISPATCH_GUARD.getByName("staging-lifecycle-dispatch-v1").settle(control.digest);
  await publishStaging(env.RESULT_BUCKET, `settlement/${control.nonce}.json`, { ...outcome, digest: control.digest,
    nonce: control.nonce, environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    observedAtMs: Date.now() });
}
