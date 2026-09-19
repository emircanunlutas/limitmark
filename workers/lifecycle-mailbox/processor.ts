import type { R2Bucket } from "@cloudflare/workers-types";
import type { GuardOutcome } from "./dispatch-guard";
import { boundedResult, parseControl, readBounded } from "./wire";

export type GuardStub = {
  processInitialization(artifact: string): Promise<GuardOutcome>;
  processRotation(artifact: string): Promise<GuardOutcome>;
  settle(digest: string): Promise<{ version: 1; settled: boolean }>;
};
export type MailboxEnvironment = {
  REQUEST_BUCKET: R2Bucket;
  RESULT_BUCKET: R2Bucket;
  DISPATCH_GUARD: { getByName(name: string): GuardStub };
};

export async function publish(bucket: R2Bucket, key: string, value: object): Promise<void> {
  // A failed or malformed acknowledgement is transport ambiguity, never a
  // lifecycle refusal. No caller of this function enters mutation dispatch.
  if (await bucket.head(key)) return;
  const written = await bucket.put(key, boundedResult(value));
  if (!written || typeof written !== "object" || written.key !== key)
    throw new Error("result-publication-unconfirmed");
}

export async function processSlot(env: MailboxEnvironment, key: "initialize.json" | "rotate-release.json"): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get(key), 4_096);
  if (!bytes) return;
  const artifact = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (artifact.charCodeAt(0) === 0xfeff) return;
  const guard = env.DISPATCH_GUARD.getByName("production-lifecycle-dispatch-v1");
  const outcome = key === "initialize.json" ? await guard.processInitialization(artifact) : await guard.processRotation(artifact);
  // An active different command is a temporary supervisory refusal. Do not
  // freeze it as the digest's immutable result before that digest is consumed.
  if (outcome.status !== "UNAVAILABLE" && outcome.reason !== "consumed" && /^[a-f0-9]{64}$/u.test(outcome.digest))
    await publish(env.RESULT_BUCKET, `lifecycle/${outcome.digest}.json`, { ...outcome, environment: "production",
      authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now() });
}

export async function processSettlement(env: MailboxEnvironment): Promise<void> {
  const bytes = await readBounded(await env.REQUEST_BUCKET.get("settle.json"), 1_024);
  if (!bytes) return;
  const control = parseControl(bytes);
  const outcome = await env.DISPATCH_GUARD.getByName("production-lifecycle-dispatch-v1").settle(control.digest);
  await publish(env.RESULT_BUCKET, `settlement/${control.nonce}.json`, { ...outcome, digest: control.digest,
    nonce: control.nonce, environment: "production", authorityId: "production-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    observedAtMs: Date.now() });
}
