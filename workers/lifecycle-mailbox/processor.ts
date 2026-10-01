import type { R2Bucket } from "@cloudflare/workers-types";
import type { GuardOutcome } from "./dispatch-guard";
import { unsignedDiagnostic } from "../../operator/attested-relay";
import { boundedResult, parseControl, publishSignedEnvelope, readBounded } from "./wire";

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
  if (!/^[a-f0-9]{64}$/u.test(outcome.digest)) return;
  const resultKey = `lifecycle/${outcome.digest}.json`;
  // Signed evidence is stored as the Authority's exact bytes. The relay neither reads nor adds any semantic to it.
  if (outcome.status === "ATTESTED") await publishSignedEnvelope(env.RESULT_BUCKET, resultKey, outcome.envelope);
  // An active different command is a temporary supervisory refusal. Do not
  // freeze it as the digest's immutable result before that digest is consumed.
  // Everything else is an explicit, unsigned, never-positive diagnostic.
  else if (outcome.status !== "UNAVAILABLE" && outcome.reason !== "consumed")
    await publish(env.RESULT_BUCKET, resultKey, unsignedDiagnostic(outcome.digest, outcome.status, outcome.reason));
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
