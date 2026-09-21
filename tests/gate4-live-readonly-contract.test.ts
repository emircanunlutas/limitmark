import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  LIVE_READONLY_OBSERVATION_FRESHNESS_MS,
  validateNeverInitializedStagingLifecycleSnapshot,
  validateStagingLiveReadonlyHarnessConfig,
} from "../deployment/lifecycle-private-contract";

// Gate 4B: local-only proof that the never-initialized snapshot contract
// rejects every mismatch (including a live "initialized" authority, wrong
// environment/authority/epoch, and a receipt/release presence that Gate 4
// must never observe against a never-initialized authority) and that it never
// repairs, retries or falls back -- it only ever throws or returns. This does
// not and cannot prove live Cloudflare/remote-binding behavior; it proves the
// operator-side check that will be applied to whatever the live harness
// returns.

const root = fileURLToPath(new URL("../", import.meta.url));
const now = 1_800_000_000_000;
const neverInitialized = { version: 1, environment: "staging", authorityId: "staging-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: now, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND",
  receipt: null, releases: [] as unknown[] };

test("never-initialized staging snapshot contract accepts only the exact expected shape", () => {
  assert.doesNotThrow(() => validateNeverInitializedStagingLifecycleSnapshot(neverInitialized, now));
  const reject = (mutate: (v: Record<string, unknown>) => void, nowMs = now) => {
    const value = { ...neverInitialized }; mutate(value);
    assert.throws(() => validateNeverInitializedStagingLifecycleSnapshot(value, nowMs), /unsafe-live-readonly/u);
  };
  reject((v) => { v.version = 2; });
  reject((v) => { v.environment = "production"; });
  reject((v) => { v.authorityId = "production-public-inquiries-v1"; });
  reject((v) => { v.authorityId = "wrong-authority"; });
  reject((v) => { v.policyEpoch = "phase5c-i1-epoch-2"; });
  reject((v) => { v.initialized = true; }); // a live authority someone already initialized must never pass Gate 4's never-initialized proof
  reject((v) => { v.coverage = "INCOMPLETE"; });
  reject((v) => { v.status = "HISTORY_INCOMPLETE"; });
  reject((v) => { v.status = "UNAVAILABLE"; });
  reject((v) => { v.status = "EXACT_RECEIPT"; });
  reject((v) => { v.receipt = { digest: "x" }; }); // any receipt presence must be rejected, never trusted or merged
  reject((v) => { v.releases = [{ releaseId: "r", keyId: "k", activatedMs: 1, retiredMs: null }]; });
  reject((v) => { delete v.observedAtMs; });
  reject((v) => { v.observedAtMs = "not-a-number"; });
  reject((v) => { v.observedAtMs = -1; });
  reject((v) => { v.observedAtMs = now - LIVE_READONLY_OBSERVATION_FRESHNESS_MS - 1; });
  reject((v) => { v.observedAtMs = now + LIVE_READONLY_OBSERVATION_FRESHNESS_MS + 1; });
  reject((v) => { v.extra = "unexpected"; });
  reject((v) => { delete v.coverage; });
  assert.throws(() => validateNeverInitializedStagingLifecycleSnapshot(null), /unsafe-live-readonly/u);
  assert.throws(() => validateNeverInitializedStagingLifecycleSnapshot("not-an-object"), /unsafe-live-readonly/u);
  assert.throws(() => validateNeverInitializedStagingLifecycleSnapshot([]), /unsafe-live-readonly/u);
});

test("live-readonly harness config is the exact closed, single-remote-binding shape", async () => {
  const config = JSON.parse(await readFile(join(root, "wrangler.staging-admission-live-readonly.local.jsonc"), "utf8")) as Record<string, unknown>;
  assert.doesNotThrow(() => validateStagingLiveReadonlyHarnessConfig(config));
  const reject = (mutate: (c: Record<string, unknown>) => void) => {
    const mutated = JSON.parse(JSON.stringify(config)) as Record<string, unknown>; mutate(mutated);
    assert.throws(() => validateStagingLiveReadonlyHarnessConfig(mutated), /unsafe-live-readonly-harness/u);
  };
  reject((c) => { c.workers_dev = true; });
  reject((c) => { c.preview_urls = true; });
  reject((c) => { c.routes = [{ pattern: "example.com/*" }]; });
  reject((c) => { c.account_id = "a".repeat(32); });
  reject((c) => { c.durable_objects = { bindings: [] }; });
  reject((c) => { c.r2_buckets = []; });
  reject((c) => { c.triggers = { crons: ["* * * * *"] }; });
  reject((c) => { (c.services as unknown[]).push({ binding: "EXTRA", service: "other" }); });
  reject((c) => { (c.services as Array<Record<string, unknown>>)[0].remote = false; });
  reject((c) => { (c.services as Array<Record<string, unknown>>)[0].entrypoint = "StagingAuthorityLifecycleOnly"; });
  reject((c) => { (c.services as Array<Record<string, unknown>>)[0].service = "limitmark-admission-service-production"; });
});

test("live-readonly harness source has no write-entrypoint or lifecycle-only reference", async () => {
  const source = await readFile(join(root, "workers", "staging-admission-live-readonly-harness.ts"), "utf8");
  for (const forbidden of ["LifecycleOnly", "initializeAuthorityFromOperator", "rotateAuthorityReleaseFromOperator", "AUTHORITY_OPERATOR_PUBLIC_KEY"])
    assert.ok(!source.includes(forbidden), `harness source must never reference ${forbidden}`);
});
