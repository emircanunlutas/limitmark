import assert from "node:assert/strict";
import { test } from "node:test";
import { createCliResultHarness } from "./workers/support/i3b-cli-result-harness";

const digest = "a".repeat(64);
const nonce = "b".repeat(32);
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const envelope = () => ({ version: 1, digest, environment: "production", authorityId: "production-public-inquiries-v1",
  policyEpoch: "phase5c-i1-epoch-1", observedAtMs: Date.now(), status: "UNCONFIRMED" });

test("actual CLI read-result treats malformed, stale and mismatched HTTP-200 observations as UNCONFIRMED", async () => {
  const cli = await createCliResultHarness();
  try {
    const cases = [
      new TextEncoder().encode("{"),
      encode({ ...envelope(), extra: true }),
      encode({ ...envelope(), observedAtMs: Date.now() - 300_001 }),
      encode({ ...envelope(), digest: "c".repeat(64) }),
      encode({ ...envelope(), environment: "staging" }),
      encode({ ...envelope(), authorityId: "other" }),
      encode({ ...envelope(), policyEpoch: "other" }),
      encode({ ...envelope(), version: 2 }),
    ];
    for (const bytes of cases) {
      const result = await cli.run(bytes, "lifecycle", digest);
      assert.equal(result.exitCode, 3, result.stderr);
      assert.equal((JSON.parse(result.stdout) as { status: string }).status, "UNCONFIRMED");
      assert.deepEqual(result.methods, ["GET"], "reading a result never submits a mutation");
    }
    const wrongNonce = encode({ ...envelope(), nonce: "c".repeat(32), status: "UNAVAILABLE" });
    const result = await cli.run(wrongNonce, "reconciliation", digest, nonce);
    assert.equal(result.exitCode, 3, result.stderr);
    assert.equal((JSON.parse(result.stdout) as { status: string }).status, "UNCONFIRMED");
    assert.deepEqual(result.methods, ["GET"]);
  } finally { await cli.dispose(); }
});
