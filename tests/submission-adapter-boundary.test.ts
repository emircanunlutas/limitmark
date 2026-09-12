import assert from "node:assert/strict";
import test from "node:test";
import { requestSchema } from "../src/lib/request-schema";
import { submitToAdapter } from "../src/lib/submission-adapter";

const request = requestSchema.parse({
  name: "Synthetic Request",
  email: "qa@example.test",
  service: "web",
  system: "Disposable test target",
  objective: "Verify the runtime boundary",
  environment: "staging",
  authority: "authorized",
});
const token = "A".repeat(43);

test("Vercel Production can never return demo-accepted", async () => {
  const production = {
    NODE_ENV: "production",
    VERCEL: "1",
    VERCEL_ENV: "production",
    ALLOW_DEMO_SUBMISSIONS: "true",
  };
  assert.deepEqual(await submitToAdapter(request, token, undefined, production), { status: "unavailable" });
  assert.deepEqual(await submitToAdapter(request, token, undefined, {
    ...production, REQUEST_SUBMISSION_MODE: "demo",
  }), { status: "unavailable" });
});

test("intentional Preview and local demo flows remain non-persistent demo results", async () => {
  assert.deepEqual(await submitToAdapter(request, token, undefined, {
    NODE_ENV: "production", VERCEL: "1", VERCEL_ENV: "preview",
    REQUEST_SUBMISSION_MODE: "demo", ALLOW_DEMO_SUBMISSIONS: "true",
  }), { status: "demo-accepted" });
  assert.deepEqual(await submitToAdapter(request, token, undefined, {
    NODE_ENV: "development", REQUEST_SUBMISSION_MODE: "demo",
  }), { status: "demo-accepted" });
});
