import assert from "node:assert/strict";
import test from "node:test";
import { createLaboratoryRuntimeDependencies } from "../src/lib/public-inquiry-runtime.server";

const disabled = {
  LIMITMARK_RUNTIME: undefined,
  REQUEST_SUBMISSION_MODE: "postgres",
  ENABLE_PERSISTENT_SUBMISSIONS: "true",
};

test("laboratory runtime is disabled unless explicitly selected", async () => {
  assert.deepEqual(await createLaboratoryRuntimeDependencies(disabled), { enabled: false, reason: "disabled" });
});

test("laboratory runtime fails closed when required laboratory configuration is incomplete", async () => {
  assert.deepEqual(await createLaboratoryRuntimeDependencies({
    ...disabled,
    LIMITMARK_RUNTIME: "cloud-run-lab",
  }), { enabled: false, reason: "invalid" });
});

test("laboratory runtime rejects production credentials and test database configuration", async () => {
  const result = await createLaboratoryRuntimeDependencies({
    ...disabled,
    LIMITMARK_RUNTIME: "cloud-run-lab",
    DATABASE_URL: "postgresql://production.example/app",
    TEST_DATABASE_URL: "postgresql://test.example/app",
  });
  assert.deepEqual(result, { enabled: false, reason: "invalid" });
});

test("laboratory runtime rejects a database URL without a CA trust anchor", async () => {
  const result = await createLaboratoryRuntimeDependencies({
    ...disabled,
    LIMITMARK_RUNTIME: "cloud-run-lab",
    LAB_DATABASE_URL: "postgresql://lab@10.80.0.10/limitmark_lab",
  });
  assert.deepEqual(result, { enabled: false, reason: "invalid" });
});

test("laboratory runtime does not make an unauthenticated direct route available", async () => {
  const response = await import("../src/lib/public-inquiry-runtime.server").then(({ handleLaboratoryPublicInquiry }) =>
    handleLaboratoryPublicInquiry(new Request("https://lab.limitmark.test/api/public-inquiries", {
      method: "POST",
      body: "name=x",
      headers: { "content-type": "application/x-www-form-urlencoded" },
    }), disabled));
  assert.equal(response.status, 503);
});
