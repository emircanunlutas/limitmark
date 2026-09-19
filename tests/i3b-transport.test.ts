import assert from "node:assert/strict";
import { test } from "node:test";
import { oneR2Request, type R2Sender } from "../operator/r2-transport";

const target = { accountId: "a".repeat(32), bucket: "limitmark-lifecycle-requests-production" };
const credential = { accessKeyId: "synthetic-access", secretAccessKey: "synthetic-secret" };
const body = new TextEncoder().encode("sealed-test-only");

test("one SigV4 PUT pins HTTPS endpoint, bucket, key and timeout", async () => {
  let calls = 0;
  const send: R2Sender = async (options, requestBody) => {
    calls++;
    assert.equal(options.protocol, "https:");
    assert.equal(options.hostname, `${target.accountId}.r2.cloudflarestorage.com`);
    assert.equal(options.path, `/${target.bucket}/initialize.json`);
    assert.equal(options.method, "PUT");
    assert.equal(options.timeout, 10_000);
    assert.deepEqual(requestBody, body);
    const headers = options.headers as Record<string, string>;
    assert.match(headers.authorization, /^AWS4-HMAC-SHA256 Credential=synthetic-access\/20260919\/auto\/s3\/aws4_request,/u);
    assert.equal(headers["content-length"], String(body.length));
    return { statusCode: 200, body: new Uint8Array() };
  };
  await oneR2Request("PUT", target, credential, "initialize.json", body, 8_192, new Date("2026-09-19T12:00:00.000Z"), send);
  assert.equal(calls, 1);
});

test("429, 5xx, redirect, reset and timeout never cause another PUT", async () => {
  for (const fault of [429, 500, 503, 302, "reset", "timeout"] as const) {
    let calls = 0;
    const send: R2Sender = async () => {
      calls++;
      if (typeof fault === "string") throw new Error(fault);
      return { statusCode: fault, body: new Uint8Array() };
    };
    if (typeof fault === "string") await assert.rejects(() => oneR2Request("PUT", target, credential, "rotate-release.json", body,
      1_024, new Date("2026-09-19T12:00:00.000Z"), send));
    else assert.equal((await oneR2Request("PUT", target, credential, "rotate-release.json", body,
      1_024, new Date("2026-09-19T12:00:00.000Z"), send)).statusCode, fault);
    assert.equal(calls, 1, String(fault));
  }
});
