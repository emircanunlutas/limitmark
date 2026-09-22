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

// Gate 6C: DELETE reuses the exact same SigV4/path-style request the PUT and
// GET tests above already prove -- no second signer, no arbitrary method.

test("one SigV4 DELETE pins the same HTTPS endpoint/path/timeout shape as GET, with no body", async () => {
  let calls = 0;
  const key = "gate6-iam-test/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json";
  const send: R2Sender = async (options, requestBody) => {
    calls++;
    assert.equal(options.protocol, "https:");
    assert.equal(options.hostname, `${target.accountId}.r2.cloudflarestorage.com`);
    assert.equal(options.path, `/${target.bucket}/${key}`);
    assert.equal(options.method, "DELETE");
    assert.equal(options.timeout, 10_000);
    assert.equal(requestBody, undefined);
    const headers = options.headers as Record<string, string>;
    assert.equal(headers["content-length"], undefined, "a DELETE request must never carry a body/content-length");
    assert.match(headers.authorization, /^AWS4-HMAC-SHA256 Credential=synthetic-access\/20260919\/auto\/s3\/aws4_request,/u);
    return { statusCode: 403, body: new Uint8Array() };
  };
  const response = await oneR2Request("DELETE", target, credential, key, undefined, 1_024, new Date("2026-09-19T12:00:00.000Z"), send);
  assert.equal(response.statusCode, 403);
  assert.equal(calls, 1);
});

test("a DELETE carrying a body, or a PUT with none, is refused before any request is sent", async () => {
  let calls = 0;
  const send: R2Sender = async () => { calls++; return { statusCode: 200, body: new Uint8Array() }; };
  await assert.rejects(() => oneR2Request("DELETE", target, credential, "rotate-release.json", body, 1_024, new Date(), send));
  await assert.rejects(() => oneR2Request("PUT", target, credential, "rotate-release.json", undefined, 1_024, new Date(), send));
  assert.equal(calls, 0, "an invalid method/body pairing must never reach the transport");
});
