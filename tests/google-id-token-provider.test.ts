import assert from "node:assert/strict";
import { test } from "node:test";
import { createGoogleIdTokenProvider } from "../workers/ingress-signer/google-id-token";

const audience = "https://origin-lab.run.app";

async function credentials() {
  const key = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  const base64 = btoa(binary).match(/.{1,64}/gu)!.join("\n");
  return JSON.stringify({
    type: "service_account",
    client_email: "lab-invoker@limitmark-field-qual.iam.gserviceaccount.com",
    private_key_id: "lab-key-1",
    private_key: `-----BEGIN PRIVATE KEY-----\n${base64}\n-----END PRIVATE KEY-----\n`,
  });
}

function idToken(now: number, tokenAudience = audience, expiration = now + 3600): string {
  const encode = (value: object) => {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
  };
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ aud: tokenAudience, iat: now - 1, exp: expiration })}.signature`;
}

function mockGoogle(now: number, token = idToken(now), calls: string[] = []) {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (url === "https://oauth2.googleapis.com/token") {
      assert.equal(init?.method, "POST");
      assert.match(String(init?.body), /grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer/u);
      return new Response(JSON.stringify({ access_token: "access-token", expires_in: 3600 }), { status: 200 });
    }
    assert.match(url, /:generateIdToken$/u);
    assert.equal((init?.headers as Record<string, string>).authorization, "Bearer access-token");
    assert.deepEqual(JSON.parse(String(init?.body)), { audience, includeEmail: true });
    return new Response(JSON.stringify({ token }), { status: 200 });
  };
}

test("acquires an exact-audience ID token using a JWT bearer assertion", async () => {
  const now = 1_700_000_000;
  const provider = createGoogleIdTokenProvider(await credentials(), audience, { now: () => now * 1000, fetch: mockGoogle(now) });
  assert.equal(await provider(), idToken(now));
});

test("reuses cached tokens and refreshes them inside the expiration margin", async () => {
  let now = 1_700_000_000;
  let tokenCalls = 0;
  const fetch = async (...args: Parameters<typeof globalThis.fetch>) => {
    tokenCalls++;
    return mockGoogle(now)(...args);
  };
  const provider = createGoogleIdTokenProvider(await credentials(), audience, { now: () => now * 1000, fetch });
  await provider();
  await provider();
  assert.equal(tokenCalls, 2);
  now += 3_541;
  await provider();
  assert.equal(tokenCalls, 4);
});

test("rejects malformed credentials, wrong audience, expired tokens, and endpoint failures", async () => {
  const now = 1_700_000_000;
  await assert.rejects(createGoogleIdTokenProvider("{not-json", audience, { now: () => now * 1000 })(), /acquisition-failed/u);
  await assert.rejects(createGoogleIdTokenProvider(await credentials(), audience, {
    now: () => now * 1000, fetch: mockGoogle(now, idToken(now, "https://wrong.example")),
  })(), /acquisition-failed/u);
  await assert.rejects(createGoogleIdTokenProvider(await credentials(), audience, {
    now: () => now * 1000, fetch: mockGoogle(now, idToken(now, audience, now - 1)),
  })(), /acquisition-failed/u);
  await assert.rejects(createGoogleIdTokenProvider(await credentials(), audience, {
    now: () => now * 1000, fetch: async () => new Response(null, { status: 500 }),
  })(), /acquisition-failed/u);
});

test("does not provide an unauthenticated fallback", async () => {
  const provider = createGoogleIdTokenProvider(undefined, audience);
  await assert.rejects(provider(), /acquisition-failed/u);
});
