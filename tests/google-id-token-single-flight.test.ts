import assert from "node:assert/strict";
import { test } from "node:test";
import { createGoogleIdTokenProvider } from "../workers/ingress-signer/google-id-token";

// Single-flight lifecycle of the ID-token provider. Everything is gated by promises the test controls and waits on CONDITIONS (never on elapsed time), so the
// interleavings are deterministic. The real WebCrypto signs the assertion (it completes off the microtask queue), hence the condition polling.

const audience = "https://origin-lab.run.app";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const FAILURE = "google-id-token-acquisition-failed";

async function credentials(): Promise<string> {
  const key = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key.privateKey));
  let binary = "";
  for (const byte of der) binary += String.fromCharCode(byte);
  return JSON.stringify({
    type: "service_account", client_email: "lab-invoker@limitmark-field-qual.iam.gserviceaccount.com", private_key_id: "lab-key-1",
    private_key: `-----BEGIN PRIVATE KEY-----\n${btoa(binary).match(/.{1,64}/gu)!.join("\n")}\n-----END PRIVATE KEY-----\n`,
  });
}

function idToken(now: number, id: string): string {
  const encode = (value: object) => {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
  };
  return `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ aud: audience, iat: now - 1, exp: now + 3600, jti: id })}.signature`;
}

type Gate = { promise: Promise<void>; open(): void };
const gate = (): Gate => { let open!: () => void; const promise = new Promise<void>((resolve) => { open = resolve; }); return { promise, open }; };
const drain = async (rounds = 30): Promise<void> => { for (let index = 0; index < rounds; index++) await new Promise<void>((resolve) => setImmediate(resolve)); };
async function until(condition: () => boolean, label: string): Promise<void> {
  for (let index = 0; index < 20_000; index++) { if (condition()) return; await new Promise<void>((resolve) => setImmediate(resolve)); }
  assert.fail(`condition never held: ${label}`);
}

/** A Google stand-in whose every endpoint waits for a gate and whose behavior per acquisition number is chosen by the test. */
function rig(now: { seconds: number }, options: { failTokenEndpointOn?: ReadonlySet<number> } = {}) {
  const tokenCalls: Gate[] = []; // one gate per call of the access-token endpoint
  const iamCalls: Gate[] = [];
  const fetch = async (input: RequestInfo | URL): Promise<Response> => {
    const url = String(input);
    if (url === TOKEN_URL) {
      const number = tokenCalls.length + 1;
      const own = gate(); tokenCalls.push(own);
      await own.promise;
      if (options.failTokenEndpointOn?.has(number)) return new Response("{}", { status: 500 });
      return new Response(JSON.stringify({ access_token: "access-token", expires_in: 3600 }), { status: 200 });
    }
    const own = gate(); iamCalls.push(own);
    await own.promise;
    return new Response(JSON.stringify({ token: idToken(now.seconds, `acquisition-${iamCalls.length}`) }), { status: 200 });
  };
  return { tokenCalls, iamCalls, fetch };
}

async function provider(now: { seconds: number }, google: ReturnType<typeof rig>) {
  return createGoogleIdTokenProvider(await credentials(), audience, { now: () => now.seconds * 1000, fetch: google.fetch });
}

test("simultaneous callers share ONE acquisition (one access-token fetch and one ID-token fetch for any number of callers)", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const getToken = await provider(now, google);
  const callers = [getToken(), getToken(), getToken()];
  await until(() => google.tokenCalls.length === 1, "first access-token fetch");
  await drain();
  assert.equal(google.tokenCalls.length, 1, "joining callers did not start another fetch");
  google.tokenCalls[0].open();
  await until(() => google.iamCalls.length === 1, "ID-token fetch");
  await drain();
  assert.equal(google.iamCalls.length, 1);
  google.iamCalls[0].open();
  const tokens = await Promise.all(callers);
  assert.equal(new Set(tokens).size, 1, "every caller got the same token");
  assert.equal(tokens[0], idToken(now.seconds, "acquisition-1"));
  assert.equal(google.tokenCalls.length + google.iamCalls.length, 2);
});

test("a third caller arriving while the original acquisition is still pending joins it and starts nothing", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const getToken = await provider(now, google);
  const first = getToken();
  await until(() => google.tokenCalls.length === 1, "first access-token fetch");
  const second = getToken();
  await drain();
  const third = getToken(); // arrives after the second has already joined, still while the first fetch is pending
  await drain();
  google.tokenCalls[0].open();
  await until(() => google.iamCalls.length === 1, "ID-token fetch");
  const fourth = getToken(); // arrives while the SECOND stage of the same acquisition is pending
  await drain();
  assert.equal(google.tokenCalls.length, 1);
  assert.equal(google.iamCalls.length, 1);
  google.iamCalls[0].open();
  const tokens = await Promise.all([first, second, third, fourth]);
  assert.equal(new Set(tokens).size, 1);
  assert.equal(google.tokenCalls.length + google.iamCalls.length, 2, "four callers, one acquisition");
});

test("successful completion caches the token: later callers inside the validity window fetch nothing", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const getToken = await provider(now, google);
  const pending = getToken();
  await until(() => google.tokenCalls.length === 1, "access-token fetch");
  google.tokenCalls[0].open();
  await until(() => google.iamCalls.length === 1, "ID-token fetch");
  google.iamCalls[0].open();
  const token = await pending;
  assert.equal(await getToken(), token);
  assert.equal(await getToken(), token);
  await drain();
  assert.equal(google.tokenCalls.length + google.iamCalls.length, 2, "no fetch after completion while the token is valid");
});

test("rejection: every waiting caller gets the same fixed error, the acquisition is cleaned up, and the next caller starts a NEW one that can succeed", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now, { failTokenEndpointOn: new Set([1]) });
  const getToken = await provider(now, google);
  const callers = [getToken(), getToken(), getToken()];
  const settled = Promise.allSettled(callers);
  await until(() => google.tokenCalls.length === 1, "first access-token fetch");
  await drain();
  google.tokenCalls[0].open(); // answers 500
  const results = await settled;
  for (const result of results) {
    assert.equal(result.status, "rejected");
    assert.equal((result as PromiseRejectedResult).reason.message, FAILURE, "fixed error string, no detail");
  }
  assert.equal(google.tokenCalls.length, 1, "no hidden retry");
  // cleaned up: a later caller must start a fresh acquisition (not await the dead one) and it must be able to succeed
  const retry = getToken();
  await until(() => google.tokenCalls.length === 2, "second acquisition started");
  google.tokenCalls[1].open();
  await until(() => google.iamCalls.length === 1, "ID-token fetch of the second acquisition");
  google.iamCalls[0].open();
  assert.equal(await retry, idToken(now.seconds, "acquisition-1"));
});

test("rejection while callers keep arriving: a failed acquisition's waiters never clear (or poison) the acquisition that replaced it", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now, { failTokenEndpointOn: new Set([1]) });
  const getToken = await provider(now, google);
  const failed = Promise.allSettled([getToken(), getToken()]);
  await until(() => google.tokenCalls.length === 1, "first acquisition");
  google.tokenCalls[0].open();
  await failed;
  // second acquisition, pending; callers join it from several points in time and must all share it
  const leader = getToken();
  await until(() => google.tokenCalls.length === 2, "second acquisition");
  const joiners = [getToken()];
  await drain();
  joiners.push(getToken());
  await drain();
  assert.equal(google.tokenCalls.length, 2, "joiners did not start a third acquisition");
  google.tokenCalls[1].open();
  await until(() => google.iamCalls.length === 1, "second acquisition ID-token fetch");
  joiners.push(getToken());
  await drain();
  assert.equal(google.iamCalls.length, 1);
  google.iamCalls[0].open();
  const tokens = await Promise.all([leader, ...joiners]);
  assert.equal(new Set(tokens).size, 1);
  assert.equal(google.tokenCalls.length + google.iamCalls.length, 3, "failed attempt (1) plus one shared acquisition (2)");
});

test("a new acquisition starts after the previous one settled and its token reached the refresh margin", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const getToken = await provider(now, google);
  const first = getToken();
  await until(() => google.tokenCalls.length === 1, "first access-token fetch");
  google.tokenCalls[0].open();
  await until(() => google.iamCalls.length === 1, "first ID-token fetch");
  google.iamCalls[0].open();
  const firstToken = await first;
  now.seconds += 3_541; // inside the 60 s refresh margin of a token that lives 3600 s from issue
  const second = getToken();
  const third = getToken();
  await until(() => google.tokenCalls.length === 2, "second acquisition");
  await drain();
  assert.equal(google.tokenCalls.length, 2, "two callers, one refresh");
  google.tokenCalls[1].open();
  await until(() => google.iamCalls.length === 2, "second ID-token fetch");
  google.iamCalls[1].open();
  const [secondToken, thirdToken] = await Promise.all([second, third]);
  assert.equal(secondToken, thirdToken);
  assert.notEqual(secondToken, firstToken, "a fresh token, not the stale one");
});

test("misconfiguration is rejected with the fixed error without starting any fetch, and does not disturb the next call", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const unconfigured = createGoogleIdTokenProvider(undefined, audience, { now: () => now.seconds * 1000, fetch: google.fetch });
  await assert.rejects(unconfigured(), { message: FAILURE });
  const badAudience = createGoogleIdTokenProvider(await credentials(), "http://not-https.example", { now: () => now.seconds * 1000, fetch: google.fetch });
  await assert.rejects(badAudience(), { message: FAILURE });
  assert.equal(google.tokenCalls.length + google.iamCalls.length, 0);
});

test("a caller served from the cache never clears an acquisition another caller has in flight (the clock stepping back is the reachable case)", async () => {
  const now = { seconds: 1_700_000_000 }; const google = rig(now);
  const getToken = await provider(now, google);
  const first = getToken();
  await until(() => google.tokenCalls.length === 1, "first access-token fetch");
  google.tokenCalls[0].open();
  await until(() => google.iamCalls.length === 1, "first ID-token fetch");
  google.iamCalls[0].open();
  await first;
  const issuedAt = now.seconds;
  now.seconds = issuedAt + 3_541; // refresh margin reached: a refresh starts and stays pending
  const refresh = getToken();
  await until(() => google.tokenCalls.length === 2, "refresh started");
  now.seconds = issuedAt + 10; // the wall clock steps BACK: the cached token looks valid again and this caller is answered from the cache
  assert.equal(await getToken(), idToken(issuedAt, "acquisition-1"));
  now.seconds = issuedAt + 3_541; // forward again: a new caller must JOIN the refresh that is still pending
  const joiner = getToken();
  await drain();
  assert.equal(google.tokenCalls.length, 2, "the cache-served caller did not detach the pending refresh, so no second refresh started");
  google.tokenCalls[1].open();
  await until(() => google.iamCalls.length === 2, "refresh ID-token fetch");
  google.iamCalls[1].open();
  assert.equal(await refresh, await joiner);
});
