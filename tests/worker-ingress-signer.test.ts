import assert from "node:assert/strict";
import test from "node:test";
import { INGRESS_HEADER, decodeCanonicalBase64url, encodeBase64url, splitIngressEnvelope, toArrayBuffer } from "../src/lib/ingress-protocol";
import { createIngressSigner } from "../workers/ingress-signer/signer";
import { deriveClientPseudonym, parseCloudflareClientAddress } from "../workers/ingress-signer/identity";

const hmacKey = encodeBase64url(Uint8Array.from({ length: 32 }, (_, index) => index));

test("Cloudflare identity normalizes IPv4, IPv6 and mapped IPv6 without exposing address text", async () => {
  assert.deepEqual(parseCloudflareClientAddress("203.0.113.9"), { family: 4, bytes: Uint8Array.of(203, 0, 113, 9) });
  const expanded = parseCloudflareClientAddress("2001:0DB8:0:0:0:0:ABCD:0001");
  assert.deepEqual(expanded, parseCloudflareClientAddress("2001:db8::abcd:1"));
  assert.deepEqual(parseCloudflareClientAddress("::ffff:203.0.113.9"), parseCloudflareClientAddress("::ffff:cb00:7109"));
  const pseudonym = await deriveClientPseudonym("203.0.113.9", hmacKey);
  assert.match(pseudonym!, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(pseudonym!.includes("203"), false);
});

test("Cloudflare identity rejects malformed, multi-hop, port, zone, sentinel and pseudo IPv4 values", async () => {
  for (const value of [null, "", " 203.0.113.9", "203.0.113.9:443", "203.0.113.9,198.51.100.1", "[2001:db8::1]", "fe80::1%eth0", "2a06:98c0:3600::103", "240.0.0.1", "203.000.113.9", "invalid"]) {
    assert.equal(parseCloudflareClientAddress(value), null);
    assert.equal(await deriveClientPseudonym(value, hmacKey), null);
  }
});

async function signerFixture() {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privatePkcs8 = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const forwarded: Array<{ url: string; init?: RequestInit }> = [];
  const signer = createIngressSigner({
    environment: "production", publicHosts: ["limitmark.com", "www.limitmark.com"], targetOrigin: "https://limitmark.com",
    audience: "prj_limitmark", deploymentId: "dpl_reviewed", keyId: "key-current", signingPrivateKeyPkcs8: privatePkcs8,
    identityHmacKey: hmacKey, originSecret: "o".repeat(43), vercelBypassSecret: "b".repeat(43),
  }, {
    now: () => 1_000_000,
    random: (bytes) => { bytes.fill(7); return bytes; },
    fetch: async (input, init) => { forwarded.push({ url: String(input), init }); return new Response("ok", { status: 200, headers: { [INGRESS_HEADER]: "must-not-reflect" } }); },
  });
  return { signer, forwarded, pair };
}

test("signer hashes and forwards exact raw mutation bytes while stripping caller credentials and raw identity", async () => {
  const { signer, forwarded, pair } = await signerFixture();
  const body = "name=A%2BB&objective=line1%0Aline2";
  const request = new Request("https://limitmark.com/api/public-inquiries", {
    method: "POST", body,
    headers: {
      "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "203.0.113.9",
      [INGRESS_HEADER]: "caller-value", "x-vercel-protection-bypass": "caller-bypass", "x-real-ip": "198.51.100.1",
      "x-forwarded-host": "attacker.example", "x-forwarded-proto": "http", "x-forwarded-port": "444",
    },
  });
  const response = await signer(request);
  assert.equal(response.status, 200);
  assert.equal(response.headers.has(INGRESS_HEADER), false);
  assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].url, "https://limitmark.com/api/public-inquiries");
  assert.equal(new TextDecoder().decode(forwarded[0].init!.body as Uint8Array), body);
  const headers = forwarded[0].init!.headers as Headers;
  for (const name of ["cf-connecting-ip", "x-real-ip", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port"]) {
    assert.equal(headers.has(name), false);
  }
  assert.equal(headers.get("host"), "limitmark.com");
  assert.equal(headers.get("x-vercel-protection-bypass"), "b".repeat(43));
  assert.equal(forwarded[0].init!.redirect, "manual");
  const envelope = headers.get(INGRESS_HEADER)!;
  const decoded = splitIngressEnvelope(envelope);
  assert.equal(decoded.payload[13], new TextEncoder().encode(body).length);
  assert.equal(decoded.payload[16].includes("203.0.113.9"), false);
  assert.equal(await crypto.subtle.verify("Ed25519", pair.publicKey, toArrayBuffer(decoded.signature),
    toArrayBuffer(new Uint8Array([...new TextEncoder().encode("limitmark:ingress:ed25519:v1\0"), ...decoded.payloadBytes]))), true);
});

test("signer denies unsupported topology, host/path/query/encoding, false length and byte 32769 without forwarding", async () => {
  const { signer, forwarded } = await signerFixture();
  const base = { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": "203.0.113.9" };
  const cases = [
    new Request("https://www.limitmark.com/api/public-inquiries", { method: "POST", body: "a=1", headers: base }),
    new Request("https://limitmark.com/api/public-inquiries?x=1", { method: "POST", body: "a=1", headers: base }),
    new Request("https://limitmark.com/api/public-inquiries/", { method: "POST", body: "a=1", headers: base }),
    new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: "a=1", headers: { ...base, "content-encoding": "gzip" } }),
    new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: "a=1", headers: { ...base, "cf-worker": "upstream.example" } }),
    new Request("https://limitmark.com/api/public-inquiries", { method: "POST", body: new Uint8Array(32_769), headers: base }),
  ];
  for (const request of cases) assert.notEqual((await signer(request)).status, 200);
  assert.equal(forwarded.length, 0);
  assert.throws(() => decodeCanonicalBase64url("A".repeat(42) + "="));
});

test("credential-bearing fetch construction cannot escape the fixed approved origin", async () => {
  const { signer, forwarded } = await signerFixture();
  const headers = { "cf-connecting-ip": "203.0.113.9" };
  for (const path of ["//attacker.example/escape", "/%2F%2Fattacker.example/encoded", "/safe/read?bounded=1"]) {
    assert.equal((await signer(new Request(`https://limitmark.com${path}`, { method: "GET", headers }))).status, 200);
  }
  assert.equal((await signer(new Request("https://limitmark.com/\\\\attacker.example/backslash", { method: "HEAD", headers }))).status, 200);
  const forwardedBeforeRejected = forwarded.length;
  const userinfoRequest = { url: "https://user:pass@limitmark.com/safe", method: "GET", headers: new Headers(headers) } as Request;
  assert.notEqual((await signer(userinfoRequest)).status, 200);
  assert.notEqual((await signer(new Request("https://limitmark.com:444/safe", { method: "GET", headers }))).status, 200);
  assert.equal(forwarded.length, forwardedBeforeRejected);
  for (const item of forwarded) {
    const target = new URL(item.url);
    assert.equal(target.origin, "https://limitmark.com");
    assert.equal(target.username, "");
    assert.equal(target.password, "");
    assert.equal(target.port, "");
    assert.equal((item.init!.headers as Headers).get("host"), "limitmark.com");
    assert.equal(item.init!.redirect, "manual");
    assert.equal((item.init!.headers as Headers).has("content-encoding"), false);
  }
  assert.equal(forwarded[0].url, "https://limitmark.com//attacker.example/escape");
});
