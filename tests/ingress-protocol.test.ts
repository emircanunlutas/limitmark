import assert from "node:assert/strict";
import test from "node:test";
import {
  INGRESS_BODY_ENCODING,
  INGRESS_ENVIRONMENT,
  INGRESS_IDENTITY_VERSION,
  INGRESS_MUTATION_CONTENT_TYPE,
  INGRESS_MUTATION_PATH,
  INGRESS_VERSION,
  IngressProtocolError,
  assertIngressFresh,
  createIngressEnvelope,
  decodeCanonicalBase64url,
  encodeBase64url,
  encodeIngressPayload,
  sha256Base64url,
  splitIngressEnvelope,
  verifyIngressEnvelope,
  type IngressPayload,
} from "../src/lib/ingress-protocol";

async function fixture() {
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const body = new TextEncoder().encode("name=Synthetic&email=qa%40example.test");
  const payload: IngressPayload = [
    INGRESS_VERSION, "key-2026-09", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed",
    2_000_000, "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "",
    INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length, await sha256Base64url(body),
    INGRESS_IDENTITY_VERSION, encodeBase64url(crypto.getRandomValues(new Uint8Array(32))),
    encodeBase64url(crypto.getRandomValues(new Uint8Array(16))),
  ];
  const envelope = await createIngressEnvelope(payload, keys.privateKey);
  return { keys, body, payload, envelope };
}

test("v1 Ed25519 envelope is canonical and verifies only with its allowlisted key", async () => {
  const { keys, payload, envelope } = await fixture();
  const verified = await verifyIngressEnvelope(envelope, new Map([[payload[1], keys.publicKey]]));
  assert.deepEqual(verified.payload, payload);
  assert.deepEqual(verified.payloadBytes, encodeIngressPayload(payload));
  const other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  await assert.rejects(() => verifyIngressEnvelope(envelope, new Map([[payload[1], other.publicKey]])), /signature/);
  await assert.rejects(() => verifyIngressEnvelope(envelope, new Map()), /key-id/);
});

test("envelope rejects signature changes, padding, merging and noncanonical encodings", async () => {
  const { envelope } = await fixture();
  const [payload, signature] = envelope.split(".");
  const changed = `${payload}.${signature.slice(0, -1)}${signature.endsWith("A") ? "B" : "A"}`;
  const keys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  await assert.rejects(() => verifyIngressEnvelope(changed, new Map([["key-2026-09", keys.publicKey]])));
  for (const malformed of [`${payload}=.${signature}`, `${payload}.${signature}=`, `${envelope},${envelope}`, ` ${envelope}`, `${payload}..${signature}`]) {
    assert.throws(() => splitIngressEnvelope(malformed), IngressProtocolError);
  }
  assert.throws(() => decodeCanonicalBase64url("AB=="), /base64url/);
});

test("fixed array rejects malformed JSON, invalid UTF-8, extra/missing fields and unsafe integers", async () => {
  const { envelope, payload } = await fixture();
  const signature = envelope.split(".")[1];
  for (const text of [
    JSON.stringify(payload.slice(0, -1)), JSON.stringify([...payload, "extra"]),
    JSON.stringify(payload).replace(",2000000,", ",9007199254740992,"),
    JSON.stringify(payload, null, 1), "{}", "[", "null",
  ]) {
    assert.throws(() => splitIngressEnvelope(`${encodeBase64url(new TextEncoder().encode(text))}.${signature}`));
  }
  assert.throws(() => splitIngressEnvelope(`${encodeBase64url(Uint8Array.of(0xc3, 0x28))}.${signature}`), /utf8/);
});

test("every closed protocol literal and bounded mutation field is enforced", async () => {
  const { payload } = await fixture();
  const cases: Array<[number, unknown]> = [
    [0, "lm-ingress-v2"], [1, "x".repeat(33)], [2, "preview"], [3, "*"], [4, "x".repeat(129)],
    [5, -1], [6, "post"], [7, "http"], [8, "LIMITMARK.COM"], [9, "/api/other"], [10, "a=1"],
    [11, "application/json"], [12, "gzip"], [13, 32769], [14, "short"], [15, "prod-ip-hmac-v2"],
    [16, encodeBase64url(new Uint8Array(31))], [17, "-"],
  ];
  for (const [index, value] of cases) {
    const changed = [...payload] as unknown[];
    changed[index] = value;
    assert.throws(() => encodeIngressPayload(changed as unknown as IngressPayload), `field ${index}`);
  }
});

test("freshness has exact 5-second future and 30-second old inclusive boundaries", () => {
  assert.doesNotThrow(() => assertIngressFresh(95_000, 100_000));
  assert.doesNotThrow(() => assertIngressFresh(70_000, 100_000));
  assert.throws(() => assertIngressFresh(105_001, 100_000), /future/);
  assert.throws(() => assertIngressFresh(69_999, 100_000), /stale/);
});
