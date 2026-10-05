import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeCanonicalB64 } from "../defense/core/hop-proof";
import { EMPTY_BODY_SHA256, FORM_CONTENT_TYPE, MAX_SEMANTIC_BODY, sha256B64 } from "../defense/core/semantic-request";
import { L1_LIMITS } from "../defense/core/types";
import {
  EMPTY_SHA256_BASE64URL, INGRESS_FUTURE_SKEW_MS, INGRESS_MAX_BODY_BYTES, INGRESS_MUTATION_CONTENT_TYPE, decodeCanonicalBase64url, sha256Base64url,
} from "../src/lib/ingress-protocol";
import { HOP_SKEW_MS, PB_MAX_LIFETIME_MS } from "../defense/core/hop-proof";

// defense/ may not import src/. The primitives it needs (canonical base64url, SHA-256 base64url body digest, the body bound) were REVIEWED
// in src/lib/ingress-protocol.ts; this test, which may import both sides, pins that the independent reimplementation behaves identically.

const VECTORS = [
  "", "A", "QQ", "QR", "QUI", "QUJD", "QUJDRA", "-_", "_-", "AA", "AAAA", "AAA", "AA=", "AAAA=", "Zm9v", "Zm9vYg", "Zm9vYmE", "Zm9vYmFy", "a b", "AAAA\n", " AAAA", "AAAA ",
  "éééé", "+/+/", "Zm9v+", "A".repeat(43), "A".repeat(86), "4".repeat(22), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFV",
];

test("canonical base64url decoding is identical to the reviewed ingress decoder: same bytes, same acceptance, same rejection", () => {
  for (const vector of VECTORS) {
    let reference: Uint8Array | null;
    try { reference = decodeCanonicalBase64url(vector); } catch { reference = null; }
    const mine = decodeCanonicalB64(vector);
    assert.equal(mine === null, reference === null, `acceptance for ${JSON.stringify(vector)}`);
    if (mine !== null && reference !== null) assert.deepEqual([...mine], [...reference], `bytes for ${JSON.stringify(vector)}`);
  }
  for (const [vector, length] of [["47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", 32], ["AAAA", 3], ["AAAA", 4], ["AAAAAAAAAAAAAAAAAAAAAA", 16]] as const) {
    let reference: Uint8Array | null;
    try { reference = decodeCanonicalBase64url(vector, length); } catch { reference = null; }
    assert.equal(decodeCanonicalB64(vector, length) === null, reference === null, `length-constrained acceptance for ${vector}/${length}`);
  }
});

test("the SHA-256 base64url body digest equals the reviewed one for empty, small, binary and maximum-size bodies, and the empty-body constant is the same", async () => {
  assert.equal(EMPTY_BODY_SHA256, EMPTY_SHA256_BASE64URL);
  assert.equal(sha256B64(new Uint8Array()), EMPTY_SHA256_BASE64URL);
  for (const body of [Buffer.from("name=A"), Buffer.from([0, 1, 2, 255, 254]), Buffer.alloc(MAX_SEMANTIC_BODY, 0x61), Buffer.from("café")]) {
    assert.equal(sha256B64(body), await sha256Base64url(new Uint8Array(body)));
  }
});

test("the bounds and constants the hop proofs share with the reviewed ingress protocol are equal", () => {
  assert.equal(MAX_SEMANTIC_BODY, INGRESS_MAX_BODY_BYTES);
  assert.equal(MAX_SEMANTIC_BODY, L1_LIMITS.maxBodyBytes);
  assert.equal(FORM_CONTENT_TYPE, INGRESS_MUTATION_CONTENT_TYPE);
  assert.ok(HOP_SKEW_MS <= INGRESS_FUTURE_SKEW_MS, "the hop skew is no looser than the reviewed ingress skew");
  assert.ok(PB_MAX_LIFETIME_MS <= 30_000, "a hop proof is no longer-lived than the reviewed ingress envelope");
});
