import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { test } from "node:test";
import {
  BA_DOMAIN, BA_MAX_LIFETIME_MS, BA_ROLE, HOP_SKEW_MS, PB_DOMAIN, PB_HEADER_MAX, PB_MAX_LIFETIME_MS, PB_ROLE, checkProofWindow, decodeCanonicalB64, decodeProof,
  importPrivateKey, importPublicKey, issueBa, issuePb, proofTag, sealVerifiedPb, verifyProofSignature, type BaClaims, type PbClaims,
} from "../defense/core/hop-proof";
import { buildApprovedRequest, sha256B64 } from "../defense/core/semantic-request";
import type { LayerRequest } from "../defense/core/types";
import { HopTrustRoot, type OracleRequest } from "../lab/defense/hop-keys";

const FORM = "application/x-www-form-urlencoded";
const get = (target = "/gizlilik", headers: [string, string][] = [["host", "limitmark.test"]]): LayerRequest => ({ method: "GET", target, headers, bodyStatus: "none", body: null });
const approve = (request: LayerRequest) => { const built = buildApprovedRequest(request); assert.ok(built.ok); return built.approved; };

const pair = () => generateKeyPairSync("ed25519");
const P = pair();
const B = pair();
const NOW = 1_800_000_000_000;
const ID_BOUNDARY = "b".repeat(22);
const ID_APP = "a".repeat(22);
const pbConfig = { kid: "pb-test", privateKey: P.privateKey, boundaryId: ID_BOUNDARY, lifetimeMs: 4_000, now: () => NOW };
const baConfig = { kid: "ba-test", privateKey: B.privateKey, appId: ID_APP, lifetimeMs: 1_500, now: () => NOW };
const CORR = "c".repeat(22);

function issuePair() {
  const approved = approve(get());
  const pb = issuePb(pbConfig, approved, { hop: 7, corr: CORR });
  const decoded = decodeProof(pb.header, "pb");
  assert.ok(decoded.ok);
  const verified = sealVerifiedPb(decoded.value.claims as PbClaims, pb.header);
  const ba = issueBa(baConfig, verified);
  return { pb, ba, approved, verified };
}

test("a PB proof round-trips: strict decode, the signed claims equal what the plane approved, and only K_P verifies it", () => {
  const { pb, approved } = issuePair();
  const decoded = decodeProof(pb.header, "pb");
  assert.ok(decoded.ok);
  const claims = decoded.value.claims as PbClaims;
  assert.equal(claims.role, "pb");
  assert.deepEqual([claims.kid, claims.aud, claims.hop, claims.corr], ["pb-test", ID_BOUNDARY, 7, CORR]);
  assert.deepEqual(claims.request, { method: "GET", target: "/gizlilik", pairs: [["host", "limitmark.test"]], bodyLen: 0, bodySha256: approved.bodySha256 });
  assert.equal(claims.exp - claims.iat, 4_000);
  assert.equal(verifyProofSignature("pb", decoded.value, P.publicKey), true);
  assert.equal(verifyProofSignature("pb", decoded.value, B.publicKey), false, "a different key never verifies it");
  assert.ok(pb.header.length <= PB_HEADER_MAX);
  assert.equal(pb.tag, proofTag("pb", pb.jti));
  assert.equal(pb.tag.length, 16);
});

test("a BA proof carries the PB's request fields and commits to that exact PB by jti and hash", () => {
  const { pb, ba } = issuePair();
  const decodedBa = decodeProof(ba.header, "ba");
  const decodedPb = decodeProof(pb.header, "pb");
  assert.ok(decodedBa.ok && decodedPb.ok);
  const baClaims = decodedBa.value.claims as BaClaims;
  const pbClaims = decodedPb.value.claims as PbClaims;
  assert.equal(baClaims.role, "ba");
  assert.equal(baClaims.aud, ID_APP);
  assert.equal(baClaims.pbJti, pbClaims.jti);
  assert.equal(baClaims.pbSha256, sha256B64(Buffer.from(pb.header, "utf8")));
  assert.deepEqual([baClaims.hop, baClaims.corr, baClaims.request], [pbClaims.hop, pbClaims.corr, pbClaims.request]);
  assert.ok(baClaims.exp - baClaims.iat <= BA_MAX_LIFETIME_MS);
  assert.equal(verifyProofSignature("ba", decodedBa.value, B.publicKey), true);
  assert.equal(verifyProofSignature("ba", decodedBa.value, P.publicKey), false);
});

test("the hops are cryptographically distinct: role string, signing domain, key, audience and tag namespace each separate PB from BA", () => {
  const { pb, ba } = issuePair();
  assert.notEqual(PB_ROLE, BA_ROLE);
  assert.notEqual(PB_DOMAIN, BA_DOMAIN);
  // role: each decoder names the OTHER hop's proof as `wrong_hop`
  assert.deepEqual(decodeProof(pb.header, "ba"), { ok: false, reason: "ob.wrong_hop" });
  assert.deepEqual(decodeProof(ba.header, "pb"), { ok: false, reason: "ob.wrong_hop" });
  // domain: even with the right key, a signature made for one hop does not verify as the other
  const decodedPb = decodeProof(pb.header, "pb"); const decodedBa = decodeProof(ba.header, "ba");
  assert.ok(decodedPb.ok && decodedBa.ok);
  assert.equal(verifyProofSignature("ba", decodedPb.value, P.publicKey), false, "a PB never verifies under the BA domain");
  assert.equal(verifyProofSignature("pb", decodedBa.value, B.publicKey), false, "a BA never verifies under the PB domain");
  // tags: the same jti has a different tag per role, so a PB tag can never be mistaken for a BA tag in the ledger
  assert.notEqual(proofTag("pb", "x".repeat(22)), proofTag("ba", "x".repeat(22)));
  assert.notEqual(proofTag("pb", "x".repeat(22)), proofTag("ln", "x".repeat(22)));
});

test("the oracle (an independent encoder under lab/) interoperates with the defense decoder, and its payload text equals the defense encoding", () => {
  const root = new HopTrustRoot();
  const request: OracleRequest = { method: "POST", target: "/api/public-inquiries", host: "limitmark.test", origin: "http://limitmark.test", contentType: FORM, body: Buffer.from("name=A") };
  const minted = root.mintPb({ request, corr: CORR });
  const decoded = decodeProof(minted.header, "pb");
  assert.ok(decoded.ok, "the independent encoder produced a proof the defense decoder accepts");
  const material = root.keyMaterial();
  assert.equal(verifyProofSignature("pb", decoded.value, importPublicKey(material.publicP)), true);
  // identical claims through the defense issuer give identical payload text (the independent encodings agree byte for byte)
  const claims = decoded.value.claims as PbClaims;
  const approved = approve({ method: "POST", target: request.target, headers: [["host", request.host], ["origin", request.origin!], ["content-type", FORM], ["content-length", "6"]], bodyStatus: "complete", body: new Uint8Array(request.body) });
  const issued = issuePb({ kid: claims.kid, privateKey: importPrivateKey(material.privateP), boundaryId: claims.aud, lifetimeMs: claims.exp - claims.iat, now: () => claims.iat }, approved, { hop: claims.hop, corr: CORR });
  const text = (header: string) => Buffer.from(header.split(".")[0], "base64url").toString("utf8");
  const replaceJti = (value: string, from: string, to: string) => value.replace(from, to);
  assert.equal(replaceJti(text(issued.header), issued.jti, claims.jti), text(minted.header));
});

test("a golden PB vector pins the wire format (role, field order, canonical JSON)", () => {
  const seed = Buffer.from("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "hex");
  const key = importPrivateKey(Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]).toString("base64url"));
  const issued = issuePb({ kid: "pb-golden", privateKey: key, boundaryId: ID_BOUNDARY, lifetimeMs: 5_000, now: () => 1_700_000_000_000 }, approve(get("/", [["host", "limitmark.test"]])), { hop: 3, corr: CORR });
  const payload = Buffer.from(issued.header.split(".")[0], "base64url").toString("utf8");
  const parsed = JSON.parse(payload) as unknown[];
  assert.equal(parsed.length, 13);
  assert.deepEqual(parsed.slice(0, 5), [PB_ROLE, "pb-golden", ID_BOUNDARY, 1_700_000_000_000, 1_700_000_005_000]);
  assert.deepEqual([parsed[6], parsed[7], parsed[8], parsed[9], parsed[10], parsed[11]], [3, CORR, "GET", "/", [["host", "limitmark.test"]], 0]);
  assert.equal(parsed[12], "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
  assert.equal(JSON.stringify(parsed), payload, "the payload is canonical JSON");
  // Ed25519 is deterministic: the same key and message always give the same signature
  assert.equal(issuePb({ kid: "pb-golden", privateKey: key, boundaryId: ID_BOUNDARY, lifetimeMs: 5_000, now: () => 1_700_000_000_000 }, approve(get("/", [["host", "limitmark.test"]])), { hop: 3, corr: CORR }).header.split(".")[1].length, 86);
});

test("decoding is strict: non-canonical encodings, wrong shapes and every malformed variant are refused", () => {
  const { pb } = issuePair();
  const [payload, signature] = pb.header.split(".");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bump = (value: string) => `${value.slice(0, -1)}${alphabet[(alphabet.indexOf(value.at(-1)!) + 1) % 64]}`;
  const text = Buffer.from(payload, "base64url").toString("utf8");
  const parsed = JSON.parse(text) as unknown[];
  const reencode = (value: unknown, raw?: string) => `${Buffer.from(raw ?? JSON.stringify(value)).toString("base64url")}.${signature}`;
  const cases: [string, string, string][] = [
    ["empty", "", "ob.proof_malformed"],
    ["no dot", payload, "ob.proof_malformed"],
    ["three parts", `${pb.header}.AAAA`, "ob.proof_malformed"],
    ["comma", `${payload},x.${signature}`, "ob.proof_malformed"],
    ["padding", `${payload}=.${signature}`, "ob.proof_malformed"],
    ["non-canonical signature", `${payload}.${bump(signature)}`, "ob.proof_malformed"],
    ["short signature", `${payload}.${signature.slice(0, 80)}`, "ob.proof_malformed"],
    ["json object", reencode({}), "ob.proof_malformed"],
    ["whitespace in json", reencode(parsed, ` ${JSON.stringify(parsed)}`), "ob.proof_malformed"],
    ["pretty json (not byte-canonical)", reencode(parsed, JSON.stringify(parsed, null, 1)), "ob.proof_malformed"],
    ["one field short", reencode(parsed.slice(0, 12)), "ob.proof_malformed"],
    ["one field extra", reencode([...parsed, 1]), "ob.proof_malformed"],
    ["unknown version", reencode(["ba0-pb-v9", ...parsed.slice(1)]), "ob.version_unsupported"],
    ["non-string role", reencode([7, ...parsed.slice(1)]), "ob.proof_malformed"],
    ["method not GET/POST", reencode([...parsed.slice(0, 8), "PUT", ...parsed.slice(9)]), "ob.proof_malformed"],
    ["target without slash", reencode([...parsed.slice(0, 9), "gizlilik", ...parsed.slice(10)]), "ob.proof_malformed"],
    ["header name outside the bound set", reencode([...parsed.slice(0, 10), [["host", "limitmark.test"], ["x-evil", "1"]], ...parsed.slice(11)]), "ob.proof_malformed"],
    ["unsorted pairs", reencode([...parsed.slice(0, 10), [["origin", "http://x"], ["host", "limitmark.test"]], ...parsed.slice(11)]), "ob.proof_malformed"],
    ["no host pair", reencode([...parsed.slice(0, 10), [["origin", "http://x"]], ...parsed.slice(11)]), "ob.proof_malformed"],
    ["empty header value", reencode([...parsed.slice(0, 10), [["host", ""]], ...parsed.slice(11)]), "ob.proof_malformed"],
    ["GET with a body length", reencode([...parsed.slice(0, 11), 5, ...parsed.slice(12)]), "ob.proof_malformed"],
    ["jti of the wrong length", reencode([...parsed.slice(0, 5), "short", ...parsed.slice(6)]), "ob.proof_malformed"],
    ["hop zero", reencode([...parsed.slice(0, 6), 0, ...parsed.slice(7)]), "ob.proof_malformed"],
    ["fractional time", reencode([...parsed.slice(0, 3), 1.5, ...parsed.slice(4)]), "ob.proof_malformed"],
  ];
  for (const [label, header, reason] of cases) assert.deepEqual(decodeProof(header, "pb"), { ok: false, reason }, label);
  assert.deepEqual(decodeProof("A".repeat(PB_HEADER_MAX + 1), "pb"), { ok: false, reason: "ob.proof_oversize" });
  assert.deepEqual([...decodeCanonicalB64("QQ") ?? []], [0x41], "QQ is the canonical encoding of one byte");
  assert.equal(decodeCanonicalB64("QR"), null, "the same byte with non-zero trailing bits is not canonical");
  assert.equal(decodeCanonicalB64("QQ", 2), null, "expected length is enforced");
});

test("window checks: kid, audience, lifetime shape, freshness, then the verifier-start fence, in that order", () => {
  const { pb } = issuePair();
  const decoded = decodeProof(pb.header, "pb");
  assert.ok(decoded.ok);
  const claims = decoded.value.claims as PbClaims;
  const keys = new Map<string, KeyObject>([["pb-test", P.publicKey]]);
  const base = { keys, aud: ID_BOUNDARY, nowMs: NOW, fenceMs: NOW - 10 };
  assert.equal(checkProofWindow(claims, base), null);
  assert.equal(checkProofWindow({ ...claims, kid: "pb-other" }, base), "ob.key_unknown");
  assert.equal(checkProofWindow(claims, { ...base, aud: ID_APP }), "ob.audience_mismatch");
  assert.equal(checkProofWindow({ ...claims, exp: claims.iat }, base), "ob.lifetime_invalid");
  assert.equal(checkProofWindow({ ...claims, exp: claims.iat + PB_MAX_LIFETIME_MS + 1 }, base), "ob.lifetime_invalid");
  assert.equal(checkProofWindow(claims, { ...base, nowMs: claims.iat - HOP_SKEW_MS - 1 }), "ob.not_yet_valid");
  assert.equal(checkProofWindow(claims, { ...base, nowMs: claims.iat - HOP_SKEW_MS }), null, "within the skew");
  assert.equal(checkProofWindow(claims, { ...base, nowMs: claims.exp + HOP_SKEW_MS + 1 }), "ob.expired");
  assert.equal(checkProofWindow(claims, { ...base, nowMs: claims.exp + HOP_SKEW_MS }), null, "within the skew");
  assert.equal(checkProofWindow(claims, { ...base, fenceMs: claims.iat + 1 }), "ob.before_fence");
  assert.equal(checkProofWindow({ ...claims, iat: NOW - 20_000, exp: NOW - 16_000 }, { ...base, fenceMs: NOW }), "ob.expired", "expiry is reported before the fence, so an old proof is `expired` not `before_fence`");
});

test("issuing is capability-shaped: a PB needs an ApprovedRequest, a BA needs a sealed VerifiedPb, and neither can be fabricated", () => {
  const fake = { method: "GET", target: "/", pairs: [["host", "x"]], bodyLen: 0, bodySha256: "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", approved: true };
  assert.throws(() => issuePb(pbConfig, fake as never, { hop: 1, corr: CORR }), /ApprovedRequest/);
  const { pb } = issuePair();
  const decoded = decodeProof(pb.header, "pb");
  assert.ok(decoded.ok);
  const forged = { claims: decoded.value.claims, header: pb.header, verifiedPb: true };
  assert.throws(() => issueBa(baConfig, forged as never), /VerifiedPb/);
  assert.throws(() => issuePb({ ...pbConfig, lifetimeMs: PB_MAX_LIFETIME_MS + 1 }, approve(get()), { hop: 1, corr: CORR }), /lifetime/);
  assert.throws(() => issueBa({ ...baConfig, lifetimeMs: BA_MAX_LIFETIME_MS + 1 }, issuePair().verified), /lifetime/);
});

test("key material is canonical base64url DER and an invalid key refuses to import", () => {
  const privateDer = P.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url");
  const publicDer = P.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  assert.equal(importPrivateKey(privateDer).asymmetricKeyType, "ed25519");
  assert.equal(importPublicKey(publicDer).asymmetricKeyType, "ed25519");
  assert.throws(() => importPublicKey("not a key"));
  assert.throws(() => importPrivateKey("AAAA"));
});
