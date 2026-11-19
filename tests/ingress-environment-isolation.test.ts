import assert from "node:assert/strict";
import test from "node:test";
import {
  INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER, INGRESS_IDENTITY_VERSION, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION,
  LAB_INGRESS_ENVIRONMENT, createIngressEnvelope, encodeBase64url, encodeIngressPayload, sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";
import { importRequestBindingKey, verifyMutationIngress, type IngressVerificationPolicy } from "../src/lib/ingress-verifier.server";

// Direct negative tests for the lab environment added to src/lib/ingress-protocol.ts (migration review; test-only, no production file is modified). Synthetic in-process Ed25519 keys only.
// What is pinned: the structural validator accepts the lab environment, but (1) the Production `limitmark.com` host pin is still enforced for every Production payload, (2) the lab
// exception cannot be reached by naming Production, (3) unknown environment values fail closed, and (4) the verifier keeps the two environments apart in both directions.

const NOW = 1_000_000; const LAB_HOST = "lab.example.test"; const LAB_ORIGIN = "origin-lab.example.run.app"; const AUD = "lab-aud"; const DEP = "lab-dep";
const nonce = encodeBase64url(new Uint8Array(16).fill(4)); const client = encodeBase64url(new Uint8Array(32).fill(3));
let bindingKey: CryptoKey; let pair: CryptoKeyPair; let other: CryptoKeyPair; let labPolicy: IngressVerificationPolicy; let prodPolicy: IngressVerificationPolicy;
test.before(async () => {
  bindingKey = await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9)));
  pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  other = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
  labPolicy = { audience: AUD, deploymentId: DEP, environment: "cloud-run-lab", publicHostname: LAB_HOST, originHostname: LAB_ORIGIN, publicKeys: new Map([["k1", pair.publicKey]]), requestBindingKey: bindingKey, now: () => NOW };
  prodPolicy = { audience: "prj_limitmark", deploymentId: "dpl_reviewed", publicKeys: new Map([["k1", pair.publicKey]]), requestBindingKey: bindingKey, now: () => NOW };
});

const BODY = "name=Synthetic";
async function payload(environment: unknown, host: string, audience: string, deployment: string): Promise<IngressPayload> {
  const body = new TextEncoder().encode(BODY);
  return [INGRESS_VERSION, "k1", environment, audience, deployment, NOW, "POST", "https", host, INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING, body.length, await sha256Base64url(body), INGRESS_IDENTITY_VERSION, client, nonce] as unknown as IngressPayload;
}
async function request(p: IngressPayload, key: CryptoKey, hostHeader: string, forwarded: string): Promise<{ request: Request; body: Uint8Array }> {
  const envelope = await createIngressEnvelope(p, key);
  return { request: new Request(`https://${hostHeader}${INGRESS_MUTATION_PATH}`, { method: "POST", body: BODY, headers: { host: hostHeader, "x-forwarded-host": forwarded, "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": "identity", [INGRESS_HEADER]: envelope } }), body: new TextEncoder().encode(BODY) };
}

test("the Production host pin is enforced by the protocol itself: a Production-environment POST naming any other host cannot even be encoded or signed", async () => {
  for (const host of [LAB_HOST, "attacker.example", "www.limitmark.com", "limitmark.com.evil.example", "LIMITMARK.COM"]) {
    const p = await payload(INGRESS_ENVIRONMENT, host, "prj_limitmark", "dpl_reviewed");
    assert.throws(() => encodeIngressPayload(p), /mutation-policy|host/u, host);
    await assert.rejects(() => createIngressEnvelope(p, pair.privateKey), /mutation-policy|host/u, host);
  }
  assert.doesNotThrow(() => encodeIngressPayload(awaitedProduction), "the genuine Production payload is still accepted");
});
let awaitedProduction: IngressPayload;
test.before(async () => { awaitedProduction = await payload(INGRESS_ENVIRONMENT, "limitmark.com", "prj_limitmark", "dpl_reviewed"); });

test("the lab exception exists only for the lab environment value, and only the exact values are environments: unknown, look-alike and case-variant environments fail closed", async () => {
  assert.doesNotThrow(() => encodeIngressPayload(awaitedLab), "the lab environment may name another host");
  for (const environment of ["staging", "production ", "Production", "PRODUCTION", "cloud-run-lab ", "Cloud-Run-Lab", "lab", "", "*", null, undefined, 1, ["production"]]) {
    const p = await payload(environment, LAB_HOST, AUD, DEP);
    assert.throws(() => encodeIngressPayload(p), /environment/u, JSON.stringify(environment));
  }
  // the pin cannot be dodged by flipping only the environment of a Production payload to the lab value AFTER signing: the signature covers the environment
  const signed = await createIngressEnvelope(awaitedProduction, pair.privateKey);
  const [encodedPayload, signature] = signed.split(".");
  const decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encodedPayload.replace(/-/gu, "+").replace(/_/gu, "/")), (c) => c.charCodeAt(0)))) as unknown[];
  decoded[2] = LAB_INGRESS_ENVIRONMENT; decoded[8] = LAB_HOST;
  const forgedPayload = encodeBase64url(new TextEncoder().encode(JSON.stringify(decoded)));
  const body = new TextEncoder().encode(BODY);
  const forged = new Request(`https://${LAB_ORIGIN}${INGRESS_MUTATION_PATH}`, { method: "POST", body: BODY, headers: { host: LAB_ORIGIN, "x-forwarded-host": LAB_HOST, "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": "identity", [INGRESS_HEADER]: `${forgedPayload}.${signature}` } });
  await assert.rejects(() => verifyMutationIngress(forged, body, { ...labPolicy, audience: "prj_limitmark", deploymentId: "dpl_reviewed" }));
});
let awaitedLab: IngressPayload;
test.before(async () => { awaitedLab = await payload(LAB_INGRESS_ENVIRONMENT, LAB_HOST, AUD, DEP); });

test("a lab-signed payload is never accepted as Production traffic, and a Production payload is never accepted by the lab policy", async () => {
  // lab payload carrying EVERY other value the Production policy expects still fails on the environment
  const labAsProd = await payload(LAB_INGRESS_ENVIRONMENT, "limitmark.com", "prj_limitmark", "dpl_reviewed");
  const a = await request(labAsProd, pair.privateKey, "limitmark.com", "limitmark.com");
  await assert.rejects(() => verifyMutationIngress(a.request, a.body, prodPolicy), /ingress-audience/u);
  // the genuine lab payload against the Production policy
  const lab = await request(awaitedLab, pair.privateKey, LAB_ORIGIN, LAB_HOST);
  await assert.rejects(() => verifyMutationIngress(lab.request, lab.body, prodPolicy));
  await assert.doesNotReject(() => verifyMutationIngress(lab.request, lab.body, labPolicy), "control: it verifies under the lab policy");
  // and the reverse
  const prod = await request(awaitedProduction, pair.privateKey, "limitmark.com", "limitmark.com");
  await assert.rejects(() => verifyMutationIngress(prod.request, prod.body, labPolicy), /ingress-audience/u);
  await assert.doesNotReject(() => verifyMutationIngress(prod.request, prod.body, prodPolicy), "control: it verifies under the Production policy");
});

test("wrong audience, deployment, host and signature all fail closed under both policies", async () => {
  const cases: [string, IngressPayload, IngressVerificationPolicy, string, string, CryptoKey][] = [
    ["lab wrong audience", await payload(LAB_INGRESS_ENVIRONMENT, LAB_HOST, "other-aud", DEP), labPolicy, LAB_ORIGIN, LAB_HOST, pair.privateKey],
    ["lab wrong deployment", await payload(LAB_INGRESS_ENVIRONMENT, LAB_HOST, AUD, "other-dep"), labPolicy, LAB_ORIGIN, LAB_HOST, pair.privateKey],
    ["lab wrong signed host", await payload(LAB_INGRESS_ENVIRONMENT, "other.example.test", AUD, DEP), labPolicy, LAB_ORIGIN, LAB_HOST, pair.privateKey],
    ["lab wrong forwarded host", awaitedLab, labPolicy, LAB_ORIGIN, "attacker.example", pair.privateKey],
    ["lab wrong origin host header", awaitedLab, labPolicy, "attacker.example", LAB_HOST, pair.privateKey],
    ["lab wrong signature key", awaitedLab, labPolicy, LAB_ORIGIN, LAB_HOST, other.privateKey],
    ["production wrong audience", await payload(INGRESS_ENVIRONMENT, "limitmark.com", "other", "dpl_reviewed"), prodPolicy, "limitmark.com", "limitmark.com", pair.privateKey],
    ["production wrong deployment", await payload(INGRESS_ENVIRONMENT, "limitmark.com", "prj_limitmark", "other"), prodPolicy, "limitmark.com", "limitmark.com", pair.privateKey],
    ["production wrong forwarded host", awaitedProduction, prodPolicy, "limitmark.com", "www.limitmark.com", pair.privateKey],
    ["production wrong signature key", awaitedProduction, prodPolicy, "limitmark.com", "limitmark.com", other.privateKey],
  ];
  for (const [label, p, policy, hostHeader, forwarded, key] of cases) {
    const built = await request(p, key, hostHeader, forwarded);
    await assert.rejects(() => verifyMutationIngress(built.request, built.body, policy), /./u, label);
  }
});

test("a Production policy is selected by the absence of any lab setting: it cannot be talked into the lab host relaxation by the request", async () => {
  // the Production policy never reads the environment from the request: headers naming the lab runtime change nothing
  const lab = await request(awaitedLab, pair.privateKey, LAB_ORIGIN, LAB_HOST);
  for (const header of ["x-limitmark-runtime", "x-limitmark-environment", "x-environment"]) {
    const headers = new Headers(lab.request.headers); headers.set(header, "cloud-run-lab");
    const spoofed = new Request(lab.request.url, { method: "POST", body: BODY, headers });
    await assert.rejects(() => verifyMutationIngress(spoofed, lab.body, prodPolicy), /./u, header);
  }
  assert.equal(prodPolicy.environment, undefined);
});
