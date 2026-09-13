import assert from "node:assert/strict";
import test, { before } from "node:test";
import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";
import { createVercelOidcVerifier, type VercelOidcPolicy } from "../workers/admission-service/auth";
import { BoundedRs256JwksResolver } from "../workers/shared/bounded-jwks";

const policy: VercelOidcPolicy = {
  issuer: "https://oidc.vercel.com/limitmark-team", audience: "https://admission.limitmark.test",
  subject: "owner:limitmark-team:project:limitmark:environment:production", ownerId: "team_synthetic", projectId: "prj_synthetic",
};
const nowSeconds = 1_800_000_000;
let primary: Awaited<ReturnType<typeof generateKeyPair>>;
let rotated: Awaited<ReturnType<typeof generateKeyPair>>;
let primaryJwk: JWK;
let rotatedJwk: JWK;

before(async () => {
  primary = await generateKeyPair("RS256", { extractable: true });
  rotated = await generateKeyPair("RS256", { extractable: true });
  primaryJwk = { ...(await exportJWK(primary.publicKey)), kid: "primary", alg: "RS256", use: "sig" };
  rotatedJwk = { ...(await exportJWK(rotated.publicKey)), kid: "rotated", alg: "RS256", use: "sig" };
});

type ClaimChanges = { issuer?: string; audience?: string | string[]; subject?: string; ownerId?: unknown; projectId?: unknown; environment?: unknown;
  issuedAt?: unknown; notBefore?: unknown; expiration?: unknown; kid?: string; key?: CryptoKey; alg?: "RS256" | "HS256"; omitKid?: boolean };
async function token(changes: ClaimChanges = {}): Promise<string> {
  const changed = (name: "issuedAt" | "notBefore" | "expiration", fallback: number) =>
    Object.hasOwn(changes, name) ? changes[name] : fallback;
  const jwt = new SignJWT({ owner: "limitmark-team", project: "limitmark", owner_id: changes.ownerId ?? policy.ownerId,
    project_id: changes.projectId ?? policy.projectId, environment: changes.environment ?? "production",
    iat: changed("issuedAt", nowSeconds), nbf: changed("notBefore", nowSeconds - 1), exp: changed("expiration", nowSeconds + 600) } as never)
    .setProtectedHeader({ alg: changes.alg ?? "RS256", ...(changes.omitKid ? {} : { kid: changes.kid ?? "primary" }), typ: "JWT" })
    .setIssuer(changes.issuer ?? policy.issuer).setAudience(changes.audience ?? policy.audience).setSubject(changes.subject ?? policy.subject);
  if (changes.alg === "HS256") return jwt.sign(new Uint8Array(32).fill(7));
  return jwt.sign(changes.key ?? primary.privateKey);
}
const jwksResponse = (...keys: JWK[]) => new Response(JSON.stringify({ keys }), { status: 200, headers: { "content-type": "application/json" } });

test("valid Vercel RS256 workload token verifies against the fixed team JWKS", async () => {
  const requested: string[] = [];
  const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000,
    fetch: async (input, init) => { requested.push(String(input)); assert.equal(init?.redirect, "manual"); return jwksResponse(primaryJwk); } });
  const claims = await verifier.verify(await token(), nowSeconds * 1_000);
  assert.equal(claims.ownerId, policy.ownerId);
  assert.equal(claims.projectId, policy.projectId);
  assert.deepEqual(requested, ["https://oidc.vercel.com/limitmark-team/.well-known/jwks"]);
});

test("timestamp ceiling and five-second boundaries match exchanged Production tokens", async () => {
  const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: async () => jwksResponse(primaryJwk) });
  const accepted: ClaimChanges[] = [
    { issuedAt: nowSeconds - 7_200, expiration: nowSeconds },
    { issuedAt: nowSeconds - 60, notBefore: nowSeconds - 3_600, expiration: nowSeconds + 120 },
    { issuedAt: nowSeconds, notBefore: nowSeconds - 3_600 },
    { issuedAt: nowSeconds + 5, expiration: nowSeconds + 600 },
    { notBefore: nowSeconds + 5 },
    { expiration: nowSeconds - 4, issuedAt: nowSeconds - 600 },
  ];
  for (const changes of accepted) await verifier.verify(await token(changes), nowSeconds * 1_000);

  const rejected: ClaimChanges[] = [
    { issuedAt: nowSeconds - 7_201, expiration: nowSeconds },
    { issuedAt: nowSeconds - 7_260, expiration: nowSeconds },
    { issuedAt: nowSeconds + 6, expiration: nowSeconds + 600 },
    { notBefore: nowSeconds + 6 },
    { expiration: nowSeconds - 5, issuedAt: nowSeconds - 600 },
    { expiration: nowSeconds - 6, issuedAt: nowSeconds - 600 },
  ];
  for (const changes of rejected) await assert.rejects(async () => verifier.verify(await token(changes), nowSeconds * 1_000));
});

test("exact singleton audience arrays are accepted without weakening exact audience policy", async () => {
  const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: async () => jwksResponse(primaryJwk) });
  assert.deepEqual((await verifier.verify(await token({ audience: [policy.audience] }), nowSeconds * 1_000)).audience, [policy.audience]);
  for (const audience of [[], [policy.audience, "other"], [policy.audience, policy.audience], ["wrong"]]) {
    await assert.rejects(async () => verifier.verify(await token({ audience }), nowSeconds * 1_000));
  }
});

test("malformed and noninteger NumericDate claims are rejected", async () => {
  const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: async () => jwksResponse(primaryJwk) });
  for (const changes of [
    { issuedAt: "1800000000" }, { issuedAt: nowSeconds + 0.5 }, { issuedAt: -1 },
    { notBefore: "1800000000" }, { notBefore: nowSeconds + 0.5 }, { notBefore: -1 },
    { expiration: "1800000600" }, { expiration: nowSeconds + 0.5 }, { expiration: -1 },
  ] satisfies ClaimChanges[]) await assert.rejects(async () => verifier.verify(await token(changes), nowSeconds * 1_000));
});

test("wrong workload claims and time bounds deny before authority use", async () => {
  for (const changes of [
    { issuer: "https://oidc.vercel.com/attacker" }, { audience: "wrong" }, { audience: [policy.audience, "other"] }, { subject: "wrong" },
    { ownerId: "team_wrong" }, { projectId: "prj_wrong" }, { environment: "preview" }, { expiration: nowSeconds - 10 },
    { notBefore: nowSeconds + 20 }, { issuedAt: nowSeconds + 20 }, { key: rotated.privateKey },
  ] satisfies ClaimChanges[]) {
    let fetches = 0;
    const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: async () => { fetches++; return jwksResponse(primaryJwk); } });
    const signed = await token(changes);
    await assert.rejects(() => verifier.verify(signed, nowSeconds * 1_000));
    if (changes.issuer || changes.audience || changes.subject || changes.ownerId || changes.projectId || changes.environment) assert.equal(fetches, 0);
  }
});

test("malformed, duplicate, unsupported-alg and missing-kid JWTs fail without JWKS traffic", async () => {
  let fetches = 0;
  const verifier = createVercelOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: async () => { fetches++; return jwksResponse(primaryJwk); } });
  await assert.rejects(() => verifier.verify("malformed", nowSeconds * 1_000));
  const unsupported = await token({ alg: "HS256" });
  const missingKid = await token({ omitKid: true });
  await assert.rejects(() => verifier.verify(unsupported, nowSeconds * 1_000));
  await assert.rejects(() => verifier.verify(missingKid, nowSeconds * 1_000));
  const header = Buffer.from('{"alg":"RS256","kid":"one","kid":"two"}').toString("base64url");
  const payload = Buffer.from("{}").toString("base64url");
  await assert.rejects(() => verifier.verify(`${header}.${payload}.${"A".repeat(342)}`, nowSeconds * 1_000));
  const validHeader = Buffer.from('{"alg":"RS256","kid":"primary"}').toString("base64url");
  const duplicateClaims = Buffer.from(`{"iss":"${policy.issuer}","iss":"${policy.issuer}"}`).toString("base64url");
  await assert.rejects(() => verifier.verify(`${validHeader}.${duplicateClaims}.${"A".repeat(342)}`, nowSeconds * 1_000));
  assert.equal(fetches, 0);
});

test("JWKS schema, size, redirect and timeout failures deny", async () => {
  const cases: Array<typeof fetch> = [
    async () => new Response("{not-json", { status: 200 }),
    async () => new Response(JSON.stringify({ keys: [{ ...primaryJwk, d: "private" }] }), { status: 200 }),
    async () => new Response("x", { status: 200, headers: { "content-length": "70000" } }),
    async () => new Response(null, { status: 302, headers: { location: "https://attacker.test/jwks" } }),
    async (_input, init) => new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("timeout", "AbortError")))) ,
  ];
  for (const request of cases) {
    const resolver = new BoundedRs256JwksResolver({ endpoint: new URL("https://oidc.vercel.com/limitmark-team/.well-known/jwks"),
      fetch: request, now: () => 0, timeoutMs: 10 });
    await assert.rejects(async () => resolver.resolve({ alg: "RS256", kid: "primary" }, {} as never));
  }
});

test("unknown-kid refresh is bounded and cached known keys get only a finite outage grace", async () => {
  let nowMs = 0;
  let fetches = 0;
  let mode: "primary" | "rotated" | "outage" = "primary";
  const request: typeof fetch = async () => {
    fetches++;
    if (mode === "outage") throw new Error("network");
    return jwksResponse(mode === "primary" ? primaryJwk : rotatedJwk);
  };
  const resolver = new BoundedRs256JwksResolver({ endpoint: new URL("https://oidc.vercel.com/limitmark-team/.well-known/jwks"), fetch: request, now: () => nowMs });
  assert.ok(await resolver.resolve({ alg: "RS256", kid: "primary" }, {} as never));
  assert.equal(fetches, 1);
  await assert.rejects(async () => resolver.resolve({ alg: "RS256", kid: "unknown-a" }, {} as never));
  await assert.rejects(async () => resolver.resolve({ alg: "RS256", kid: "unknown-b" }, {} as never));
  assert.equal(fetches, 1);
  nowMs = 30_000; mode = "rotated";
  assert.ok(await resolver.resolve({ alg: "RS256", kid: "rotated" }, {} as never));
  assert.equal(fetches, 2);

  const outageResolver = new BoundedRs256JwksResolver({ endpoint: new URL("https://oidc.vercel.com/limitmark-team/.well-known/jwks"), fetch: request, now: () => nowMs });
  mode = "primary"; await outageResolver.resolve({ alg: "RS256", kid: "primary" }, {} as never);
  mode = "outage"; nowMs += 10 * 60_000 + 1;
  assert.ok(await outageResolver.resolve({ alg: "RS256", kid: "primary" }, {} as never));
  nowMs += 5 * 60_000;
  await assert.rejects(async () => outageResolver.resolve({ alg: "RS256", kid: "primary" }, {} as never));
});
