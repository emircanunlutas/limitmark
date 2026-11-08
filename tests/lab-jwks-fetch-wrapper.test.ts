import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createGoogleOidcVerifier, type GoogleOidcPolicy } from "../workers/admission-service/auth";

const policy: GoogleOidcPolicy = { issuer: "https://accounts.google.com", audience: "https://lab.synthetic.test",
  serviceAccountEmail: "lab@synthetic.iam.gserviceaccount.com", serviceAccountSubject: "123456789012345678901" };
const nowSeconds = 1_800_000_000;

// Models the Workers runtime: the native fetch throws unless it is called with the global (or no) receiver.
function workersLikeFetch(body: string): (this: unknown, ...args: Parameters<typeof fetch>) => Promise<Response> {
  return function (this: unknown) {
    if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation: function called with incorrect `this` reference");
    return Promise.resolve(new Response(body, { status: 200 }));
  };
}

async function material() {
  const keys = await generateKeyPair("RS256", { extractable: true });
  const jwk = { ...(await exportJWK(keys.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  const token = await new SignJWT({ email: policy.serviceAccountEmail, email_verified: true, iat: nowSeconds, exp: nowSeconds + 600 })
    .setProtectedHeader({ alg: "RS256", kid: "k1", typ: "JWT" }).setIssuer(policy.issuer).setAudience(policy.audience).setSubject(policy.serviceAccountSubject!).sign(keys.privateKey);
  return { body: JSON.stringify({ keys: [jwk] }), token };
}

test("the shared resolver calls a receiver-sensitive fetch as a plain function (regression: it used to invoke it as a method)", async () => {
  const { body, token } = await material();
  const verifier = createGoogleOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: workersLikeFetch(body) });
  assert.equal((await verifier.verify(token, nowSeconds * 1_000)).email, policy.serviceAccountEmail);
});

test("a plain-function wrapper (the lab fix) satisfies the receiver check and verification succeeds", async () => {
  const { body, token } = await material();
  const native = workersLikeFetch(body);
  const verifier = createGoogleOidcVerifier(policy, { now: () => nowSeconds * 1_000, fetch: (input, init) => native.call(undefined, input, init) });
  assert.equal((await verifier.verify(token, nowSeconds * 1_000)).email, policy.serviceAccountEmail);
});

test("only the laboratory verifier construction passes the wrapper; production and staging construction is unchanged", () => {
  const source = readFileSync("workers/admission-service/index.ts", "utf8");
  assert.match(source, /createGoogleOidcVerifier\(policy, \{[^}]*fetch: \(input, init\) => fetch\(input, init\),?\s*\}\)/u);
  assert.equal(source.match(/createGoogleOidcVerifier\(/gu)?.length, 1, "exactly one lab construction site");
  assert.match(source, /oidcVerifier: createVercelOidcVerifier\(policy\), authority \}\)/u, "the Production/staging construction has no fetch option");
  assert.doesNotMatch(source, /createVercelOidcVerifier\(policy, /u);
});
