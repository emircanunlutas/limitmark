import assert from "node:assert/strict";
import test from "node:test";
import { handlePublicInquiry, type PublicInquiryHandlerDependencies } from "../src/lib/public-inquiry-handler.server";
import { INGRESS_HEADER, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH } from "../src/lib/ingress-protocol";

// Laboratory hostname-gate regression tests. Next.js derives request.url from the server bind address (0.0.0.0 under
// `next start --hostname 0.0.0.0`), so the laboratory handler must not compare url.hostname with the Cloud Run hostname; the Cloud Run hostname is
// enforced through the Host header behind the origin secret. All values are synthetic. A request that passes the gate reaches signed-envelope
// verification, which rejects the missing/invalid envelope with 400; a gate rejection is the generic 503.
const secret = "A".repeat(43), other = "B".repeat(43);
const PUBLIC_HOST = "lab.example.test", ORIGIN_HOST = "origin-lab.example.run.app", NEXT_URL_HOST = "0.0.0.0:8080";
const labEnv: Record<string, string | undefined> = { LIMITMARK_RUNTIME: "cloud-run-lab", REQUEST_SUBMISSION_MODE: "postgres", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret,
  PUBLIC_ORIGIN_HOSTNAME: ORIGIN_HOST, PUBLIC_ORIGIN_PUBLIC_HOSTNAME: PUBLIC_HOST };
const prodEnv = { REQUEST_SUBMISSION_MODE: "postgres", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: secret, VERCEL: "1", VERCEL_ENV: "production" };
const deps = (environment: Record<string, string | undefined>, over: Partial<PublicInquiryHandlerDependencies> = {}): PublicInquiryHandlerDependencies =>
  ({ environment, ingressPolicy: {} as never, admission: {} as never, turnstile: {} as never, repository: {} as never, ...over });
const labHeaders = { origin: `https://${PUBLIC_HOST}`, "x-limitmark-origin-secret": secret, host: ORIGIN_HOST, "x-forwarded-host": PUBLIC_HOST };
async function post(urlBase: string, headers: Record<string, string | undefined>, dependencies: PublicInquiryHandlerDependencies): Promise<number> {
  const h = new Headers({ "content-type": INGRESS_MUTATION_CONTENT_TYPE });
  for (const [k, v] of Object.entries(headers)) if (v !== undefined) h.set(k, v);
  return (await handlePublicInquiry(new Request(`${urlBase}${INGRESS_MUTATION_PATH}`, { method: "POST", body: "a=1", headers: h }), dependencies)).status;
}
const lab = (headers: Record<string, string | undefined>, over: Partial<PublicInquiryHandlerDependencies> = {}, env = labEnv, base = `https://${NEXT_URL_HOST}`) =>
  post(base, headers, deps(env, over));

test("laboratory: Next.js bind-address URL host 0.0.0.0 with valid headers passes the gate and reaches envelope verification", async () => {
  assert.equal(await lab(labHeaders), 400);
  assert.equal(await lab({ ...labHeaders, [INGRESS_HEADER]: "not-an-envelope" }), 400);
});
test("laboratory: any URL host passes the gate when headers are valid (no bind-address dependence)", async () => {
  for (const host of ["localhost", "10.0.0.1:8080", ORIGIN_HOST, PUBLIC_HOST]) assert.equal(await lab(labHeaders, {}, labEnv, `https://${host}`), 400, host);
});
test("laboratory: Host header must equal the configured Cloud Run hostname", async () => {
  for (const host of [undefined, "", PUBLIC_HOST, "evil.example", `${ORIGIN_HOST}:443`]) assert.equal(await lab({ ...labHeaders, host }), 503, String(host));
});
test("laboratory: x-forwarded-host must equal the configured public hostname", async () => {
  for (const value of [undefined, "", ORIGIN_HOST, "evil.example"]) assert.equal(await lab({ ...labHeaders, "x-forwarded-host": value }), 503, String(value));
});
test("laboratory: browser Origin must equal https://<public hostname>", async () => {
  for (const origin of [undefined, "", "null", `https://${ORIGIN_HOST}`, "https://evil.example", `http://${PUBLIC_HOST}`, `https://${PUBLIC_HOST}:444`]) assert.equal(await lab({ ...labHeaders, origin }), 503, String(origin));
});
test("laboratory: origin secret is mandatory and must match", async () => {
  for (const value of [undefined, "", other, secret.slice(1), `${secret}A`]) assert.equal(await lab({ ...labHeaders, "x-limitmark-origin-secret": value }), 503, String(value));
});
test("laboratory: HTTP instead of HTTPS is rejected", async () => {
  assert.equal(await lab(labHeaders, {}, labEnv, `http://${NEXT_URL_HOST}`), 503);
});
test("laboratory: missing or invalid configuration fails closed", async () => {
  for (const patch of [{ PUBLIC_ORIGIN_SECRET: undefined }, { PUBLIC_ORIGIN_SECRET: "short" }, { PUBLIC_ORIGIN_HOSTNAME: undefined }, { PUBLIC_ORIGIN_PUBLIC_HOSTNAME: undefined },
    { PUBLIC_ORIGIN_PROTECTION: undefined }, { PUBLIC_ORIGIN_PROTECTION: "disabled" }, { REQUEST_SUBMISSION_MODE: "demo" }, { REQUEST_SUBMISSION_MODE: undefined }]) {
    const status = await lab(labHeaders, {}, { ...labEnv, ...patch });
    assert.equal(status, 503, JSON.stringify(patch));
  }
  for (const missing of ["ingressPolicy", "admission", "turnstile", "repository"] as const) assert.equal(await lab(labHeaders, { [missing]: undefined }), 503, missing);
});
test("laboratory: a missing or invalid signed envelope is rejected after the gate (never accepted)", async () => {
  assert.equal(await lab(labHeaders), 400);
  assert.equal(await lab({ ...labHeaders, [INGRESS_HEADER]: "a.b" }), 400);
});
test("laboratory exemption requires the explicit cloud-run-lab runtime (request input cannot select it)", async () => {
  const { LIMITMARK_RUNTIME: _omitted, ...nonLab } = labEnv;
  assert.equal(await lab(labHeaders, {}, nonLab), 503);
  assert.equal(await lab({ ...labHeaders, "x-limitmark-runtime": "cloud-run-lab" }, {}, nonLab), 503);
});
test("production: url.hostname comparison is unchanged", async () => {
  const prodHeaders = { origin: "https://limitmark.com", "x-limitmark-origin-secret": secret, host: "limitmark.com", "x-forwarded-host": "limitmark.com" };
  assert.equal(await post("https://limitmark.com", prodHeaders, deps(prodEnv)), 400);
  assert.equal(await post(`https://${NEXT_URL_HOST}`, prodHeaders, deps(prodEnv)), 503);
  assert.equal(await post("https://www.limitmark.com", prodHeaders, deps(prodEnv)), 503);
  assert.equal(await post("https://evil.example", prodHeaders, deps(prodEnv)), 503);
  assert.equal(await post("http://limitmark.com", prodHeaders, deps(prodEnv)), 503);
  assert.equal(await post("https://limitmark.com", { ...prodHeaders, origin: `https://${PUBLIC_HOST}` }, deps(prodEnv)), 503);
});
