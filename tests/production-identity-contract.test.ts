import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PRODUCTION_FORBIDDEN_EXACT_NAMES, PRODUCTION_FORBIDDEN_NAME_PREFIXES, isForbiddenProductionApplicationVariable, validateVercelProjectContract } from "../deployment/secret-policy";
import { createProductionRuntimeDependencies } from "../src/lib/public-inquiry-production-runtime.server";
import { INGRESS_VERSION, encodeBase64url } from "../src/lib/ingress-protocol";

// Production identity isolation: (a) the production admission Worker entry exports no lab (or staging) class, (b) the Vercel production project contract
// forbids the laboratory selector/credentials/Google-lab identity, (c) the runtime factory enforces the same names. The lab environment keeps its own entry.

const json = async (path: string) => JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), "utf8")) as Record<string, any>;
const code = (source: string) => source.replace(/\/\*[\s\S]*?\*\//gu, "").replace(/^\s*\/\/.*$/gmu, "");

test("the production admission entry module exports exactly the four production names and the default; no lab or staging class", async () => {
  const entry = code(await readFile(new URL("../workers/admission-service/production-index.ts", import.meta.url), "utf8"));
  const exported = [...entry.matchAll(/export \{([^}]+)\} from "\.\/index";/gu)].flatMap((match) => match[1].split(",").map((name) => name.trim()));
  assert.deepEqual(exported.sort(), ["AdmissionServiceWorker", "AdmissionServiceWorker as default", "AuthorityLifecycleOnly", "AuthorityLifecycleReadOnly", "ProductionAdmissionAuthority"]);
  assert.doesNotMatch(entry, /Lab|Staging|export \*|export default/u);
  // the production deployment template builds from it and binds/migrates only the production class
  const template = await json("deployment/admission-service.template.jsonc");
  assert.equal(template.main, "../workers/admission-service/production-index.ts");
  assert.deepEqual(template.durable_objects.bindings, [{ name: "AUTHORITY", class_name: "ProductionAdmissionAuthority" }]);
  assert.deepEqual(template.migrations.map((m: { new_sqlite_classes: string[] }) => m.new_sqlite_classes), [["ProductionAdmissionAuthority"]]);
});

test("the lab environment keeps its own entry and its tests: lab-index exports only lab classes; staging still builds from the shared module", async () => {
  const lab = code(await readFile(new URL("../workers/admission-service/lab-index.ts", import.meta.url), "utf8"));
  const labNames = lab.split("\n").filter((line) => line.startsWith("export {")).flatMap((line) => line.slice(line.indexOf("{") + 1, line.indexOf("}")).split(",").map((name) => name.trim().split(" as ")[0]));
  assert.ok(labNames.length >= 4 && labNames.every((name) => name.startsWith("Lab")), "lab-index exports only Lab* classes");
  assert.equal((await json("deployment/admission-service.lab.template.jsonc")).main, "../workers/admission-service/lab-index.ts");
  assert.equal((await json("deployment/admission-service.staging.template.jsonc")).main, "../workers/admission-service/index.ts");
});

test("the Vercel production project contract pins the forbidden names, and the validator rejects any weakening of them", async () => {
  const contract = await json("deployment/vercel-project-contract.json");
  const forbidden = contract.productionApplicationProject.forbiddenEnvironmentConfiguration;
  assert.deepEqual(forbidden.exactNames, [...PRODUCTION_FORBIDDEN_EXACT_NAMES]);
  assert.deepEqual(forbidden.namePrefixes, [...PRODUCTION_FORBIDDEN_NAME_PREFIXES]);
  assert.deepEqual(forbidden.exactNames, ["LIMITMARK_RUNTIME", "ADMISSION_IDENTITY_MODE"]);
  assert.deepEqual(forbidden.namePrefixes, ["LAB_", "GOOGLE_"]);
  const resolved = structuredClone(contract); resolved.productionApplicationProject.expectedProjectId = "prj_prod"; resolved.previewApplicationProject.expectedProjectId = "prj_preview";
  assert.equal(validateVercelProjectContract(resolved), true, "the contract (with project ids resolved) validates");
  const mutate = (change: (copy: Record<string, any>) => void) => { const copy = structuredClone(resolved); change(copy); return validateVercelProjectContract(copy); };
  assert.equal(mutate((c) => { delete c.productionApplicationProject.forbiddenEnvironmentConfiguration; }), false);
  assert.equal(mutate((c) => { c.productionApplicationProject.forbiddenEnvironmentConfiguration.exactNames = ["LIMITMARK_RUNTIME"]; }), false);
  assert.equal(mutate((c) => { c.productionApplicationProject.forbiddenEnvironmentConfiguration.namePrefixes = ["LAB_"]; }), false);
  assert.equal(mutate((c) => { c.productionApplicationProject.forbiddenEnvironmentConfiguration.namePrefixes = []; }), false);
  assert.equal(mutate((c) => { c.productionApplicationProject.forbiddenEnvironmentConfiguration.exactNames.push("EXTRA"); }), false, "the pinned list is exact, not a floor");
});

test("name predicate: lab selector, lab credentials, Google-lab identity and the identity-mode switch are forbidden; ordinary production names are not", () => {
  for (const name of ["LIMITMARK_RUNTIME", "ADMISSION_IDENTITY_MODE", "LAB_DATABASE_URL", "LAB_PUBLIC_ORIGIN_SECRET", "GOOGLE_OIDC_AUDIENCE", "GOOGLE_SERVICE_ACCOUNT_EMAIL", "GOOGLE_ANYTHING"]) assert.equal(isForbiddenProductionApplicationVariable(name), true, name);
  for (const name of ["DATABASE_URL", "VERCEL_ENV", "ADMISSION_OIDC_AUDIENCE", "PUBLIC_ORIGIN_SECRET", "TURNSTILE_SECRET_KEY", "ADMISSION_RELEASE_ID", "ELABORATE", "MYLAB_X", "LIMITMARK_RUNTIME_X"]) assert.equal(isForbiddenProductionApplicationVariable(name), false, name);
});

test("the runtime factory enforces exactly the same names (checked after the launch registry is injected so only identity isolation can refuse)", async () => {
  const bytes = (fill: number) => encodeBase64url(new Uint8Array(32).fill(fill));
  const environment: Record<string, string> = {
    VERCEL: "1", VERCEL_ENV: "production", VERCEL_PROJECT_ID: "prj_x", VERCEL_DEPLOYMENT_ID: "dpl_x", REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "true",
    RATE_LIMIT_PROVIDER: "cloudflare-do", PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: bytes(1), INGRESS_PROTOCOL: INGRESS_VERSION, INGRESS_AUDIENCE: "prj_x",
    INGRESS_PUBLIC_KEYS: JSON.stringify([{ role: "current", keyId: "k", publicKey: bytes(9), activatesAtMs: 0 }]), INGRESS_REQUEST_BINDING_KEY: bytes(2), SUBMISSION_TOKEN_SECRET: bytes(3),
    ADMISSION_SERVICE_URL: "https://admission.example.test", ADMISSION_OIDC_AUDIENCE: "https://admission.example.test", ADMISSION_RELEASE_ID: "dpl_x", ADMISSION_RELEASE_KEY_ID: "k",
    ADMISSION_RELEASE_RPC_KEY: bytes(4), TURNSTILE_MODE: "enabled", TURNSTILE_SITE_KEY: "0x4AAAAAAAsite-key-value", TURNSTILE_SECRET_KEY: "0x4AAAAAAAsecret-key-value", TURNSTILE_EXPECTED_HOSTNAME: "limitmark.com",
    DATABASE_URL: "postgresql://app:synthetic@db.example.test:5432/limitmark?sslmode=verify-full",
  };
  for (const name of ["LIMITMARK_RUNTIME", "ADMISSION_IDENTITY_MODE", "LAB_X", "LAB_DATABASE_URL", "GOOGLE_OIDC_AUDIENCE", "GOOGLE_SERVICE_ACCOUNT_EMAIL"]) {
    assert.deepEqual(await createProductionRuntimeDependencies({ ...environment, [name]: "x" }, { providers: ["cloudflare-do"] }), { enabled: false, reason: "runtime" }, name);
  }
  assert.notDeepEqual(await createProductionRuntimeDependencies(environment, { providers: ["cloudflare-do"] }), { enabled: false, reason: "runtime" }, "baseline is not refused for identity reasons");
});
