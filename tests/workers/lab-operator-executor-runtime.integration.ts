// Runtime test of the ACTUAL lab operator executor (workers/lab-operator-lifecycle-executor.ts) in workerd, over real service bindings, with a local counting stub
// in place of the lab admission lifecycle entrypoint. Disposable keys are generated per run and never persisted; no lifecycle artifact is real, no network is used.
// What it proves: which inputs reach the admission binding (exactly one valid lab artifact) and which never do (every refusal), that a transport failure is
// UNCONFIRMED with exactly one dispatch (no automatic retry), that rotation is not an RPC method at all, and that the executor has no public route.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, signAuthorityInitializationCommand, signAuthorityReleaseRotationCommand, type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `lab-executor-runtime-${process.pid}-${randomUUID()}`);
const bundlePath = (name: string) => join(runtimeRoot, `${name}.mjs`);
const entries: Record<string, string> = {
  executor: "workers/lab-operator-lifecycle-executor.ts",
  fixtures: "tests/workers/support/lab-executor-runtime-fixtures.ts",
};

const localFiles: Plugin = { name: "workspace-files", setup(api) {
  api.onResolve({ filter: /.*/ }, async (args) => {
    if (args.path === "cloudflare:workers") return { path: args.path, external: true };
    if (!args.path.startsWith(".") && !isAbsolute(args.path)) return undefined;
    const base = resolve(args.resolveDir || root, args.path);
    for (const path of [base, `${base}.ts`, `${base}.tsx`, `${base}.js`, `${base}.json`, join(base, "index.ts")]) {
      try { await readFile(path); return { path, namespace: "workspace-file" }; } catch { /* next */ }
    }
    throw new Error(`Unresolved local module: ${args.path}`);
  });
  api.onLoad({ filter: /.*/, namespace: "workspace-file" }, async (args) => ({ contents: await readFile(args.path),
    resolveDir: dirname(args.path), loader: extname(args.path) === ".ts" ? "ts" : extname(args.path) === ".json" ? "json" : "js" }));
} };

async function bundle(): Promise<void> {
  await Promise.all(Object.entries(entries).map(async ([name, entry]) => {
    const result = await build({ entryPoints: [resolve(root, entry)], outfile: bundlePath(name), bundle: true, write: false, plugins: [localFiles],
      platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"], external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(bundlePath(name), result.outputFiles[0].contents);
  }));
}

async function keyPair(): Promise<{ privatePkcs8: string; publicKey: string }> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return { privatePkcs8: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), publicKey: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey))) };
}

async function start(operatorPublicKey: string): Promise<Miniflare> {
  const date = "2026-09-13";
  const base = { modules: true, compatibilityDate: date, unsafeRegisterWorker: false };
  const executor = (name: string, environment: string, stub: string) => ({ name, scriptPath: bundlePath("executor"), ...base,
    bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, OPERATOR_EXECUTOR_ENVIRONMENT: environment },
    serviceBindings: { ADMISSION_SERVICE: { name: stub, entrypoint: "StubAdmission" } } });
  const stub = (name: string, mode: string) => ({ name, scriptPath: bundlePath("fixtures"), ...base, bindings: { MODE: mode } });
  const workers = [
    { name: "driver", scriptPath: bundlePath("fixtures"), ...base, serviceBindings: {
      EXECUTOR_LAB: "executor-lab", EXECUTOR_PRODUCTION_ENV: "executor-production-env", EXECUTOR_THROWING: "executor-throwing", EXECUTOR_GARBAGE: "executor-garbage",
      STUB_OK: { name: "stub-ok", entrypoint: "StubAdmission" }, STUB_THROW: { name: "stub-throw", entrypoint: "StubAdmission" }, STUB_GARBAGE: { name: "stub-garbage", entrypoint: "StubAdmission" } } },
    executor("executor-lab", "lab", "stub-ok"), executor("executor-production-env", "production", "stub-ok"),
    executor("executor-throwing", "lab", "stub-throw"), executor("executor-garbage", "lab", "stub-garbage"),
    stub("stub-ok", "ok"), stub("stub-throw", "throw"), stub("stub-garbage", "garbage"),
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), workers } as unknown as V4MiniflareOptions);
  options.telemetry = { enabled: false };
  const mf = new Miniflare(options);
  await mf.ready;
  return mf;
}

type Counts = { ok: number; throwing: number; garbage: number; last: { environment: string; authorityId: string; operation: string } | null };
async function drive(mf: Miniflare, path: string, executor: string, body: unknown): Promise<{ result?: Record<string, unknown>; error?: string }> {
  const response = await mf.dispatchFetch(`http://driver.local${path}?executor=${executor}`, { method: "POST", body: JSON.stringify(body) });
  return await response.json() as { result?: Record<string, unknown>; error?: string };
}
const counts = async (mf: Miniflare): Promise<Counts> => (await (await mf.dispatchFetch("http://driver.local/count")).json()) as Counts;
const sealed = (command: unknown, signature: string) => ({ sealedJson: JSON.stringify({ command, signature }) });

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(resolve(root, ".wrangler", "tests") + sep));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  const operator = await keyPair();
  const stranger = await keyPair();
  let mf: Miniflare | undefined;
  try {
    await bundle();
    mf = await start(operator.publicKey);
    const labCommand = (issued = Date.now(), authority: string = LAB_ADMISSION_AUTHORITY_ID, environment = "lab", confirm = false) =>
      [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", environment, authority, ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", issued, confirm] as unknown as AuthorityInitializationCommand;
    const sign = (command: AuthorityInitializationCommand, key = operator.privatePkcs8) => signAuthorityInitializationCommand(command, key);
    const unchanged = async (label: string) => { const c = await counts(mf!); assert.equal(c.ok, expected, `${label}: no dispatch reached the admission binding`); };
    let expected = 0;

    // 8. no unintended public route: every method and path answers an empty 404 and reaches nothing
    for (const name of ["executor-lab", "executor-production-env", "executor-throwing", "executor-garbage"]) {
      const worker = await mf.getWorker(name);
      for (const method of ["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"]) for (const path of ["/", "/submit-initialize", "/initialize", "/rotate", "/.well-known/x"]) {
        const response = await worker.fetch(`http://localhost${path}`, { method, headers: { "content-type": "application/json" }, ...(method === "GET" || method === "HEAD" ? {} : { body: "{}" }) });
        assert.equal(response.status, 404, `${name} ${method} ${path}`);
        if (method !== "HEAD") assert.equal(await response.text(), "");
      }
    }
    await unchanged("public routes");

    // 1. valid lab-bound operator authorization: exactly one dispatch, lab environment and lab authority, ATTESTED relayed with the exact opaque bytes
    const good = labCommand();
    const accepted = await drive(mf, "/submit-initialize", "lab", sealed(good, await sign(good)));
    assert.deepEqual(accepted.result, { status: "ATTESTED", relayDisposition: "APPLIED", envelopeHex: "010203" });
    expected += 1;
    const afterGood = await counts(mf);
    assert.equal(afterGood.ok, 1);
    assert.deepEqual(afterGood.last, { environment: "lab", authorityId: LAB_ADMISSION_AUTHORITY_ID, operation: "initialize" });
    // within the freshness window (issued 4 minutes ago) is accepted too
    const aged = labCommand(Date.now() - 240_000);
    assert.equal((await drive(mf, "/submit-initialize", "lab", sealed(aged, await sign(aged)))).result?.status, "ATTESTED");
    expected += 1;

    // 2. production environment rejection: (a) an executor configured as production refuses a lab artifact; (b) the lab executor refuses a production artifact
    assert.deepEqual(await drive(mf, "/submit-initialize", "productionEnv", sealed(good, await sign(good))), { error: "invalid-executor-environment" });
    const production = labCommand(Date.now(), ADMISSION_AUTHORITY_ID, "production", true);
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(production, await sign(production))), { error: "invalid-sealed-artifact" });
    const staging = labCommand(Date.now(), STAGING_ADMISSION_AUTHORITY_ID, "staging", false);
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(staging, await sign(staging))), { error: "invalid-sealed-artifact" });
    await unchanged("environment rejection");

    // 3. wrong authority: a lab command naming the production authority, the staging authority, an unknown id, or a lab command with a production confirmation
    for (const authority of [ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID, "wrong", ""]) {
      const wrong = labCommand(Date.now(), authority);
      assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(wrong, await sign(wrong).catch(() => "A".repeat(86)))), { error: "invalid-sealed-artifact" }, `authority ${authority}`);
    }
    const confirmed = labCommand(Date.now(), LAB_ADMISSION_AUTHORITY_ID, "lab", true);
    assert.equal((await drive(mf, "/submit-initialize", "lab", sealed(confirmed, "A".repeat(86)))).error, "invalid-sealed-artifact");
    await unchanged("wrong authority");

    // 4. missing or invalid operator signature
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(good, await sign(good, stranger.privatePkcs8))), { error: "operator-signature" });
    for (const bad of ["", "not-base64url!", "A".repeat(10), "A".repeat(87)]) {
      assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(good, bad)), { error: "invalid-sealed-artifact" }, `signature ${bad}`);
    }
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", { sealedJson: JSON.stringify({ command: good }) }), { error: "invalid-sealed-artifact" }, "no signature member");
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", { sealedJson: "" }), { error: "invalid-sealed-artifact" });
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", { sealedJson: "x".repeat(4_097) }), { error: "invalid-sealed-artifact" });
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", { sealedJson: `{"command":[],"command":[],"signature":"x"}` }), { error: "invalid-sealed-artifact" }, "duplicate member");
    await unchanged("signature failures");

    // 5. expired (and future-dated) authorization
    for (const skew of [-310_000, 310_000, -3_600_000, 3_600_000]) {
      const stale = labCommand(Date.now() + skew);
      assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(stale, await sign(stale))), { error: "invalid-sealed-artifact" }, `skew ${skew}`);
    }
    await unchanged("freshness");

    // 6. unsupported rotation: not an RPC method at all, and a rotate-release artifact sent to the initialization method is refused
    const rotation = await drive(mf, "/submit-rotate", "lab", { sealedJson: "x" });
    assert.match(String(rotation.error), /RPC receiver does not implement the method/u);
    const rotateCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "rotate-release", "lab", LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "r1", "k1", "r2", "k2", Date.now(), Date.now(), 1, false] as never;
    const rotateSignature = await signAuthorityReleaseRotationCommand(rotateCommand, operator.privatePkcs8).catch(() => "A".repeat(86));
    assert.deepEqual(await drive(mf, "/submit-initialize", "lab", sealed(rotateCommand, rotateSignature)), { error: "invalid-sealed-artifact" });
    await unchanged("rotation");

    // 7. transport failure: UNCONFIRMED, exactly ONE dispatch (no automatic retry); a malformed answer is UNCONFIRMED too
    const failed = await drive(mf, "/submit-initialize", "throwing", sealed(good, await sign(good)));
    assert.equal(failed.result?.status, "UNCONFIRMED");
    assert.equal(typeof failed.result?.instruction, "string");
    const garbage = await drive(mf, "/submit-initialize", "garbage", sealed(good, await sign(good)));
    assert.equal(garbage.result?.status, "UNCONFIRMED");
    const final = await counts(mf);
    assert.deepEqual([final.ok, final.throwing, final.garbage], [expected, 1, 1], "one dispatch each; nothing was retried");

    console.log("Lab operator executor runtime (workerd): PASS (valid lab artifact dispatched once; production/staging/foreign-authority/unsigned/forged/expired/oversize/duplicate-member refused before dispatch; rotation absent; transport failure and malformed answer UNCONFIRMED with one dispatch; no public route)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
void main();
