// Lab environment: a durable workerd integration exercising the ACTUAL lab runtime classes (LabAdmissionAuthority, LabAuthorityLifecycleOnly,
// LabAuthorityLifecycleReadOnly, LabOperatorLifecycleExecutor, LabLifecycleDispatchGuard, lab mailbox/observer) over real service and
// Durable Object bindings. No Production or staging runtime class stands in for lab, and no Production/staging class is bundled into the lab
// admission Worker (it is built from workers/admission-service/lab-index.ts). Keys are freshly generated per run (never provisioned).
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build, type Plugin } from "esbuild";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, LAB_ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { AUTHORITY_OPERATOR_COMMAND_VERSION, commandDigest, signAuthorityInitializationCommand,
  type AuthorityInitializationCommand } from "../../workers/admission-service/operator-command";
import { parseLabAuthorityResultTrustManifest, verifyAuthoritySignedStatement } from "../../src/lib/authority-result-trust";
import { authenticateSealedLifecycleArtifact } from "../../operator/lifecycle-submitter";
import { readLabAuthorityResult } from "../../operator/lab-authority-result";

const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `lab-mailbox-${process.pid}-${randomUUID()}`);
const paths = Object.fromEntries(["mailbox", "observer", "executor", "admission", "driver"].map((name) => [name, join(runtimeRoot, `${name}.mjs`)]));
const entries: Record<string, string> = {
  mailbox: "workers/lifecycle-mailbox/lab-index.ts",
  observer: "workers/lab-lifecycle-observer.ts",
  executor: "workers/lab-operator-lifecycle-executor.ts",
  admission: "workers/admission-service/lab-index.ts",
  driver: "tests/workers/support/lab-lifecycle-driver.ts",
};
const localFiles: Plugin = { name: "workspace-files", setup(api) {
  api.onResolve({ filter: /.*/ }, async (args) => {
    if (args.path === "cloudflare:workers") return { path: args.path, external: true };
    // Bare package specifiers (for example jose) fall through to esbuild's own resolver, which honours the workerd conditions below.
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
    const result = await build({ entryPoints: [resolve(root, entry)], outfile: paths[name], bundle: true, write: false,
      plugins: [localFiles], platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
      external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(paths[name], result.outputFiles[0].contents);
  }));
}

async function keyPair(): Promise<{ privatePkcs8: string; publicKey: string; fingerprint: string }> {
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privatePkcs8: encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))), publicKey: encodeBase64url(raw),
    fingerprint: createHash("sha256").update(raw).digest("hex") };
}

async function start(operatorPublicKey: string, attestation: { privatePkcs8: string; publicKey: string; fingerprint: string }, persistence: string): Promise<Miniflare> {
  const date = "2026-09-13";
  const admissionBindings = {
    AUTHORITY_LAB_ATTESTATION_PRIVATE_KEY: attestation.privatePkcs8, AUTHORITY_LAB_ATTESTATION_PUBLIC_KEY: attestation.publicKey,
    AUTHORITY_LAB_ATTESTATION_KEY_FINGERPRINT: attestation.fingerprint,
    AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey,
    ADMISSION_CURRENT_RPC_KEY: encodeBase64url(new Uint8Array(32).fill(7)),
    ADMISSION_CURRENT_RELEASE_ID: "lab-current", ADMISSION_CURRENT_KEY_ID: "lab-key",
    ADMISSION_CURRENT_ACTIVATED_AT_MS: "1", VERCEL_OIDC_ISSUER: "https://oidc.vercel.com/synthetic",
    VERCEL_OIDC_AUDIENCE: "synthetic", VERCEL_OIDC_SUBJECT: "owner:synthetic:project:synthetic:environment:production",
    VERCEL_OWNER_ID: "synthetic", VERCEL_PROJECT_ID: "synthetic",
  };
  const buckets = { REQUEST_BUCKET: "lab-requests", RESULT_BUCKET: "lab-results" };
  const workers = [
    { name: "mailbox", scriptPath: paths.mailbox, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["mailbox.local/*"],
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, LIFECYCLE_ENVIRONMENT: "lab" }, r2Buckets: buckets,
      durableObjects: { DISPATCH_GUARD: { className: "LabLifecycleDispatchGuard", useSQLite: true } },
      serviceBindings: { LIFECYCLE_EXECUTOR: { name: "executor" },
        LIFECYCLE_READER: { name: "admission", entrypoint: "LabAuthorityLifecycleReadOnly" } } },
    { name: "observer", scriptPath: paths.observer, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      routes: ["observer.local/*"], bindings: { LIFECYCLE_OBSERVER_ENVIRONMENT: "lab" },
      r2Buckets: buckets, serviceBindings: { LIFECYCLE_READER: { name: "admission", entrypoint: "LabAuthorityLifecycleReadOnly" } } },
    { name: "executor", scriptPath: paths.executor, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: operatorPublicKey, OPERATOR_EXECUTOR_ENVIRONMENT: "lab" },
      serviceBindings: { ADMISSION_SERVICE: { name: "admission", entrypoint: "LabAuthorityLifecycleOnly" } } },
    { name: "admission", scriptPath: paths.admission, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      bindings: admissionBindings, durableObjects: { AUTHORITY: { className: "LabAdmissionAuthority", useSQLite: true } } },
    { name: "driver", scriptPath: paths.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false,
      serviceBindings: { LAB_EXECUTOR: { name: "executor" }, LAB_ADMISSION_LIFECYCLE_ONLY: { name: "admission", entrypoint: "LabAuthorityLifecycleOnly" } } },
  ];
  const options = convertV4MiniflareOptions({ host: "127.0.0.1", port: 0, log: new Log(LogLevel.ERROR), unsafeTriggerHandlers: true,
    resourcePersistencePath: persistence, workers } as unknown as V4MiniflareOptions);
  options.unsafeInspectDurableObjects = true;
  options.telemetry = { enabled: false };
  const mf = new Miniflare(options);
  await mf.ready;
  return mf;
}

async function scheduled(mf: Miniflare, worker: "mailbox" | "observer"): Promise<void> {
  const response = await mf.dispatchFetch(`http://${worker}.local/cdn-cgi/local/scheduled`);
  assert.equal(response.status, 200);
}
async function sql(mf: Miniflare, script: string, className: string, name: string, query: string): Promise<Array<Record<string, unknown>>> {
  const storage = await mf.unsafeGetDurableObjectStorage(script, className, { name });
  return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
}
const GUARD = "lab-lifecycle-dispatch-v1";

async function main(): Promise<void> {
  const resolved = resolve(runtimeRoot);
  assert.ok(resolved.startsWith(resolve(root, ".wrangler", "tests") + sep));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  const operator = await keyPair();
  const attestation = await keyPair();
  let mf: Miniflare | undefined;
  try {
    await bundle();
    mf = await start(operator.publicKey, attestation, join(runtimeRoot, "state"));

    // No public HTTP lifecycle path exists on any private lab Worker.
    assert.equal((await (await mf.getWorker("mailbox")).fetch("http://localhost/initialize.json")).status, 404);
    assert.equal((await (await mf.getWorker("observer")).fetch("http://localhost/reconcile.json")).status, 404);
    assert.equal((await (await mf.getWorker("executor")).fetch("http://localhost/")).status, 404);

    const requests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
    const results = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
    const driver = await mf.getWorker("driver");
    const labCommand = (issued = Date.now()): AuthorityInitializationCommand => [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab",
      LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", issued, false];

    // Foreign-environment artifacts delivered to the lab runtime are rejected before any claim is consumed.
    const foreign: AuthorityInitializationCommand[] = [
      [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "production", ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", Date.now(), true],
      [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "staging", STAGING_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", Date.now(), false],
      [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab", LAB_ADMISSION_AUTHORITY_ID, ADMISSION_POLICY_EPOCH, "lab-current", "lab-key", Date.now(), true],
    ];
    for (const command of foreign) {
      const forged = await signAuthorityInitializationCommand(command, operator.privatePkcs8).catch(() => "A".repeat(86)); // a lab command with a production confirmation cannot even be signed
      await requests.put("initialize.json", JSON.stringify({ command, signature: forged }));
      await scheduled(mf, "mailbox");
    }
    assert.equal((await sql(mf, "mailbox", "LabLifecycleDispatchGuard", GUARD, "SELECT * FROM claims")).length, 0, "no foreign artifact consumes a lab dispatch claim");
    assert.equal((await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID,
      "SELECT name FROM sqlite_master WHERE type='table' AND name='authority_meta'")).length, 0, "the lab authority remains uninitialized");

    // Until initialized, the lab data plane fails closed.
    const stub = (await mf.getDurableObjectNamespace("AUTHORITY", "admission")).getByName(LAB_ADMISSION_AUTHORITY_ID) as unknown as
      Record<string, (input: unknown) => Promise<{ decision: string }>>;
    const claim = (n: number) => ({ releaseId: "lab-current", clientPseudonym: encodeBase64url(new Uint8Array(32).fill(n)),
      requestBinding: encodeBase64url(new Uint8Array(32).fill(n + 1)), nonce: encodeBase64url(new Uint8Array(16).fill(n + 2)), issuedAtMs: Date.now() });
    assert.equal((await stub.claimPre(claim(1))).decision, "unavailable", "uninitialized lab authority fails closed");

    // A valid lab initialization initializes only the lab authority.
    const command = labCommand();
    const digest = await commandDigest(command);
    const signature = await signAuthorityInitializationCommand(command, operator.privatePkcs8);
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    const claimRows = await sql(mf, "mailbox", "LabLifecycleDispatchGuard", GUARD, "SELECT digest,status FROM claims");
    assert.equal(claimRows.length, 1);
    assert.equal(claimRows[0].status, "SUCCESS");
    assert.equal(claimRows[0].digest, digest);
    const receiptRows = await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID, "SELECT digest,authority_id,environment FROM lifecycle_receipts");
    assert.equal(receiptRows.length, 1);
    assert.equal(receiptRows[0].authority_id, LAB_ADMISSION_AUTHORITY_ID);
    assert.equal(receiptRows[0].environment, "lab");

    // The stored object is the lab Authority's exact signed envelope; it verifies under the LAB trust key only and is POSITIVE for the
    // operator-authenticated lab command.
    const lifecycle = await results.get(`lifecycle/${digest}.json`);
    assert.ok(lifecycle, "the signed lab lifecycle result was published");
    const bytes = new Uint8Array(await lifecycle!.arrayBuffer());
    const trust = await parseLabAuthorityResultTrustManifest(JSON.stringify({ manifestVersion: 1, attestationVersion: 2, trustEpoch: 1, environments: [{
      environment: "lab", authorityId: LAB_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, currentKeyFingerprint: attestation.fingerprint,
      keys: [{ keyFingerprint: attestation.fingerprint, publicKey: attestation.publicKey, status: "active", notBeforeMs: 1, notAfterMs: null }] }] }));
    const verified = await verifyAuthoritySignedStatement(bytes, { kind: "lifecycle", environment: "lab", authorityId: LAB_ADMISSION_AUTHORITY_ID,
      policyEpoch: ADMISSION_POLICY_EPOCH, digest }, trust, Date.now());
    assert.equal(verified.statement.environment, "lab");
    const authenticated = await authenticateSealedLifecycleArtifact(new TextEncoder().encode(JSON.stringify({ command, signature })), operator.publicKey, { expectedEnvironment: "lab" });
    const read = await readLabAuthorityResult({ kind: "lifecycle", digest, bytes, trustManifest: trust, nowMs: Date.now(), authenticatedCommand: authenticated });
    assert.equal(read.status, "POSITIVE");

    // Replay protection is enforced by the lab Durable Object; exact artifact replay is idempotent.
    assert.equal((await stub.claimPre(claim(1))).decision, "allowed");
    assert.equal((await stub.claimPre(claim(1))).decision, "replay");
    await requests.put("initialize.json", JSON.stringify({ command, signature }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "mailbox", "LabLifecycleDispatchGuard", GUARD, "SELECT * FROM claims")).length, 1, "replay does not create a second claim");
    assert.equal((await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID, "SELECT * FROM lifecycle_receipts")).length, 1);

    // Immutability: a different, validly signed lab command cannot re-initialize.
    const second: AuthorityInitializationCommand = [AUTHORITY_OPERATOR_COMMAND_VERSION, "initialize", "lab", LAB_ADMISSION_AUTHORITY_ID,
      ADMISSION_POLICY_EPOCH, "lab-other-release", "lab-key", Date.now() + 1, false];
    await requests.put("initialize.json", JSON.stringify({ command: second, signature: await signAuthorityInitializationCommand(second, operator.privatePkcs8) }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID, "SELECT * FROM lifecycle_receipts")).length, 1, "no second receipt");
    assert.equal((await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID, "SELECT release_id FROM active_releases")).length, 1);

    // Signed read-only reconciliation through the real observer chain.
    const nonce = "a".repeat(32);
    await requests.put("reconcile.json", JSON.stringify({ version: 1, digest, nonce }));
    await scheduled(mf, "observer");
    const reconciliation = await results.get(`reconciliation/${nonce}.json`);
    assert.ok(reconciliation, "the lab observer published a signed reconciliation");
    const verifiedReconciliation = await verifyAuthoritySignedStatement(new Uint8Array(await reconciliation!.arrayBuffer()), { kind: "reconciliation", environment: "lab",
      authorityId: LAB_ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH, digest, nonce }, trust, Date.now());
    assert.equal(verifiedReconciliation.statement.kind === "reconciliation" && verifiedReconciliation.statement.status, "EXACT_RECEIPT");

    // Lab rotation is closed at the real RPC surface.
    const guardStub = (await mf.getDurableObjectNamespace("DISPATCH_GUARD", "mailbox")).getByName(GUARD) as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
    assert.deepEqual(JSON.parse(JSON.stringify(await guardStub.processRotation())), { version: 1, digest: "", status: "REFUSED", reason: "lab-rotation-not-implemented" });
    const executorProbe = await (await driver.fetch("http://localhost/probe-executor-rotation")).json() as { exposed: boolean; message?: string };
    assert.equal(executorProbe.exposed, false);
    assert.match(String(executorProbe.message), /RPC receiver does not implement the method/u);
    const admissionProbe = await (await driver.fetch("http://localhost/probe-admission-rotation")).json() as { result: unknown };
    assert.deepEqual(admissionProbe.result, { status: "refused" });
    await requests.put("rotate-release.json", JSON.stringify({ command: ["garbage"], signature: "x" }));
    await scheduled(mf, "mailbox");
    assert.equal((await sql(mf, "mailbox", "LabLifecycleDispatchGuard", GUARD, "SELECT * FROM claims")).length, 1, "a rotate artifact produces no claim");

    // The public admission Worker is fail-closed without a valid caller identity.
    const admission = await mf.getWorker("admission");
    const publicResponse = await admission.fetch("http://localhost/", { method: "POST", body: "{}" });
    assert.ok(publicResponse.status >= 400, "unauthenticated public admission request is refused");

    await mf.dispose(); mf = undefined;

    // Restart with retained SQLite storage: initialization, replay history and claim ledger persist.
    mf = await start(operator.publicKey, attestation, join(runtimeRoot, "state"));
    assert.deepEqual(await sql(mf, "admission", "LabAdmissionAuthority", LAB_ADMISSION_AUTHORITY_ID, "SELECT digest FROM lifecycle_receipts"), receiptRows.map((row) => ({ digest: row.digest })));
    assert.deepEqual(await sql(mf, "mailbox", "LabLifecycleDispatchGuard", GUARD, "SELECT digest,status FROM claims"), claimRows);
    const restarted = (await mf.getDurableObjectNamespace("AUTHORITY", "admission")).getByName(LAB_ADMISSION_AUTHORITY_ID) as unknown as
      Record<string, (input: unknown) => Promise<{ decision: string }>>;
    assert.equal((await restarted.claimPre(claim(1))).decision, "replay", "replay history survives a full restart");

    // Control-plane failure does not disable admission: with the signer binding removed, attested reads are UNAVAILABLE but claims continue.
    await mf.dispose(); mf = undefined;
    const noSigner = { privatePkcs8: "", publicKey: "", fingerprint: "" };
    mf = await start(operator.publicKey, noSigner, join(runtimeRoot, "state"));
    const degraded = (await mf.getDurableObjectNamespace("AUTHORITY", "admission")).getByName(LAB_ADMISSION_AUTHORITY_ID) as unknown as
      Record<string, (...args: unknown[]) => Promise<{ decision?: string; status?: string }>>;
    const unattested = JSON.parse(JSON.stringify(await degraded.attestAppliedLifecycle(digest))) as { status: string };
    assert.equal(unattested.status, "UNAVAILABLE", "without a signer the control plane reports UNAVAILABLE");
    assert.equal((await degraded.claimPre(claim(40))).decision, "allowed", "lab admission continues without the control plane signer");

    console.log("Lab workerd mailbox/guard/executor/admission/observer integration: PASS (actual lab classes, cross-worker RPC, foreign-artifact rejection, " +
      "initialization, signed POSITIVE result, DO replay protection, immutability, restart persistence, rotation closed, control-plane failure isolated)");
  } finally {
    if (mf) await mf.dispose();
    await rm(runtimeRoot, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
void main();
