import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, extname, isAbsolute, join, resolve, sep } from "node:path";
import { build } from "esbuild";
import { localFiles } from "../support/worker-bundle";
import { convertV4MiniflareOptions, Log, LogLevel, Miniflare, type V4MiniflareOptions } from "miniflare";
import { encodeBase64url } from "../../src/lib/ingress-protocol";
import { ADMISSION_AUTHORITY_ID, LAB_ADMISSION_AUTHORITY_ID } from "../../workers/admission-service/authority";
import { GUARD_EXPORT_OPERATION, GUARD_EXPORT_REQUEST_VERSION, guardExportRequestDigest, signGuardExportRequest, type GuardExportRequest } from "../../workers/lifecycle-mailbox/guard-export";
import { guardLedgerExportFromMailboxResult } from "../../operator/guard-ledger-export";

// Real workerd: the mailbox Worker (guard Durable Object + read-only LifecycleGuardReadOnly entrypoint), the observer Worker with ONLY a service binding
// to that entrypoint, and a driver that can call the same entrypoint. Proves: authenticated read-only export through the observer slot; no result for
// unauthenticated requests; environment/account confusion refused; the entrypoint exposes nothing but exportLedger; no mutation of the ledger; the
// observer cannot be used to dispatch; the mailbox is never scheduled in this posture.

const GUARD = "production-lifecycle-dispatch-v1";
const ACCOUNT = "c".repeat(32);
const root = process.cwd();
const runtimeRoot = join(root, ".wrangler", "tests", `guard-export-${process.pid}-${randomUUID()}`);
const names = ["mailbox", "observer", "stub", "driver"] as const;
const paths = Object.fromEntries(names.map((name) => [name, join(runtimeRoot, `${name}.mjs`)])) as Record<(typeof names)[number], string>;
const entries: Record<(typeof names)[number], string> = { mailbox: "workers/lifecycle-mailbox/index.ts", observer: "workers/lifecycle-observer.ts",
  stub: "tests/workers/support/guard-export-stub.ts", driver: "tests/workers/support/guard-export-driver.ts" };


async function bundle(): Promise<void> {
  await Promise.all(names.map(async (name) => {
    const result = await build({ entryPoints: [resolve(root, entries[name])], outfile: paths[name], bundle: true, write: false,
      plugins: [localFiles], platform: "browser", format: "esm", target: "es2022", conditions: ["workerd", "worker", "browser"],
      external: ["cloudflare:workers"], logLevel: "silent" });
    await writeFile(paths[name], result.outputFiles[0].contents);
  }));
}

async function start(publicKey: string, persistence: string): Promise<Miniflare> {
  const date = "2026-09-13";
  const buckets = { REQUEST_BUCKET: "ge-requests", RESULT_BUCKET: "ge-results" };
  const guardReader = { name: "mailbox", entrypoint: "LifecycleGuardReadOnly" };
  const workers = [
    { name: "mailbox", scriptPath: paths.mailbox, modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["mailbox.local/*"],
      bindings: { AUTHORITY_OPERATOR_PUBLIC_KEY: publicKey, LIFECYCLE_ENVIRONMENT: "production", CLOUDFLARE_ACCOUNT_ID: ACCOUNT }, r2Buckets: buckets,
      durableObjects: { DISPATCH_GUARD: { className: "LifecycleDispatchGuard", useSQLite: true } },
      serviceBindings: { LIFECYCLE_EXECUTOR: { name: "stub", entrypoint: "Inert" }, LIFECYCLE_READER: { name: "stub", entrypoint: "Inert" } } },
    // The observer has NO Durable Object binding and NO executor binding: only the Authority read-only reader (inert here) and the guard read-only entrypoint.
    { name: "observer", scriptPath: paths.observer, modules: true, compatibilityDate: date, unsafeRegisterWorker: false, routes: ["observer.local/*"], r2Buckets: buckets,
      serviceBindings: { LIFECYCLE_READER: { name: "stub", entrypoint: "Inert" }, GUARD_READER: guardReader } },
    { name: "stub", scriptPath: paths.stub, modules: true, compatibilityDate: date, unsafeRegisterWorker: false },
    { name: "driver", scriptPath: paths.driver, modules: true, compatibilityDate: date, unsafeRegisterWorker: false, serviceBindings: { GUARD_READER: guardReader } },
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
  assert.equal((await mf.dispatchFetch(`http://${worker}.local/cdn-cgi/local/scheduled`)).status, 200);
}
async function sql(mf: Miniflare, query: string): Promise<Array<Record<string, unknown>>> {
  const storage = await mf.unsafeGetDurableObjectStorage("mailbox", "LifecycleDispatchGuard", { name: GUARD });
  return storage.exec(query) as Promise<Array<Record<string, unknown>>>;
}
const dump = async (mf: Miniflare) => JSON.stringify(await Promise.all(["claims", "latch", "settlements"].map((table) => sql(mf, `SELECT * FROM ${table}`))));

async function main(): Promise<void> {
  assert.ok(resolve(runtimeRoot).startsWith(resolve(root, ".wrangler", "tests") + sep));
  await mkdir(runtimeRoot, { recursive: true });
  process.env.WRANGLER_SEND_METRICS = "false";
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)));
  const publicKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const strangerPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const strangerKey = encodeBase64url(new Uint8Array(await crypto.subtle.exportKey("pkcs8", strangerPair.privateKey)));
  let counter = 1;
  const nonce = () => (counter++).toString(16).padStart(32, "e");
  const request = (overrides: Partial<Record<number, unknown>> = {}): GuardExportRequest => {
    const base: unknown[] = [GUARD_EXPORT_REQUEST_VERSION, GUARD_EXPORT_OPERATION, "production", ADMISSION_AUTHORITY_ID, GUARD, ACCOUNT, nonce(), Date.now()];
    for (const [index, value] of Object.entries(overrides)) base[Number(index)] = value;
    return base as unknown as GuardExportRequest;
  };
  const signed = async (req: GuardExportRequest, key = privateKey) => JSON.stringify({ request: req, signature: await signGuardExportRequest(req, key) });
  let mf: Miniflare | undefined;
  try {
    await bundle();
    mf = await start(publicKey, join(runtimeRoot, "state"));
    const requests = await mf.getR2Bucket("REQUEST_BUCKET", "mailbox");
    const results = await mf.getR2Bucket("RESULT_BUCKET", "mailbox");
    const result = async (req: GuardExportRequest) => results.get(`ledger-export/${req[6]}.json`);

    // 1. empty-ledger export through the observer slot (the guard object is first activated by this read; its constructor only ensures empty tables)
    const first = request();
    await requests.put("export-ledger.json", await signed(first));
    await scheduled(mf, "observer");
    const firstObject = await result(first);
    assert.ok(firstObject, "authenticated request produces ledger-export/<nonce>.json");
    const firstText = await firstObject!.text();
    const firstDocument = guardLedgerExportFromMailboxResult(firstText, { environment: "production", guardObject: GUARD, accountId: ACCOUNT, requestDigest: await guardExportRequestDigest(first), nonce: first[6] });
    assert.deepEqual([firstDocument.derived.claimCount, firstDocument.derived.latchHeld, firstDocument.provenance.kind], [0, false, "mailbox-export"]);

    // 2. seed a stranded-looking ledger directly in the DO storage (test fixture), export it, and prove the export changed nothing
    await sql(mf, "INSERT INTO claims(digest,operation,status) VALUES('" + "a".repeat(64) + "','initialize','CLAIMED')");
    await sql(mf, "INSERT INTO latch(singleton,digest) VALUES(1,'" + "a".repeat(64) + "')");
    const beforeDump = await dump(mf);
    const second = request();
    await requests.put("export-ledger.json", await signed(second));
    await scheduled(mf, "observer");
    const secondDocument = guardLedgerExportFromMailboxResult(await (await result(second))!.text(), { environment: "production", guardObject: GUARD, accountId: ACCOUNT, requestDigest: await guardExportRequestDigest(second), nonce: second[6] });
    assert.deepEqual([secondDocument.derived.strandedCandidate, secondDocument.derived.dispatchBlocked, secondDocument.derived.latchedDigest], [true, true, "a".repeat(64)]);
    assert.equal(await dump(mf), beforeDump, "export leaves claims, latch and settlements byte-identical");

    // 3. result keys are write-once: replaying the same signed request after the ledger changed does not overwrite the published object
    const published = await (await result(second))!.text();
    await sql(mf, "INSERT INTO settlements(digest,version,status,sequence,settled_ms) VALUES('" + "a".repeat(64) + "',1,'SETTLED',1,1)");
    await sql(mf, "DELETE FROM latch");
    await scheduled(mf, "observer");
    assert.equal(await (await result(second))!.text(), published, "an existing result is never overwritten");

    // 4. authentication failures publish NOTHING (an unauthenticated writer cannot make the observer write)
    const unsignedRequest = request();
    for (const [name, text] of Object.entries({
      wrongKey: await signed(unsignedRequest, strangerKey),
      noSignature: JSON.stringify({ request: unsignedRequest }),
      garbage: "{",
      tampered: (await signed(unsignedRequest)).replace('"production"', '"productioo"'),
    })) {
      await requests.put("export-ledger.json", text);
      await scheduled(mf, "observer");
      assert.equal(await result(unsignedRequest), null, `${name}: no result object`);
    }
    assert.equal((await results.list({ prefix: "ledger-export/" })).objects.length, 2, "only the two authenticated exports exist");

    // 5. environment / account confusion and stale requests: authenticated but ineligible => refusal object naming the nonce, no row content
    for (const [name, overrides, reason] of [
      ["staging environment", { 2: "staging" }, "target-mismatch"], ["lab authority", { 3: LAB_ADMISSION_AUTHORITY_ID }, "target-mismatch"],
      ["staging guard", { 4: "staging-lifecycle-dispatch-v1" }, "target-mismatch"], ["other account", { 5: "d".repeat(32) }, "target-mismatch"],
      ["stale", { 7: Date.now() - 3_600_000 }, "stale-request"],
    ] as const) {
      const req = request(overrides);
      await requests.put("export-ledger.json", await signed(req));
      await scheduled(mf, "observer");
      const refusal = await (await result(req))!.json() as Record<string, unknown>;
      assert.deepEqual(refusal, { version: 1, status: "REFUSED", reason, nonce: req[6], requestDigest: await guardExportRequestDigest(req) }, name);
    }

    // 6. the guard entrypoint exposes ONLY exportLedger; every mutating or generic method is "not implemented" for a binding holder
    const driver = await mf.getWorker("driver");
    const call = async (method: string, body = "x") => (await driver.fetch(`http://driver.local/?method=${method}`, { method: "POST", body })).json() as Promise<{ ok: boolean; error?: string; result?: unknown }>;
    const before = await dump(mf);
    for (const method of ["processInitialization", "processRotation", "settle", "getByName", "sql", "exec", "transactionSync", "sync", "deleteClaim", "reset", "one"]) {
      const outcome = await call(method);
      assert.equal(outcome.ok, false, method);
      assert.match(outcome.error ?? "", /RPC receiver does not implement the method|not implemented|does not implement/iu, `${method} must not be callable through the read-only entrypoint`);
    }
    assert.equal(await dump(mf), before, "attempts to dispatch or mutate through the read-only entrypoint changed nothing");
    const abused = await call("exportLedger", "'; DELETE FROM claims; --");
    assert.deepEqual(abused, { ok: true, result: { version: 1, status: "REFUSED", reason: "unauthenticated" } });
    assert.equal(await dump(mf), before);

    // 7. the observer cannot be used to dispatch: a lifecycle artifact placed in the request bucket is ignored by the observer, and the stub (executor/reader) is never called
    await requests.put("initialize.json", JSON.stringify({ command: [], signature: "" }));
    await requests.put("rotate-release.json", JSON.stringify({ command: [], signature: "" }));
    await scheduled(mf, "observer");
    assert.equal(await dump(mf), before);
    const stubCalls = await (await (await mf.getWorker("stub")).fetch("http://stub.local/")).json() as { calls: number };
    assert.equal(stubCalls.calls, 0, "no executor/reader call happened on the export path");
    assert.equal((await results.list({ prefix: "lifecycle/" })).objects.length, 0, "no lifecycle result was produced");
    console.log("guard export integration: all assertions passed");
  } finally {
    await mf?.dispose();
    await rm(runtimeRoot, { recursive: true, force: true });
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
