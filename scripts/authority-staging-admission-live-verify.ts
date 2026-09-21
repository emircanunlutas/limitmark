import { createHash } from "node:crypto";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { validateNeverInitializedStagingLifecycleSnapshot } from "../deployment/lifecycle-private-contract";

// Gate 4B live-read-only proof. This is the ONLY script in the repository
// that is expected to contact Cloudflare when actually run by an operator: it
// starts `wrangler dev` (default mode -- never --local, never --remote)
// against the local-only harness in
// wrangler.staging-admission-live-readonly.local.jsonc, whose single
// `remote: true` service binding causes Wrangler to proxy exactly one call to
// the already-deployed limitmark-admission-service-staging Worker's
// StagingAuthorityLifecycleReadOnly.inspectLifecycle entrypoint while the
// harness Worker itself stays local and is never published. It performs
// exactly one inspection call, never retries it, and applies
// validateNeverInitializedStagingLifecycleSnapshot to the result: any
// mismatch -- including a live authority that already reports
// initialized:true -- is a hard refusal, never a repair, reset or broader
// fallback. It must never be executed by an automated agent: doing so
// authenticates to and reads from a live Cloudflare account.

const port = 8800;
const base = `http://127.0.0.1:${port}`;
const processOutput = new WeakMap<ChildProcess, string[]>();

function fingerprint(accountId: string): string {
  return createHash("sha256").update(accountId).digest("hex").slice(0, 16);
}

function accountId(): string {
  const value = process.env.CLOUDFLARE_ACCOUNT_ID;
  if (typeof value !== "string" || !/^[a-f0-9]{32}$/u.test(value) || /^0{32}$/u.test(value))
    throw new Error("missing-or-malformed-account-pin");
  return value;
}

function digestArg(): string {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--digest" || !args[1] || !/^[a-f0-9]{64}$/u.test(args[1]))
    throw new Error("explicit-valid-digest-required");
  return args[1];
}

function start(): ChildProcess {
  const child = spawn(process.execPath, [join(process.cwd(), "node_modules/wrangler/bin/wrangler.js"), "dev",
    "--config", "wrangler.staging-admission-live-readonly.local.jsonc", "--ip", "127.0.0.1", "--port", String(port),
    "--show-interactive-dev-session=false"], { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const output: string[] = [];
  processOutput.set(child, output);
  child.stdout?.on("data", (chunk) => output.push(String(chunk)));
  child.stderr?.on("data", (chunk) => output.push(String(chunk)));
  return child;
}

/** Readiness only: probes until the local dev socket answers at all (any HTTP
 * response, even 404, proves the server is up). The one real inspection call
 * that follows is never retried. */
async function waitForSocket(child: ChildProcess): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`wrangler dev exited early: ${child.exitCode}\n${processOutput.get(child)?.join("") ?? ""}`);
    try { await fetch(base, { signal: AbortSignal.timeout(500) }); return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("wrangler dev did not become ready");
}

async function stop(child: ChildProcess): Promise<void> {
  if (process.platform === "win32" && child.pid) spawnSync("taskkill.exe", ["/pid", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
  else if (child.exitCode === null) child.kill("SIGTERM");
  if (child.exitCode !== null) return;
  await new Promise<void>((resolve) => { child.once("exit", () => resolve()); setTimeout(resolve, 3_000); });
}

async function main(): Promise<void> {
  const digest = digestArg();
  const pin = accountId();
  const child = start();
  let snapshot: unknown;
  try {
    await waitForSocket(child);
    const response = await fetch(`${base}/__gate4-live-readonly/inspect`, {
      method: "POST", signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json", "x-gate4-live-readonly-harness": "phase5c-gate4b" },
      body: JSON.stringify({ digest }),
    });
    if (!response.ok) throw new Error(`live-readonly-harness-refused-${response.status}`);
    snapshot = await response.json();
  } finally { await stop(child); }
  validateNeverInitializedStagingLifecycleSnapshot(snapshot);
  process.stdout.write(`${JSON.stringify({ status: "PASS", proof: "live-never-initialized", accountFingerprint: fingerprint(pin), digest })}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`Gate 4B live read-only proof: REFUSED (${error instanceof Error ? error.message : "unknown"}). No mutation was attempted; this result is not retried automatically.\n`);
  process.exitCode = 2;
});
