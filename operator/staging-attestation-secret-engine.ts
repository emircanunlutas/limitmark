import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { ATTESTATION_SIGNER_BINDINGS } from "../workers/admission-service/authority-attestation-config";
import { AttestationKeyError, readStagingAttestationKeyForSecretPut } from "./staging-attestation-key";
import { readBounded, type StagingRenderPins } from "./staging-config-renderer";
import { parseStrictJson } from "./lifecycle-submitter";
import { assertNoImplicitWranglerDotenv, resolveReviewedWrangler, WranglerPinError } from "./staging-wrangler-pin";

// R06 activation tooling: the CLOSED-SET engine behind `wrangler secret put` for the three staging Authority-attestation bindings. It is
// the ONLY R06 code that can spawn Wrangler, and it can construct exactly one argv shape:
//
//     <pinned local wrangler.js> secret put <ONE OF THE THREE REVIEWED NAMES> --name limitmark-admission-service-staging
//
// with the value on stdin -- never argv, never an environment variable, never a file argument, never logged.
//
// WHAT A CALLER CAN CHOOSE. Only the process environment. Everything that decides what is spawned, where, against which account and with
// which secret is either a literal in this file (Worker name, the three names from ATTESTATION_SIGNER_BINDINGS.staging, their order, the
// argv shape, the Node executable = process.execPath) or fixed once, at construction, by the production binding
// (operator/staging-attestation-secret.ts: repository root derived from that module's own location, the reviewed account pin, the
// operator key directory, the real clock). There is NO plan object that a caller builds, edits or passes in: `submit` re-derives and
// re-validates the whole plan from those fixed inputs on every call, and again immediately before every spawn.
//
// `createAttestationSecretTooling` is therefore a CAPABILITY FACTORY. Its only legitimate importers are the production binding and the
// wrapper test (which builds a sandbox root with a recording fake Wrangler). tests/r06-activation-capability-guard.test.ts pins that with a
// structural (syntax-tree) scan -- accepted specifier grammar, exact-file resolution, parser-language agreement (tests/support/r06-import-guard.ts) --
// and pins the importers of the private-key loader, of the production `submit`, and of the signer, the same way. tests/r06-activation-hygiene.test.ts
// is only a secondary textual tripwire and enforces none of this. Both are static CI-time checks; neither runs when `put` runs.

export const ATTESTATION_SECRET_WORKER = "limitmark-admission-service-staging";
const names = ATTESTATION_SIGNER_BINDINGS.staging;
export const ATTESTATION_SECRET_ORDER = Object.freeze([names.writerKeyFingerprint, names.publicKey, names.privateKey] as const);
/** Operator-supplied, name-only proof that the staging Admission Worker already exists (see `readWorkerConfirmation`). */
export const WORKER_CONFIRMATION_FILE = "staging-admission-worker-confirmation.json";
export const WORKER_CONFIRMATION_MAX_AGE_MS = 6 * 60 * 60_000;
const WORKER_CONFIRMATION_MAX_FUTURE_SKEW_MS = 60_000;
const WORKER_CONFIRMATION_EVIDENCE = ["wrangler-versions-list", "dashboard-inspection"] as const;
const SPAWN_TIMEOUT_MS = 120_000;

export class AttestationSecretError extends Error {
  constructor(readonly code: string) { super(code); this.name = "AttestationSecretError"; }
}
const refuse = (code: string): never => { throw new AttestationSecretError(code); };
/** Same predicate as the frozen protocol's isSafeTime, kept local so this engine does not import the frozen attestation module. */
const isSafeTime = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
const fingerprint16 = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 16);

// ---------------------------------------------------------------------------
// B1: the child environment is built, never inherited
// ---------------------------------------------------------------------------

const PRIVATE_KEY_ENVIRONMENT = /^AUTHORITY_.*PRIVATE_KEY$/iu;
/** The only Cloudflare values the child may receive: the pinned account and, optionally, an API token. Nothing else CLOUDFLARE_*. */
const ALLOWED_CLOUDFLARE = new Set(["CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"]);
/** Proxy configuration would route the secret (and the token) through an intermediary. Exact names: `npm run` itself exports npm_config_noproxy. */
const PROXY_VARIABLES = new Set(["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "SOCKS_PROXY", "SOCKS5_PROXY", "WS_PROXY", "WSS_PROXY",
  "NPM_CONFIG_PROXY", "NPM_CONFIG_HTTPS_PROXY", "NPM_CONFIG_HTTP_PROXY", "GLOBAL_AGENT_HTTP_PROXY", "GLOBAL_AGENT_HTTPS_PROXY"]);
/** Process/runtime injection: code preloading, alternate trust stores, TLS relaxation. `NODE` (set by npm) is not matched; NODE_* is. */
const RUNTIME_INJECTION = /^(?:NODE_[A-Z0-9_]*|LD_[A-Z0-9_]*|DYLD_[A-Z0-9_]*|UV_[A-Z0-9_]*|V8_[A-Z0-9_]*|OPENSSL_[A-Z0-9_]*|SSL_CERT_FILE|SSL_CERT_DIR|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|ELECTRON_RUN_AS_NODE)$/u;
/** OS values a Node process genuinely needs to start and to find the operator's own Wrangler login store. Copied only when present. */
const OS_VARIABLES = ["PATH", "SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"] as const;
const SAFE_VALUE = /^[^\0\r\n]{1,32767}$/u;
const API_TOKEN = /^[\x21-\x7e]{1,512}$/u;

export type ChildEnvironment = { values: Record<string, string>; names: string[]; authentication: "CLOUDFLARE_API_TOKEN" | "wrangler-login-store" };

/** Builds the minimal explicit environment of the Wrangler child from a parent environment, or refuses. Nothing is inherited: a variable
 * reaches the child only if it is in the OS list above, is the pinned account, is a well-formed API token, or is WRANGLER_SEND_METRICS=false.
 * Anything that could redirect, relax, preload or observe the child is REFUSED rather than silently dropped, so the operator learns that
 * the shell was not the reviewed one. A variable that is defined but empty counts as defined. */
export function buildWranglerChildEnvironment(parent: Readonly<Record<string, string | undefined>>): ChildEnvironment {
  for (const key of Object.keys(parent)) {
    if (parent[key] === undefined) continue;
    const upper = key.toUpperCase();
    if (PRIVATE_KEY_ENVIRONMENT.test(key)) refuse("private-key-in-environment");
    if (upper.startsWith("CLOUDFLARE_") && !ALLOWED_CLOUDFLARE.has(upper)) refuse("unexpected-cloudflare-variable");
    if (upper.startsWith("CF_")) refuse("unexpected-cloudflare-variable");
    if (upper.startsWith("WRANGLER_") && upper !== "WRANGLER_SEND_METRICS") refuse("unexpected-wrangler-variable");
    if (upper === "WRANGLER_SEND_METRICS" && parent[key] !== "false") refuse("wrangler-metrics-must-be-disabled");
    if (PROXY_VARIABLES.has(upper)) refuse("proxy-variable-in-environment");
    if (RUNTIME_INJECTION.test(upper)) refuse("runtime-injection-variable-in-environment");
  }
  const lookup = (wanted: string): string | undefined => {
    const exact = parent[wanted];
    if (typeof exact === "string") return exact;
    const key = Object.keys(parent).find((candidate) => candidate.toUpperCase() === wanted.toUpperCase() && typeof parent[candidate] === "string");
    return key === undefined ? undefined : parent[key];
  };
  const values: Record<string, string> = {};
  const emitted = new Set<string>();
  for (const name of OS_VARIABLES) {
    // Windows treats SystemRoot/SYSTEMROOT as one variable: never emit the same variable twice under two spellings.
    if (emitted.has(name.toUpperCase())) continue;
    const value = lookup(name);
    if (value === undefined) continue;
    emitted.add(name.toUpperCase());
    if (!SAFE_VALUE.test(value)) refuse("environment-value-invalid");
    values[name] = value;
  }
  const account = lookup("CLOUDFLARE_ACCOUNT_ID");
  if (typeof account !== "string" || !/^[a-f0-9]{32}$/u.test(account) || /^0{32}$/u.test(account)) refuse("missing-or-malformed-account-pin");
  values.CLOUDFLARE_ACCOUNT_ID = account as string;
  const token = lookup("CLOUDFLARE_API_TOKEN");
  if (token !== undefined) {
    if (!API_TOKEN.test(token)) refuse("api-token-malformed");
    values.CLOUDFLARE_API_TOKEN = token;
  }
  values.WRANGLER_SEND_METRICS = "false";
  return { values, names: Object.keys(values).sort(), authentication: token === undefined ? "wrangler-login-store" : "CLOUDFLARE_API_TOKEN" };
}

// ---------------------------------------------------------------------------
// B2: Wrangler searches UPWARD for its configuration
// ---------------------------------------------------------------------------

/** What Wrangler 4.143.1's find-up (`findWranglerConfig`) and deploy-redirect (`.wrangler/deploy/config.json`) can pick up. */
const WRANGLER_CONFIG_ENTRIES = [["wrangler.json"], ["wrangler.jsonc"], ["wrangler.toml"], [".wrangler", "deploy", "config.json"]] as const;

/** Refuses if any Wrangler configuration entry exists in `realRoot` or ANY ancestor up to the filesystem root. A config anywhere above the
 * working directory would silently supply account, Worker name, bindings or routes to `secret put`. Any entry type counts (file,
 * directory, symlink, dangling link), and an entry that cannot be examined is treated as present. */
export async function assertNoWranglerConfigInAncestry(realRoot: string): Promise<void> {
  let directory = realRoot;
  for (;;) {
    for (const segments of WRANGLER_CONFIG_ENTRIES) {
      try { await lstat(join(directory, ...segments)); }
      catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT" || code === "ENOTDIR") continue;
        return refuse("wrangler-config-search-unavailable");
      }
      return refuse(directory === realRoot ? "wrangler-config-in-working-directory" : "wrangler-config-in-ancestor-directory");
    }
    const parent = dirname(directory);
    if (parent === directory) return;
    directory = parent;
  }
}

// ---------------------------------------------------------------------------
// Worker existence: `secret put` must never be allowed to create a Worker
// ---------------------------------------------------------------------------

export type WorkerConfirmation = { evidence: (typeof WORKER_CONFIRMATION_EVIDENCE)[number]; deployedVersionIdPrefix: string; confirmedAtMs: number };
const confirmationKeys = ["version", "environment", "worker", "accountFingerprint", "confirmedAtMs", "evidence", "deployedVersionIdPrefix"];

/** Reads the operator's Worker-existence confirmation from the protected key directory. Wrangler 4.143.1's non-interactive `secret put`
 * answers its own "create a new Worker?" prompt with YES and uploads a stub Worker (`createDraftWorker`, default true outside a TTY), so
 * the wrapper can never rely on Wrangler to refuse. It refuses itself unless the staging Admission Worker is already known to exist.
 *
 * The confirmation is OPERATOR-SUPPLIED provider evidence (a name-only read such as `wrangler versions list --name <worker>` or the dashboard,
 * performed outside this tooling after the Gate 4B deploy): nothing in this repository can independently verify it, exactly like every
 * other live claim in the provisioning runbook. It is exact-name, strict-JSON, bound to this Worker and this account fingerprint, and expires. */
async function readWorkerConfirmation(keyDirectory: string, pins: StagingRenderPins, nowMs: number): Promise<WorkerConfirmation> {
  let directory: string, resolved: string;
  try { directory = await realpath(keyDirectory); resolved = await realpath(join(directory, WORKER_CONFIRMATION_FILE)); }
  catch { return refuse("worker-confirmation-missing"); }
  if (dirname(resolved) !== directory || basename(resolved) !== WORKER_CONFIRMATION_FILE) refuse("worker-confirmation-not-exact");
  let value: unknown;
  try {
    const bytes = await readBounded(resolved, 1_024, "worker-confirmation-size");
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.charCodeAt(0) === 0xfeff) return refuse("worker-confirmation-bom");
    value = parseStrictJson(text);
  } catch (error) { if (error instanceof AttestationSecretError) throw error; return refuse("worker-confirmation-unreadable"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return refuse("worker-confirmation-shape");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== confirmationKeys.length || !confirmationKeys.every((key) => Object.hasOwn(record, key))) return refuse("worker-confirmation-shape");
  if (record.version !== 1 || record.environment !== "staging" || !isSafeTime(record.confirmedAtMs) ||
      !WORKER_CONFIRMATION_EVIDENCE.includes(record.evidence as never) ||
      typeof record.deployedVersionIdPrefix !== "string" || !/^[a-f0-9]{8}$/u.test(record.deployedVersionIdPrefix)) return refuse("worker-confirmation-shape");
  if (record.worker !== ATTESTATION_SECRET_WORKER) refuse("worker-confirmation-wrong-worker");
  if (record.accountFingerprint !== pins.accountFingerprint) refuse("worker-confirmation-wrong-account");
  const confirmedAtMs = record.confirmedAtMs as number;
  if (confirmedAtMs > nowMs + WORKER_CONFIRMATION_MAX_FUTURE_SKEW_MS) refuse("worker-confirmation-in-the-future");
  if (nowMs - confirmedAtMs > WORKER_CONFIRMATION_MAX_AGE_MS) refuse("worker-confirmation-expired");
  return { evidence: record.evidence as WorkerConfirmation["evidence"], deployedVersionIdPrefix: record.deployedVersionIdPrefix, confirmedAtMs };
}

// ---------------------------------------------------------------------------
// The capability factory
// ---------------------------------------------------------------------------

export type ClosedSetConstants = {
  /** The repository root. The production binding derives it from its own module location; it is never caller input. */
  root: string;
  /** The reviewed account pin (STAGING_RENDER_PINS in production). */
  pins: StagingRenderPins;
  /** The operator's protected key directory. Resolved at call time. */
  keyDirectory: () => string;
  /** The wall clock. Callers cannot supply a time (a stale `nowMs` would defeat the confirmation's freshness bound). */
  clock: () => number;
  /** Only a test needs this: it proves the "attestation key must differ from the operator key" refusal with synthetic keys. */
  operatorFingerprint?: string;
};

export type AttestationSecretInput = { env: Readonly<Record<string, string | undefined>> };
export type AttestationSecretDescription = {
  worker: typeof ATTESTATION_SECRET_WORKER;
  accountFingerprint: string;
  attestationKeyFingerprint: string;
  plannedSecretNames: readonly string[];
  plannedCommand: readonly string[];
  valuesVia: "stdin";
  wranglerVersion: string;
  workerConfirmation: { evidence: string; deployedVersionIdPrefix: string; ageSeconds: number };
  childEnvironment: { names: readonly string[]; authentication: string };
};
export type AttestationSecretSubmission = { submitted: string[]; stoppedAt: string | null };

type ClosedPlan = {
  realRoot: string;
  wranglerBin: string;
  child: ChildEnvironment;
  /** Values by secret name. Held only in memory for the duration of one call; the private entry is never printed or logged. */
  values: Readonly<Record<string, string>>;
  description: AttestationSecretDescription;
};

export function createAttestationSecretTooling(constants: ClosedSetConstants) {
  async function verifiedRoot(): Promise<string> {
    let realRoot: string;
    try { realRoot = await realpath(constants.root); } catch { return refuse("repository-root-unavailable"); }
    return realRoot;
  }

  /** Wrangler loads `.env`/`.env.local` from its working directory on its own, whatever environment the wrapper gives it (audit F1): any
   * implicit dotenv entry in the verified root refuses. See operator/staging-wrangler-pin.ts for the exact prohibited set. */
  async function assertNoDotenv(realRoot: string): Promise<void> {
    try { await assertNoImplicitWranglerDotenv(realRoot); } catch (error) { if (error instanceof WranglerPinError) return refuse(error.code); throw error; }
  }

  /** The checks that must hold again immediately before EVERY spawn: no config above the working directory, no implicit dotenv entry in it,
   * and the pinned Wrangler. */
  async function revalidateLaunch(realRoot: string, expectedBin: string): Promise<void> {
    if (await verifiedRoot() !== realRoot) refuse("working-directory-changed");
    await assertNoWranglerConfigInAncestry(realRoot);
    await assertNoDotenv(realRoot);
    let bin: string;
    try { bin = (await resolveReviewedWrangler(realRoot)).bin; } catch (error) { if (error instanceof WranglerPinError) return refuse(error.code); throw error; }
    if (bin !== expectedBin) refuse("pinned-wrangler-changed");
  }

  async function derive(input: AttestationSecretInput): Promise<ClosedPlan> {
    const nowMs = constants.clock();
    // Account pin first: nothing else is examined for an environment that is not the reviewed account's.
    const account = input.env.CLOUDFLARE_ACCOUNT_ID;
    if (typeof account !== "string" || !/^[a-f0-9]{32}$/u.test(account) || /^0{32}$/u.test(account)) refuse("missing-or-malformed-account-pin");
    if (fingerprint16(account as string) !== constants.pins.accountFingerprint) refuse("account-fingerprint-mismatch");
    const child = buildWranglerChildEnvironment(input.env);
    const realRoot = await verifiedRoot();
    await assertNoWranglerConfigInAncestry(realRoot);
    await assertNoDotenv(realRoot);
    let wrangler;
    try { wrangler = await resolveReviewedWrangler(realRoot); } catch (error) { if (error instanceof WranglerPinError) return refuse(error.code); throw error; }
    const keyDirectory = constants.keyDirectory();
    let key;
    try { key = await readStagingAttestationKeyForSecretPut({ directory: keyDirectory, repositoryRoot: realRoot, nowMs, operatorFingerprint: constants.operatorFingerprint }); }
    catch (error) { if (error instanceof AttestationKeyError) return refuse(`attestation-key-${error.code}`); throw error; }
    // Last, because it is the only check that depends on something the operator wrote by hand: the Worker must already exist.
    const confirmation = await readWorkerConfirmation(keyDirectory, constants.pins, nowMs);
    return {
      realRoot, wranglerBin: wrangler.bin, child,
      values: Object.freeze({ [names.writerKeyFingerprint]: key.keyFingerprint, [names.publicKey]: key.publicKey, [names.privateKey]: key.privateKey }),
      description: {
        worker: ATTESTATION_SECRET_WORKER, accountFingerprint: fingerprint16(account as string), attestationKeyFingerprint: key.keyFingerprint,
        plannedSecretNames: ATTESTATION_SECRET_ORDER, plannedCommand: ["wrangler", "secret", "put", "<NAME>", "--name", ATTESTATION_SECRET_WORKER],
        valuesVia: "stdin", wranglerVersion: wrangler.version,
        workerConfirmation: { evidence: confirmation.evidence, deployedVersionIdPrefix: confirmation.deployedVersionIdPrefix,
          ageSeconds: Math.max(0, Math.round((nowMs - confirmation.confirmedAtMs) / 1000)) },
        childEnvironment: { names: child.names, authentication: child.authentication },
      },
    };
  }

  return {
    /** Every local check, no spawn. Returns the public, non-secret description of what `submit` would do. */
    async preflight(input: AttestationSecretInput): Promise<AttestationSecretDescription> {
      return (await derive(input)).description;
    },

    /** The provider mutation. Re-derives and re-validates the entire closed plan from the fixed constants, then spawns the pinned local
     * Wrangler once per name, in order, stopping at the first failure. Success is NOT provider evidence. */
    async submit(input: AttestationSecretInput): Promise<AttestationSecretSubmission> {
      const plan = await derive(input);
      const submitted: string[] = [];
      for (const name of ATTESTATION_SECRET_ORDER) {
        try { await revalidateLaunch(plan.realRoot, plan.wranglerBin); }
        catch (error) {
          // Before the first spawn a refusal is a plain refusal ("no Wrangler invocation occurred"). After it, the partial state must be
          // reported like any other stop, never hidden behind a refusal message.
          if (submitted.length === 0) throw error;
          return { submitted, stoppedAt: name };
        }
        const result = spawnSync(process.execPath, [plan.wranglerBin, "secret", "put", name, "--name", ATTESTATION_SECRET_WORKER], {
          cwd: plan.realRoot, env: plan.child.values as NodeJS.ProcessEnv, input: plan.values[name], stdio: ["pipe", "inherit", "inherit"],
          shell: false, windowsHide: true, timeout: SPAWN_TIMEOUT_MS,
        });
        if (result.error || result.status !== 0) return { submitted, stoppedAt: name };
        submitted.push(name);
      }
      return { submitted, stoppedAt: null };
    },
  };
}
