import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { open, readFile, realpath } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
  validateStagingAdmissionServiceConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";
import { isSafeTime } from "../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest } from "../src/lib/authority-result-trust";
import { decodeCanonicalBase64url } from "../src/lib/ingress-protocol";
import { parseStrictJson } from "./lifecycle-submitter";
import { AttestationKeyError, verifyStagingAttestationKey } from "./staging-attestation-key";
import { STAGING_RENDER_PINS, type StagingRenderPins } from "./staging-config-renderer";
import { STAGING_GATE7_KEY_FINGERPRINT } from "./staging-gate7-continuity";
import { REVIEWED_WRANGLER_VERSION, WranglerPinError, assertNoImplicitWranglerDotenv } from "./staging-wrangler-pin";

// R06 activation tooling (T4): the composite LOCAL preflight for the R06 activation design. It reads repository and operator-local
// files and runs read-only `git` queries. It never spawns Wrangler, opens a socket, reads an operator private key into the preflight's
// own state, or contacts a provider, and it AUTHORIZES NOTHING: PASS only means every local precondition of the reviewed design holds.
// Authorization of any provider mutation is a separate, explicit, human decision outside this repository.
//
// Scope is the minimum activation (admission + attestation secrets + observer). The mailbox and executor are deliberately NOT checked
// or rendered: the design leaves them at their deployed revision (accepted version skew).

// The single definition lives in operator/staging-wrangler-pin.ts, which the secret-put path ALSO enforces at the point of use.
export { REVIEWED_WRANGLER_VERSION };
const PRIVATE_KEY_ENVIRONMENT = /^AUTHORITY_.*PRIVATE_KEY$/iu;
const HEAD_PATTERN = /^[a-f0-9]{40}$/u;

export class R06PreflightError extends Error {
  constructor(readonly code: string) { super(code); this.name = "R06PreflightError"; }
}
const refuse = (code: string): never => { throw new R06PreflightError(code); };

export type GitRunner = (args: readonly string[]) => { status: number | null; stdout: string };

export function defaultGit(root: string): GitRunner {
  return (args) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const name of Object.keys(env)) if (/^GIT_(DIR|WORK_TREE|INDEX_FILE|OBJECT_DIRECTORY|NAMESPACE)$/iu.test(name)) delete env[name];
    const result = spawnSync("git", [...args], { cwd: root, encoding: "utf8", env, timeout: 30_000, maxBuffer: 1 << 20 });
    return { status: result.status, stdout: typeof result.stdout === "string" ? result.stdout : "" };
  };
}

export type R06PreflightRequest = {
  root: string;
  expectedHead: string;
  env: Readonly<Record<string, string | undefined>>;
  keyDirectory: string;
  nowMs: number;
  git: GitRunner;
  pins?: StagingRenderPins;
  /** Full SHA-256 of the pinned Gate 7 operator public key; a parameter only so tests can use synthetic keys. */
  operatorFingerprint?: string;
};

export type R06PreflightResult = {
  status: "PASS";
  authorization: "none";
  head: string;
  accountFingerprint: string;
  wranglerVersion: string;
  operatorKeyFingerprint: string;
  attestationKeyFingerprint: string;
  scope: { included: readonly string[]; excludedByDesign: readonly string[] };
  plannedSequence: readonly string[];
  providerContact: "none";
};

const sha256Hex = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");

async function readJson(directory: string, name: string, maximum: number, code: string): Promise<unknown> {
  let resolved: string;
  try { resolved = await realpath(join(directory, name)); } catch { return refuse(`${code}-missing`); }
  // Exact name after realpath(): a symlink at this name pointing elsewhere resolves to another dirname/basename and is refused.
  if (dirname(resolved) !== directory || basename(resolved) !== name) refuse(`${code}-not-exact`);
  let text: string;
  try {
    const file = await open(resolved, "r");
    try {
      const stat = await file.stat();
      if (!stat.isFile() || stat.size < 1 || stat.size > maximum) return refuse(`${code}-size`);
      const data = new Uint8Array(stat.size + 1);
      let length = 0;
      while (length < data.length) {
        const { bytesRead } = await file.read(data, length, data.length - length, length);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length !== stat.size) return refuse(`${code}-changed-while-reading`);
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(data.subarray(0, length));
    } finally { await file.close(); }
  } catch (error) { if (error instanceof R06PreflightError) throw error; return refuse(`${code}-unreadable`); }
  if (text.charCodeAt(0) === 0xfeff) refuse(`${code}-bom`);
  try { return parseStrictJson(text); } catch { return refuse(`${code}-not-strict-json`); }
}

async function readText(path: string, code: string): Promise<string> {
  try { return await readFile(path, "utf8"); } catch { return refuse(code); }
}

export async function runR06ActivationPreflight(request: R06PreflightRequest): Promise<R06PreflightResult> {
  const pins = request.pins ?? STAGING_RENDER_PINS;
  const operatorPin = request.operatorFingerprint ?? STAGING_GATE7_KEY_FINGERPRINT;
  if (!HEAD_PATTERN.test(request.expectedHead)) refuse("expected-head-malformed");
  if (!isSafeTime(request.nowMs)) refuse("clock-unavailable");

  // 1. No private signing key may be present in the process environment (defined at all, even empty).
  for (const name of Object.keys(request.env)) if (PRIVATE_KEY_ENVIRONMENT.test(name) && request.env[name] !== undefined) refuse("private-key-in-environment");

  // 2. Account pin, by one-way fingerprint only.
  const account = request.env.CLOUDFLARE_ACCOUNT_ID;
  if (typeof account !== "string" || !/^[a-f0-9]{32}$/u.test(account) || /^0{32}$/u.test(account)) refuse("account-pin-missing-or-malformed");
  if (sha256Hex(account as string).slice(0, 16) !== pins.accountFingerprint) refuse("account-fingerprint-mismatch");

  // 3. Exact reviewed commit, clean tree. (Rendered configs and key material are git-ignored or outside the repository.)
  const head = request.git(["rev-parse", "HEAD"]);
  if (head.status !== 0 || !HEAD_PATTERN.test(head.stdout.trim())) refuse("git-head-unavailable");
  if (head.stdout.trim() !== request.expectedHead) refuse("git-head-not-the-reviewed-commit");
  const status = request.git(["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.status !== 0) refuse("git-status-unavailable");
  if (status.stdout.length !== 0) refuse("git-tree-not-clean");

  // 4. Wrangler is the one reviewed version, consistently across package.json, the lockfile and the installed package.
  const manifest = JSON.parse(await readText(join(request.root, "package.json"), "package-json-unavailable")) as
    { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  const declared = manifest.devDependencies?.wrangler ?? manifest.dependencies?.wrangler;
  const lock = JSON.parse(await readText(join(request.root, "package-lock.json"), "package-lock-unavailable")) as
    { packages?: Record<string, { version?: string }> };
  const locked = lock.packages?.["node_modules/wrangler"]?.version;
  const installed = (JSON.parse(await readText(join(request.root, "node_modules", "wrangler", "package.json"), "wrangler-not-installed")) as { version?: string }).version;
  if (declared !== REVIEWED_WRANGLER_VERSION || locked !== REVIEWED_WRANGLER_VERSION || installed !== REVIEWED_WRANGLER_VERSION)
    refuse("wrangler-version-not-the-reviewed-pin");
  // The version and path checks above are NOT binary integrity: they read three version strings and a path, never the executable's bytes.
  // Wrangler also loads `.env`/`.env.local` from its working directory by itself (audit F1); these files are git-ignored (`.env*`), so the
  // clean-tree check above cannot see them. The same prohibition the secret wrapper applies before every spawn is applied here too.
  try { await assertNoImplicitWranglerDotenv(await realpath(request.root)); }
  catch (error) { return refuse(error instanceof WranglerPinError ? error.code : "dotenv-search-unavailable"); }

  // 5. Rendered artifacts, exact names, existing contract validators, mutual continuity.
  let directory: string;
  try { directory = await realpath(join(request.root, "deployment")); } catch { return refuse("deployment-directory-unavailable"); }
  const transport = await readJson(directory, "lifecycle-transport.staging.json", 2_048, "transport-manifest");
  try { validateStagingLifecycleTransportManifest(transport, false); } catch { return refuse("transport-manifest-contract-failed"); }
  const transportKey = (transport as { operatorPublicKey: string }).operatorPublicKey;
  let operatorRaw: Uint8Array;
  try { operatorRaw = decodeCanonicalBase64url(transportKey, 32); } catch { return refuse("operator-public-key-not-canonical"); }
  const operatorFingerprint = sha256Hex(operatorRaw);
  if (operatorFingerprint !== operatorPin || operatorFingerprint.slice(0, 16) !== pins.keyFingerprint) refuse("operator-key-continuity-failed");
  if (sha256Hex((transport as { accountId: string }).accountId).slice(0, 16) !== pins.accountFingerprint) refuse("transport-account-mismatch");

  const admission = await readJson(directory, "admission-service.staging.jsonc", 16_384, "admission-config");
  try { validateStagingAdmissionServiceConfig(admission, false); } catch { return refuse("admission-config-contract-failed"); }
  if ((admission as { vars: Record<string, string> }).vars.AUTHORITY_OPERATOR_PUBLIC_KEY !== transportKey) refuse("admission-operator-key-differs-from-transport");

  const observer = await readJson(directory, "lifecycle-observer.staging.armed.jsonc", 16_384, "observer-armed-config");
  try { validateStagingLifecycleObserverConfig(observer, false, "STAGING_SCHEDULE_ARMED"); } catch { return refuse("observer-armed-config-contract-failed"); }
  if ((observer as { account_id?: string }).account_id !== account) refuse("observer-account-differs-from-pin");

  // 6. Attestation key custody (public facts only are kept) and the trust manifest that names it.
  let key;
  try { key = await verifyStagingAttestationKey({ directory: request.keyDirectory, repositoryRoot: request.root, nowMs: request.nowMs, operatorFingerprint: operatorPin }); }
  catch (error) { if (error instanceof AttestationKeyError) return refuse(`attestation-key-${error.code}`); throw error; }
  if (key.keyFingerprint === operatorFingerprint) refuse("attestation-key-equals-operator-key");

  const trustText = JSON.stringify(await readJson(directory, "authority-result-trust.json", 16_384, "trust-manifest"));
  let trust;
  try { trust = await parseAuthorityResultTrustManifest(trustText); } catch { return refuse("trust-manifest-contract-failed"); }
  const [production, staging] = trust.environments;
  const stagingKey = staging.keys[0];
  if (staging.keys.length !== 1 || staging.currentKeyFingerprint !== key.keyFingerprint || stagingKey.publicKey !== key.publicKey ||
      stagingKey.status !== "active" || stagingKey.notBeforeMs !== key.createdAtMs || stagingKey.notAfterMs !== null || stagingKey.notBeforeMs > request.nowMs)
    refuse("trust-manifest-staging-section-does-not-match-key");
  if (production.keys.length !== 1 || production.keys[0].keyFingerprint === key.keyFingerprint || production.keys[0].keyFingerprint === operatorFingerprint)
    refuse("trust-manifest-production-section-collides");

  return {
    status: "PASS", authorization: "none", head: request.expectedHead, accountFingerprint: pins.accountFingerprint, wranglerVersion: REVIEWED_WRANGLER_VERSION,
    operatorKeyFingerprint: operatorFingerprint.slice(0, 16), attestationKeyFingerprint: key.keyFingerprint,
    scope: { included: ["admission", "attestation-secrets", "observer"], excludedByDesign: ["mailbox", "executor"] },
    plannedSequence: [
      "A admission code at the reviewed commit (Gate 4B wrapper)",
      "B three attestation secrets: fingerprint, public key, private key last (closed-set secret wrapper)",
      "C observer at the reviewed commit (Gate 7A armed wrapper)",
      "D one fresh-nonce reconcile of the Gate 7 digest, read with the staging reader",
    ],
    providerContact: "none",
  };
}
