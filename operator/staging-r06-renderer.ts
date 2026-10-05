import { createHash, generateKeyPairSync } from "node:crypto";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { validateStagingAdmissionServiceConfig, validateStagingLifecycleTransportManifest } from "../deployment/lifecycle-private-contract";
import { isSafeTime } from "../src/lib/authority-result-attestation";
import { parseAuthorityResultTrustManifest } from "../src/lib/authority-result-trust";
import { decodeCanonicalBase64url, encodeBase64url } from "../src/lib/ingress-protocol";
import { parseStrictJson } from "./lifecycle-submitter";
import { AttestationKeyError, verifyStagingAttestationKey } from "./staging-attestation-key";
import { occurrences, readBounded, STAGING_RENDER_PINS, StagingRenderError, type StagingRenderPins } from "./staging-config-renderer";

// R06 activation tooling (T2 trust manifest, T3 admission config). Local only: this module never spawns a process, opens a socket or
// contacts a provider. Closed modes, like the Gate 7C renderer (which this module deliberately does not modify): each mode hardcodes
// its template, its exact output name and its existing contract validator, takes no path/key/cron/account argument, and refuses to
// overwrite an existing output.
//
//   staging-admission  deployment/admission-service.staging.template.jsonc -> deployment/admission-service.staging.jsonc
//                      The operator PUBLIC key comes from the existing validated staging transport manifest (fingerprint pinned), so
//                      the Gate 7 operator PRIVATE key is never read.
//   staging-trust      deployment/authority-result-trust.template.json -> deployment/authority-result-trust.json
//                      The frozen parser requires BOTH environment sections, but no Production attestation key exists. D1 Option A: the
//                      Production section carries a throwaway Ed25519 key generated in memory whose private half is never exported,
//                      written or logged. It is a trust anchor nobody can sign with; Production reading fails closed against it. The
//                      staging section carries the custody-verified staging attestation public key.

export const R06_RENDER_MODES = ["staging-admission", "staging-trust"] as const;
export type R06RenderMode = (typeof R06_RENDER_MODES)[number];

const MAX_FILE_BYTES = 16_384;
const OPERATOR_KEY_PLACEHOLDER = "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__";

export class R06RenderError extends Error {
  constructor(readonly code: string) { super(code); this.name = "R06RenderError"; }
}
const refuse = (code: string): never => { throw new R06RenderError(code); };

async function guarded<T>(operation: () => Promise<T>, code: string): Promise<T> {
  try { return await operation(); } catch (error) {
    if (error instanceof R06RenderError) throw error;
    if (error instanceof AttestationKeyError) throw new R06RenderError(`attestation-key-${error.code}`);
    throw new R06RenderError(error instanceof StagingRenderError ? error.code : code);
  }
}

const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

export type R06RenderRequest = {
  mode: string;
  /** Repository root; the output is always <root>/deployment/<exact output name>. */
  root: string;
  /** Protected key directory (outside the repository); read only by staging-trust. */
  keyDirectory: string;
  nowMs: number;
  pins?: StagingRenderPins;
};

export type R06RenderResult = {
  status: "PASS";
  mode: R06RenderMode;
  output: string;
  /** staging-admission: the pinned operator key fingerprint (16 hex). staging-trust: the staging attestation key fingerprint (64 hex). */
  keyFingerprint: string;
  productionTrustAnchor: "inert-no-private-key" | null;
  providerContact: "none";
};

async function deploymentDirectory(root: string): Promise<{ realRoot: string; directory: string }> {
  let realRoot: string, directory: string;
  try { realRoot = await realpath(root); directory = await realpath(join(root, "deployment")); }
  catch { return refuse("deployment-directory-unavailable"); }
  if (directory !== join(realRoot, "deployment")) refuse("deployment-directory-not-exact");
  return { realRoot, directory };
}

async function requireAbsent(path: string): Promise<void> {
  try { await lstat(path); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    refuse("output-state-unavailable");
  }
  refuse("output-already-exists");
}

async function readExact(directory: string, name: string, maximum: number, missing: string): Promise<string> {
  let resolved: string;
  try { resolved = await realpath(join(directory, name)); } catch { return refuse(missing); }
  if (dirname(resolved) !== directory || basename(resolved) !== name) refuse(`${missing}-not-exact`);
  const bytes = await guarded(() => readBounded(resolved, maximum, `${missing}-size`), missing);
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { return refuse(`${missing}-not-utf8`); }
  if (text.charCodeAt(0) === 0xfeff) refuse(`${missing}-bom`);
  return text;
}

/** Exclusive create: an existing output is never opened for writing; a failed write removes the (just-created) file again. */
async function writeExclusive(path: string, text: string): Promise<void> {
  const bytes = new TextEncoder().encode(text);
  if (bytes.length < 1 || bytes.length > MAX_FILE_BYTES || bytes[0] === 0xef) refuse("rendered-size-or-bom");
  let handle;
  try { handle = await open(path, "wx"); }
  catch (error) { return refuse((error as NodeJS.ErrnoException).code === "EEXIST" ? "output-already-exists" : "output-create-failed"); }
  try { await handle.writeFile(bytes); await handle.close(); }
  catch { await handle.close().catch(() => {}); await unlink(path).catch(() => {}); refuse("output-write-failed"); }
}

// -------------------------------------------------------------------------------------------------------------------------------
// staging-admission (T3)
// -------------------------------------------------------------------------------------------------------------------------------
async function renderAdmission(directory: string, pins: StagingRenderPins): Promise<R06RenderResult> {
  const outputName = "admission-service.staging.jsonc";
  await requireAbsent(join(directory, outputName));

  // The operator PUBLIC key: from the existing, contract-validated staging transport manifest. No private key is read.
  const manifestText = await readExact(directory, "lifecycle-transport.staging.json", 2_048, "transport-manifest-unavailable");
  let manifest: Record<string, unknown>;
  try {
    const parsed = parseStrictJson(manifestText);
    validateStagingLifecycleTransportManifest(parsed, false);
    manifest = parsed as Record<string, unknown>;
  } catch { return refuse("transport-manifest-contract-failed"); }
  const publicKey = manifest.operatorPublicKey as string;
  let raw: Uint8Array;
  try { raw = decodeCanonicalBase64url(publicKey, 32); } catch { return refuse("operator-public-key-not-canonical"); }
  if (sha256Hex(raw).slice(0, 16) !== pins.keyFingerprint) refuse("operator-key-fingerprint-mismatch");
  if (sha256Hex(new TextEncoder().encode(manifest.accountId as string)).slice(0, 16) !== pins.accountFingerprint) refuse("account-fingerprint-mismatch");

  const templateText = await readExact(directory, "admission-service.staging.template.jsonc", MAX_FILE_BYTES, "template-unavailable");
  const placeholder = JSON.stringify(OPERATOR_KEY_PLACEHOLDER);
  if (occurrences(templateText, OPERATOR_KEY_PLACEHOLDER) !== 1 || occurrences(templateText, placeholder) !== 1) refuse("template-placeholder-not-exactly-once");
  if (occurrences(templateText, "__REQUIRED_") !== 1) refuse("template-unexpected-placeholder");
  let template: unknown;
  try { template = parseStrictJson(templateText); validateStagingAdmissionServiceConfig(template, true); }
  catch { return refuse("template-shape-not-reviewed"); }
  if ((template as { vars?: Record<string, unknown> }).vars?.AUTHORITY_OPERATOR_PUBLIC_KEY !== OPERATOR_KEY_PLACEHOLDER) refuse("template-placeholder-misplaced");

  const renderedText = templateText.replace(placeholder, () => JSON.stringify(publicKey));
  if (renderedText.includes("__REQUIRED_")) refuse("rendered-unresolved-placeholder");
  let rendered: unknown;
  try { rendered = parseStrictJson(renderedText); } catch { return refuse("rendered-not-strict-json"); }
  const expected = JSON.parse(JSON.stringify(template)) as { vars: Record<string, unknown> };
  expected.vars.AUTHORITY_OPERATOR_PUBLIC_KEY = publicKey;
  if (JSON.stringify(rendered) !== JSON.stringify(expected)) refuse("rendered-structure-not-preserved");
  try { validateStagingAdmissionServiceConfig(rendered, false); } catch { return refuse("rendered-contract-validation-failed"); }
  // The admission config is the one staging config that carries no account_id: the account is pinned by the deploy wrapper's environment.
  if (Object.hasOwn(rendered as object, "account_id")) refuse("admission-config-must-not-carry-account-id");

  await writeExclusive(join(directory, outputName), renderedText);
  return { status: "PASS", mode: "staging-admission", output: `deployment/${outputName}`, keyFingerprint: pins.keyFingerprint,
    productionTrustAnchor: null, providerContact: "none" };
}

// -------------------------------------------------------------------------------------------------------------------------------
// staging-trust (T2, D1 Option A)
// -------------------------------------------------------------------------------------------------------------------------------
const TRUST_PLACEHOLDERS = {
  productionFingerprint: "__REQUIRED_PRODUCTION_WRITER_KEY_FINGERPRINT__",
  productionPublicKey: "__REQUIRED_PRODUCTION_WRITER_ED25519_PUBLIC_KEY__",
  productionNotBefore: "__REQUIRED_PRODUCTION_NOT_BEFORE_MS__",
  stagingFingerprint: "__REQUIRED_STAGING_WRITER_KEY_FINGERPRINT__",
  stagingPublicKey: "__REQUIRED_STAGING_WRITER_ED25519_PUBLIC_KEY__",
  stagingNotBefore: "__REQUIRED_STAGING_NOT_BEFORE_MS__",
} as const;

/** The exact leaf positions the reviewed template carries each placeholder at: the only places a value may be substituted. */
const TRUST_POSITIONS: ReadonlyArray<{ placeholder: string; path: readonly (string | number)[] }> = [
  { placeholder: TRUST_PLACEHOLDERS.productionFingerprint, path: ["environments", 0, "currentKeyFingerprint"] },
  { placeholder: TRUST_PLACEHOLDERS.productionFingerprint, path: ["environments", 0, "keys", 0, "keyFingerprint"] },
  { placeholder: TRUST_PLACEHOLDERS.productionPublicKey, path: ["environments", 0, "keys", 0, "publicKey"] },
  { placeholder: TRUST_PLACEHOLDERS.productionNotBefore, path: ["environments", 0, "keys", 0, "notBeforeMs"] },
  { placeholder: TRUST_PLACEHOLDERS.stagingFingerprint, path: ["environments", 1, "currentKeyFingerprint"] },
  { placeholder: TRUST_PLACEHOLDERS.stagingFingerprint, path: ["environments", 1, "keys", 0, "keyFingerprint"] },
  { placeholder: TRUST_PLACEHOLDERS.stagingPublicKey, path: ["environments", 1, "keys", 0, "publicKey"] },
  { placeholder: TRUST_PLACEHOLDERS.stagingNotBefore, path: ["environments", 1, "keys", 0, "notBeforeMs"] },
];

function at(value: unknown, path: readonly (string | number)[]): unknown {
  let current = value;
  for (const step of path) {
    if (current === null || typeof current !== "object" || !Object.hasOwn(current, step)) return undefined;
    current = (current as Record<string | number, unknown>)[step];
  }
  return current;
}

function assign(value: unknown, path: readonly (string | number)[], replacement: string | number): void {
  let current = value as Record<string | number, unknown>;
  for (const step of path.slice(0, -1)) current = current[step] as Record<string | number, unknown>;
  current[path[path.length - 1]] = replacement;
}

/** A fresh throwaway Ed25519 public key. The private KeyObject never leaves this function: it is not exported, written or logged. */
function throwawayProductionAnchor(): { publicKey: string; fingerprint: string } {
  const { publicKey } = generateKeyPairSync("ed25519");
  const x = publicKey.export({ format: "jwk" }).x;
  const raw = decodeCanonicalBase64url(typeof x === "string" ? x : "", 32);
  return { publicKey: encodeBase64url(raw), fingerprint: sha256Hex(raw) };
}

async function renderTrust(directory: string, request: R06RenderRequest, realRoot: string): Promise<R06RenderResult> {
  const outputName = "authority-result-trust.json";
  await requireAbsent(join(directory, outputName));
  if (!isSafeTime(request.nowMs)) refuse("clock-unavailable");

  // Custody-verified PUBLIC facts about the staging attestation key (distinct from the operator key; signer self-test passed).
  const staging = await guarded(() => verifyStagingAttestationKey({ directory: request.keyDirectory, repositoryRoot: realRoot, nowMs: request.nowMs }), "attestation-key-unavailable");

  const templateText = await readExact(directory, "authority-result-trust.template.json", MAX_FILE_BYTES, "template-unavailable");
  let template: unknown;
  try { template = parseStrictJson(templateText); } catch { return refuse("template-not-strict-json"); }
  const expectedCounts = new Map<string, number>();
  for (const position of TRUST_POSITIONS) expectedCounts.set(position.placeholder, (expectedCounts.get(position.placeholder) ?? 0) + 1);
  for (const [placeholder, count] of expectedCounts) if (occurrences(templateText, JSON.stringify(placeholder)) !== count) refuse("template-placeholder-count-not-reviewed");
  if (occurrences(templateText, "__REQUIRED_") !== TRUST_POSITIONS.length) refuse("template-unexpected-placeholder");
  for (const position of TRUST_POSITIONS) if (at(template, position.path) !== position.placeholder) refuse("template-placeholder-misplaced");

  const production = throwawayProductionAnchor();
  if (production.fingerprint === staging.keyFingerprint || production.publicKey === staging.publicKey) refuse("production-anchor-collides-with-staging-key");
  const values: Record<string, string | number> = {
    [TRUST_PLACEHOLDERS.productionFingerprint]: production.fingerprint,
    [TRUST_PLACEHOLDERS.productionPublicKey]: production.publicKey,
    [TRUST_PLACEHOLDERS.productionNotBefore]: request.nowMs,
    [TRUST_PLACEHOLDERS.stagingFingerprint]: staging.keyFingerprint,
    [TRUST_PLACEHOLDERS.stagingPublicKey]: staging.publicKey,
    [TRUST_PLACEHOLDERS.stagingNotBefore]: staging.createdAtMs,
  };
  const rendered = JSON.parse(JSON.stringify(template)) as unknown;
  for (const position of TRUST_POSITIONS) {
    const value = values[position.placeholder];
    assign(rendered, position.path, value);
  }
  // Structure preservation: undoing exactly the recorded substitutions must reproduce the template, byte for byte as JSON.
  const restored = JSON.parse(JSON.stringify(rendered)) as unknown;
  for (const position of TRUST_POSITIONS) assign(restored, position.path, position.placeholder);
  if (JSON.stringify(restored) !== JSON.stringify(template)) refuse("rendered-structure-not-preserved");

  const renderedText = `${JSON.stringify(rendered, null, 2)}\n`;
  if (renderedText.includes("__REQUIRED_")) refuse("rendered-unresolved-placeholder");
  // The frozen parser is the contract: both sections, prime-order keys, fingerprints matching their public keys.
  let manifest;
  try { manifest = await parseAuthorityResultTrustManifest(new TextEncoder().encode(renderedText)); }
  catch { return refuse("rendered-contract-validation-failed"); }
  const [productionSection, stagingSection] = manifest.environments;
  if (stagingSection.currentKeyFingerprint !== staging.keyFingerprint || stagingSection.keys.length !== 1 ||
      stagingSection.keys[0].publicKey !== staging.publicKey || stagingSection.keys[0].status !== "active" ||
      stagingSection.keys[0].notBeforeMs !== staging.createdAtMs || stagingSection.keys[0].notAfterMs !== null) refuse("rendered-staging-section-not-as-intended");
  if (productionSection.keys.length !== 1 || productionSection.keys[0].keyFingerprint === staging.keyFingerprint) refuse("rendered-production-section-not-as-intended");

  await writeExclusive(join(directory, outputName), renderedText);
  return { status: "PASS", mode: "staging-trust", output: `deployment/${outputName}`, keyFingerprint: staging.keyFingerprint,
    productionTrustAnchor: "inert-no-private-key", providerContact: "none" };
}

/** Renders one closed R06 mode. Nothing is written unless every check passes; an existing output is never modified. */
export async function renderR06Artifact(request: R06RenderRequest): Promise<R06RenderResult> {
  if (!(R06_RENDER_MODES as readonly string[]).includes(request.mode)) refuse("unknown-r06-render-mode");
  const pins = request.pins ?? STAGING_RENDER_PINS;
  const { realRoot, directory } = await deploymentDirectory(request.root);
  return request.mode === "staging-admission" ? renderAdmission(directory, pins) : renderTrust(directory, request, realRoot);
}
