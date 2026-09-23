import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify, type KeyObject } from "node:crypto";
import { lstat, open, realpath, unlink } from "node:fs/promises";
import { basename, dirname, join, relative, isAbsolute } from "node:path";
import {
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";
import { decodeCanonicalBase64url, encodeBase64url } from "../src/lib/ingress-protocol";
import { parseStrictJson } from "./lifecycle-submitter";

// Gate 7C deterministic staging rendered-config reconstruction. Local only:
// this module never spawns a process, opens a socket or contacts a provider.
// It renders exactly three reviewed staging files from their exact committed
// templates -- the staging transport manifest and the schedule-inactive
// mailbox/observer configs -- by replacing only the reviewed `__REQUIRED_`
// placeholders of each template, and nothing else. There is no generic mode:
// each closed mode hardcodes its template name, output name, placeholders and
// the existing contract validators; Production templates and identities are
// not reachable from here. Substituted values come only from
// CLOUDFLARE_ACCOUNT_ID (pinned by fingerprint) and the public key derived
// from the existing protected staging PKCS8 key (pinned by fingerprint);
// the private key is never returned, logged or included in an error.

export const STAGING_RENDER_MODES = ["staging-transport", "staging-mailbox", "staging-observer"] as const;
export type StagingRenderMode = (typeof STAGING_RENDER_MODES)[number];

/** The reviewed live staging identity, recorded at Gates 4 and 5. */
export const STAGING_RENDER_PINS = { accountFingerprint: "0df3a690b3154513", keyFingerprint: "74f6e266c7cbdced" } as const;
export type StagingRenderPins = { accountFingerprint: string; keyFingerprint: string };

const ACCOUNT_PLACEHOLDER = "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__";
const KEY_PLACEHOLDER = "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__";
const MAX_TEMPLATE_BYTES = 16_384;
const MAX_KEY_FILE_BYTES = 256;

type Source = "account" | "publicKey" | "literal";
type Substitution = { placeholder: string; field: readonly string[]; source: Source; literal?: string };
type ModeSpec = {
  templateName: string;
  outputName: string;
  substitutions: readonly Substitution[];
  validateTemplate: (value: unknown) => void;
  validateRendered: (value: unknown) => void;
  scheduled: boolean;
};

const specs: Record<StagingRenderMode, ModeSpec> = {
  "staging-transport": {
    templateName: "lifecycle-transport.staging.template.json",
    outputName: "lifecycle-transport.staging.json",
    substitutions: [
      { placeholder: ACCOUNT_PLACEHOLDER, field: ["accountId"], source: "account" },
      { placeholder: KEY_PLACEHOLDER, field: ["operatorPublicKey"], source: "publicKey" },
    ],
    validateTemplate: (value) => validateStagingLifecycleTransportManifest(value, true),
    validateRendered: (value) => validateStagingLifecycleTransportManifest(value, false),
    scheduled: false,
  },
  "staging-mailbox": {
    templateName: "lifecycle-mailbox.staging.template.jsonc",
    outputName: "lifecycle-mailbox.staging.jsonc",
    substitutions: [
      { placeholder: "__REQUIRED_RENDERED_STAGING_MAILBOX_MAIN__.ts", field: ["main"], source: "literal",
        literal: "../workers/lifecycle-mailbox/staging-index.ts" },
      { placeholder: ACCOUNT_PLACEHOLDER, field: ["account_id"], source: "account" },
      { placeholder: KEY_PLACEHOLDER, field: ["vars", "AUTHORITY_OPERATOR_PUBLIC_KEY"], source: "publicKey" },
    ],
    validateTemplate: (value) => { validateStagingLifecycleMailboxConfig(value, true, "STAGING_DEPLOYMENT_INACTIVE"); },
    validateRendered: (value) => { validateStagingLifecycleMailboxConfig(value, false, "STAGING_DEPLOYMENT_INACTIVE"); },
    scheduled: true,
  },
  "staging-observer": {
    templateName: "lifecycle-observer.staging.template.jsonc",
    outputName: "lifecycle-observer.staging.jsonc",
    substitutions: [
      { placeholder: "__REQUIRED_RENDERED_STAGING_OBSERVER_MAIN__.ts", field: ["main"], source: "literal",
        literal: "../workers/staging-lifecycle-observer.ts" },
      { placeholder: ACCOUNT_PLACEHOLDER, field: ["account_id"], source: "account" },
    ],
    validateTemplate: (value) => { validateStagingLifecycleObserverConfig(value, true, "STAGING_DEPLOYMENT_INACTIVE"); },
    validateRendered: (value) => { validateStagingLifecycleObserverConfig(value, false, "STAGING_DEPLOYMENT_INACTIVE"); },
    scheduled: true,
  },
};

/** Error carrying only a fixed kebab-case code; never a value, path or key byte. */
export class StagingRenderError extends Error {
  constructor(readonly code: string) { super(code); this.name = "StagingRenderError"; }
}
const refuse = (code: string): never => { throw new StagingRenderError(code); };

export type StagingRenderRequest = {
  mode: string;
  /** Repository root; the output is always <root>/deployment/<exact output name>. */
  root: string;
  /** Protected staging PKCS8 key file; read only by modes that embed the public key. */
  keyPath: string;
  accountId: string | undefined;
  pins: StagingRenderPins;
};

export type StagingRenderResult = {
  status: "PASS";
  mode: StagingRenderMode;
  output: string;
  accountFingerprint: string;
  keyFingerprint: string | null;
  scheduleState: "STAGING_DEPLOYMENT_INACTIVE" | null;
  providerContact: "none";
};

export function stagingRenderSpec(mode: StagingRenderMode): Readonly<Pick<ModeSpec, "templateName" | "outputName">> & {
  placeholders: readonly string[]; usesPublicKey: boolean;
} {
  const spec = specs[mode];
  return { templateName: spec.templateName, outputName: spec.outputName, placeholders: spec.substitutions.map((s) => s.placeholder),
    usesPublicKey: spec.substitutions.some((s) => s.source === "publicKey") };
}

const sha256Hex16 = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex").slice(0, 16);

function pinnedAccount(accountId: string | undefined, pins: StagingRenderPins): { accountId: string; fingerprint: string } {
  if (typeof accountId !== "string" || !/^[a-f0-9]{32}$/u.test(accountId) || /^0{32}$/u.test(accountId))
    refuse("missing-or-malformed-account-pin");
  const fingerprint = sha256Hex16(accountId as string);
  if (fingerprint !== pins.accountFingerprint) refuse("account-fingerprint-mismatch");
  return { accountId: accountId as string, fingerprint };
}

async function readBounded(path: string, maximum: number, sizeCode: string): Promise<Uint8Array> {
  const file = await open(path, "r");
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum) refuse(sizeCode);
    const data = new Uint8Array(stat.size + 1);
    let length = 0;
    while (length < data.length) {
      const result = await file.read(data, length, data.length - length, length);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length !== stat.size) refuse("file-changed-while-reading");
    return data.subarray(0, length);
  } finally { await file.close(); }
}

function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

/** Derives and proves the staging public key; returns only public values. */
async function derivePinnedPublicKey(keyPath: string, realRoot: string, pins: StagingRenderPins): Promise<{ publicKey: string; fingerprint: string }> {
  let resolved: string;
  try { resolved = await realpath(keyPath); } catch { return refuse("staging-key-file-unavailable"); }
  if (isWithin(realRoot, resolved)) refuse("staging-key-file-inside-repository");
  let bytes: Uint8Array;
  try { bytes = await readBounded(resolved, MAX_KEY_FILE_BYTES, "staging-key-file-size"); }
  catch (error) { if (error instanceof StagingRenderError) throw error; return refuse("staging-key-file-unavailable"); }
  let der: Uint8Array;
  try { der = decodeCanonicalBase64url(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { return refuse("staging-key-not-canonical-base64url"); }
  let privateKey: KeyObject;
  try { privateKey = createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" }); }
  catch { return refuse("staging-key-not-pkcs8"); }
  if (privateKey.asymmetricKeyType !== "ed25519") refuse("staging-key-not-ed25519");
  const publicKeyObject = createPublicKey(privateKey);
  const x = publicKeyObject.export({ format: "jwk" }).x;
  let raw: Uint8Array;
  try { raw = decodeCanonicalBase64url(typeof x === "string" ? x : "", 32); }
  catch { return refuse("staging-public-key-not-canonical-32-byte"); }
  const publicKey = encodeBase64url(raw);
  if (publicKey !== x || publicKey.length !== 43) refuse("staging-public-key-not-canonical-32-byte");
  const probe = randomBytes(32);
  const signature = sign(null, probe, privateKey);
  const tampered = Buffer.from(probe); tampered[0] ^= 0xff;
  if (!verify(null, probe, publicKeyObject, signature) || verify(null, tampered, publicKeyObject, signature))
    refuse("staging-key-pair-correspondence-failed");
  const fingerprint = sha256Hex16(raw);
  if (fingerprint !== pins.keyFingerprint) refuse("staging-key-fingerprint-mismatch");
  return { publicKey, fingerprint };
}

const occurrences = (source: string, needle: string) => source.split(needle).length - 1;

function fieldValue(value: unknown, field: readonly string[]): unknown {
  let current = value;
  for (const name of field) {
    if (!current || typeof current !== "object" || Array.isArray(current) || !Object.hasOwn(current, name)) return undefined;
    current = (current as Record<string, unknown>)[name];
  }
  return current;
}

function withField(value: unknown, field: readonly string[], replacement: string): void {
  let current = value as Record<string, unknown>;
  for (const name of field.slice(0, -1)) current = current[name] as Record<string, unknown>;
  current[field[field.length - 1]] = replacement;
}

/**
 * Renders one closed staging mode. Order: exact paths and absent output ->
 * account pin -> exact template shape and placeholders -> (key continuity) ->
 * substitute -> parse -> structural-preservation check -> existing contract
 * validator -> exclusive create. Nothing is written unless every step passes.
 */
export async function renderStagingConfig(request: StagingRenderRequest): Promise<StagingRenderResult> {
  if (!(STAGING_RENDER_MODES as readonly string[]).includes(request.mode)) refuse("unknown-staging-render-mode");
  const mode = request.mode as StagingRenderMode;
  const spec = specs[mode];

  let realRoot: string, deploymentDir: string;
  try { realRoot = await realpath(request.root); deploymentDir = await realpath(join(request.root, "deployment")); }
  catch { return refuse("deployment-directory-unavailable"); }
  if (deploymentDir !== join(realRoot, "deployment")) refuse("deployment-directory-not-exact");

  const outputPath = join(deploymentDir, spec.outputName);
  try { await lstat(outputPath); return refuse("output-already-exists"); }
  catch (error) { if (error instanceof StagingRenderError) throw error; if ((error as NodeJS.ErrnoException).code !== "ENOENT") refuse("output-state-unavailable"); }

  const account = pinnedAccount(request.accountId, request.pins);

  let templatePath: string;
  try { templatePath = await realpath(join(deploymentDir, spec.templateName)); } catch { return refuse("template-unavailable"); }
  if (dirname(templatePath) !== deploymentDir || basename(templatePath) !== spec.templateName) refuse("template-not-exact");
  let templateSource: string;
  try { templateSource = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await readBounded(templatePath, MAX_TEMPLATE_BYTES, "template-size")); }
  catch (error) { if (error instanceof StagingRenderError) throw error; return refuse("template-not-utf8"); }
  if (templateSource.charCodeAt(0) === 0xfeff) refuse("template-bom");

  const expectedPlaceholders = new Set(spec.substitutions.map((s) => s.placeholder));
  for (const placeholder of expectedPlaceholders) {
    if (occurrences(templateSource, placeholder) !== 1 || occurrences(templateSource, JSON.stringify(placeholder)) !== 1)
      refuse("template-placeholder-not-exactly-once");
  }
  if (occurrences(templateSource, "__REQUIRED_") !== expectedPlaceholders.size) refuse("template-unexpected-placeholder");

  let template: unknown;
  try { template = parseStrictJson(templateSource); } catch { return refuse("template-not-strict-json"); }
  try { spec.validateTemplate(template); } catch { return refuse("template-shape-not-reviewed"); }
  for (const s of spec.substitutions) if (fieldValue(template, s.field) !== s.placeholder) refuse("template-placeholder-misplaced");

  const key = spec.substitutions.some((s) => s.source === "publicKey")
    ? await derivePinnedPublicKey(request.keyPath, realRoot, request.pins) : null;

  const valueFor = (s: Substitution): string =>
    s.source === "account" ? account.accountId : s.source === "publicKey" ? key!.publicKey : s.literal!;
  let renderedSource = templateSource;
  const expected = JSON.parse(JSON.stringify(template)) as unknown;
  for (const s of spec.substitutions) {
    const replacement = JSON.stringify(valueFor(s));
    renderedSource = renderedSource.replace(JSON.stringify(s.placeholder), () => replacement);
    withField(expected, s.field, valueFor(s));
  }
  if (renderedSource.includes("__REQUIRED_")) refuse("rendered-unresolved-placeholder");

  let rendered: unknown;
  try { rendered = parseStrictJson(renderedSource); } catch { return refuse("rendered-not-strict-json"); }
  if (JSON.stringify(rendered) !== JSON.stringify(expected)) refuse("rendered-structure-not-preserved");
  try { spec.validateRendered(rendered); } catch { return refuse("rendered-contract-validation-failed"); }
  if (spec.scheduled && JSON.stringify((rendered as Record<string, unknown>).triggers) !== JSON.stringify({ crons: [] }))
    refuse("rendered-schedule-not-inactive");
  if (mode === "staging-observer" && Object.hasOwn(rendered as object, "vars")) refuse("observer-must-not-carry-vars");

  const bytes = new TextEncoder().encode(renderedSource);
  if (bytes.length < 1 || bytes.length > MAX_TEMPLATE_BYTES || bytes[0] === 0xef) refuse("rendered-size-or-bom");

  let handle;
  try { handle = await open(outputPath, "wx"); }
  catch (error) { return refuse((error as NodeJS.ErrnoException).code === "EEXIST" ? "output-already-exists" : "output-create-failed"); }
  try { await handle.writeFile(bytes); await handle.close(); }
  catch {
    await handle.close().catch(() => {});
    await unlink(outputPath).catch(() => {});
    refuse("output-write-failed");
  }

  return {
    status: "PASS", mode, output: `deployment/${spec.outputName}`, accountFingerprint: account.fingerprint,
    keyFingerprint: key ? key.fingerprint : null, scheduleState: spec.scheduled ? "STAGING_DEPLOYMENT_INACTIVE" : null,
    providerContact: "none",
  };
}
