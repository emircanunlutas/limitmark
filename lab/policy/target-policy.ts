/**
 * Fail-closed target policy for every lab load/failure tool.
 *
 * Principles
 *  - Positive allowlist first: a target exists only if it is a built-in loopback
 *    fixture or an operator target definition that passes `validateTargetDefinition`.
 *  - The CLI never supplies a URL. It names a target ID, a workload ID and optional
 *    LOWER limits. Everything network-facing is derived here.
 *  - Refusal is a pure function of its inputs: no DNS, no sockets, no filesystem.
 *    `authorizeRun` / `authorizeRequest` run before any network activity, and the
 *    HTTP engine only accepts the branded objects they return.
 *  - Deny rules (live LimitMark hosts, provider infrastructure, admission-rpc, cron)
 *    are defence in depth that apply even to an allowlisted entry.
 */
import {
  HARD_CEILINGS,
  WORKLOADS,
  isWorkloadId,
  type PhaseSpec,
  type WorkloadId,
  type WorkloadSpec,
} from "./workloads";

export type PolicyRefusalCode =
  | "target-unknown"
  | "target-definition-invalid"
  | "target-expired"
  | "target-live-limitmark"
  | "target-provider-infrastructure"
  | "target-address-forbidden"
  | "workload-unknown"
  | "workload-local-only"
  | "method-forbidden"
  | "path-forbidden"
  | "path-denied-endpoint"
  | "limit-invalid"
  | "limit-above-reviewed-ceiling"
  | "redirect-forbidden"
  | "clean-tree-required";

export class PolicyRefusal extends Error {
  constructor(readonly code: PolicyRefusalCode, detail: string) {
    super(`lab policy refused (${code}): ${detail}`);
    this.name = "PolicyRefusal";
  }
}

// ---------------------------------------------------------------------------
// Static deny knowledge
// ---------------------------------------------------------------------------

/** Live LimitMark. Zero lab traffic of any method is permitted. */
const LIVE_LIMITMARK_DOMAIN = "limitmark.com";

/** Provider infrastructure the lab must never touch. Suffix match on a normalized hostname. */
const PROVIDER_DOMAIN_SUFFIXES = [
  "cloudflare.com", "cloudflare.net", "cloudflareinsights.com", "cloudflarestorage.com", "cloudflare-dns.com",
  "workers.dev", "pages.dev", "r2.dev", "trycloudflare.com",
  "vercel.com", "vercel.app", "vercel.sh", "vercel-dns.com", "now.sh",
  "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
  "appspot.com", "run.app", "cloudfunctions.net", "gvt1.com", "withgoogle.com",
  "resend.com", "resend.dev",
] as const;

/** Best-effort published ranges (defence in depth only; the allowlist is the primary control). */
const PROVIDER_IPV4_RANGES: readonly [string, number][] = [
  // Cloudflare published edge ranges
  ["173.245.48.0", 20], ["103.21.244.0", 22], ["103.22.200.0", 22], ["103.31.4.0", 22],
  ["141.101.64.0", 18], ["108.162.192.0", 18], ["190.93.240.0", 20], ["188.114.96.0", 20],
  ["197.234.240.0", 22], ["198.41.128.0", 17], ["162.158.0.0", 15], ["104.16.0.0", 13],
  ["104.24.0.0", 14], ["172.64.0.0", 13], ["131.0.72.0", 22], ["1.1.1.0", 24], ["1.0.0.0", 24],
  // Vercel anycast ingress
  ["76.76.21.0", 24], ["76.76.19.0", 24], ["66.33.60.0", 24],
  // Google public DNS and metadata
  ["8.8.8.0", 24], ["8.8.4.0", 24],
];

/** Never targetable on any lab target, whatever the allowlist says. */
const DENIED_PATH_ROOTS = ["/api/cron", "/v1", "/admin"] as const;
const DENIED_HOST_LABELS = ["admission-rpc"] as const;

/**
 * The only application paths a lab workload may name. A target definition may select
 * a subset; it can never add a path.
 */
export const LAB_PATH_CATALOGUE = Object.freeze([
  "/", "/gizlilik", "/test-talep-et", "/test-talep-et/tesekkurler", "/api/public-inquiries",
] as const);
const POST_PATHS: readonly string[] = ["/api/public-inquiries"];

export const MAX_REMOTE_TARGET_LIFETIME_HOURS = 72;

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

function parseIpv4(host: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  if (octets.some((octet, index) => octet > 255 || String(octet) !== match[index + 1])) return null;
  return octets;
}

function ipv4ToInt(octets: number[]): number {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

function inRange(octets: number[], base: string, prefix: number): boolean {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (ipv4ToInt(octets) & mask) === (ipv4ToInt(parseIpv4(base)!) & mask);
}

export function normalizeHostname(host: string): string {
  return host.trim().toLowerCase().replace(/\.+$/, "");
}

export function isLiveLimitmarkHost(host: string): boolean {
  const normalized = normalizeHostname(host);
  return normalized === LIVE_LIMITMARK_DOMAIN || normalized.endsWith(`.${LIVE_LIMITMARK_DOMAIN}`) ||
    DENIED_HOST_LABELS.some((label) => normalized.split(".").includes(label));
}

export function isProviderInfrastructureHost(host: string): boolean {
  const normalized = normalizeHostname(host);
  if (PROVIDER_DOMAIN_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`))) return true;
  const octets = parseIpv4(normalized);
  return octets !== null && PROVIDER_IPV4_RANGES.some(([base, prefix]) => inRange(octets, base, prefix));
}

/** Loopback only; used by the built-in fixtures. */
function isLoopbackLiteral(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/** Addresses a remote disposable target may never use (loopback, link-local/metadata, multicast, reserved). */
function forbiddenRemoteAddress(octets: number[]): boolean {
  return octets[0] === 0 || octets[0] === 127 || octets[0] >= 224 ||
    (octets[0] === 169 && octets[1] === 254) || inRange(octets, "100.64.0.0", 10);
}

// ---------------------------------------------------------------------------
// Target registry
// ---------------------------------------------------------------------------

export type TargetClass = "lab-local" | "lab-remote";
export type TargetMethod = "GET" | "POST";

export type TargetDefinition = {
  id: string;
  class: TargetClass;
  scheme: "http" | "https";
  host: string;
  port: number;
  allowedPaths: readonly string[];
  allowedMethods: readonly TargetMethod[];
  /** lab-remote only: ISO-8601 instant after which the target is refused (ephemeral IPs get reassigned). */
  expiresAt?: string;
  /** lab-remote only: operator statement that the system is a disposable lab system. Must be exactly true. */
  disposable?: boolean;
};

const ID_PATTERN = /^[a-z][a-z0-9-]{2,40}$/;

/** Built-in fixtures: loopback only, no real IP or hostname of any future system. */
export const BUILTIN_TARGETS: readonly TargetDefinition[] = Object.freeze([
  {
    id: "local-app", class: "lab-local", scheme: "http", host: "127.0.0.1", port: 3000,
    allowedPaths: LAB_PATH_CATALOGUE, allowedMethods: ["GET", "POST"],
  },
  {
    id: "local-app-alt", class: "lab-local", scheme: "http", host: "127.0.0.1", port: 3100,
    allowedPaths: LAB_PATH_CATALOGUE, allowedMethods: ["GET", "POST"],
  },
]);

export type LabTarget = Readonly<TargetDefinition> & { readonly origin: string };

/** Throws PolicyRefusal for any definition that is not unambiguously a disposable lab target. */
export function validateTargetDefinition(definition: unknown, now: Date): LabTarget {
  const fail = (code: PolicyRefusalCode, detail: string): never => { throw new PolicyRefusal(code, detail); };
  if (typeof definition !== "object" || definition === null || Array.isArray(definition)) return fail("target-definition-invalid", "not an object");
  const d = definition as Record<string, unknown>;
  const allowedKeys = new Set(["id", "class", "scheme", "host", "port", "allowedPaths", "allowedMethods", "expiresAt", "disposable"]);
  for (const key of Object.keys(d)) if (!allowedKeys.has(key)) fail("target-definition-invalid", `unknown field ${key}`);
  if (typeof d.id !== "string" || !ID_PATTERN.test(d.id)) fail("target-definition-invalid", "id must match ^[a-z][a-z0-9-]{2,40}$");
  if (d.class !== "lab-local" && d.class !== "lab-remote") fail("target-definition-invalid", "class must be lab-local or lab-remote");
  if (d.scheme !== "http" && d.scheme !== "https") fail("target-definition-invalid", "scheme must be explicit http or https");
  if (typeof d.host !== "string" || d.host.length === 0 || d.host.length > 64) fail("target-definition-invalid", "host required");
  if (typeof d.port !== "number" || !Number.isSafeInteger(d.port) || d.port < 1 || d.port > 65535) fail("target-definition-invalid", "explicit integer port required");
  if (!Array.isArray(d.allowedPaths) || d.allowedPaths.length === 0 || d.allowedPaths.some((path) => typeof path !== "string")) fail("target-definition-invalid", "allowedPaths required");
  if (!Array.isArray(d.allowedMethods) || d.allowedMethods.length === 0 || d.allowedMethods.some((method) => method !== "GET" && method !== "POST")) fail("target-definition-invalid", "allowedMethods must be GET and/or POST");

  const host = normalizeHostname(d.host as string);
  // Hostname-class refusals come first so the reason is precise.
  if (isLiveLimitmarkHost(host)) fail("target-live-limitmark", "live LimitMark hosts are never lab targets");
  if (isProviderInfrastructureHost(host)) fail("target-provider-infrastructure", "provider infrastructure is never a lab target");
  const octets = parseIpv4(host);
  if (d.class === "lab-local") {
    if (!isLoopbackLiteral(host)) fail("target-address-forbidden", "lab-local targets must be a loopback literal");
    if (d.expiresAt !== undefined || d.disposable !== undefined) fail("target-definition-invalid", "expiresAt/disposable apply to lab-remote only");
  } else {
    // Remote targets must be an explicit IPv4 literal: no DNS, so no rebinding or CNAME surprises.
    if (!octets) fail("target-address-forbidden", "lab-remote host must be a dotted-quad IPv4 literal");
    if (forbiddenRemoteAddress(octets as number[])) fail("target-address-forbidden", "loopback, link-local, multicast, reserved and CGNAT addresses are refused");
    if (d.disposable !== true) fail("target-definition-invalid", "lab-remote requires disposable: true");
    if (typeof d.expiresAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/.test(d.expiresAt)) fail("target-definition-invalid", "lab-remote requires expiresAt (UTC ISO-8601)");
    const expires = Date.parse(d.expiresAt as string);
    if (!Number.isFinite(expires)) fail("target-definition-invalid", "expiresAt unparseable");
    if (expires <= now.getTime()) fail("target-expired", "target definition has expired");
    if (expires - now.getTime() > MAX_REMOTE_TARGET_LIFETIME_HOURS * 3_600_000) fail("target-definition-invalid", `expiresAt more than ${MAX_REMOTE_TARGET_LIFETIME_HOURS}h ahead`);
  }
  for (const path of d.allowedPaths as string[]) {
    if (!(LAB_PATH_CATALOGUE as readonly string[]).includes(path)) fail("target-definition-invalid", `path ${path} is not in the reviewed catalogue`);
  }
  if ((d.allowedMethods as string[]).includes("POST") && !(d.allowedPaths as string[]).some((path) => POST_PATHS.includes(path))) {
    fail("target-definition-invalid", "POST needs an allowed POST path");
  }
  const origin = `${d.scheme}://${host.includes(":") ? `[${host.replace(/^\[|\]$/g, "")}]` : host}:${d.port}`;
  return Object.freeze({
    id: d.id as string,
    class: d.class as TargetClass,
    scheme: d.scheme as "http" | "https",
    host,
    port: d.port as number,
    allowedPaths: Object.freeze([...(d.allowedPaths as string[])]),
    allowedMethods: Object.freeze([...(d.allowedMethods as TargetMethod[])]),
    ...(d.class === "lab-remote" ? { expiresAt: d.expiresAt as string, disposable: true } : {}),
    origin,
  });
}

export type TargetRegistry = ReadonlyMap<string, LabTarget>;

/** Operator definitions are validated individually; a single invalid entry fails the whole load. */
export function buildRegistry(operatorDefinitions: readonly unknown[], now: Date): TargetRegistry {
  const registry = new Map<string, LabTarget>();
  for (const definition of [...BUILTIN_TARGETS, ...operatorDefinitions]) {
    const target = validateTargetDefinition(definition, now);
    if (registry.has(target.id)) throw new PolicyRefusal("target-definition-invalid", `duplicate target id ${target.id}`);
    registry.set(target.id, target);
  }
  return registry;
}

// ---------------------------------------------------------------------------
// Path / request authorization
// ---------------------------------------------------------------------------

/** Exact-match path after rejecting every encoding and traversal trick. */
export function checkPath(path: string): void {
  if (typeof path !== "string" || path.length === 0 || path.length > 128 || !path.startsWith("/") ||
      !/^[\x21-\x7e]+$/.test(path) || /[?#\\%]/.test(path) || path.includes("//") || path.split("/").some((segment) => segment === "." || segment === "..")) {
    throw new PolicyRefusal("path-forbidden", "path must be a plain absolute path without query, fragment, encoding, backslash or traversal");
  }
  const lowered = path.toLowerCase();
  for (const root of DENIED_PATH_ROOTS) {
    if (lowered === root || lowered.startsWith(`${root}/`)) {
      throw new PolicyRefusal("path-denied-endpoint", "cron, admission-rpc and admin endpoints are never targetable");
    }
  }
}

declare const authorizedBrand: unique symbol;
const issuedAuthorizations = new WeakSet<object>();

export type AuthorizedRequest = Readonly<{
  [authorizedBrand]: true;
  method: TargetMethod;
  url: string;
  targetId: string;
  path: string;
  scheme: "http" | "https";
  host: string;
  port: number;
}>;

export function isAuthorizedRequest(value: unknown): value is AuthorizedRequest {
  return typeof value === "object" && value !== null && issuedAuthorizations.has(value);
}

export type EffectiveLimits = Readonly<{
  /** Per-phase effective phases after applying LOWER-only caps. */
  phases: readonly PhaseSpec[];
  maxTotalRequests: number;
  maxDurationSeconds: number;
  maxRequestsPerSecond: number;
  maxConcurrency: number;
}>;

export type AuthorizedRun = Readonly<{
  target: LabTarget;
  workload: WorkloadSpec;
  limits: EffectiveLimits;
  authorizeRequest(method: TargetMethod, path: string): AuthorizedRequest;
  /** Used to vet a redirect Location: returns true only if it would itself be authorized. */
  wouldAuthorizeUrl(location: string, method: TargetMethod): boolean;
}>;

export type CliLimits = { maxRate?: number; maxConcurrency?: number; maxDurationSeconds?: number };

/** Strict decimal integer parser: rejects 1e3, 0x10, " 5", "+5", "5.0", "", NaN, negatives, > safe. */
export function parseStrictPositiveInteger(raw: unknown, name: string): number {
  if (typeof raw !== "string" || !/^[1-9][0-9]{0,8}$/.test(raw)) {
    throw new PolicyRefusal("limit-invalid", `${name} must be a plain positive decimal integer`);
  }
  return Number(raw);
}

/**
 * Applies lower-only caps. A cap above the reviewed workload value is REFUSED (not clamped), so a
 * typo like `--rate 100000` cannot silently look accepted.
 */
export function applyCliLimits(workload: WorkloadSpec, limits: CliLimits): EffectiveLimits {
  const reviewed = workload.ceilings;
  const rate = limits.maxRate ?? reviewed.requestsPerSecond;
  const concurrency = limits.maxConcurrency ?? reviewed.concurrency;
  const duration = limits.maxDurationSeconds ?? reviewed.durationSeconds;
  for (const [name, value, ceiling] of [
    ["rate", rate, reviewed.requestsPerSecond],
    ["concurrency", concurrency, reviewed.concurrency],
    ["duration", duration, reviewed.durationSeconds],
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1) throw new PolicyRefusal("limit-invalid", `${name} must be a positive integer`);
    if (value > ceiling) throw new PolicyRefusal("limit-above-reviewed-ceiling", `${name} ${value} exceeds the reviewed ${workload.id} ceiling ${ceiling}`);
  }
  // Defence in depth: the reviewed ceilings must themselves sit under the hard ceilings.
  if (rate > HARD_CEILINGS.maxRequestsPerSecond || concurrency > HARD_CEILINGS.maxConcurrency || duration > HARD_CEILINGS.maxDurationSeconds) {
    throw new PolicyRefusal("limit-above-reviewed-ceiling", "hard ceiling exceeded");
  }
  // A shorter duration clips a single-phase workload. Multi-phase workloads (stepped, burst, timeout,
  // failure) only have meaning as a whole, so a reduced duration is refused instead of silently dropping phases.
  if (duration < reviewed.durationSeconds && workload.phases.length > 1) {
    throw new PolicyRefusal("limit-invalid", `${workload.id} has several phases and runs its full reviewed shape; lower the rate or concurrency instead`);
  }
  const phases = workload.phases.map((phase) => Object.freeze({
    ...phase,
    durationSeconds: Math.min(phase.durationSeconds, duration),
    ratePerSecond: Math.min(phase.ratePerSecond, rate),
    concurrency: Math.min(phase.concurrency, concurrency),
    timeoutMs: Math.min(phase.timeoutMs, HARD_CEILINGS.maxRequestTimeoutMs),
  }));
  const totalRequests = Math.min(
    reviewed.totalRequests,
    phases.reduce((sum, phase) => sum + phase.durationSeconds * phase.ratePerSecond, 0),
    HARD_CEILINGS.maxTotalRequests,
  );
  return Object.freeze({
    phases: Object.freeze(phases),
    maxTotalRequests: totalRequests,
    maxDurationSeconds: Math.min(duration, reviewed.durationSeconds, HARD_CEILINGS.maxDurationSeconds),
    maxRequestsPerSecond: rate,
    maxConcurrency: concurrency,
  });
}

export type RunRequest = {
  targetId: string;
  workloadId: string;
  limits?: CliLimits;
  registry: TargetRegistry;
  now: Date;
  /** Whether the git working tree is clean; lab-remote runs require it. */
  treeIsClean?: boolean;
};

function authorizeOne(target: LabTarget, workload: WorkloadSpec, method: TargetMethod, path: string): AuthorizedRequest {
  if (isLiveLimitmarkHost(target.host)) throw new PolicyRefusal("target-live-limitmark", "live LimitMark hosts receive no lab traffic");
  if (isProviderInfrastructureHost(target.host)) throw new PolicyRefusal("target-provider-infrastructure", "provider infrastructure is never targetable");
  if (method !== "GET" && method !== "POST") throw new PolicyRefusal("method-forbidden", `method ${String(method)} is not permitted`);
  if (!workload.methods.includes(method) || !target.allowedMethods.includes(method)) throw new PolicyRefusal("method-forbidden", `${method} is not permitted by the workload and target`);
  checkPath(path);
  if (!workload.paths.includes(path) || !target.allowedPaths.includes(path)) throw new PolicyRefusal("path-forbidden", `${path} is not allowlisted for this workload and target`);
  if (method === "POST" && !POST_PATHS.includes(path)) throw new PolicyRefusal("method-forbidden", "POST is limited to the demo submission path");
  const authorized = Object.freeze({
    method, url: `${target.origin}${path}`, targetId: target.id, path, scheme: target.scheme, host: target.host, port: target.port,
  }) as unknown as AuthorizedRequest;
  issuedAuthorizations.add(authorized);
  return authorized;
}

/** The single entry point for HTTP workloads. Pure: no I/O. */
export function authorizeRun(request: RunRequest): AuthorizedRun {
  const target = request.registry.get(request.targetId);
  if (!target) throw new PolicyRefusal("target-unknown", "target id is not in the allowlist");
  if (!isWorkloadId(request.workloadId)) throw new PolicyRefusal("workload-unknown", "workload id is not in the reviewed catalogue");
  const workload = WORKLOADS[request.workloadId as WorkloadId];
  if (isLiveLimitmarkHost(target.host)) throw new PolicyRefusal("target-live-limitmark", "live LimitMark hosts receive no lab traffic");
  if (isProviderInfrastructureHost(target.host)) throw new PolicyRefusal("target-provider-infrastructure", "provider infrastructure is never targetable");
  if (target.expiresAt && Date.parse(target.expiresAt) <= request.now.getTime()) throw new PolicyRefusal("target-expired", "target definition has expired");
  if (workload.engine === "managed-postgres") throw new PolicyRefusal("workload-local-only", "the PostgreSQL workload has no HTTP target; it is authorized by authorizeManagedPostgresRun");
  if (workload.localOnly && target.class !== "lab-local") throw new PolicyRefusal("workload-local-only", "failure workloads act only on lab-managed local processes");
  if (target.class === "lab-remote" && request.treeIsClean !== true) throw new PolicyRefusal("clean-tree-required", "remote lab runs need a clean, recorded git tree");
  const limits = applyCliLimits(workload, request.limits ?? {});
  // Eagerly authorize every (method, path) the workload can issue: any refusal happens now, before any network.
  for (const method of workload.methods) for (const path of workload.paths) authorizeOne(target, workload, method, path);
  return Object.freeze({
    target,
    workload,
    limits,
    authorizeRequest: (method: TargetMethod, path: string) => authorizeOne(target, workload, method, path),
    wouldAuthorizeUrl: (location: string, method: TargetMethod) => {
      try {
        const parsed = new URL(location, target.origin);
        if (parsed.origin !== target.origin || parsed.username || parsed.password || parsed.search || parsed.hash) return false;
        authorizeOne(target, workload, method, parsed.pathname);
        return true;
      } catch { return false; }
    },
  });
}

/** Managed-resource guard for the PostgreSQL failure workload: only lab-labelled local containers. */
export const LAB_CONTAINER_PREFIX = "limitmark-lab-";
export const LAB_CONTAINER_LABEL = "limitmark.lab=disposable";
export function assertLabContainer(name: string, labels: Readonly<Record<string, string>>): void {
  if (!new RegExp(`^${LAB_CONTAINER_PREFIX}[a-z0-9-]{1,40}$`).test(name) || labels["limitmark.lab"] !== "disposable") {
    throw new PolicyRefusal("target-unknown", "only containers created by the lab (name prefix and disposable label) may be controlled");
  }
}

/** The PostgreSQL failure workload has no HTTP target: it acts on the lab-owned container only. */
export function authorizeManagedPostgresRun(workloadId: string, limits: CliLimits = {}): { workload: WorkloadSpec; limits: EffectiveLimits } {
  if (!isWorkloadId(workloadId)) throw new PolicyRefusal("workload-unknown", "workload id is not in the reviewed catalogue");
  const workload = WORKLOADS[workloadId as WorkloadId];
  if (workload.engine !== "managed-postgres") throw new PolicyRefusal("workload-unknown", "not a managed PostgreSQL workload");
  return { workload, limits: applyCliLimits(workload, limits) };
}
