/**
 * Milestone 2: pure customer-origin-policy-v1 activator, validator and verifier-bound classifier.
 *
 * Security boundaries:
 *   - Policies are compiled ONLY from immutable UTF-8 source bytes via `activateCustomerOriginPolicy()`, deriving
 *     the SHA-256 digest from those exact bytes and verifying it (constant-time) plus scope/revision against an
 *     explicit trusted `PolicyActivationRecord`. There is no API that accepts a caller-chosen digest.
 *   - There is NO exported request sealer or synthetic verifier here. Verified request classification runs only
 *     through a caller-injected trusted `OriginRequestVerifier` capability whose output binds `proofExpiresAtWallMs`.
 *   - Uses only TypeScript and `node:crypto` (no external packages, no I/O, no L2 or telemetry imports).
 */
import { createHash, timingSafeEqual } from "node:crypto";
import type {
  AccessCategory,
  AuthenticatedRequestData,
  CapacityLimits,
  ChannelSpec,
  ClassificationResult,
  ClassSpec,
  CompiledCustomerOriginPolicy,
  CustomerOriginPolicyManifest,
  DomainSpec,
  HttpScheme,
  JourneySpec,
  JourneyStepSpec,
  OperationBodySpec,
  OperationEffect,
  OperationMethod,
  OperationSpec,
  OriginRequestVerifier,
  PolicyActivationRecord,
  VerificationBody,
} from "./capacity-port";

export const POLICY_VERSION = "customer-origin-policy-v1" as const;
export const POLICY_REQUEST_PROFILE = "bounded-http-v1" as const;
export const MAX_MANIFEST_BYTES = 262_144;
export const MAX_TARGET_LENGTH = 1_024;
export const MAX_COUNT = 65_535;
export const MAX_SIZE_BYTES = 1_073_741_824;
export const MAX_DURATION_MS = 2_147_483_647;

const ID_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const SEGMENT_PATTERN = /^[A-Za-z0-9._~-]{1,64}$/;
const PARAMETER_PATTERN = /^:[a-z][a-z0-9-]{0,31}$/;
const LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const PORT_PATTERN = /^[1-9][0-9]{0,4}$/;
const QUERY_PATTERN = /^(?:[A-Za-z0-9._~-]{1,64}=[A-Za-z0-9._~-]{1,64})?$/;
const MEDIA_TYPE_PATTERN = /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

const ACCESS_SET: ReadonlySet<string> = new Set<AccessCategory>(["public", "operational"]);
const SCHEME_SET: ReadonlySet<string> = new Set<HttpScheme>(["http", "https"]);
const METHOD_SET: ReadonlySet<string> = new Set<OperationMethod>(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
const EFFECT_SET: ReadonlySet<string> = new Set<OperationEffect>(["read", "write"]);

export class PolicyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyValidationError";
  }
}

function fail(message: string): never {
  throw new PolicyValidationError(message);
}

function asClosedObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail(`${label} must be a plain object`);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record);
  const allowed = new Set(keys);
  for (const key of actual) if (!allowed.has(key)) fail(`${label}: unknown member "${key}"`);
  for (const key of keys) if (!Object.hasOwn(record, key)) fail(`${label}: missing member "${key}"`);
  return record;
}

function asId(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) fail(`${label} must be a valid id`);
  return value;
}

function asIntRange(value: unknown, min: number, max: number, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    fail(`${label} must be an integer in [${min}, ${max}]`);
  }
  return value;
}

function asArray(value: unknown, min: number, max: number, label: string): unknown[] {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    fail(`${label} must be an array of length ${min}..${max}`);
  }
  return value;
}

function assertUnique(values: readonly string[], field: string): void {
  if (new Set(values).size !== values.length) fail(`duplicate ${field}`);
}

export function isValidPolicyPath(value: string, allowParameters: boolean): boolean {
  if (value.length > MAX_TARGET_LENGTH) return false;
  if (value === "/") return true;
  if (!value.startsWith("/")) return false;
  const parts = value.slice(1).split("/");
  if (parts.length > 16) return false;
  return parts.every(
    (part) => (allowParameters && PARAMETER_PATTERN.test(part)) || (part !== "." && part !== ".." && SEGMENT_PATTERN.test(part)),
  );
}

export function isValidAuthority(value: string): boolean {
  if (value.length === 0 || value.length > 259) return false;
  const [host, port, extra] = value.split(":");
  if (extra !== undefined || host.length === 0 || host.length > 253) return false;
  if (!host.split(".").every((label) => LABEL_PATTERN.test(label))) return false;
  return port === undefined || (PORT_PATTERN.test(port) && Number(port) <= MAX_COUNT);
}

export function pathsIntersect(left: string, right: string): boolean {
  if (left === "/" || right === "/") return left === right;
  const leftParts = left.slice(1).split("/");
  const rightParts = right.slice(1).split("/");
  if (leftParts.length !== rightParts.length) return false;
  return leftParts.every(
    (part, index) => part === rightParts[index] || PARAMETER_PATTERN.test(part) || PARAMETER_PATTERN.test(rightParts[index]),
  );
}

export function matchesOperationTarget(rule: Pick<OperationSpec, "path" | "queries">, target: string): boolean {
  if (target.length > MAX_TARGET_LENGTH) return false;
  const [pathname, search, extra] = target.split("?");
  if (extra !== undefined || search === "") return false;
  if (!isValidPolicyPath(pathname, false)) return false;
  return rule.queries.includes(search ?? "") && pathsIntersect(rule.path, pathname);
}

function parseDomain(raw: unknown): DomainSpec {
  const obj = asClosedObject(raw, ["id", "backendRef", "instances"], "domain");
  const id = asId(obj.id, "domain.id");
  const backendRef = asId(obj.backendRef, "domain.backendRef");
  if (obj.instances !== 1) fail("domain.instances must be 1");
  return Object.freeze({ id, backendRef, instances: 1 as const });
}

function parseChannel(raw: unknown, index: number): ChannelSpec {
  const obj = asClosedObject(raw, ["id", "access", "principal", "audience", "scheme", "authority"], `channels[${index}]`);
  const id = asId(obj.id, `channels[${index}].id`);
  if (typeof obj.access !== "string" || !ACCESS_SET.has(obj.access)) fail(`channels[${index}].access invalid`);
  const principal = asId(obj.principal, `channels[${index}].principal`);
  const audience = asId(obj.audience, `channels[${index}].audience`);
  if (typeof obj.scheme !== "string" || !SCHEME_SET.has(obj.scheme)) fail(`channels[${index}].scheme invalid`);
  if (typeof obj.authority !== "string" || !isValidAuthority(obj.authority)) fail(`channels[${index}].authority invalid`);
  return Object.freeze({
    id,
    access: obj.access as AccessCategory,
    principal,
    audience,
    scheme: obj.scheme as HttpScheme,
    authority: obj.authority,
  });
}

function parseCapacity(raw: unknown): CapacityLimits {
  const obj = asClosedObject(
    raw,
    ["activeUnits", "maxQueued", "maxQueuedBytes", "maxBodyBytes", "metadataBytesPerRequest", "proofWindowMs", "dispatchMarginMs", "executionTimeoutMs", "callerBudgetMs"],
    "capacity",
  );
  return Object.freeze({
    activeUnits: asIntRange(obj.activeUnits, 1, MAX_COUNT, "capacity.activeUnits"),
    maxQueued: asIntRange(obj.maxQueued, 0, MAX_COUNT, "capacity.maxQueued"),
    maxQueuedBytes: asIntRange(obj.maxQueuedBytes, 0, MAX_SIZE_BYTES, "capacity.maxQueuedBytes"),
    maxBodyBytes: asIntRange(obj.maxBodyBytes, 0, MAX_SIZE_BYTES, "capacity.maxBodyBytes"),
    metadataBytesPerRequest: asIntRange(obj.metadataBytesPerRequest, 1, MAX_SIZE_BYTES, "capacity.metadataBytesPerRequest"),
    proofWindowMs: asIntRange(obj.proofWindowMs, 1, MAX_DURATION_MS, "capacity.proofWindowMs"),
    dispatchMarginMs: asIntRange(obj.dispatchMarginMs, 1, MAX_DURATION_MS, "capacity.dispatchMarginMs"),
    executionTimeoutMs: asIntRange(obj.executionTimeoutMs, 1, MAX_DURATION_MS, "capacity.executionTimeoutMs"),
    callerBudgetMs: asIntRange(obj.callerBudgetMs, 1, MAX_DURATION_MS, "capacity.callerBudgetMs"),
  });
}

function parseClass(raw: unknown, index: number): ClassSpec {
  const obj = asClosedObject(raw, ["id", "access", "reservedUnits", "maxActiveUnits", "maxQueued", "maxWaitMs"], `classes[${index}]`);
  const id = asId(obj.id, `classes[${index}].id`);
  if (typeof obj.access !== "string" || !ACCESS_SET.has(obj.access)) fail(`classes[${index}].access invalid`);
  return Object.freeze({
    id,
    access: obj.access as AccessCategory,
    reservedUnits: asIntRange(obj.reservedUnits, 0, MAX_COUNT, `classes[${index}].reservedUnits`),
    maxActiveUnits: asIntRange(obj.maxActiveUnits, 1, MAX_COUNT, `classes[${index}].maxActiveUnits`),
    maxQueued: asIntRange(obj.maxQueued, 0, MAX_COUNT, `classes[${index}].maxQueued`),
    maxWaitMs: asIntRange(obj.maxWaitMs, 0, MAX_DURATION_MS, `classes[${index}].maxWaitMs`),
  });
}

function parseOperationBody(raw: unknown, label: string): OperationBodySpec | null {
  if (raw === null) return null;
  const obj = asClosedObject(raw, ["mediaType", "maxBytes", "requireSameOrigin"], label);
  if (typeof obj.mediaType !== "string" || obj.mediaType.length > 127 || !MEDIA_TYPE_PATTERN.test(obj.mediaType)) {
    fail(`${label}.mediaType invalid`);
  }
  const maxBytes = asIntRange(obj.maxBytes, 1, MAX_SIZE_BYTES, `${label}.maxBytes`);
  if (typeof obj.requireSameOrigin !== "boolean") fail(`${label}.requireSameOrigin must be boolean`);
  return Object.freeze({ mediaType: obj.mediaType, maxBytes, requireSameOrigin: obj.requireSameOrigin });
}

function parseOperation(raw: unknown, index: number): OperationSpec {
  const obj = asClosedObject(raw, ["id", "channel", "method", "path", "queries", "body", "classId", "costUnits", "effect"], `operations[${index}]`);
  const id = asId(obj.id, `operations[${index}].id`);
  const channel = asId(obj.channel, `operations[${index}].channel`);
  const classId = asId(obj.classId, `operations[${index}].classId`);
  const costUnits = asIntRange(obj.costUnits, 1, MAX_COUNT, `operations[${index}].costUnits`);
  if (typeof obj.method !== "string" || !METHOD_SET.has(obj.method)) fail(`operations[${index}].method invalid`);
  if (typeof obj.effect !== "string" || !EFFECT_SET.has(obj.effect)) fail(`operations[${index}].effect invalid`);
  if (typeof obj.path !== "string" || !isValidPolicyPath(obj.path, true)) fail(`operations[${index}].path invalid`);
  const rawQueries = asArray(obj.queries, 1, 32, `operations[${index}].queries`);
  const queries: string[] = [];
  for (let qIndex = 0; qIndex < rawQueries.length; qIndex++) {
    const entry = rawQueries[qIndex];
    if (typeof entry !== "string" || !QUERY_PATTERN.test(entry)) fail(`operations[${index}].queries[${qIndex}] invalid`);
    queries.push(entry);
  }
  const body = parseOperationBody(obj.body, `operations[${index}].body`);
  return Object.freeze({
    id,
    channel,
    method: obj.method as OperationMethod,
    path: obj.path,
    queries: Object.freeze(queries),
    body,
    classId,
    costUnits,
    effect: obj.effect as OperationEffect,
  });
}

function parseJourneyStep(raw: unknown, label: string): JourneyStepSpec {
  const obj = asClosedObject(raw, ["operationId", "target", "status", "result", "receipt"], label);
  const operationId = asId(obj.operationId, `${label}.operationId`);
  if (typeof obj.target !== "string" || obj.target.length > MAX_TARGET_LENGTH) fail(`${label}.target invalid`);
  const status = asIntRange(obj.status, 200, 399, `${label}.status`);
  if (typeof obj.result !== "string") fail(`${label}.result must be a string`);
  const trimmedResult = obj.result.trim();
  if (trimmedResult.length < 1 || trimmedResult.length > 256) fail(`${label}.result must be 1..256 trimmed characters`);
  const receipt = obj.receipt === null ? null : asId(obj.receipt, `${label}.receipt`);
  return Object.freeze({ operationId, target: obj.target, status, result: trimmedResult, receipt });
}

function parseJourney(raw: unknown, index: number): JourneySpec {
  const obj = asClosedObject(raw, ["id", "minCompletionBps", "p95LimitMs", "recoveryLimitMs", "steps"], `journeys[${index}]`);
  const id = asId(obj.id, `journeys[${index}].id`);
  const minCompletionBps = asIntRange(obj.minCompletionBps, 1, 10_000, `journeys[${index}].minCompletionBps`);
  const p95LimitMs = asIntRange(obj.p95LimitMs, 1, MAX_DURATION_MS, `journeys[${index}].p95LimitMs`);
  const recoveryLimitMs = asIntRange(obj.recoveryLimitMs, 1, MAX_DURATION_MS, `journeys[${index}].recoveryLimitMs`);
  const rawSteps = asArray(obj.steps, 1, 32, `journeys[${index}].steps`);
  const steps = Object.freeze(rawSteps.map((step, sIndex) => parseJourneyStep(step, `journeys[${index}].steps[${sIndex}]`)));
  return Object.freeze({ id, minCompletionBps, p95LimitMs, recoveryLimitMs, steps });
}

/** Validates an unknown parsed JSON object against every customer-origin-policy-v1 invariant. */
export function validateCustomerOriginPolicyManifest(input: unknown): { manifest: CustomerOriginPolicyManifest; sharedUnits: number } {
  const root = asClosedObject(
    input,
    ["version", "revision", "tenantId", "deploymentId", "requestProfile", "unsupported", "domain", "channels", "capacity", "classes", "operations", "journeys"],
    "manifest",
  );
  if (root.version !== POLICY_VERSION) fail(`unsupported version "${String(root.version)}"`);
  const revision = asIntRange(root.revision, 1, MAX_COUNT, "revision");
  const tenantId = asId(root.tenantId, "tenantId");
  const deploymentId = asId(root.deploymentId, "deploymentId");
  if (root.requestProfile !== POLICY_REQUEST_PROFILE) fail(`unsupported requestProfile "${String(root.requestProfile)}"`);
  if (root.unsupported !== "deny") fail(`unsupported policy must be "deny"`);

  const domain = parseDomain(root.domain);
  const channels = Object.freeze(asArray(root.channels, 1, 16, "channels").map((entry, idx) => parseChannel(entry, idx)));
  const capacity = parseCapacity(root.capacity);
  const classes = Object.freeze(asArray(root.classes, 1, 32, "classes").map((entry, idx) => parseClass(entry, idx)));
  const operations = Object.freeze(asArray(root.operations, 1, 128, "operations").map((entry, idx) => parseOperation(entry, idx)));
  const journeys = Object.freeze(asArray(root.journeys, 1, 32, "journeys").map((entry, idx) => parseJourney(entry, idx)));

  for (const entries of [channels, classes, operations, journeys]) assertUnique(entries.map((entry) => entry.id), "id");
  assertUnique(channels.map((c) => JSON.stringify([c.principal, c.audience, c.scheme, c.authority])), "channel binding");

  const publicChannels = channels.filter((c) => c.access === "public");
  for (const ops of channels.filter((c) => c.access === "operational")) {
    if (!publicChannels.every((c) => c.principal !== ops.principal)) fail("public operational principal reuse");
    if (!publicChannels.every((c) => c.audience !== ops.audience)) fail("public operational audience reuse");
  }

  const reservedSum = classes.reduce((sum, c) => sum + c.reservedUnits, 0);
  const sharedUnits = capacity.activeUnits - reservedSum;
  if (sharedUnits < 0) fail("overcommitted reservations");
  if ((capacity.maxQueued === 0) !== (capacity.maxQueuedBytes === 0)) fail("queue count/bytes disagree");
  if (capacity.maxQueued > 0 && capacity.maxQueuedBytes < capacity.metadataBytesPerRequest) fail("queue metadata cannot fit");

  const classById = new Map<string, ClassSpec>();
  for (const c of classes) {
    if (c.reservedUnits > c.maxActiveUnits || c.maxActiveUnits > c.reservedUnits + sharedUnits) fail(`invalid class ceiling: ${c.id}`);
    if (c.maxQueued > capacity.maxQueued || (c.maxQueued === 0) !== (c.maxWaitMs === 0)) fail(`invalid class queue: ${c.id}`);
    if (c.maxWaitMs + capacity.dispatchMarginMs >= capacity.proofWindowMs) fail(`wait exceeds proof budget: ${c.id}`);
    if (c.maxWaitMs + capacity.dispatchMarginMs + capacity.executionTimeoutMs > capacity.callerBudgetMs) fail(`wait exceeds caller budget: ${c.id}`);
    classById.set(c.id, c);
  }

  const channelById = new Map<string, ChannelSpec>(channels.map((c) => [c.id, c]));
  const operationById = new Map<string, OperationSpec>();
  for (let index = 0; index < operations.length; index++) {
    const op = operations[index];
    const source = channelById.get(op.channel);
    const owner = classById.get(op.classId);
    if (!source || !owner) fail(`unknown channel or class on operation "${op.id}"`);
    if (source.access !== owner.access) fail(`channel lacks class access on operation "${op.id}"`);
    if (op.costUnits > owner.maxActiveUnits || (owner.reservedUnits > 0 && op.costUnits > owner.reservedUnits)) {
      fail(`cost cannot fit on operation "${op.id}"`);
    }
    const isRead = op.method === "GET" || op.method === "HEAD";
    if (op.effect !== (isRead ? "read" : "write")) fail(`method/effect mismatch on operation "${op.id}"`);
    if (isRead && op.body !== null) fail(`read body unsupported on operation "${op.id}"`);
    if (op.body !== null && op.body.maxBytes > capacity.maxBodyBytes) fail(`body exceeds domain limit on operation "${op.id}"`);
    assertUnique(op.queries, "query");
    assertUnique(op.path.split("/").filter((part) => PARAMETER_PATTERN.test(part)), "parameter");
    for (let prior = 0; prior < index; prior++) {
      const other = operations[prior];
      if (other.channel === op.channel && other.method === op.method && pathsIntersect(other.path, op.path) && other.queries.some((q) => op.queries.includes(q))) {
        fail(`overlapping operations: ${other.id} and ${op.id}`);
      }
    }
    operationById.set(op.id, op);
  }

  const covered = new Set<string>();
  for (const journey of journeys) {
    for (const step of journey.steps) {
      const op = operationById.get(step.operationId);
      if (!op || !matchesOperationTarget(op, step.target)) fail(`journey step does not match its operation: ${journey.id}/${step.operationId}`);
      if ((step.receipt !== null) !== (op.effect === "write")) fail(`journey receipt disagrees with effect: ${journey.id}/${step.operationId}`);
      covered.add(op.id);
    }
  }
  if (covered.size !== operations.length) fail("operation missing from journeys");

  const manifest: CustomerOriginPolicyManifest = Object.freeze({
    version: POLICY_VERSION,
    revision,
    tenantId,
    deploymentId,
    requestProfile: POLICY_REQUEST_PROFILE,
    unsupported: "deny",
    domain,
    channels,
    capacity,
    classes,
    operations,
    journeys,
  });
  return { manifest, sharedUnits };
}

// ---------------------------------------------------------------------------
// Trusted policy activation (authoritative internals live in a private WeakMap)
// ---------------------------------------------------------------------------

export type CompiledPolicyInternal = {
  readonly manifest: CustomerOriginPolicyManifest;
  readonly digest: string;
  readonly sharedUnits: number;
};

const compiledPolicyInternals = new WeakMap<object, CompiledPolicyInternal>();

export const isCompiledCustomerOriginPolicy = (value: unknown): value is CompiledCustomerOriginPolicy =>
  typeof value === "object" && value !== null && compiledPolicyInternals.has(value);

/** Returns the private, immutable policy internals owned by `capacity-policy.ts`, rejecting forged/uncompiled handles. */
export function readCompiledPolicyInternal(policy: CompiledCustomerOriginPolicy): CompiledPolicyInternal {
  const internal = typeof policy === "object" && policy !== null ? compiledPolicyInternals.get(policy) : undefined;
  if (internal === undefined) fail("policy must be activated via activateCustomerOriginPolicy");
  return internal;
}

function parseActivationRecord(raw: unknown): PolicyActivationRecord {
  const obj = asClosedObject(raw, ["tenantId", "deploymentId", "domainId", "revision", "expectedDigest"], "activation");
  const tenantId = asId(obj.tenantId, "activation.tenantId");
  const deploymentId = asId(obj.deploymentId, "activation.deploymentId");
  const domainId = asId(obj.domainId, "activation.domainId");
  const revision = asIntRange(obj.revision, 1, MAX_COUNT, "activation.revision");
  if (typeof obj.expectedDigest !== "string" || !DIGEST_PATTERN.test(obj.expectedDigest)) {
    fail("activation.expectedDigest must be 64 lowercase hex characters");
  }
  return { tenantId, deploymentId, domainId, revision, expectedDigest: obj.expectedDigest };
}

/**
 * The ONLY way to compile a `CompiledCustomerOriginPolicy`:
 * copies the source bytes immediately (preventing caller mutation), derives SHA-256 directly from those bytes,
 * validates UTF-8, duplicate JSON members, and all M1 invariants, and matches derived digest + identity against
 * the trusted `PolicyActivationRecord`.
 */
export function activateCustomerOriginPolicy(bytes: Uint8Array, activation: PolicyActivationRecord): CompiledCustomerOriginPolicy {
  if (!(bytes instanceof Uint8Array)) fail("manifest bytes must be a Uint8Array");
  if (bytes.byteLength > MAX_MANIFEST_BYTES) fail("manifest too large");
  const expected = parseActivationRecord(activation);

  // Copy immediately so subsequent mutation of the caller's Uint8Array cannot diverge parsed content from hashed bytes.
  const immutableBytes = Uint8Array.from(bytes);
  const derivedDigest = createHash("sha256").update(immutableBytes).digest("hex");
  const derivedBuf = Buffer.from(derivedDigest, "hex");
  const expectedBuf = Buffer.from(expected.expectedDigest, "hex");
  if (!timingSafeEqual(derivedBuf, expectedBuf)) fail("policy digest mismatch against activation record");

  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(immutableBytes);
  } catch {
    fail("manifest is not valid UTF-8");
  }
  let decodedMembers = 0;
  let parsed: unknown;
  try {
    parsed = JSON.parse(source, (_key, value: unknown) => {
      if (typeof value === "object" && value !== null && !Array.isArray(value)) decodedMembers += Object.keys(value).length;
      return value;
    });
  } catch {
    fail("manifest is not valid JSON");
  }
  // In valid JSON, only an object member name is a string token immediately followed by a colon.
  let memberTokenCount = 0;
  for (const match of source.matchAll(/"(?:\\.|[^"\\])*"\s*(:)?/g)) {
    if (match[1] !== undefined) memberTokenCount++;
  }
  if (memberTokenCount !== decodedMembers) fail("duplicate JSON member");

  const { manifest, sharedUnits } = validateCustomerOriginPolicyManifest(parsed);
  if (
    manifest.tenantId !== expected.tenantId ||
    manifest.deploymentId !== expected.deploymentId ||
    manifest.domain.id !== expected.domainId ||
    manifest.revision !== expected.revision
  ) {
    fail("policy scope or revision mismatch against activation record");
  }

  const internal: CompiledPolicyInternal = Object.freeze({ manifest, digest: derivedDigest, sharedUnits });
  const handle: CompiledCustomerOriginPolicy = Object.freeze({ manifest, digest: derivedDigest, sharedUnits });
  compiledPolicyInternals.set(handle, internal);
  return handle;
}

// ---------------------------------------------------------------------------
// Verifier-bound classification (no exported sealer; proof expiry bound inside verifier result)
// ---------------------------------------------------------------------------

function extractAuthenticatedFacts(raw: unknown): AuthenticatedRequestData | null {
  if (typeof raw !== "object" || raw === null) return null;
  const {
    tenantId, deploymentId, domainId, digest, principal, audience, scheme, authority,
    method, target, mediaType, bodyBytes, origin, proofExpiresAtWallMs,
  } = raw as Record<string, unknown>;
  if (
    typeof tenantId !== "string" ||
    typeof deploymentId !== "string" ||
    typeof domainId !== "string" ||
    typeof digest !== "string" ||
    typeof principal !== "string" ||
    typeof audience !== "string" ||
    typeof scheme !== "string" ||
    typeof authority !== "string" ||
    typeof method !== "string" ||
    typeof target !== "string" ||
    (mediaType !== null && typeof mediaType !== "string") ||
    typeof bodyBytes !== "number" ||
    (origin !== null && typeof origin !== "string") ||
    typeof proofExpiresAtWallMs !== "number" ||
    !Number.isFinite(proofExpiresAtWallMs)
  ) {
    return null;
  }
  // Copy ONLY the closed authenticated-fact fields; extra caller properties (channel, classId, priority, etc.) are ignored.
  return {
    tenantId, deploymentId, domainId, digest, principal, audience, scheme, authority,
    method, target, mediaType, bodyBytes, origin, proofExpiresAtWallMs,
  };
}

/**
 * Verifies a raw candidate through the trusted verifier capability and classifies it strictly against
 * the private activated policy internals. Any verifier throw or malformed result fails closed as `"unverified"`.
 */
export function classifyVerifiedCandidate<TInput>(
  policy: CompiledCustomerOriginPolicy,
  verifier: OriginRequestVerifier<TInput>,
  candidate: TInput,
  wallNowMs: number,
  body?: VerificationBody,
): ClassificationResult {
  const internal = readCompiledPolicyInternal(policy);
  if (!verifier || !Number.isFinite(wallNowMs)) return { kind: "unverified" };

  let facts: AuthenticatedRequestData | null;
  try {
    const verified = verifier.verify(candidate, policy, wallNowMs, body);
    if (typeof verified !== "object" || verified === null || verified.ok !== true) return { kind: "unverified" };
    facts = extractAuthenticatedFacts(verified.authenticated);
  } catch {
    return { kind: "unverified" };
  }
  if (facts === null) return { kind: "unverified" };

  const p = internal.manifest;
  if (
    facts.tenantId !== p.tenantId ||
    facts.deploymentId !== p.deploymentId ||
    facts.domainId !== p.domain.id ||
    facts.digest !== internal.digest
  ) {
    return { kind: "scope-mismatch" };
  }
  const channel = p.channels.find(
    (c) =>
      c.principal === facts.principal &&
      c.audience === facts.audience &&
      c.scheme === facts.scheme &&
      c.authority === facts.authority,
  );
  if (!channel) return { kind: "untrusted-channel" };
  const op = p.operations.find(
    (candidateOp) => candidateOp.channel === channel.id && candidateOp.method === facts.method && matchesOperationTarget(candidateOp, facts.target),
  );
  if (
    !op ||
    !Number.isSafeInteger(facts.bodyBytes) ||
    facts.bodyBytes < 0 ||
    facts.mediaType !== (op.body?.mediaType ?? null) ||
    facts.bodyBytes > (op.body?.maxBytes ?? 0) ||
    (op.body?.requireSameOrigin === true && facts.origin !== `${channel.scheme}://${channel.authority}`)
  ) {
    return { kind: "unsupported" };
  }
  return {
    kind: "classified",
    operationId: op.id,
    classId: op.classId,
    channelId: channel.id,
    access: channel.access,
    costUnits: op.costUnits,
    effect: op.effect,
    bodyBytes: facts.bodyBytes,
    proofExpiresAtWallMs: facts.proofExpiresAtWallMs,
  };
}
