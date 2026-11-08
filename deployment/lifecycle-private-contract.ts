import { decodeCanonicalBase64url } from "../src/lib/ingress-protocol";

function exact(value: unknown, keys: string[]): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key));
}
const common = ["$schema", "name", "main", "account_id", "compatibility_date", "workers_dev", "preview_urls", "triggers", "r2_buckets", "services"];
const buckets = [
  { binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-production" },
  { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-production" },
];
const reader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-production", entrypoint: "AuthorityLifecycleReadOnly" };
/** The observer reaches the guard ledger ONLY through this read-only entrypoint (one method, `exportLedger`); it never binds the guard Durable Object itself. */
const guardReader = { binding: "GUARD_READER", service: "limitmark-lifecycle-mailbox-production", entrypoint: "LifecycleGuardReadOnly" };
const stagingBuckets = [
  { binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
  { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" },
];
const stagingReader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };
/** Production schedule states. Production mailbox/observer rollouts start INACTIVE (no Cron trigger can process lifecycle objects before bindings,
 * secrets and routes have been inspected); ARMED is a separate, explicitly authorized later step. Only these two exact `triggers` shapes exist; any
 * other shape (extra crons, another expression, missing key) is refused. A validator never infers the state: the caller names the state it requires. */
export type ProductionScheduleState = "PRODUCTION_DEPLOYMENT_INACTIVE" | "PRODUCTION_SCHEDULE_ARMED";
const productionScheduleTriggers: Record<ProductionScheduleState, string> = {
  PRODUCTION_DEPLOYMENT_INACTIVE: JSON.stringify({ crons: [] }),
  PRODUCTION_SCHEDULE_ARMED: JSON.stringify({ crons: ["* * * * *"] }),
};
export function productionScheduleState(triggers: unknown): ProductionScheduleState {
  const serialized = JSON.stringify(triggers);
  if (serialized === productionScheduleTriggers.PRODUCTION_DEPLOYMENT_INACTIVE) return "PRODUCTION_DEPLOYMENT_INACTIVE";
  if (serialized === productionScheduleTriggers.PRODUCTION_SCHEDULE_ARMED) return "PRODUCTION_SCHEDULE_ARMED";
  throw new Error("unsafe-production-schedule-state");
}
function base(value: unknown, kind: "mailbox" | "observer", template: boolean, requireScheduleState: ProductionScheduleState): Record<string, unknown> {
  const extra = kind === "mailbox" ? ["durable_objects", "migrations", "vars"] : [];
  if (!exact(value, [...common, ...extra]) || value.$schema !== "../node_modules/wrangler/config-schema.json" ||
      value.name !== `limitmark-lifecycle-${kind}-production` || value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false ||
      JSON.stringify(value.triggers) !== productionScheduleTriggers[requireScheduleState] ||
      JSON.stringify(value.r2_buckets) !== JSON.stringify(buckets) ||
      value.main !== (template ? `__REQUIRED_RENDERED_${kind.toUpperCase()}_MAIN__.ts` : `../workers/${kind === "mailbox" ? "lifecycle-mailbox/index" : "lifecycle-observer"}.ts`))
    throw new Error("unsafe-lifecycle-config");
  const expectedServices = kind === "mailbox" ? [
    { binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-production", entrypoint: "OperatorLifecycleExecutor" }, reader,
  ] : [reader, guardReader];
  if (JSON.stringify(value.services) !== JSON.stringify(expectedServices)) throw new Error("unsafe-lifecycle-services");
  if (kind === "mailbox") {
    if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [{ name: "DISPATCH_GUARD", class_name: "LifecycleDispatchGuard" }] }) ||
        JSON.stringify(value.migrations) !== JSON.stringify([{ tag: "i3b-guard-v1", new_sqlite_classes: ["LifecycleDispatchGuard"] }]) ||
        !exact(value.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY", "CLOUDFLARE_ACCOUNT_ID", "LIFECYCLE_ENVIRONMENT"]) ||
        value.vars.LIFECYCLE_ENVIRONMENT !== "production" || value.vars.CLOUDFLARE_ACCOUNT_ID !== value.account_id) throw new Error("unsafe-lifecycle-guard");
    const key = value.vars.AUTHORITY_OPERATOR_PUBLIC_KEY;
    if (template ? key !== "__REQUIRED_OPERATOR_ED25519_PUBLIC_KEY__" : typeof key !== "string" || key.startsWith("__REQUIRED_"))
      throw new Error("unsafe-lifecycle-key");
    if (!template) decodeCanonicalBase64url(key as string, 32);
  }
  if (template ? value.account_id !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" :
      typeof value.account_id !== "string" || !/^[a-f0-9]{32}$/u.test(value.account_id) || /^0{32}$/u.test(value.account_id))
    throw new Error("unsafe-lifecycle-account");
  return value;
}
/** `requireScheduleState` defaults to INACTIVE: a production mailbox/observer config is accepted as armed only when the caller explicitly asks for it. */
export function validateLifecycleMailboxConfig(value: unknown, template = true, requireScheduleState: ProductionScheduleState = "PRODUCTION_DEPLOYMENT_INACTIVE"): ProductionScheduleState {
  base(value, "mailbox", template, requireScheduleState); return requireScheduleState;
}
export function validateLifecycleObserverConfig(value: unknown, template = true, requireScheduleState: ProductionScheduleState = "PRODUCTION_DEPLOYMENT_INACTIVE"): ProductionScheduleState {
  base(value, "observer", template, requireScheduleState); return requireScheduleState;
}

export function validateLifecycleTransportManifest(value: unknown, template = true): void {
  if (!exact(value, ["version", "environment", "accountId", "requestBucket", "resultBucket", "authorityId", "policyEpoch", "operatorPublicKey"]) ||
      value.version !== 1 || value.environment !== "production" || value.requestBucket !== buckets[0].bucket_name ||
      value.resultBucket !== buckets[1].bucket_name || value.authorityId !== "production-public-inquiries-v1" ||
      value.policyEpoch !== "phase5c-i1-epoch-1" ||
      (template ? value.accountId !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" || value.operatorPublicKey !== "__REQUIRED_OPERATOR_ED25519_PUBLIC_KEY__" :
        typeof value.accountId !== "string" || !/^[a-f0-9]{32}$/u.test(value.accountId) || /^0{32}$/u.test(value.accountId) ||
        typeof value.operatorPublicKey !== "string" || value.operatorPublicKey.startsWith("__REQUIRED_"))) throw new Error("unsafe-lifecycle-manifest");
  if (!template) decodeCanonicalBase64url(value.operatorPublicKey as string, 32);
}

// ---------------------------------------------------------------------------
// Gate 2 staging capability. These validators are structurally independent of
// base()/validateLifecycleTransportManifest above: they pin the distinct
// staging resource identities and never accept a Production name, so a
// rendered config cannot satisfy both the Production and staging validator at
// once. The schedule-state check additionally distinguishes an initial
// no-active-Cron rollout (STAGING_DEPLOYMENT_INACTIVE) from a later, reviewed
// armed rollout (STAGING_SCHEDULE_ARMED); only these two exact `triggers`
// shapes are accepted, so partial/garbled cron state fails closed.
// ---------------------------------------------------------------------------

export type StagingScheduleState = "STAGING_DEPLOYMENT_INACTIVE" | "STAGING_SCHEDULE_ARMED";

function stagingScheduleState(triggers: unknown): StagingScheduleState {
  if (JSON.stringify(triggers) === JSON.stringify({ crons: [] })) return "STAGING_DEPLOYMENT_INACTIVE";
  if (JSON.stringify(triggers) === JSON.stringify({ crons: ["* * * * *"] })) return "STAGING_SCHEDULE_ARMED";
  throw new Error("unsafe-staging-schedule-state");
}

function stagingBase(value: unknown, kind: "mailbox" | "observer", template: boolean): { config: Record<string, unknown>; scheduleState: StagingScheduleState } {
  const extra = kind === "mailbox" ? ["durable_objects", "migrations", "vars"] : [];
  if (!exact(value, [...common, ...extra])) throw new Error("unsafe-lifecycle-config");
  const scheduleState = stagingScheduleState(value.triggers);
  if (value.$schema !== "../node_modules/wrangler/config-schema.json" ||
      value.name !== `limitmark-lifecycle-${kind}-staging` || value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false ||
      JSON.stringify(value.r2_buckets) !== JSON.stringify(stagingBuckets) ||
      value.main !== (template ? `__REQUIRED_RENDERED_STAGING_${kind.toUpperCase()}_MAIN__.ts` :
        `../workers/${kind === "mailbox" ? "lifecycle-mailbox/staging-index" : "staging-lifecycle-observer"}.ts`))
    throw new Error("unsafe-lifecycle-config");
  const expectedServices = kind === "mailbox" ? [
    { binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-staging", entrypoint: "StagingOperatorLifecycleExecutor" }, stagingReader,
  ] : [stagingReader];
  if (JSON.stringify(value.services) !== JSON.stringify(expectedServices)) throw new Error("unsafe-lifecycle-services");
  if (kind === "mailbox") {
    if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [{ name: "DISPATCH_GUARD", class_name: "StagingLifecycleDispatchGuard" }] }) ||
        JSON.stringify(value.migrations) !== JSON.stringify([{ tag: "i3b-staging-guard-v1", new_sqlite_classes: ["StagingLifecycleDispatchGuard"] }]) ||
        !exact(value.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY", "LIFECYCLE_ENVIRONMENT"]) ||
        value.vars.LIFECYCLE_ENVIRONMENT !== "staging") throw new Error("unsafe-lifecycle-guard");
    const key = value.vars.AUTHORITY_OPERATOR_PUBLIC_KEY;
    if (template ? key !== "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__" : typeof key !== "string" || key.startsWith("__REQUIRED_"))
      throw new Error("unsafe-lifecycle-key");
    if (!template) decodeCanonicalBase64url(key as string, 32);
  }
  if (template ? value.account_id !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" :
      typeof value.account_id !== "string" || !/^[a-f0-9]{32}$/u.test(value.account_id) || /^0{32}$/u.test(value.account_id))
    throw new Error("unsafe-lifecycle-account");
  return { config: value, scheduleState };
}

/** Validates a rendered/template staging mailbox config. Returns which of the
 * two reviewed schedule states the config is in; pass `requireScheduleState`
 * to assert a specific one (e.g. deployment-time must be INACTIVE). */
export function validateStagingLifecycleMailboxConfig(value: unknown, template = true, requireScheduleState?: StagingScheduleState): StagingScheduleState {
  const { scheduleState } = stagingBase(value, "mailbox", template);
  if (requireScheduleState && scheduleState !== requireScheduleState) throw new Error("unsafe-staging-schedule-state");
  return scheduleState;
}
export function validateStagingLifecycleObserverConfig(value: unknown, template = true, requireScheduleState?: StagingScheduleState): StagingScheduleState {
  const { scheduleState } = stagingBase(value, "observer", template);
  if (requireScheduleState && scheduleState !== requireScheduleState) throw new Error("unsafe-staging-schedule-state");
  return scheduleState;
}

export function validateStagingLifecycleTransportManifest(value: unknown, template = true): void {
  if (!exact(value, ["version", "environment", "accountId", "requestBucket", "resultBucket", "authorityId", "policyEpoch", "operatorPublicKey"]) ||
      value.version !== 1 || value.environment !== "staging" || value.requestBucket !== stagingBuckets[0].bucket_name ||
      value.resultBucket !== stagingBuckets[1].bucket_name || value.authorityId !== "staging-public-inquiries-v1" ||
      value.policyEpoch !== "phase5c-i1-epoch-1" ||
      (template ? value.accountId !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" || value.operatorPublicKey !== "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__" :
        typeof value.accountId !== "string" || !/^[a-f0-9]{32}$/u.test(value.accountId) || /^0{32}$/u.test(value.accountId) ||
        typeof value.operatorPublicKey !== "string" || value.operatorPublicKey.startsWith("__REQUIRED_"))) throw new Error("unsafe-lifecycle-manifest");
  if (!template) decodeCanonicalBase64url(value.operatorPublicKey as string, 32);
}

export function validateLifecycleEnvironmentGates(value: unknown): void {
  if (!exact(value, ["version", "production", "staging", "lab", "crossEnvironmentKeyReuseAllowed", "crossEnvironmentCredentialReuseAllowed",
    "crossEnvironmentNamespaceReuseAllowed", "publicPersistenceEnabled"]) || value.version !== 1 ||
      value.crossEnvironmentKeyReuseAllowed !== false || value.crossEnvironmentCredentialReuseAllowed !== false ||
      value.crossEnvironmentNamespaceReuseAllowed !== false || value.publicPersistenceEnabled !== false) throw new Error("unsafe-lifecycle-environments");
  const fields = ["requestBucket", "resultBucket", "mailboxWorker", "observerWorker", "guardObject", "executorWorker", "admissionWorker", "authorityObject"];
  const gates = ["requestCredentialScopeLiveVerified", "resultCredentialScopeLiveVerified", "retentionLiveVerified", "provisioningOpen"];
  const retention = ["requestObjectRetentionHours", "resultObjectRetentionDays"];
  if (!exact(value.production, [...fields, ...gates, ...retention]) || !exact(value.staging, [...fields, ...gates, ...retention, "rotationImplemented"]))
    throw new Error("unsafe-lifecycle-environments");
  const production = value.production as Record<string, unknown>;
  const staging = value.staging as Record<string, unknown>;
  const expected = {
    production: ["limitmark-lifecycle-requests-production", "limitmark-lifecycle-results-production", "limitmark-lifecycle-mailbox-production",
      "limitmark-lifecycle-observer-production", "production-lifecycle-dispatch-v1", "limitmark-authority-operator-executor-production",
      "limitmark-admission-service-production", "production-public-inquiries-v1"],
    staging: ["limitmark-lifecycle-requests-staging", "limitmark-lifecycle-results-staging", "limitmark-lifecycle-mailbox-staging",
      "limitmark-lifecycle-observer-staging", "staging-lifecycle-dispatch-v1", "limitmark-authority-operator-executor-staging",
      "limitmark-admission-service-staging", "staging-public-inquiries-v1"],
  };
  for (const [index, field] of fields.entries())
    if (production[field] !== expected.production[index] || staging[field] !== expected.staging[index])
      throw new Error("unsafe-lifecycle-environments");
  if (gates.some((gate) => production[gate] !== false || staging[gate] !== false) || staging.rotationImplemented !== false)
    throw new Error("unsafe-lifecycle-environments");
  if (production.requestObjectRetentionHours !== 24 || staging.requestObjectRetentionHours !== 24 ||
      production.resultObjectRetentionDays !== 30 || staging.resultObjectRetentionDays !== 30)
    throw new Error("unsafe-lifecycle-environments");
  validateLabEnvironmentGate(value.lab);
  // No resource identity may be shared between any two environments (checked on the pinned values, not by pattern).
  const identities = [production, staging, value.lab as Record<string, unknown>].flatMap((section) => fields.map((field) => section[field]));
  if (new Set(identities).size !== identities.length) throw new Error("unsafe-lifecycle-environments");
}

// ---------------------------------------------------------------------------
// Gate 4 staging capability: the staging admission Worker's own deployment
// config (the host of StagingAdmissionAuthority, StagingAuthorityLifecycleOnly
// and StagingAuthorityLifecycleReadOnly). Structurally independent of every
// validator above: the exact top-level key allowlist below has no "routes"
// member at all, so a Production-shaped config (which carries one) is
// rejected before any field is even compared, and every literal value pinned
// here (Worker name, DO class, migration tag, key placeholder) is the
// staging-only identity, never the Production one. Gate 4 deploys this
// Worker and proves its read-only entrypoint; it must never initialize the
// authority (Gate 7) or expose a public route/workers_dev/preview surface.
// ---------------------------------------------------------------------------

const stagingAdmissionServiceKeys = ["$schema", "name", "main", "compatibility_date", "workers_dev", "preview_urls", "durable_objects", "migrations", "vars"];
const stagingAdmissionServiceBinding = { name: "AUTHORITY", class_name: "StagingAdmissionAuthority" };
const stagingAdmissionServiceMigration = { tag: "staging-admission-v1", new_sqlite_classes: ["StagingAdmissionAuthority"] };

/** Validates a rendered/template staging admission-service config. Rejects any
 * key outside the exact allowlist (in particular "routes"/"route"/
 * "custom_domains", any R2/service/queue/workflow/asset/browser/dispatch
 * binding, and Cron triggers, none of which are members of the allowlist),
 * the wrong Worker name/main/compatibility date, any exposure flag other than
 * false, the wrong DO binding/class (including a second binding), the wrong
 * or missing migration/class, a Production or malformed public-key value, and
 * any extra/unknown vars member. */
export function validateStagingAdmissionServiceConfig(value: unknown, template = true): void {
  if (!exact(value, stagingAdmissionServiceKeys)) throw new Error("unsafe-staging-admission-config");
  if (value.$schema !== "../node_modules/wrangler/config-schema.json" ||
      value.name !== "limitmark-admission-service-staging" ||
      value.main !== "../workers/admission-service/index.ts" ||
      value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false)
    throw new Error("unsafe-staging-admission-config");
  if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [stagingAdmissionServiceBinding] }))
    throw new Error("unsafe-staging-admission-binding");
  if (JSON.stringify(value.migrations) !== JSON.stringify([stagingAdmissionServiceMigration]))
    throw new Error("unsafe-staging-admission-migration");
  if (!exact(value.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY"])) throw new Error("unsafe-staging-admission-vars");
  const key = (value.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY;
  if (template ? key !== "__REQUIRED_STAGING_OPERATOR_ED25519_PUBLIC_KEY__" : typeof key !== "string" || key.startsWith("__REQUIRED_"))
    throw new Error("unsafe-staging-admission-key");
  if (!template) decodeCanonicalBase64url(key as string, 32);
}

// ---------------------------------------------------------------------------
// Gate 4B: the local-only live-read-only-proof harness and its verifier
// contract. This Worker is never deployed (see
// wrangler.staging-admission-live-readonly.local.jsonc) and its `main` lives
// outside deployment/ like the other *.local.jsonc harnesses; it holds only a
// single `remote: true` service binding to the already-deployed
// limitmark-admission-service-staging Worker's StagingAuthorityLifecycleReadOnly
// entrypoint, so `wrangler dev` (default mode -- never --remote, never
// --local) proxies only that one call to the live authority while the harness
// itself stays local and unpublished. Structurally independent of every
// validator above: the allowlist has no durable_objects/migrations/vars/
// r2_buckets/triggers/account_id member, so neither a Production nor a
// staging admission config can satisfy it.
// ---------------------------------------------------------------------------

const liveReadonlyHarnessKeys = ["$schema", "name", "main", "compatibility_date", "workers_dev", "preview_urls", "services"];
const liveReadonlyHarnessService = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly", remote: true };

/** Validates the local-only Gate 4B live-read-only-proof harness config.
 * Rejects any key outside the exact allowlist (in particular "routes"/
 * "account_id"/"durable_objects"/"r2_buckets"/"triggers", none of which are
 * members), the wrong Worker name/main/compatibility date, any exposure flag
 * other than false, and any services array other than the exact single
 * remote-bound read-only reader binding. */
export function validateStagingLiveReadonlyHarnessConfig(value: unknown): void {
  if (!exact(value, liveReadonlyHarnessKeys)) throw new Error("unsafe-live-readonly-harness-config");
  if (value.$schema !== "./node_modules/wrangler/config-schema.json" ||
      value.name !== "limitmark-phase5c-staging-admission-live-readonly-harness" ||
      value.main !== "workers/staging-admission-live-readonly-harness.ts" ||
      value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false)
    throw new Error("unsafe-live-readonly-harness-config");
  if (JSON.stringify(value.services) !== JSON.stringify([liveReadonlyHarnessService]))
    throw new Error("unsafe-live-readonly-harness-services");
}

const neverInitializedStagingSnapshotKeys = ["version", "environment", "authorityId", "policyEpoch", "observedAtMs", "initialized", "coverage", "status", "receipt", "releases"];
/** Bound on how stale `observedAtMs` may be relative to the caller's local
 * clock; matches the +/-300000ms freshness window already used for operator
 * command validation elsewhere in this file. */
export const LIVE_READONLY_OBSERVATION_FRESHNESS_MS = 300_000;

/** The exact never-initialized staging shape the Gate 4 live-read-only proof
 * must observe against a freshly deployed, never-initialized authority (see
 * inspectLifecycleAuthority's own never-initialized branches). Rejects any
 * mismatch outright: it never repairs, retries, initializes, resets, deletes
 * or falls back to a broader entrypoint. */
export function validateNeverInitializedStagingLifecycleSnapshot(value: unknown, nowMs: number = Date.now()): void {
  if (!exact(value, neverInitializedStagingSnapshotKeys)) throw new Error("unsafe-live-readonly-snapshot");
  if (value.version !== 1 || value.environment !== "staging" || value.authorityId !== "staging-public-inquiries-v1" ||
      value.policyEpoch !== "phase5c-i1-epoch-1" || value.initialized !== false || value.coverage !== "COMPLETE" ||
      value.status !== "NOT_FOUND" || value.receipt !== null || !Array.isArray(value.releases) || value.releases.length !== 0)
    throw new Error("unsafe-live-readonly-snapshot");
  if (typeof value.observedAtMs !== "number" || !Number.isSafeInteger(value.observedAtMs) || value.observedAtMs < 0 ||
      Math.abs(nowMs - value.observedAtMs) > LIVE_READONLY_OBSERVATION_FRESHNESS_MS)
    throw new Error("unsafe-live-readonly-observation-freshness");
}

// ---------------------------------------------------------------------------
// Laboratory environment (third environment, additive). Structurally independent of the Production and staging validators above:
// every literal is the lab-only identity, there is NO wildcard or pattern acceptance of environment names, and a Production or
// staging config can never satisfy a lab validator (nor the reverse). Lab rotation is not implemented.
// ---------------------------------------------------------------------------

export const LAB_RESOURCES = Object.freeze({
  requestBucket: "limitmark-lifecycle-requests-lab",
  resultBucket: "limitmark-lifecycle-results-lab",
  mailboxWorker: "limitmark-lifecycle-mailbox-lab",
  observerWorker: "limitmark-lifecycle-observer-lab",
  guardObject: "lab-lifecycle-dispatch-v1",
  executorWorker: "limitmark-authority-operator-executor-lab",
  admissionWorker: "limitmark-admission-service-lab",
  authorityObject: "lab-public-inquiries-v1",
  publicHostname: "lab.limitmark.com",
  admissionHostname: "lab-admission.limitmark.com",
});
const labBuckets = [
  { binding: "REQUEST_BUCKET", bucket_name: LAB_RESOURCES.requestBucket },
  { binding: "RESULT_BUCKET", bucket_name: LAB_RESOURCES.resultBucket },
];
const labReader = { binding: "LIFECYCLE_READER", service: LAB_RESOURCES.admissionWorker, entrypoint: "LabAuthorityLifecycleReadOnly" };

function labBase(value: unknown, kind: "mailbox" | "observer", template: boolean): StagingScheduleState {
  const extra = kind === "mailbox" ? ["durable_objects", "migrations", "vars"] : [];
  if (!exact(value, [...common, ...extra])) throw new Error("unsafe-lifecycle-config");
  const scheduleState = stagingScheduleState(value.triggers);
  if (value.$schema !== "../node_modules/wrangler/config-schema.json" ||
      value.name !== (kind === "mailbox" ? LAB_RESOURCES.mailboxWorker : LAB_RESOURCES.observerWorker) || value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false ||
      JSON.stringify(value.r2_buckets) !== JSON.stringify(labBuckets) ||
      value.main !== (template ? `__REQUIRED_RENDERED_LAB_${kind.toUpperCase()}_MAIN__.ts` :
        `../workers/${kind === "mailbox" ? "lifecycle-mailbox/lab-index" : "lab-lifecycle-observer"}.ts`))
    throw new Error("unsafe-lifecycle-config");
  const expectedServices = kind === "mailbox" ? [
    { binding: "LIFECYCLE_EXECUTOR", service: LAB_RESOURCES.executorWorker, entrypoint: "LabOperatorLifecycleExecutor" }, labReader,
  ] : [labReader];
  if (JSON.stringify(value.services) !== JSON.stringify(expectedServices)) throw new Error("unsafe-lifecycle-services");
  if (kind === "mailbox") {
    if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [{ name: "DISPATCH_GUARD", class_name: "LabLifecycleDispatchGuard" }] }) ||
        JSON.stringify(value.migrations) !== JSON.stringify([{ tag: "lab-guard-v1", new_sqlite_classes: ["LabLifecycleDispatchGuard"] }]) ||
        !exact(value.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY", "LIFECYCLE_ENVIRONMENT"]) ||
        value.vars.LIFECYCLE_ENVIRONMENT !== "lab") throw new Error("unsafe-lifecycle-guard");
    const key = value.vars.AUTHORITY_OPERATOR_PUBLIC_KEY;
    if (template ? key !== "__REQUIRED_LAB_OPERATOR_ED25519_PUBLIC_KEY__" : typeof key !== "string" || key.startsWith("__REQUIRED_"))
      throw new Error("unsafe-lifecycle-key");
    if (!template) decodeCanonicalBase64url(key as string, 32);
  }
  if (template ? value.account_id !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" :
      typeof value.account_id !== "string" || !/^[a-f0-9]{32}$/u.test(value.account_id) || /^0{32}$/u.test(value.account_id))
    throw new Error("unsafe-lifecycle-account");
  return scheduleState;
}
/** Lab mailbox/observer validators. Same two reviewed schedule states as staging (initially no active Cron). */
export function validateLabLifecycleMailboxConfig(value: unknown, template = true, requireScheduleState?: StagingScheduleState): StagingScheduleState {
  const state = labBase(value, "mailbox", template);
  if (requireScheduleState && state !== requireScheduleState) throw new Error("unsafe-staging-schedule-state");
  return state;
}
export function validateLabLifecycleObserverConfig(value: unknown, template = true, requireScheduleState?: StagingScheduleState): StagingScheduleState {
  const state = labBase(value, "observer", template);
  if (requireScheduleState && state !== requireScheduleState) throw new Error("unsafe-staging-schedule-state");
  return state;
}

export function validateLabLifecycleTransportManifest(value: unknown, template = true): void {
  if (!exact(value, ["version", "environment", "accountId", "requestBucket", "resultBucket", "authorityId", "policyEpoch", "operatorPublicKey"]) ||
      value.version !== 1 || value.environment !== "lab" || value.requestBucket !== LAB_RESOURCES.requestBucket ||
      value.resultBucket !== LAB_RESOURCES.resultBucket || value.authorityId !== LAB_RESOURCES.authorityObject ||
      value.policyEpoch !== "phase5c-i1-epoch-1" ||
      (template ? value.accountId !== "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__" || value.operatorPublicKey !== "__REQUIRED_LAB_OPERATOR_ED25519_PUBLIC_KEY__" :
        typeof value.accountId !== "string" || !/^[a-f0-9]{32}$/u.test(value.accountId) || /^0{32}$/u.test(value.accountId) ||
        typeof value.operatorPublicKey !== "string" || value.operatorPublicKey.startsWith("__REQUIRED_"))) throw new Error("unsafe-lifecycle-manifest");
  if (!template) decodeCanonicalBase64url(value.operatorPublicKey as string, 32);
}

const labAdmissionServiceKeys = ["$schema", "name", "main", "compatibility_date", "workers_dev", "preview_urls", "routes", "durable_objects", "migrations", "vars"];
const labAdmissionVars = ["ADMISSION_IDENTITY_MODE", "GOOGLE_OIDC_ISSUER", "GOOGLE_OIDC_AUDIENCE", "GOOGLE_SERVICE_ACCOUNT_EMAIL",
  "GOOGLE_SERVICE_ACCOUNT_SUBJECT", "AUTHORITY_OPERATOR_PUBLIC_KEY", "ADMISSION_CURRENT_RELEASE_ID", "ADMISSION_CURRENT_KEY_ID", "ADMISSION_CURRENT_ACTIVATED_AT_MS"];
/** The lab admission Worker: public admission fetch (Google-OIDC lab identity mode) on the single pinned lab admission hostname, plus the
 * lab-only lifecycle entrypoints. Hosts ONLY LabAdmissionAuthority; any Production/staging DO class, route, or hostname is rejected. */
export function validateLabAdmissionServiceConfig(value: unknown, template = true): void {
  if (!exact(value, labAdmissionServiceKeys)) throw new Error("unsafe-lab-admission-config");
  if (value.$schema !== "../node_modules/wrangler/config-schema.json" || value.name !== LAB_RESOURCES.admissionWorker ||
      value.main !== "../workers/admission-service/lab-index.ts" || value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false)
    throw new Error("unsafe-lab-admission-config");
  if (JSON.stringify(value.routes) !== JSON.stringify([{ pattern: LAB_RESOURCES.admissionHostname, custom_domain: true }]))
    throw new Error("unsafe-lab-admission-route");
  if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [{ name: "AUTHORITY", class_name: "LabAdmissionAuthority" }] }))
    throw new Error("unsafe-lab-admission-binding");
  if (JSON.stringify(value.migrations) !== JSON.stringify([{ tag: "lab-admission-v1", new_sqlite_classes: ["LabAdmissionAuthority"] }]))
    throw new Error("unsafe-lab-admission-migration");
  if (!exact(value.vars, labAdmissionVars)) throw new Error("unsafe-lab-admission-vars");
  const vars = value.vars as Record<string, unknown>;
  if (vars.ADMISSION_IDENTITY_MODE !== "google-lab" || vars.GOOGLE_OIDC_ISSUER !== "https://accounts.google.com" ||
      vars.GOOGLE_OIDC_AUDIENCE !== `https://${LAB_RESOURCES.admissionHostname}`) throw new Error("unsafe-lab-admission-vars");
  const key = vars.AUTHORITY_OPERATOR_PUBLIC_KEY;
  if (template ? key !== "__REQUIRED_LAB_OPERATOR_ED25519_PUBLIC_KEY__" : typeof key !== "string" || key.startsWith("__REQUIRED_"))
    throw new Error("unsafe-lab-admission-key");
  if (!template) decodeCanonicalBase64url(key as string, 32);
  if (!template) for (const name of ["GOOGLE_SERVICE_ACCOUNT_EMAIL", "GOOGLE_SERVICE_ACCOUNT_SUBJECT", "ADMISSION_CURRENT_RELEASE_ID",
    "ADMISSION_CURRENT_KEY_ID", "ADMISSION_CURRENT_ACTIVATED_AT_MS"])
    if (typeof vars[name] !== "string" || (vars[name] as string).startsWith("__REQUIRED_") || vars[name] === "") throw new Error("unsafe-lab-admission-vars");
}

/** Lab section of deployment/lifecycle-environment-gates.json. Pinned allowlist; provisioning stays closed until the project owner opens the lab gates. */
export function validateLabEnvironmentGate(value: unknown): void {
  const labFields = ["requestBucket", "resultBucket", "mailboxWorker", "observerWorker", "guardObject", "executorWorker", "admissionWorker", "authorityObject",
    "publicHostname", "admissionHostname", "requestObjectRetentionHours", "resultObjectRetentionDays", "retentionLiveVerified", "rotationImplemented",
    "requestCredentialScopeLiveVerified", "resultCredentialScopeLiveVerified", "provisioningOpen", "isolatedFromProduction", "productionProvisioningImplied"];
  if (!exact(value, labFields)) throw new Error("unsafe-lifecycle-environments");
  const lab = value as Record<string, unknown>;
  for (const field of ["requestBucket", "resultBucket", "mailboxWorker", "observerWorker", "guardObject", "executorWorker", "admissionWorker", "authorityObject",
    "publicHostname", "admissionHostname"] as const)
    if (lab[field] !== LAB_RESOURCES[field]) throw new Error("unsafe-lifecycle-environments");
  if (lab.requestObjectRetentionHours !== 24 || lab.resultObjectRetentionDays !== 30 || lab.retentionLiveVerified !== false ||
      lab.rotationImplemented !== false || lab.requestCredentialScopeLiveVerified !== false || lab.resultCredentialScopeLiveVerified !== false ||
      lab.provisioningOpen !== false || lab.isolatedFromProduction !== true || lab.productionProvisioningImplied !== false)
    throw new Error("unsafe-lifecycle-environments");
}

/**
 * Recovery-evidence posture (Gate 11A preparation; local validation only, deploys nothing): the OBSERVER is armed so it can relay signed
 * reconciliations, while the MAILBOX stays INACTIVE (no cron) and therefore can never dispatch an initialization or rotation. Both configs are
 * validated by the exact same production validators (exact key set, bindings, services, R2 buckets, rendered main) -- so the observer provably has
 * NO executor service binding, NO Durable Object binding and NO vars -- and must belong to the same Cloudflare account. The caller passes the two
 * configs explicitly; nothing is inferred from file names or ambient state.
 */
export function validateRecoveryEvidencePosture(observer: unknown, mailbox: unknown, template = false): { observer: ProductionScheduleState; mailbox: ProductionScheduleState } {
  const observerState = validateLifecycleObserverConfig(observer, template, "PRODUCTION_SCHEDULE_ARMED");
  const mailboxState = validateLifecycleMailboxConfig(mailbox, template, "PRODUCTION_DEPLOYMENT_INACTIVE");
  if (!template && (observer as { account_id: unknown }).account_id !== (mailbox as { account_id: unknown }).account_id) throw new Error("recovery-posture-account-mismatch");
  return { observer: observerState, mailbox: mailboxState };
}
