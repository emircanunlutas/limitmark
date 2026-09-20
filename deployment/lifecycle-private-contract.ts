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
const stagingBuckets = [
  { binding: "REQUEST_BUCKET", bucket_name: "limitmark-lifecycle-requests-staging" },
  { binding: "RESULT_BUCKET", bucket_name: "limitmark-lifecycle-results-staging" },
];
const stagingReader = { binding: "LIFECYCLE_READER", service: "limitmark-admission-service-staging", entrypoint: "StagingAuthorityLifecycleReadOnly" };
function base(value: unknown, kind: "mailbox" | "observer", template: boolean): Record<string, unknown> {
  const extra = kind === "mailbox" ? ["durable_objects", "migrations", "vars"] : [];
  if (!exact(value, [...common, ...extra]) || value.$schema !== "../node_modules/wrangler/config-schema.json" ||
      value.name !== `limitmark-lifecycle-${kind}-production` || value.compatibility_date !== "2026-09-13" ||
      value.workers_dev !== false || value.preview_urls !== false ||
      JSON.stringify(value.triggers) !== JSON.stringify({ crons: ["* * * * *"] }) ||
      JSON.stringify(value.r2_buckets) !== JSON.stringify(buckets) ||
      value.main !== (template ? `__REQUIRED_RENDERED_${kind.toUpperCase()}_MAIN__.ts` : `../workers/${kind === "mailbox" ? "lifecycle-mailbox/index" : "lifecycle-observer"}.ts`))
    throw new Error("unsafe-lifecycle-config");
  const expectedServices = kind === "mailbox" ? [
    { binding: "LIFECYCLE_EXECUTOR", service: "limitmark-authority-operator-executor-production", entrypoint: "OperatorLifecycleExecutor" }, reader,
  ] : [reader];
  if (JSON.stringify(value.services) !== JSON.stringify(expectedServices)) throw new Error("unsafe-lifecycle-services");
  if (kind === "mailbox") {
    if (JSON.stringify(value.durable_objects) !== JSON.stringify({ bindings: [{ name: "DISPATCH_GUARD", class_name: "LifecycleDispatchGuard" }] }) ||
        JSON.stringify(value.migrations) !== JSON.stringify([{ tag: "i3b-guard-v1", new_sqlite_classes: ["LifecycleDispatchGuard"] }]) ||
        !exact(value.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY", "LIFECYCLE_ENVIRONMENT"]) ||
        value.vars.LIFECYCLE_ENVIRONMENT !== "production") throw new Error("unsafe-lifecycle-guard");
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
export function validateLifecycleMailboxConfig(value: unknown, template = true): void { base(value, "mailbox", template); }
export function validateLifecycleObserverConfig(value: unknown, template = true): void { base(value, "observer", template); }

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
  if (!exact(value, ["version", "production", "staging", "crossEnvironmentKeyReuseAllowed", "crossEnvironmentCredentialReuseAllowed",
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
}
