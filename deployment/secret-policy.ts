import matrix from "./secret-matrix.json";

export type RuntimeName = keyof typeof matrix.runtimes;
type Environment = Record<string, unknown>;

type JsonObject = Record<string, unknown>;
const object = (value: unknown): JsonObject | null => value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;

export function validateRuntimeSecrets(runtime: RuntimeName, environment: Environment, requireAll = true): boolean {
  const policy = matrix.runtimes[runtime];
  if (policy.unconsumedPlatformSecrets.some((name) => policy.requiredSecrets.includes(name as never) || policy.forbiddenSecrets.includes(name as never))) return false;
  if ([...policy.forbiddenSecrets, ...policy.forbiddenPublicKeys, ...policy.forbiddenBindings]
    .some((name) => environment[name] !== undefined && environment[name] !== "")) return false;
  if (requireAll && [...policy.requiredSecrets, ...policy.requiredPublicKeys, ...policy.requiredBindings]
    .some((name) => environment[name] === undefined || environment[name] === "")) return false;
  const values = matrix.collisionSensitive.map((name) => environment[name]).filter((value): value is string => typeof value === "string" && value !== "");
  return new Set(values).size === values.length;
}

export function validateVercelProjectContract(value: unknown): boolean {
  const contract = object(value);
  const production = object(contract?.productionApplicationProject);
  const preview = object(contract?.previewApplicationProject);
  const admission = object(contract?.admissionService);
  const shared = object(contract?.sharedRequirements);
  const targets = object(production?.gatewayTargets);
  const publicTarget = object(targets?.publicSigner);
  const adminTarget = object(targets?.adminGateway);
  const bypass = object(production?.bypassCredentials);
  const publicBypass = object(bypass?.public);
  const adminBypass = object(bypass?.admin);
  const pId = production?.expectedProjectId;
  const qId = preview?.expectedProjectId;
  const previewForbidden = preview?.forbiddenProductionConfiguration;
  const bypassDoesNotSatisfy = production?.bypassDoesNotSatisfy;
  if (!production || !preview || !admission || !shared || !publicTarget || !adminTarget || !publicBypass || !adminBypass) return false;
  if (production.projectRef !== "P" || preview.projectRef !== "Q" || preview.mustDifferFromProjectRef !== "P" || pId === qId ||
      typeof pId !== "string" || !pId || typeof qId !== "string" || !qId) return false;
  if (production.systemEnvironmentVariableAccess !== "enabled" || production.deploymentProtectionScope !== "all-deployments" ||
      JSON.stringify(production.productionBoundary) !== JSON.stringify({ VERCEL: "1", VERCEL_ENV: "production" }) ||
      JSON.stringify(production.applicationRoutes) !== JSON.stringify(["public", "admin"])) return false;
  if (publicTarget.projectRef !== "P" || adminTarget.projectRef !== "P" || typeof adminTarget.target !== "string" || !adminTarget.target) return false;
  if (publicBypass.contractId !== "B-public" || adminBypass.contractId !== "B-admin" ||
      publicBypass.authorityScope !== "project-wide-deployment-protection-bypass" || adminBypass.authorityScope !== "project-wide-deployment-protection-bypass" ||
      publicBypass.applicationAuthorization !== false || adminBypass.applicationAuthorization !== false || publicBypass.routeScoped !== false || adminBypass.routeScoped !== false ||
      publicBypass.independentlyRevocable !== true || adminBypass.independentlyRevocable !== true ||
      publicBypass.selectedForSystemEnvironmentExposure !== true || adminBypass.selectedForSystemEnvironmentExposure !== false ||
      adminBypass.ordinaryApplicationEnvironmentConfiguration !== "forbidden" || adminBypass.applicationRequestTimeObservation !== "possible") return false;
  if (!Array.isArray(bypassDoesNotSatisfy) || !["signed-ingress", "origin-bearer", "admission-oidc-mac", "turnstile", "persistence-authorization", "access-jwt", "require-admin"]
    .every((gate) => bypassDoesNotSatisfy.includes(gate))) return false;
  if (!Array.isArray(previewForbidden) || !["DATABASE_URL", "ADMISSION_RELEASE_RPC_KEY", "VERCEL_AUTOMATION_BYPASS_SECRET",
    "VERCEL_ADMIN_AUTOMATION_BYPASS_SECRET", "INGRESS_SIGNING_PRIVATE_KEY", "INGRESS_IDENTITY_HMAC_KEY", "PUBLIC_ORIGIN_SECRET",
    "TURNSTILE_SECRET_KEY", "RESEND_API_KEY", "AUTHORITY_OPERATOR_PRIVATE_KEY", "AUTHORITY"].every((name) => previewForbidden.includes(name))) return false;
  if (admission.hosting !== "cloudflare-worker-custom-domain" || admission.vercelProjectRef !== null || admission.authorityBindingPlacement !== "admission-service-only") return false;
  return shared.productionAndPreviewProjectIdsMustDiffer === true && shared.publicAndAdminBypassCredentialsMustDiffer === true &&
    shared.staticChecksAreRuntimeSecrecyProof === false && shared.realSettingsChangeAuthorized === false;
}
