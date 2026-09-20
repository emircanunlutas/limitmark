import { readFile } from "node:fs/promises";
import path from "node:path";
import { validateVercelProjectContract } from "../deployment/secret-policy";
import { validateOperatorExecutorTemplate, validateStagingOperatorExecutorTemplate } from "../deployment/operator-executor-contract";
import {
  validateLifecycleEnvironmentGates, validateLifecycleMailboxConfig, validateLifecycleObserverConfig, validateLifecycleTransportManifest,
  validateStagingLifecycleMailboxConfig, validateStagingLifecycleObserverConfig, validateStagingLifecycleTransportManifest,
} from "../deployment/lifecycle-private-contract";

async function main() {
  const root = process.cwd();
  const files = ["public-signer.template.jsonc", "admin-gateway.template.jsonc", "admission-service.template.jsonc"];
  const configs = await Promise.all(files.map(async (file) => JSON.parse(await readFile(path.join(root, "deployment", file), "utf8")) as Record<string, unknown>));
  for (const config of configs) {
    if (config.workers_dev !== false || config.preview_urls !== false || config.compatibility_date !== "2026-09-13") throw new Error("unsafe-worker-entrypoint");
    if (typeof config.name !== "string" || !config.name.endsWith("-production")) throw new Error("worker-name");
    if (!JSON.stringify(config).includes("__REQUIRED_")) throw new Error("template-must-remain-blocked");
  }
  const [signer, gateway, admission] = configs;
  const executor = JSON.parse(await readFile(path.join(root, "deployment", "operator-lifecycle-executor.template.jsonc"), "utf8")) as Record<string, unknown>;
  validateOperatorExecutorTemplate(executor);
  const [mailbox, observer, transport] = await Promise.all([
    "lifecycle-mailbox.template.jsonc", "lifecycle-observer.template.jsonc", "lifecycle-transport.production.template.json",
  ].map(async (file) => JSON.parse(await readFile(path.join(root, "deployment", file), "utf8"))));
  validateLifecycleMailboxConfig(mailbox);
  validateLifecycleObserverConfig(observer);
  validateLifecycleTransportManifest(transport);
  validateLifecycleEnvironmentGates(JSON.parse(await readFile(path.join(root, "deployment", "lifecycle-environment-gates.json"), "utf8")));
  // Gate 2 staging capability: the initial rendered staging templates must be
  // schedule-inactive (no active Cron trigger can process lifecycle objects
  // before bindings/IAM/route inspection).
  const stagingExecutor = JSON.parse(await readFile(path.join(root, "deployment", "operator-lifecycle-executor.staging.template.jsonc"), "utf8")) as Record<string, unknown>;
  validateStagingOperatorExecutorTemplate(stagingExecutor);
  const [stagingMailbox, stagingObserver, stagingTransport] = await Promise.all([
    "lifecycle-mailbox.staging.template.jsonc", "lifecycle-observer.staging.template.jsonc", "lifecycle-transport.staging.template.json",
  ].map(async (file) => JSON.parse(await readFile(path.join(root, "deployment", file), "utf8"))));
  const mailboxScheduleState = validateStagingLifecycleMailboxConfig(stagingMailbox, true, "STAGING_DEPLOYMENT_INACTIVE");
  const observerScheduleState = validateStagingLifecycleObserverConfig(stagingObserver, true, "STAGING_DEPLOYMENT_INACTIVE");
  validateStagingLifecycleTransportManifest(stagingTransport);
  if (mailboxScheduleState !== "STAGING_DEPLOYMENT_INACTIVE" || observerScheduleState !== "STAGING_DEPLOYMENT_INACTIVE")
    throw new Error("staging-schedule-must-render-inactive");
  const patterns = configs.flatMap((config) => (config.routes as Array<{ pattern: string }>).map((route) => route.pattern));
  if (new Set(patterns).size !== patterns.length) throw new Error("overlapping-worker-routes");
  if (signer.durable_objects !== undefined || gateway.durable_objects !== undefined ||
      JSON.stringify((admission.durable_objects as { bindings?: unknown[] }).bindings) !== JSON.stringify([{ name: "AUTHORITY", class_name: "ProductionAdmissionAuthority" }]))
    throw new Error("authority-binding-placement");
  const projectContract = JSON.parse(await readFile(path.join(root, "deployment", "vercel-project-contract.json"), "utf8")) as Record<string, unknown>;
  if (!validateVercelProjectContract(projectContract)) throw new Error("vercel-project-contract");
  const production = projectContract.productionApplicationProject as Record<string, unknown>;
  const target = ((production.gatewayTargets as Record<string, Record<string, unknown>>).adminGateway).target;
  if ((gateway.vars as Record<string, unknown>).VERCEL_ADMIN_UPSTREAM_ORIGIN !== target) throw new Error("admin-upstream-not-shared-production-project");
  if (process.argv.includes("--production")) throw new Error("Production validation refuses unresolved template placeholders; render an independently reviewed config first");
  process.stdout.write("Worker deployment templates retain unresolved values; the private executor requires separate rendered preflight.\n");
}
main().catch((error: unknown) => { process.stderr.write(`${error instanceof Error ? error.message : "worker-contract-validation"}\n`); process.exitCode = 1; });
