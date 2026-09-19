import { decodeCanonicalBase64url } from "../src/lib/ingress-protocol";

export const EXECUTOR_NAME = "limitmark-authority-operator-executor-production";
export const ADMISSION_SERVICE_NAME = "limitmark-admission-service-production";
export const EXECUTOR_MAIN = "../workers/operator-lifecycle-executor.ts";
export const EXECUTOR_TEMPLATE_MAIN = "__REQUIRED_RENDERED_EXECUTOR_MAIN__.ts";
export const EXECUTOR_TEMPLATE_ACCOUNT = "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__";
export const EXECUTOR_TEMPLATE_NAME = "__REQUIRED_REVIEWED_EXECUTOR_WORKER_NAME__";
export const EXECUTOR_TEMPLATE_SERVICE = "__REQUIRED_REVIEWED_ADMISSION_SERVICE_NAME__";
export const EXECUTOR_TEMPLATE_KEY = "__REQUIRED_OPERATOR_ED25519_PUBLIC_KEY__";
export const EXECUTOR_TEMPLATE_ENV = "__REQUIRED_PRODUCTION_ENVIRONMENT__";

const topLevel = ["$schema", "name", "main", "account_id", "compatibility_date", "workers_dev", "preview_urls", "services", "vars"];
const schemaPath = "../node_modules/wrangler/config-schema.json";

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function base(config: unknown): asserts config is Record<string, unknown> {
  if (!exactKeys(config, topLevel) || config.$schema !== schemaPath || config.compatibility_date !== "2026-09-13" ||
      config.workers_dev !== false || config.preview_urls !== false ||
      !Array.isArray(config.services) || config.services.length !== 1 ||
      !exactKeys(config.services[0], ["binding", "service"]) || config.services[0].binding !== "ADMISSION_SERVICE" ||
      !exactKeys(config.vars, ["AUTHORITY_OPERATOR_PUBLIC_KEY", "OPERATOR_EXECUTOR_ENVIRONMENT"])) {
    throw new Error("unsafe-private-operator-executor");
  }
}

/** The only raw-template shape. It is not deployable because `main` does not exist. */
export function validateOperatorExecutorTemplate(config: unknown): void {
  base(config);
  if (config.name !== EXECUTOR_TEMPLATE_NAME || config.main !== EXECUTOR_TEMPLATE_MAIN ||
      config.account_id !== EXECUTOR_TEMPLATE_ACCOUNT ||
      (config.services as Array<Record<string, unknown>>)[0].service !== EXECUTOR_TEMPLATE_SERVICE ||
      (config.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY !== EXECUTOR_TEMPLATE_KEY ||
      (config.vars as Record<string, unknown>).OPERATOR_EXECUTOR_ENVIRONMENT !== EXECUTOR_TEMPLATE_ENV) {
    throw new Error("unsafe-private-operator-executor-template");
  }
}

/** Mandatory local preflight for a rendered, reviewed executor config. */
export function validateRenderedOperatorExecutorConfig(config: unknown): void {
  base(config);
  const account = config.account_id;
  const key = (config.vars as Record<string, unknown>).AUTHORITY_OPERATOR_PUBLIC_KEY;
  if (config.name !== EXECUTOR_NAME || config.main !== EXECUTOR_MAIN ||
      typeof account !== "string" || !/^[a-f0-9]{32}$/u.test(account) || /^0{32}$/u.test(account) ||
      (config.services as Array<Record<string, unknown>>)[0].service !== ADMISSION_SERVICE_NAME ||
      (config.vars as Record<string, unknown>).OPERATOR_EXECUTOR_ENVIRONMENT !== "production" ||
      typeof key !== "string" || key.startsWith("__REQUIRED_")) throw new Error("incomplete-private-operator-executor");
  try { decodeCanonicalBase64url(key, 32); }
  catch { throw new Error("invalid-operator-public-key"); }
}
