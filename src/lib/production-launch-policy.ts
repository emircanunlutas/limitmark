import { isIP } from "node:net";
import postgres from "postgres";
import { getDatabaseClientOptions } from "./db/database.server";

// Local, offline production launch policy. Nothing here contacts a database, a provider or the network: it only decides, from configuration and the
// installed postgres.js driver's own option parser, whether a production runtime may be assembled. It never relaxes any other gate.

export type ProductionLaunchRefusal =
  | "database-url" | "database-socket" | "database-host-literal" | "database-tls-not-verified" | "database-tls-parameter" | "database-tls-environment" | "telemetry-enabled";
export type ProductionLaunchAssessment = { ok: true } | { ok: false; refusal: ProductionLaunchRefusal };

type Environment = Readonly<Record<string, string | undefined>>;
const present = (value: string | undefined): value is string => value !== undefined && value !== "";

/**
 * Production PostgreSQL transport security. The effective mode is NOT read from the connection string: it is what the installed driver computes
 * (`postgres(url).options.ssl`) from the URL AND its environment defaults (PGSSL). Only the driver's `verify-full` mode is accepted, because in
 * postgres.js 3.4.9 it is the mode that reaches `tls.connect` with certificate-chain verification and hostname verification (servername = host)
 * and without the `rejectUnauthorized = false` that `require`/`prefer`/`allow` set. Anything else (no sslmode = plaintext, disable, require, prefer,
 * allow, verify-ca, an object) is refused, and so is any setting that weakens or reshapes verification outside the driver's reviewed modes.
 */
export function assessProductionDatabaseTls(databaseUrl: string, environments: readonly Environment[]): ProductionLaunchAssessment {
  if (environments.some((environment) => environment.NODE_TLS_REJECT_UNAUTHORIZED === "0")) return { ok: false, refusal: "database-tls-environment" };
  let url: URL;
  try { url = new URL(databaseUrl); } catch { return { ok: false, refusal: "database-url" }; }
  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") return { ok: false, refusal: "database-url" };
  // These are forwarded by postgres.js as server startup parameters (unknown keys) or are silently ignored; neither provides a verified custom CA.
  for (const key of ["sslcert", "sslkey", "sslpassword", "sslcrl", "sslcrldir", "sslsni", "ssl_min_protocol_version", "sslcompression"]) {
    if (url.searchParams.has(key)) return { ok: false, refusal: "database-tls-parameter" };
  }
  const rootCert = url.searchParams.get("sslrootcert");
  if (rootCert !== null && rootCert !== "system") return { ok: false, refusal: "database-tls-parameter" };
  if (url.hostname === "" || url.hostname.includes("/") || url.searchParams.has("host") || url.searchParams.has("hostaddr")) return { ok: false, refusal: "database-socket" };
  let effective: unknown;
  let hosts: unknown;
  let path: unknown;
  const sql = (() => { try { return postgres(databaseUrl, getDatabaseClientOptions(1)); } catch { return null; } })();
  if (!sql) return { ok: false, refusal: "database-url" };
  try {
    const options = sql.options as unknown as { ssl: unknown; host: unknown; path: unknown };
    effective = options.ssl; hosts = options.host; path = options.path;
  } finally { void sql.end({ timeout: 0 }); }
  if (path) return { ok: false, refusal: "database-socket" };
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.some((host) => typeof host !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/u.test(host))) return { ok: false, refusal: "database-socket" };
  // postgres.js passes NO servername to tls.connect for an IP-literal host, so Node then checks the certificate against "localhost", not the IP
  // (demonstrated in tests/production-launch-policy.test.ts). Hostname verification is only meaningful for a DNS name.
  if (hosts.some((host) => typeof host === "string" && isIP(host) !== 0)) return { ok: false, refusal: "database-host-literal" };
  if (effective !== "verify-full") return { ok: false, refusal: "database-tls-not-verified" };
  return { ok: true };
}

/** Production launches with OpenTelemetry metrics OFF. Any value other than absent/empty/"false" for the flag, and any endpoint/service override, refuses. */
export function assessProductionTelemetry(environment: Environment): ProductionLaunchAssessment {
  const flag = environment.PUBLIC_INQUIRY_OTEL_METRICS;
  if (present(flag) && flag !== "false") return { ok: false, refusal: "telemetry-enabled" };
  if (Object.keys(environment).some((key) => key.startsWith("PUBLIC_INQUIRY_OTEL_") && key !== "PUBLIC_INQUIRY_OTEL_METRICS" && present(environment[key]))) return { ok: false, refusal: "telemetry-enabled" };
  return { ok: true };
}
