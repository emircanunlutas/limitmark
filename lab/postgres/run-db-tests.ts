/**
 * Runs the TEST_DATABASE_URL-gated suites against a freshly created disposable lab database
 * (PostgreSQL 16 and/or 17), always tears the lab down, and writes an evidence manifest.
 *
 *   tsx --conditions=react-server lab/postgres/run-db-tests.ts 16|17|both
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { evidenceSafeError } from "../evidence/redact";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState } from "../evidence/manifest";
import { EXPECTED_DB_TESTS } from "../linux/results";
import { assertVersion, labDbDown, labDbUp, teardownOnCrash, testEnvironment, type PgVersion } from "./lab-db";

/** Reviewed count of TEST_DATABASE_URL-gated tests; a different count is reported as FAIL so it is noticed. */
export { EXPECTED_DB_TESTS };
const SUITES = [
  "tests/persistence.integration.test.ts",
  "tests/notification-outbox.integration.test.ts",
  "tests/admin-inquiry-repository.integration.test.ts",
  "tests/admin-inquiry-mutations.integration.test.ts",
];

type Summary = { tests: number; pass: number; fail: number; skipped: number; cancelled: number; exitCode: number };

function runSuites(environment: Record<string, string>): Promise<Summary> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      path.join(REPOSITORY_ROOT, "node_modules", "tsx", "dist", "cli.mjs"),
      "--conditions=react-server", "--test", "--test-concurrency=1", "--test-reporter=spec", ...SUITES,
    ], { cwd: REPOSITORY_ROOT, env: { ...process.env, ...environment }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let output = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    child.on("error", reject);
    child.on("close", (code) => {
      const read = (label: string) => Number(new RegExp(`^ℹ ${label} (\\d+)`, "m").exec(output)?.[1] ?? NaN);
      process.stdout.write(output.split("\n").filter((line) => /^(ℹ|✖|✔ )/.test(line) || line.includes("ℹ")).slice(-40).join("\n") + "\n");
      resolve({ tests: read("tests"), pass: read("pass"), fail: read("fail"), skipped: read("skipped"), cancelled: read("cancelled"), exitCode: code ?? 1 });
    });
  });
}

async function runVersion(version: PgVersion): Promise<{ summary: Summary; serverVersion: string }> {
  const state = await labDbUp(version);
  try {
    return { summary: await runSuites(testEnvironment(state)), serverVersion: state.serverVersion };
  } finally {
    await labDbDown(version);
  }
}

async function main(): Promise<void> {
  const arg = process.argv[2];
  const versions: PgVersion[] = arg === "both" ? ["16", "17"] : [assertVersion(arg)];
  teardownOnCrash(versions);
  let failed = false;
  for (const version of versions) {
    const evidence = new EvidenceRun("db-integration", `db-tests-pg${version}`);
    const startedAt = new Date();
    let result: "PASS" | "FAIL" | "ERROR" = "ERROR";
    const reasons: string[] = [];
    let metrics: Record<string, unknown> = {};
    let serverVersion: string | null = null;
    try {
      const outcome = await runVersion(version);
      serverVersion = outcome.serverVersion;
      const { summary } = outcome;
      metrics = { ...summary, expectedTests: EXPECTED_DB_TESTS };
      if (summary.exitCode !== 0) reasons.push(`test process exit code ${summary.exitCode}`);
      if (summary.fail !== 0 || summary.cancelled !== 0) reasons.push(`${summary.fail} failed, ${summary.cancelled} cancelled`);
      if (summary.skipped !== 0) reasons.push(`${summary.skipped} skipped (the lab must run every DB test)`);
      if (summary.tests !== EXPECTED_DB_TESTS) reasons.push(`ran ${summary.tests} tests, reviewed count is ${EXPECTED_DB_TESTS}`);
      result = reasons.length === 0 ? "PASS" : "FAIL";
    } catch (error) {
      reasons.push(evidenceSafeError(error));
    }
    evidence.addJsonArtifact("suites.json", { suites: SUITES });
    evidence.finalize({
      git: collectGitState(), environment: collectEnvironment(serverVersion), target: { id: `postgres-lab-${version}`, class: "lab-local" },
      workload: { id: "db-integration-suites", phases: [] }, ceilings: { expectedTests: EXPECTED_DB_TESTS },
      thresholds: null, engine: "node-test", endedAt: new Date(), result, resultReasons: reasons, metrics,
    });
    console.log(`PostgreSQL ${version}: ${result}${reasons.length ? ` (${reasons.join("; ")})` : ""} [started ${startedAt.toISOString()}] evidence=${evidence.id}`);
    failed ||= result !== "PASS";
  }
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : error); process.exit(1); });
}
