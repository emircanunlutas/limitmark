/**
 * Pure verdicts over the output of parity steps. Kept free of Docker and the filesystem so the false-green cases
 * (missing counts, skips, a known library fault hiding behind exit code 0) are unit-tested.
 */

export type NodeTestCounts = { tests: number; pass: number; fail: number; skipped: number; cancelled: number };

/** Reviewed counts. A different number is a failed step so that a silently missing or newly skipped test is noticed. */
export const EXPECTED_DB_TESTS = 34;
/** `npm test` skips exactly the TEST_DATABASE_URL-gated tests (they run in the DB steps, and only there). */
export const EXPECTED_NPM_TEST_SKIPPED = EXPECTED_DB_TESTS;

const KNOWN_FAULT = /Cannot read properties of null \(reading 'write'\)/;

/** Parses node:test summary lines (`ℹ tests 34` for the spec reporter, `# tests 34` for TAP). Returns undefined if any count is absent. */
export function nodeTestCounts(output: string): NodeTestCounts | undefined {
  const read = (label: string) => {
    const match = new RegExp(`^(?:ℹ|#) ${label} (\\d+)\\s*$`, "m").exec(output);
    return match ? Number(match[1]) : NaN;
  };
  const counts = { tests: read("tests"), pass: read("pass"), fail: read("fail"), skipped: read("skipped"), cancelled: read("cancelled") };
  return Object.values(counts).some(Number.isNaN) ? undefined : counts;
}

export function evaluateDbRun(output: string, exitCode: number): { counts: NodeTestCounts | undefined; failure?: string } {
  const counts = nodeTestCounts(output);
  if (exitCode !== 0) return { counts, failure: `exit code ${exitCode}` };
  if (!counts) return { counts, failure: "no test summary in the output (the suites may not have run)" };
  if (KNOWN_FAULT.test(output)) return { counts, failure: "known postgres.js defect observed in the output (a finding; never a pass)" };
  if (counts.tests !== EXPECTED_DB_TESTS || counts.pass !== EXPECTED_DB_TESTS || counts.fail !== 0 || counts.cancelled !== 0 || counts.skipped !== 0) {
    return { counts, failure: `expected exactly ${EXPECTED_DB_TESTS} passing tests and no skips` };
  }
  return { counts };
}

export function evaluateNpmTestRun(output: string, exitCode: number): { counts: NodeTestCounts | undefined; failure?: string } {
  const counts = nodeTestCounts(output);
  if (exitCode !== 0) return { counts, failure: `exit code ${exitCode}` };
  if (!counts) return { counts, failure: "no test summary in the output (the tests may not have run)" };
  if (KNOWN_FAULT.test(output)) return { counts, failure: "known postgres.js defect observed in the output (a finding; never a pass)" };
  if (counts.tests < 1 || counts.fail !== 0 || counts.cancelled !== 0) return { counts, failure: "failed or cancelled tests, or none ran" };
  if (counts.skipped !== EXPECTED_NPM_TEST_SKIPPED) return { counts, failure: `${counts.skipped} tests were skipped; exactly the ${EXPECTED_NPM_TEST_SKIPPED} database-gated tests may be` };
  return { counts };
}
