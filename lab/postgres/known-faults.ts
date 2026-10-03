/**
 * Library fault observed while the lab deliberately kills database backends:
 * postgres.js 3.4.9 can throw `TypeError: Cannot read properties of null (reading 'write')`
 * from a setImmediate callback (connection.js nextWrite) after the socket was destroyed.
 * Because it is thrown outside any promise it is an UNCAUGHT exception: in a real Node
 * process that is fatal. The lab tolerates it only in tools that kill backends on purpose,
 * counts every occurrence and reports it as a finding (never as a pass).
 */
export const libraryFaults = { postgresJsNullSocketWrite: 0 };

export function isPostgresJsNullSocketWrite(reason: unknown): boolean {
  return reason instanceof TypeError &&
    /Cannot read properties of null \(reading 'write'\)/.test(reason.message) &&
    (reason.stack ?? "").replaceAll("\\", "/").includes("node_modules/postgres/cjs/src/connection.js");
}

/**
 * The known postgres.js defect (see above) is a FINDING, never a pass. Any run that observed it ends FAIL, whatever else
 * succeeded; a result that is already worse (STOP/ERROR/REFUSED) is kept. The reasons carry the count.
 */
export function applyKnownFaultVerdict<R extends string>(result: R, reasons: string[], faults: { postgresJsNullSocketWrite: number }): { result: R | "FAIL" } {
  if (faults.postgresJsNullSocketWrite === 0) return { result };
  reasons.push(`known postgres.js defect observed ${faults.postgresJsNullSocketWrite} time(s): an uncaught null-socket write TypeError after a backend was terminated (a finding; never a pass)`);
  return { result: result === "PASS" ? "FAIL" : result };
}
