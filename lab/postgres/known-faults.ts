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
