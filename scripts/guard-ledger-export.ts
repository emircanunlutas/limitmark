import { readFileSync, statSync } from "node:fs";
import {
  GUARD_LEDGER_MAX_FILE_BYTES, GuardExportRefusal, exportGuardLedger, serializeGuardLedgerExport, sqliteGuardLedgerSource, verifyGuardLedgerExport,
} from "../operator/guard-ledger-export";

// Read-only guard ledger export / verification. LOCAL FILES ONLY: no provider contact, no Wrangler, no network, no file written (the result goes to
// stdout; redirect it yourself). Never claims, settles, initializes or replaces anything.
//   export  --environment <production|staging|lab> --guard-object <name> --sqlite <file>
//   verify  --environment <production|staging|lab> --guard-object <name> --file <export.json>

function options(args: string[], allowed: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith("--") || !allowed.includes(key.slice(2)) || value === undefined || value.startsWith("--") || key.slice(2) in result) throw new GuardExportRefusal("arguments");
    result[key.slice(2)] = value;
  }
  if (allowed.some((name) => !(name in result))) throw new GuardExportRefusal("arguments");
  return result;
}

function main(): void {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "export") {
    const given = options(rest, ["environment", "guard-object", "sqlite"]);
    process.stdout.write(serializeGuardLedgerExport(exportGuardLedger(sqliteGuardLedgerSource(given.sqlite), { environment: given.environment, guardObject: given["guard-object"] })));
    return;
  }
  if (command === "verify") {
    const given = options(rest, ["environment", "guard-object", "file"]);
    const stat = statSync(given.file);
    if (!stat.isFile() || stat.size < 1 || stat.size > GUARD_LEDGER_MAX_FILE_BYTES) throw new GuardExportRefusal("export-size");
    const verified = verifyGuardLedgerExport(readFileSync(given.file, "utf8"), { environment: given.environment, guardObject: given["guard-object"] });
    process.stdout.write(`VERIFIED ${verified.contentSha256}\n`);
    return;
  }
  throw new GuardExportRefusal("arguments");
}

try { main(); }
catch (error) {
  process.stderr.write(`Guard ledger export: REFUSED (${error instanceof GuardExportRefusal ? error.code : "unreadable"}). Nothing was changed.\n`);
  process.exitCode = 2;
}
