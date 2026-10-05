import { spawnSync } from "node:child_process";
import { chmod, mkdir } from "node:fs/promises";
import { join } from "node:path";

// R06 activation tests: create a key directory protected the way an operator must protect %USERPROFILE%/.limitmark-keys/staging, because
// the custody tooling now VERIFIES protection instead of assuming it (operator/staging-key-protection.ts). A fresh directory under %TEMP%
// inherits whatever ACL the machine gives it (on a CI or sandbox host that can include extra groups), which the check correctly refuses.
//
//   Windows: break inheritance and grant full control to SYSTEM, Administrators and the current user ONLY, by SID (language-independent).
//   POSIX:   chmod 0700.
//
// This is test scaffolding and the same procedure the runbook gives the operator. It touches only the directory it is handed.

const SYSTEM = "*S-1-5-18";
const ADMINISTRATORS = "*S-1-5-32-544";

function windowsTool(tool: "icacls" | "whoami", args: string[]): string {
  const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "C:\\Windows";
  const result = spawnSync(join(systemRoot, "System32", `${tool}.exe`), args, { encoding: "utf8", windowsHide: true, timeout: 30_000 });
  if (result.status !== 0) throw new Error(`${tool} failed: ${result.stderr || result.stdout}`);
  return result.stdout;
}

export function currentWindowsSid(): string {
  const match = /"(S-1-[0-9]+(?:-[0-9]+)+)"\s*$/u.exec(windowsTool("whoami", ["/user", "/fo", "csv", "/nh"]).trim());
  if (!match) throw new Error("cannot determine the current user's SID");
  return match[1];
}

/** Applies the owner-only protection to an existing directory. Files created inside afterwards inherit it. */
export async function protectKeyDirectory(directory: string): Promise<void> {
  if (process.platform === "win32") {
    // /reset first: it drops every explicit entry (a previously added Everyone grant survives /inheritance:r and /grant:r otherwise).
    windowsTool("icacls", [directory, "/reset"]);
    windowsTool("icacls", [directory, "/inheritance:r", "/grant:r", `${SYSTEM}:(OI)(CI)F`, `${ADMINISTRATORS}:(OI)(CI)F`, `*${currentWindowsSid()}:(OI)(CI)F`]);
    return;
  }
  await chmod(directory, 0o700);
}

/** Creates `<home>/.limitmark-keys/staging` (recursively) and protects it. Returns the key directory. */
export async function createProtectedKeyDirectory(home: string): Promise<string> {
  const keys = join(home, ".limitmark-keys", "staging");
  await mkdir(keys, { recursive: true });
  await protectKeyDirectory(keys);
  return keys;
}

/** Test-only: widens a directory so the protection check has something real to refuse. Windows: Everyone read; POSIX: world read/exec. */
export async function widenKeyDirectoryForTest(directory: string): Promise<void> {
  if (process.platform === "win32") { windowsTool("icacls", [directory, "/grant", "*S-1-1-0:(OI)(CI)R"]); return; }
  await chmod(directory, 0o757);
}
