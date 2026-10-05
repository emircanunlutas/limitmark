import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// R06 activation tooling (remediation, Windows key protection): fail-closed check that the operator's key directory and private key file
// are readable by the operator only. Local only: it reads file metadata and, on Windows, runs the two read-only OS tools `icacls` and
// `whoami` with fixed argv (no shell, no network). It never reads, prints or logs key bytes.
//
// WHY THIS IS NOT A 0o600 CLAIM. POSIX permission bits are the protection on POSIX only. On Windows a file's `mode` is synthesized, `chmod
// 0o600` is a no-op for access control, and what protects the key is the NTFS DACL, which a directory under the user profile, a synced
// folder or %TEMP% may widen through INHERITED entries. So on Windows the DACL itself is read (as SDDL, which names principals by SID and
// is therefore independent of the OS language) and the check is an ALLOWLIST: every access-allowing entry must be for SYSTEM,
// BUILTIN\Administrators, Creator Owner, or the current user. Anything else -- Everyone, Users, Authenticated Users, an unrelated
// group or account, a NULL DACL, or an unreadable ACL -- refuses. This reduces exposure; it is not a guarantee against an administrator,
// malware running as the user, a backup or sync agent running as an allowed principal, or an offline disk read.

export class KeyProtectionError extends Error {
  constructor(readonly code: string) { super(code); this.name = "KeyProtectionError"; }
}
const refuse = (code: string): never => { throw new KeyProtectionError(code); };

export const WINDOWS_SYSTEM_SID = "S-1-5-18";
export const WINDOWS_ADMINISTRATORS_SID = "S-1-5-32-544";
export const WINDOWS_CREATOR_OWNER_SID = "S-1-3-0";
const SDDL_ALIASES: Readonly<Record<string, string>> = Object.freeze({ SY: WINDOWS_SYSTEM_SID, BA: WINDOWS_ADMINISTRATORS_SID, CO: WINDOWS_CREATOR_OWNER_SID });
const ALLOWING_ACE_TYPES = new Set(["A", "OA", "XA", "ZA"]);
const SID = /^S-1-[0-9]+(?:-[0-9]+){1,15}$/u;

/** Parses the DACL of an SDDL string and refuses unless every access-allowing entry names SYSTEM, Administrators, Creator Owner or
 * `currentUserSid`. Pure: no I/O, so every hostile ACL shape is testable on any platform. */
export function assertSddlOwnerOnly(sddl: string, currentUserSid: string): void {
  if (!SID.test(currentUserSid)) refuse("custody-acl-current-user-unknown");
  const allowed = new Set([WINDOWS_SYSTEM_SID, WINDOWS_ADMINISTRATORS_SID, WINDOWS_CREATOR_OWNER_SID, currentUserSid.toUpperCase()]);
  // The DACL must start the string (icacls /save emits the DACL only) and the ACE list must be consumed COMPLETELY: a conditional ACE with
  // nested parentheses would otherwise end the match early and silently skip every entry after it. No DACL section is refused too
  // (a NULL DACL grants everyone full access).
  const text = sddl.trim();
  const match = /^D:([A-Z]*)((?:\([^()]*\))*)/u.exec(text);
  if (!match) return refuse("custody-acl-unreadable");
  const remainder = text.slice(match[0].length);
  if (remainder !== "" && !remainder.startsWith("S:")) return refuse("custody-acl-unreadable");
  const entries = [...match[2].matchAll(/\(([^()]*)\)/gu)].map((entry) => entry[1].split(";"));
  if (entries.length === 0) return refuse("custody-acl-unreadable");
  for (const fields of entries) {
    if (fields.length < 6) return refuse("custody-acl-unreadable");
    const type = fields[0].toUpperCase();
    if (!ALLOWING_ACE_TYPES.has(type)) {
      // Deny and audit entries cannot widen access. Any other type is not understood, so it is not trusted.
      if (type === "D" || type === "OD" || type === "XD" || type === "AU" || type === "OU" || type === "XU" || type === "ML" || type === "SP" || type === "RA" || type === "SA" || type === "AL") continue;
      return refuse("custody-acl-unreadable");
    }
    const trustee = fields[5].trim().toUpperCase();
    const sid = SDDL_ALIASES[trustee] ?? trustee;
    if (!SID.test(sid) || !allowed.has(sid)) refuse("custody-acl-untrusted-principal");
  }
}

/** `icacls /save` writes UTF-16LE: the path on the first line, its SDDL on the next. Returns the SDDL line. */
export function sddlFromIcaclsSave(bytes: Uint8Array): string {
  const text = Buffer.from(bytes).toString("utf16le").replace(/^\uFEFF/u, "");
  const line = text.split(/\r?\n/u).map((entry) => entry.trim()).find((entry) => entry.startsWith("D:"));
  if (!line) return refuse("custody-acl-unreadable");
  return line;
}

/** The current user's SID from `whoami /user /fo csv /nh` (`"DOMAIN\\user","S-1-5-21-..."`). */
export function sidFromWhoami(output: string): string {
  const match = /"(S-1-[0-9]+(?:-[0-9]+)+)"\s*$/u.exec(output.trim());
  return match ? match[1] : refuse("custody-acl-current-user-unknown");
}

type WindowsTool = "icacls" | "whoami";
const WINDOWS_TOOL_TIMEOUT_MS = 15_000;

/** The only process-spawn site of this module: one of two fixed read-only Windows tools, absolute path, no shell. */
function runWindowsTool(tool: WindowsTool, args: readonly string[]): string {
  const systemRoot = process.env.SystemRoot ?? process.env.SYSTEMROOT ?? "C:\\Windows";
  const executable = join(systemRoot, "System32", `${tool}.exe`);
  try {
    return execFileSync(executable, [...args], { encoding: "utf8", windowsHide: true, timeout: WINDOWS_TOOL_TIMEOUT_MS, stdio: ["ignore", "pipe", "ignore"], env: { SystemRoot: systemRoot } as unknown as NodeJS.ProcessEnv });
  } catch { return refuse("custody-acl-unverifiable"); }
}

async function windowsDaclOf(path: string): Promise<string> {
  const workDirectory = await mkdtemp(join(tmpdir(), "limitmark-acl-"));
  try {
    const output = join(workDirectory, "acl.txt");
    runWindowsTool("icacls", [path, "/save", output]);
    return sddlFromIcaclsSave(await readFile(output));
  } catch (error) { if (error instanceof KeyProtectionError) throw error; return refuse("custody-acl-unverifiable"); }
  finally { await rm(workDirectory, { recursive: true, force: true }).catch(() => undefined); }
}

async function assertWindowsProtected(paths: readonly string[]): Promise<void> {
  const currentUserSid = sidFromWhoami(runWindowsTool("whoami", ["/user", "/fo", "csv", "/nh"]));
  for (const path of paths) assertSddlOwnerOnly(await windowsDaclOf(path), currentUserSid);
}

/** POSIX: the private file carries no group/other permission bits, the directory is not writable by group/other, and both belong to the
 * current user. (POSIX bits only; Windows is handled by the DACL check above.) */
export function assertPosixModes(entries: ReadonlyArray<{ kind: "directory" | "file"; mode: number; uid: number }>, currentUid: number | null): void {
  for (const entry of entries) {
    if (currentUid !== null && entry.uid !== currentUid) refuse("custody-owner-mismatch");
    if (entry.kind === "file" && (entry.mode & 0o077) !== 0) refuse("custody-file-too-permissive");
    if (entry.kind === "directory" && (entry.mode & 0o022) !== 0) refuse("custody-directory-writable-by-others");
  }
}

export type CustodyTargets = { directory: string; files: readonly string[] };

/** Refuses unless the (already realpath'd) key directory and every listed file are protected for the running platform. */
export async function assertCustodyProtected(targets: CustodyTargets, platform: NodeJS.Platform = process.platform): Promise<void> {
  if (platform === "win32") { await assertWindowsProtected([targets.directory, ...targets.files]); return; }
  const entries: Array<{ kind: "directory" | "file"; mode: number; uid: number }> = [];
  try {
    const directory = await stat(targets.directory);
    if (!directory.isDirectory()) return refuse("custody-protection-unverifiable");
    entries.push({ kind: "directory", mode: directory.mode, uid: directory.uid });
    for (const file of targets.files) {
      const info = await stat(file);
      if (!info.isFile()) return refuse("custody-protection-unverifiable");
      entries.push({ kind: "file", mode: info.mode, uid: info.uid });
    }
  } catch (error) { if (error instanceof KeyProtectionError) throw error; return refuse("custody-protection-unverifiable"); }
  assertPosixModes(entries, typeof process.getuid === "function" ? process.getuid() : null);
}
