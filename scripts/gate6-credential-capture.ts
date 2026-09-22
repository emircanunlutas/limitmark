import { open, realpath, chmod } from "node:fs/promises";
import { basename, dirname, join, resolve, sep } from "node:path";
import { createHash } from "node:crypto";
import { readMaskedField } from "./gate6-secure-input";

// Gate 6A local credential-capture tool. Writes exactly one protected local
// file containing the two fields the existing staging submitter's strict
// reader already requires (scripts/authority-staging-submit.ts's
// credential()): exactly { accessKeyId, secretAccessKey }, both nonempty
// strings, UTF-8 without BOM, at most 1,024 bytes. This tool never places
// either value in argv, an environment variable, a log, or a generated shell
// command; it captures both fields with no terminal echo at all
// (scripts/gate6-secure-input.ts) and prints only a bounded one-way
// fingerprint of accessKeyId afterward, never either raw value. Request-write
// and result-read credentials are always captured to two separate files by
// two separate invocations -- this tool has no "both at once" mode -- and
// --role is mandatory with no default, so a credential can never be captured
// without the operator explicitly naming its purpose.

const roles = ["request-write", "result-read"] as const;
type Role = (typeof roles)[number];
const roleLabel: Record<Role, string> = {
  "request-write": "REQUEST-WRITE (scoped to the staging request bucket; this pipeline only ever calls PUT -- any coarser same-bucket read/list/delete right the provider preset also grants is not relied upon)",
  "result-read": "RESULT-READ (intended scope: result-bucket object GET only)",
};
const MAX_FIELD_BYTES = 256;
const MAX_FILE_BYTES = 1_024;
const printable = /^[\x20-\x7e]+$/u;

function fail(message: string): never { throw new Error(message); }

function parseArgs(): { role: Role; output: string } {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--role" || args[2] !== "--output") fail("gate6-capture-usage");
  const role = args[1];
  if (!(roles as readonly string[]).includes(role)) fail("gate6-capture-usage");
  const output = args[3];
  if (!output || output.startsWith("--")) fail("gate6-capture-usage");
  return { role: role as Role, output };
}

/** Resolves the final write path from an operator-supplied path. Requires
 * the parent directory to already exist (this tool never creates
 * directories) and, after realpath() canonicalization of that parent,
 * refuses outright if it is the repository root or nested under it -- a
 * symlinked parent pointing back into the repository is refused the same as
 * a literal in-repo path, since the comparison is against the *resolved*
 * parent, not the argument text. */
async function resolveOutputPath(outputArg: string): Promise<string> {
  const target = resolve(process.cwd(), outputArg);
  const name = basename(target);
  if (!name || name === "." || name === "..") fail("gate6-capture-output-required");
  let parent: string;
  try { parent = await realpath(dirname(target)); }
  catch { fail("gate6-capture-output-directory-must-already-exist"); }
  let repoRoot: string;
  try { repoRoot = await realpath(process.cwd()); }
  catch { fail("gate6-capture-repository-root-unavailable"); }
  if (parent === repoRoot || parent.startsWith(repoRoot + sep)) fail("gate6-capture-refuses-repo-contained-path");
  return join(parent, name);
}

function validateField(value: string, label: string): string {
  if (!value || value.length > MAX_FIELD_BYTES || !printable.test(value)) fail(`gate6-capture-invalid-${label}`);
  return value;
}

async function main(): Promise<void> {
  const { role, output } = parseArgs();
  const finalPath = await resolveOutputPath(output);
  // Refuse overwrite unconditionally -- there is no --force. A prior
  // capture attempt at this exact path, successful or not, must be resolved
  // by the operator choosing a fresh path (and, if a real credential was
  // involved, treating the earlier attempt per the Gate 6A secret-incident
  // model: revoke/reissue rather than retry over it).
  let handle;
  try { handle = await open(finalPath, "wx"); }
  catch { fail("gate6-capture-refuses-overwrite"); }
  try {
    process.stderr.write(`Gate 6A credential capture -- role: ${roleLabel[role]}\n`);
    process.stderr.write("Two values will be requested. Neither is echoed to the terminal.\n");
    const accessKeyId = validateField(await readMaskedField(`${role} accessKeyId`), "access-key-id");
    const secretAccessKey = validateField(await readMaskedField(`${role} secretAccessKey`), "secret-access-key");
    const body = JSON.stringify({ accessKeyId, secretAccessKey });
    const bytes = new TextEncoder().encode(body);
    if (bytes.byteLength > MAX_FILE_BYTES) fail("gate6-capture-credential-too-large");
    await handle.writeFile(bytes);
    try { await chmod(finalPath, 0o600); } catch { /* best-effort; not every platform honors owner-only POSIX bits */ }
    const fingerprint = createHash("sha256").update(accessKeyId).digest("hex").slice(0, 12);
    process.stdout.write(`${JSON.stringify({ status: "CAPTURED", role, output: finalPath, accessKeyIdFingerprint: fingerprint,
      capturedAtMs: Date.now() })}\n`);
  } catch (error) {
    await handle.close().catch(() => {});
    throw error;
  }
  await handle.close();
}

main().catch((error: unknown) => {
  process.stderr.write(`Gate 6A credential capture: REFUSED${error instanceof Error && error.message === "gate6-capture-aborted" ? " (aborted by operator)" : ""}. No credential file was completed.\n`);
  process.exitCode = 2;
});
