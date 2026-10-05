import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  AttestationKeyError, STAGING_ATTESTATION_KEY_FILE, generateStagingAttestationKey, readStagingAttestationKeyForSecretPut, verifyStagingAttestationKey,
} from "../operator/staging-attestation-key";
import {
  KeyProtectionError, assertCustodyProtected, assertPosixModes, assertSddlOwnerOnly, sddlFromIcaclsSave, sidFromWhoami,
} from "../operator/staging-key-protection";
import { createProtectedKeyDirectory, currentWindowsSid, protectKeyDirectory, widenKeyDirectoryForTest } from "./support/r06-key-directory";

// R06 activation (remediation: Windows key protection). The custody tooling VERIFIES that the key directory and the private key file are
// readable by the operator only. POSIX 0o600 protects nothing on Windows, so on Windows the NTFS DACL is read (as SDDL, which names
// principals by SID and is therefore independent of the OS language) and checked against an ALLOWLIST. The parser is pure and tested with
// hostile ACLs on every platform; the real check runs against real files and the real OS tools on whichever platform runs the suite.

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const ME = "S-1-5-21-1111111111-2222222222-3333333333-1001";
const OTHER_USER = "S-1-5-21-1111111111-2222222222-3333333333-1002";
const refusesWith = (action: () => unknown, code: string) => assert.throws(action, (error: unknown) => error instanceof KeyProtectionError && error.code === code, `expected ${code}`);
const NOW = Date.now();

test("SDDL: an ACL naming only SYSTEM, Administrators, Creator Owner and the current user is accepted", () => {
  assertSddlOwnerOnly(`D:PAI(A;OICI;FA;;;${ME})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)`, ME);
  assertSddlOwnerOnly(`D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;${ME})`, ME);
  assertSddlOwnerOnly("D:PAI(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICIIO;FA;;;CO)(A;;FA;;;" + ME.toLowerCase() + ")", ME);
  // deny and audit entries cannot widen access
  assertSddlOwnerOnly(`D:PAI(D;OICI;FA;;;WD)(A;OICI;FA;;;${ME})(A;OICI;FA;;;SY)S:(AU;SA;FA;;;WD)`, ME);
});

test("SDDL: every other principal is refused, however little access it has", () => {
  const principals: Array<[string, string]> = [
    ["Everyone", "WD"], ["Users", "BU"], ["Authenticated Users", "AU"], ["Interactive", "IU"], ["Network", "NU"], ["Guests", "BG"], ["Anonymous", "AN"],
    ["Power Users", "PU"], ["Domain Users", "DU"], ["Local account", "S-1-5-113"], ["Everyone by SID", "S-1-1-0"], ["Users by SID", "S-1-5-32-545"],
    ["another local user", OTHER_USER], ["a sandbox group", "S-1-5-21-1111111111-2222222222-3333333333-1002"], ["Owner Rights", "OW"],
  ];
  for (const [label, trustee] of principals) {
    refusesWith(() => assertSddlOwnerOnly(`D:PAI(A;OICI;FA;;;${ME})(A;OICI;FR;;;${trustee})`, ME), "custody-acl-untrusted-principal");
    refusesWith(() => assertSddlOwnerOnly(`D:PAI(A;OICI;0x120089;;;${trustee})(A;OICI;FA;;;SY)`, ME), "custody-acl-untrusted-principal");
    void label;
  }
  // object, callback and compound allow entries count as allow entries too
  refusesWith(() => assertSddlOwnerOnly(`D:(OA;;CC;;;WD)(A;;FA;;;${ME})`.replace("OA;;CC;;;WD", "OA;;CC;{00000000-0000-0000-0000-000000000000};{00000000-0000-0000-0000-000000000000};WD"), ME), "custody-acl-untrusted-principal");
  refusesWith(() => assertSddlOwnerOnly(`D:(XA;;FA;;;WD;(@User.x==1))(A;;FA;;;${ME})`, ME), "custody-acl-unreadable");
});

test("SDDL: a NULL/absent/empty/malformed DACL or a string that is not a DACL is refused (fail closed)", () => {
  for (const sddl of ["", "   ", "D:", "D:P", "D:PAI", "O:BAG:SY", `O:BAG:SYD:PAI(A;;FA;;;${ME})`, "S:(AU;SA;FA;;;WD)", "garbage", "D:(A;;FA;;;SY", "D:(A;;FA;;SY)", "D:(Q;;FA;;;SY)",
    `D:PAI(A;;FA;;;${ME})trailing`, `D:PAI(A;;FA;;;${ME})(unclosed`, `D:PAI(A;;FA;;;${ME}) (A;;FA;;;WD)`, "D:(A;;FA;;;)"])
    refusesWith(() => assertSddlOwnerOnly(sddl, ME), sddl.includes("(A;;FA;;;)") ? "custody-acl-untrusted-principal" : "custody-acl-unreadable");
  refusesWith(() => assertSddlOwnerOnly(`D:PAI(A;;FA;;;${ME})`, ""), "custody-acl-current-user-unknown");
  refusesWith(() => assertSddlOwnerOnly(`D:PAI(A;;FA;;;${ME})`, "not-a-sid"), "custody-acl-current-user-unknown");
});

test("SDDL: a conditional ACE with nested parentheses cannot hide the entries after it", () => {
  // A parser that stops at the first nested ')' would accept this as "owner only" and never see the Everyone entry.
  refusesWith(() => assertSddlOwnerOnly(`D:PAI(A;;FA;;;${ME})(XA;;FA;;;SY;(Member_of{SID(BA)}))(A;;FR;;;WD)`, ME), "custody-acl-unreadable");
});

test("icacls /save and whoami output are parsed strictly", () => {
  const sddl = `D:AI(A;ID;FA;;;SY)(A;ID;FA;;;${ME})`;
  const utf16 = Buffer.from(`key.txt\r\n${sddl}\r\n\r\n`, "utf16le");
  assert.equal(sddlFromIcaclsSave(utf16), sddl);
  assert.equal(sddlFromIcaclsSave(Buffer.concat([Buffer.from([0xff, 0xfe]), utf16])), sddl, "a BOM is tolerated");
  for (const bad of [Buffer.alloc(0), Buffer.from("not utf16 at all", "latin1"), Buffer.from("only-a-name\r\n", "utf16le"), Buffer.from(`O:BA\r\nG:SY\r\n`, "utf16le")])
    refusesWith(() => sddlFromIcaclsSave(bad), "custody-acl-unreadable");
  assert.equal(sidFromWhoami(`"desktop\\emir","${ME}"\r\n`), ME);
  for (const bad of ["", "desktop\\emir", `"x","not-a-sid"`, `"x","S-1-"`]) refusesWith(() => sidFromWhoami(bad), "custody-acl-current-user-unknown");
});

test("POSIX modes: the private file has no group/other bits, the directory is not group/other writable, and both belong to the current user", () => {
  assertPosixModes([{ kind: "directory", mode: 0o40700, uid: 1000 }, { kind: "file", mode: 0o100600, uid: 1000 }], 1000);
  assertPosixModes([{ kind: "directory", mode: 0o40755, uid: 1000 }, { kind: "file", mode: 0o100400, uid: 1000 }], 1000);
  for (const mode of [0o100640, 0o100604, 0o100660, 0o100644, 0o100666, 0o100607]) refusesWith(() => assertPosixModes([{ kind: "file", mode, uid: 1000 }], 1000), "custody-file-too-permissive");
  for (const mode of [0o40770, 0o40707, 0o40777, 0o40757, 0o40775]) refusesWith(() => assertPosixModes([{ kind: "directory", mode, uid: 1000 }], 1000), "custody-directory-writable-by-others");
  refusesWith(() => assertPosixModes([{ kind: "file", mode: 0o100600, uid: 0 }], 1000), "custody-owner-mismatch");
  assertPosixModes([{ kind: "file", mode: 0o100600, uid: 0 }], null); // no uid concept: modes alone
});

test("real files: a protected key directory and private file pass; a widened one is refused", async () => {
  const home = await mkdtemp(join(tmpdir(), "r06-protect-"));
  try {
    const keys = await createProtectedKeyDirectory(home);
    const file = join(keys, "private.bin");
    await writeFile(file, "x", { mode: 0o600 });
    await assertCustodyProtected({ directory: keys, files: [file] });
    await widenKeyDirectoryForTest(keys);
    await assert.rejects(assertCustodyProtected({ directory: keys, files: [] }),
      (error: unknown) => error instanceof KeyProtectionError && error.code === (process.platform === "win32" ? "custody-acl-untrusted-principal" : "custody-directory-writable-by-others"));
    if (process.platform !== "win32") {
      await protectKeyDirectory(keys);
      await chmod(file, 0o644);
      await assert.rejects(assertCustodyProtected({ directory: keys, files: [file] }), (error: unknown) => error instanceof KeyProtectionError && error.code === "custody-file-too-permissive");
    }
    await assert.rejects(assertCustodyProtected({ directory: join(home, "absent"), files: [] }), (error: unknown) => error instanceof KeyProtectionError);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("on Windows the live ACL is judged by SID: the current user is trusted, an unrelated principal is not (language-independent)", { skip: process.platform !== "win32" }, async () => {
  const home = await mkdtemp(join(tmpdir(), "r06-protect-win-"));
  try {
    assert.match(currentWindowsSid(), /^S-1-5-21-/u);
    const keys = await createProtectedKeyDirectory(home);
    await assertCustodyProtected({ directory: keys, files: [] });
    await widenKeyDirectoryForTest(keys);
    await assert.rejects(assertCustodyProtected({ directory: keys, files: [] }), (error: unknown) => error instanceof KeyProtectionError && error.code === "custody-acl-untrusted-principal");
    // restoring owner-only protection makes it pass again (the refusal was about the ACL, nothing else)
    await protectKeyDirectory(keys);
    await assertCustodyProtected({ directory: keys, files: [] });
  } finally { await rm(home, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------------------------------------------------------------------------
// The key module enforces it at every point where the private key is created or read
// ---------------------------------------------------------------------------------------------------------------------------------

const PROTECTION_CODE = process.platform === "win32" ? "custody-acl-untrusted-principal" : "custody-directory-writable-by-others";
const keyRefusal = (promise: Promise<unknown>, code: string) =>
  assert.rejects(promise, (error: unknown) => error instanceof AttestationKeyError && error.code === code, `expected ${code}`);

test("generation into an unprotected directory is refused BEFORE any key exists; a protected directory works", async () => {
  const home = await mkdtemp(join(tmpdir(), "r06-protect-gen-"));
  const root = await mkdtemp(join(tmpdir(), "r06-protect-root-"));
  try {
    const keys = await createProtectedKeyDirectory(home);
    await widenKeyDirectoryForTest(keys);
    await keyRefusal(generateStagingAttestationKey({ directory: keys, repositoryRoot: root, nowMs: NOW }), PROTECTION_CODE);
    assert.deepEqual(await readdir(keys), [], "no custody file was created in an unprotected directory");
    await protectKeyDirectory(keys);
    const generated = await generateStagingAttestationKey({ directory: keys, repositoryRoot: root, nowMs: NOW });
    assert.match(generated.keyFingerprint, /^[a-f0-9]{64}$/u);
  } finally { await rm(home, { recursive: true, force: true }); await rm(root, { recursive: true, force: true }); }
});

test("every read of the private key re-checks protection: verify and the secret-put loader refuse once the directory is widened", async () => {
  const home = await mkdtemp(join(tmpdir(), "r06-protect-read-"));
  const root = await mkdtemp(join(tmpdir(), "r06-protect-root-"));
  try {
    const keys = await createProtectedKeyDirectory(home);
    await generateStagingAttestationKey({ directory: keys, repositoryRoot: root, nowMs: NOW - 1_000 });
    const request = { directory: keys, repositoryRoot: root, nowMs: NOW };
    await verifyStagingAttestationKey(request);
    await readStagingAttestationKeyForSecretPut(request);
    await widenKeyDirectoryForTest(keys);
    await keyRefusal(verifyStagingAttestationKey(request), PROTECTION_CODE);
    await keyRefusal(readStagingAttestationKeyForSecretPut(request), PROTECTION_CODE);
    await protectKeyDirectory(keys);
    await verifyStagingAttestationKey(request);
    // a private file that is itself too open is refused on POSIX even in a protected directory
    if (process.platform !== "win32") {
      await chmod(join(keys, STAGING_ATTESTATION_KEY_FILE), 0o640);
      await keyRefusal(readStagingAttestationKeyForSecretPut(request), "custody-file-too-permissive");
    }
  } finally { await rm(home, { recursive: true, force: true }); await rm(root, { recursive: true, force: true }); }
});

test("the protection module has exactly one process-spawn site: a closed pair of read-only Windows tools, no shell, no network", async () => {
  const strip = (source: string) => source.split("\n").filter((line) => !line.trim().startsWith("//") && !line.trim().startsWith("*") && !line.trim().startsWith("/*")).join("\n");
  const source = strip(await readFile(join(repoRoot, "operator/staging-key-protection.ts"), "utf8"));
  assert.equal(source.match(/\bexecFileSync\(/gu)?.length, 1);
  // a bare exec( / spawn*( / fork( call; RegExp#exec is a method call and is not a process
  assert.equal(/(?<![.\w])(?:spawn\w*|exec|fork)\(|shell\s*:|node:(net|http|https|tls|dns)|\bfetch\s*\(|WebSocket/u.test(source), false);
  assert.match(source, /type WindowsTool = "icacls" \| "whoami";/u);
  assert.deepEqual([...source.matchAll(/runWindowsTool\("([a-z]+)"/gu)].map((match) => match[1]).sort(), ["icacls", "whoami"]);
  // never reads key bytes
  assert.equal(/readFile\([^)]*(?:key|private)/iu.test(source), false);
});
