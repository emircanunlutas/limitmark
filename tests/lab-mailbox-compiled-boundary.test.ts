import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

/**
 * Compiled dependency boundary of the laboratory lifecycle mailbox (owner authorization 'Six Reviewed Migrations', 2026-11-10).
 *
 * The laboratory mailbox files name the production dispatch guard in a TYPE-ONLY import. A type-only import in the source is a claim about what the
 * compiler will erase; this file checks the result instead: it bundles the real entry modules in memory and reads the bundler's own list of the
 * modules that were compiled in. The laboratory approval rests on the fact pinned here, that none of the five held Gate 11A modules (the production
 * dispatch guard with its ledger export, the export request format, the read-only reader entrypoint, the production mailbox entry and the production
 * observer) enters the laboratory runtime bundle.
 *
 * A boundary check that cannot fail proves nothing, so the same procedure is run on the production entries (positive control: the held modules ARE
 * found there) and on two synthetic one-line entries (a type-only import is erased, a value import is detected).
 *
 * Scope and limits: this is an esbuild bundle with Worker-style settings, not a Wrangler deployment build; nothing is written to disk and nothing is
 * executed. It says which repository modules are compiled into an entry. It does not review those modules, and it approves nothing.
 */
const root = path.join(__dirname, "..");

const HELD_GATE_11A = [
  "workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/guard-export.ts", "workers/lifecycle-mailbox/guard-reader.ts",
  "workers/lifecycle-mailbox/index.ts", "workers/lifecycle-observer.ts",
];
/** Text that only the held modules contribute to a compiled bundle: the export method, the production guard object and class, the export format, the reader, the rotate slot. */
const HELD_MARKERS: readonly RegExp[] = [/\bexportLedger\b/u, /production-lifecycle-dispatch-v1/u, /limitmark-guard-export/u, /\bLifecycleDispatchGuard\b/u, /\bLifecycleGuardReadOnly\b/u, /GUARD_EXPORT/u, /rotate-release\.json/u];

type Closure = { modules: string[]; text: string };
type Source = { entry: string } | { contents: string; resolveDir: string };

/** Bundles one entry in memory and returns the repository modules the bundler compiled in (POSIX paths relative to the repository root) and the output text. */
async function compiledClosure(source: Source): Promise<Closure> {
  const result = await build({
    ...("entry" in source ? { entryPoints: [source.entry] } : { stdin: { contents: source.contents, resolveDir: path.join(root, source.resolveDir), loader: "ts" as const, sourcefile: "synthetic-entry.ts" } }),
    absWorkingDir: root, bundle: true, write: false, metafile: true, format: "esm", platform: "neutral", target: "es2022", logLevel: "silent",
    external: ["cloudflare:workers", "node:*"], mainFields: ["module", "main"], conditions: ["workerd", "worker", "browser"],
  });
  const output = Object.values(result.metafile.outputs)[0];
  // Only modules that contribute bytes to the output count: a module the bundler resolved but erased entirely is not part of the runtime.
  const modules = Object.entries(output.inputs).filter(([, input]) => input.bytesInOutput > 0).map(([file]) => file.replace(/\\/gu, "/"))
    .filter((file) => !file.includes("node_modules/") && !file.endsWith("synthetic-entry.ts")).sort();
  return { modules, text: result.outputFiles.map((file) => file.text).join("\n") };
}
const held = (closure: Closure): string[] => closure.modules.filter((file) => HELD_GATE_11A.includes(file));
const markers = (closure: Closure): string[] => HELD_MARKERS.filter((marker) => marker.test(closure.text)).map(String);

test("the laboratory mailbox bundle contains none of the five held Gate 11A modules and none of their code", async () => {
  const lab = await compiledClosure({ entry: "workers/lifecycle-mailbox/lab-index.ts" });
  assert.deepEqual(held(lab), [], "a held Gate 11A module is compiled into the laboratory mailbox");
  assert.deepEqual(markers(lab), [], "code of a held Gate 11A module is present in the laboratory mailbox bundle");
  // The exact compiled closure. A module that newly enters the laboratory runtime changes this list and must be looked at on purpose.
  assert.deepEqual(lab.modules, [
    "deployment/secret-matrix.json", "deployment/secret-policy.ts", "operator/attested-relay.ts", "operator/lifecycle-observation.ts", "operator/lifecycle-submitter.ts",
    "src/lib/ingress-protocol.ts", "workers/admission-service/authority.ts", "workers/admission-service/operator-command.ts",
    "workers/lifecycle-mailbox/lab-dispatch-guard.ts", "workers/lifecycle-mailbox/lab-index.ts", "workers/lifecycle-mailbox/lab-processor.ts", "workers/lifecycle-mailbox/wire.ts",
  ]);
  // The laboratory identities are the ones compiled in.
  assert.match(lab.text, /\bLabLifecycleDispatchGuard\b/u); assert.match(lab.text, /lab-lifecycle-dispatch-v1/u); assert.match(lab.text, /lab-rotation-not-implemented/u);
});

test("the laboratory observer bundle contains none of the five held Gate 11A modules either", async () => {
  const observer = await compiledClosure({ entry: "workers/lab-lifecycle-observer.ts" });
  assert.deepEqual(held(observer), []); assert.deepEqual(markers(observer), []);
  assert.ok(observer.modules.includes("workers/lab-lifecycle-observer.ts"));
});

test("positive control: the same procedure finds the held modules and their code in the production mailbox and observer bundles", async () => {
  const mailbox = await compiledClosure({ entry: "workers/lifecycle-mailbox/index.ts" });
  assert.deepEqual(held(mailbox), ["workers/lifecycle-mailbox/dispatch-guard.ts", "workers/lifecycle-mailbox/guard-export.ts", "workers/lifecycle-mailbox/guard-reader.ts", "workers/lifecycle-mailbox/index.ts"]);
  assert.deepEqual(markers(mailbox), HELD_MARKERS.map(String), "every marker is detectable where the held code really is");
  const observer = await compiledClosure({ entry: "workers/lifecycle-observer.ts" });
  assert.deepEqual(held(observer), ["workers/lifecycle-mailbox/guard-export.ts", "workers/lifecycle-observer.ts"]);
  // Between them the two production entries contain all five held modules, so each of the five is individually detectable.
  assert.deepEqual([...new Set([...held(mailbox), ...held(observer)])].sort(), [...HELD_GATE_11A].sort());
});

test("control of the mechanism itself: a type-only import of the production guard is erased, a value import of it is detected", async () => {
  const typeOnly = await compiledClosure({ resolveDir: "workers/lifecycle-mailbox", contents: 'import type { GuardOutcome } from "./dispatch-guard";\nexport const outcome: GuardOutcome | null = null;\n' });
  assert.deepEqual(typeOnly.modules, [], "a type-only import compiles to nothing");
  assert.deepEqual(markers(typeOnly), []);
  const value = await compiledClosure({ resolveDir: "workers/lifecycle-mailbox", contents: 'import { GUARD_OBJECT_NAME } from "./dispatch-guard";\nexport const name = GUARD_OBJECT_NAME;\n' });
  assert.deepEqual(held(value), ["workers/lifecycle-mailbox/dispatch-guard.ts"], "a value import pulls the production guard module in, and the check sees it");
  assert.ok(markers(value).includes(String(/production-lifecycle-dispatch-v1/u)));
});

test("the laboratory mailbox sources name the production guard only in type-only imports (source-level statement of the same boundary)", () => {
  for (const file of ["workers/lifecycle-mailbox/lab-dispatch-guard.ts", "workers/lifecycle-mailbox/lab-processor.ts", "workers/lifecycle-mailbox/lab-index.ts"]) {
    const source = readFileSync(path.join(root, file), "utf8");
    const imports = [...source.matchAll(/^import\s+(type\s+)?[^;]*?from\s+"([^"]+)";/gmu)].map((match) => ({ typeOnly: match[1] !== undefined, from: match[2] }));
    assert.ok(imports.length > 0, file);
    for (const entry of imports.filter((candidate) => /(?:^|\/)(?:dispatch-guard|guard-export|guard-reader|index)$/u.test(candidate.from) || /lifecycle-observer$/u.test(candidate.from)))
      assert.equal(entry.typeOnly, true, `${file}: "${entry.from}" may be named in a type-only import only`);
  }
});
