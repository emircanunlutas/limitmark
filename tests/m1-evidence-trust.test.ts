import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { MANDATORY_ARTIFACTS, TALLY_EXIT, m1TallyCheck, verifyMandatoryInventory } from "../lab/defense/ba0-m1-tally-check";
import { evaluateTallyAgainstLedger, type TallyCheckInput } from "../lab/defense/m1-tally-check";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { writeFieldLikeEvidence, type EvidenceOptions } from "./support/m1-evidence-dir";
import { ledgerArtifact, remoteWorkload, validInput, workload } from "./support/m1-tally-fixture";

// R-5 (evidence inventory) and the D2 consistency checks (pinned parameters, clean source, window arithmetic, zero anomalies).

const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-c9trust-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
type Run = { exit: number; reasons: string[]; refusal: string | null; problems: string[] };
/** Writes finalized evidence, lets `tamper` change the directory AFTER finalization, then runs the real CLI. */
function run(options: EvidenceOptions, tamper?: (directory: string) => void): Run {
  const root = testRoot();
  try {
    const id = writeFieldLikeEvidence(root, options);
    const directory = path.join(root, id);
    tamper?.(directory);
    const outcome = m1TallyCheck({ serverId: id }, root);
    return { exit: outcome.exit, reasons: outcome.result?.reasons ?? [], refusal: outcome.refusal, problems: verifyMandatoryInventory(directory).problems };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
const sha = (text: string | Buffer): string => createHash("sha256").update(text).digest("hex");
const sumsPath = (directory: string): string => path.join(directory, "SHA256SUMS");
const rewriteSums = (directory: string, edit: (lines: string[]) => string[]): void => fs.writeFileSync(sumsPath(directory), `${edit(fs.readFileSync(sumsPath(directory), "utf8").trim().split("\n")).join("\n")}\n`);
const notPass = (label: string, result: Run): Run => { assert.notEqual(result.exit, TALLY_EXIT.pass, `${label}: ${result.reasons.join(",")} ${result.refusal ?? ""}`); return result; };

test("control: complete, fully inventoried evidence passes and every mandatory artifact is checksummed and in the manifest", () => {
  const result = run({});
  assert.deepEqual([result.exit, result.reasons, result.problems], [TALLY_EXIT.pass, [], []]);
  const root = testRoot();
  try {
    const directory = path.join(root, writeFieldLikeEvidence(root));
    const inventory = verifyMandatoryInventory(directory);
    assert.deepEqual([...inventory.bytes.keys()].sort(), [...MANDATORY_ARTIFACTS].sort());
    for (const [name, bytes] of inventory.bytes) assert.ok(fs.readFileSync(sumsPath(directory), "utf8").includes(`${sha(bytes)}  ${name}`), name);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("R-5 regression: the original probe (a forged kind-ledger.json that is written but not listed) was PASS and is now an ERROR", () => {
  const forged = `${JSON.stringify(ledgerArtifact([...workload(), ...remoteWorkload()]), null, 2)}\n`;
  const result = run({ artifacts: { "kind-ledger.json": null }, unlisted: { "kind-ledger.json": forged } });
  assert.equal(result.exit, TALLY_EXIT.error);
  assert.deepEqual(result.reasons, ["m1.tally.evidence_inventory_invalid"]);
  assert.ok(result.problems.includes("unlisted_mandatory:kind-ledger.json") && result.problems.includes("unlisted_artifact:kind-ledger.json"), result.problems.join(","));
});

test("R-5: an unlisted copy of EVERY mandatory artifact (valid content) is never consumed and never PASS", () => {
  for (const name of MANDATORY_ARTIFACTS.filter((entry) => entry !== "manifest.json")) {
    const root = testRoot();
    try {
      const id = writeFieldLikeEvidence(root);
      const directory = path.join(root, id);
      const content = fs.readFileSync(path.join(directory, name));
      rewriteSums(directory, (lines) => lines.filter((line) => !line.endsWith(`  ${name}`))); // the run "forgot" to list it
      const outcome = m1TallyCheck({ serverId: id }, root);
      assert.notEqual(outcome.exit, TALLY_EXIT.pass, name);
      assert.ok(verifyMandatoryInventory(directory).problems.some((problem) => problem.endsWith(name)), `${name}: ${verifyMandatoryInventory(directory).problems.join(",")}`);
      assert.equal(verifyMandatoryInventory(directory).bytes.has(name), false, `${name}: unlisted bytes are not returned`);
      assert.ok(content.length > 0);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test("R-5: a checksum that does not match the consumed bytes, or a consistently re-hashed replacement, is never PASS", () => {
  assert.equal(notPass("bytes changed", run({}, (directory) => fs.appendFileSync(path.join(directory, "kind-ledger.json"), " "))).exit, TALLY_EXIT.refused);
  // an attacker who replaces the file AND its line in SHA256SUMS still disagrees with the manifest's own artifact list
  const replaced = notPass("replaced and re-hashed", run({}, (directory) => {
    const forged = `${JSON.stringify(ledgerArtifact([...workload(), ...remoteWorkload()]), null, 4)}\n`;
    fs.writeFileSync(path.join(directory, "kind-ledger.json"), forged);
    rewriteSums(directory, (lines) => lines.map((line) => (line.endsWith("  kind-ledger.json") ? `${sha(forged)}  kind-ledger.json` : line)));
  }));
  assert.equal(replaced.exit, TALLY_EXIT.error);
  assert.deepEqual(replaced.reasons, ["m1.tally.evidence_inventory_invalid"]);
  assert.ok(replaced.problems.includes("inventory_conflict:kind-ledger.json"));
});

test("R-5: duplicate, aliased, traversing, malformed and conflicting inventory lines are refused or ERROR, never PASS", () => {
  const line = (directory: string, name: string): string => fs.readFileSync(sumsPath(directory), "utf8").split("\n").find((entry) => entry.endsWith(`  ${name}`)) ?? "";
  const refused = (label: string, tamper: (directory: string) => void): void => { const r = notPass(label, run({}, tamper)); assert.equal(r.exit, TALLY_EXIT.refused, label); };
  refused("duplicate line", (directory) => rewriteSums(directory, (lines) => [...lines, line(directory, "kind-ledger.json")]));
  refused("case alias of a listed name", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  KIND-LEDGER.json`]));
  refused("canonical alias with different case only", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  Kind-Ledger.json`]));
  refused("path traversal", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  ../kind-ledger.json`]));
  refused("nested path", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  sub/kind-ledger.json`]));
  refused("backslash path", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  ..\\kind-ledger.json`]));
  refused("absolute path", (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("x")}  /etc/passwd.json`]));
  refused("malformed hash", (directory) => rewriteSums(directory, (lines) => [...lines, "zz  other.json"]));
  refused("single space separator", (directory) => rewriteSums(directory, (lines) => lines.map((entry) => entry.replace("  kind-ledger.json", " kind-ledger.json"))));
  // an extra, unlisted artifact of any name next to the evidence
  const extra = notPass("extra unlisted json", run({ unlisted: { "kind-ledger-v2.json": "{}" } }));
  assert.equal(extra.exit, TALLY_EXIT.error);
  assert.ok(extra.problems.includes("unlisted_artifact:kind-ledger-v2.json"));
  // a listed name the manifest does not know (an entry added to SHA256SUMS only)
  const conflict = notPass("sums-only entry", run({ unlisted: { "extra.json": "{}" } }, (directory) => rewriteSums(directory, (lines) => [...lines, `${sha("{}")}  extra.json`])));
  assert.ok(conflict.problems.includes("inventory_conflict:extra.json"));
});

test("R-5: the evaluator treats any inventory problem as ERROR even for otherwise perfect evidence", () => {
  assert.equal(evaluateTallyAgainstLedger(validInput()).outcome, "PASS");
  assert.deepEqual(evaluateTallyAgainstLedger({ ...validInput(), inventoryProblems: ["unlisted_mandatory:kind-ledger.json"] }).reasons, ["m1.tally.evidence_inventory_invalid"]);
});

// ------------------------------------------------------------------------------------------------------------------------ D2
type Doc = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any
const reasonsOf = (input: TallyCheckInput): string[] => evaluateTallyAgainstLedger(input).reasons;
const withLevel = (mutate: (level: { serverLevel: Doc; core: Doc; manifest: Doc }) => void): TallyCheckInput => {
  const input = validInput(); const copy = structuredClone(input.level) as { serverLevel: Doc; core: Doc; manifest: Doc };
  mutate(copy); return { ...input, level: copy };
};

test("D2: the parameter fingerprint must be the code-pinned set for the level (both artifacts, id and version included)", () => {
  assert.deepEqual(reasonsOf(validInput()), []);
  const other = "d".repeat(64);
  // self-consistent but not the pinned parameters: previously PASS
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.paramsFingerprintSha256 = other; l.core.parameters.sha256 = other; })).includes("m1.tally.params_not_code_pinned"));
  assert.ok(reasonsOf(withLevel((l) => { l.core.parameters.sha256 = other; })).includes("m1.tally.params_not_code_pinned"));
  assert.ok(reasonsOf(withLevel((l) => { l.core.parameters.version = 2; })).includes("m1.tally.params_not_code_pinned"));
  assert.ok(reasonsOf(withLevel((l) => { l.core.parameters.id = "ba0-field-v2"; })).includes("m1.tally.params_not_code_pinned"));
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.levelId = "ba0-l7-unknown"; l.core.level.id = "ba0-l7-unknown"; })).includes("m1.tally.params_not_code_pinned"), "a level without a code-pinned set cannot be accepted");
});

test("D2: manifest.git.dirty must be the boolean false (true REJECT, absent or non-boolean ERROR)", () => {
  assert.ok(reasonsOf(withLevel((l) => { l.manifest.git.dirty = true; })).includes("m1.tally.source_tree_dirty"));
  for (const bad of [undefined, "false", 0, null]) {
    const input = withLevel((l) => { if (bad === undefined) delete l.manifest.git.dirty; else l.manifest.git.dirty = bad; });
    assert.deepEqual(evaluateTallyAgainstLedger(input).reasons, ["m1.tally.evidence_malformed_level"], String(bad));
  }
  const dirtyRun = notPass("dirty through the CLI", run({ git: { dirty: true } }));
  assert.ok(dirtyRun.reasons.includes("m1.tally.source_tree_dirty"));
});

test("D2: the window must satisfy closedAt - openedAt == elapsedMs within the documented 1 s clock skew", () => {
  assert.deepEqual(reasonsOf(withLevel((l) => { l.serverLevel.window.elapsedMs = 60_900; })), []);
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.window.elapsedMs = 58_999; })).includes("m1.tally.level_window_elapsed_inconsistent"));
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.window.elapsedMs = 61_001; })).includes("m1.tally.level_window_elapsed_inconsistent"));
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.window.elapsedMs = 0; })).includes("m1.tally.level_window_elapsed_inconsistent"));
  assert.ok(reasonsOf(withLevel((l) => { l.serverLevel.window.closedAt = "2026-11-08T10:00:00.000Z"; })).includes("m1.tally.level_window_elapsed_inconsistent"));
});

test("D2: accounting.anomalyTotal is mandatory and must be exactly zero", () => {
  assert.ok(reasonsOf({ ...validInput(), anomalyTotal: 1 }).includes("m1.tally.anomalies_nonzero"));
  for (const bad of [undefined, null, "0", -1, 0.5, Number.NaN]) assert.deepEqual(reasonsOf({ ...validInput(), anomalyTotal: bad }), ["m1.tally.evidence_malformed_accounting"], String(bad));
  const viaCli = notPass("anomalies through the CLI", run({ mutate: { "accounting.json": (content) => { content.anomalyTotal = 2; } } }));
  assert.ok(viaCli.reasons.includes("m1.tally.anomalies_nonzero"));
  const missing = notPass("anomalyTotal absent", run({ mutate: { "accounting.json": (content) => { delete content.anomalyTotal; } } }));
  assert.deepEqual(missing.reasons, ["m1.tally.evidence_malformed_accounting"]);
});
