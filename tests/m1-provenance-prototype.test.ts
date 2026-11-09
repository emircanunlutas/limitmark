import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { RetainedRecords, commitmentSeal, verifyProvenance, type CommitmentFields } from "../lab/provenance/prototype";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { FIELD_LEVELS } from "../lab/defense/field-thresholds";
import { writeFieldLikeEvidence, type EvidenceOptions } from "./support/m1-evidence-dir";
import { collectGitState } from "../lab/evidence/manifest";

// Local prototype of independent provenance (lab/provenance/prototype.ts): disposable fixtures, no keys, no network. Agreement between two local files is NOT authenticity and
// is NOT independence; the last test shows a same-actor forgery that the verifier cannot tell apart and which it must not describe as authenticated.

const sha = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
const base = (): string => path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-prov-${process.pid}-${Math.random().toString(16).slice(2, 8)}`);
const pinned = ba0FieldFingerprint(FIELD_LEVELS["ba0-l7-c1"].thresholds).sha256;
const gitSha = collectGitState().gitSha;

type World = { root: string; evidence: string; retained: RetainedRecords; runId: string };
/** A finalized package, plus the retained store as the honest generator-side party would have written it during the run. */
function world(options: EvidenceOptions = {}, fields: Partial<CommitmentFields> = {}, beaconCount = 3): World {
  const root = base();
  fs.mkdirSync(root, { recursive: true });
  const runId = writeFieldLikeEvidence(root, options);
  const evidence = path.join(root, runId);
  const retained = new RetainedRecords(path.join(root, "retained-by-generator"));
  retained.commit({ campaignId: "campaign-a", levelId: "ba0-l7-c1", paramsSha256: pinned, gitSha, committedAt: new Date(Date.now() - 3_600_000).toISOString(), nonce: "n".repeat(16), ...fields });
  announce(retained, evidence, runId, beaconCount);
  return { root, evidence, retained, runId };
}
/** What the server announces during the run: prefixes of its (append-only) journal at line boundaries, then the finalization digests. */
function announce(retained: RetainedRecords, evidence: string, runId: string, beaconCount: number): void {
  const journal = fs.readFileSync(path.join(evidence, "ledger-journal-field.ndjson"));
  const boundaries = [...journal.toString("utf8").matchAll(/\n/gu)].map((match) => match.index! + 1);
  for (let k = 1; k <= beaconCount; k++) { const cut = k === beaconCount ? journal.length : boundaries[Math.floor((boundaries.length * k) / beaconCount) - 1]; retained.beacon(runId, cut, sha(journal.subarray(0, cut))); }
  retained.finalize(runId, sha(fs.readFileSync(path.join(evidence, "SHA256SUMS"))), sha(journal));
}
/** An actor with write access to the package only: replaces an artifact and re-hashes it consistently in manifest.json and SHA256SUMS. */
function substitute(evidence: string, name: string, content: unknown): void {
  const text = `${JSON.stringify(content, null, 2)}\n`;
  fs.writeFileSync(path.join(evidence, name), text);
  const manifestPath = path.join(evidence, "manifest.json");
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as { artifacts: { name: string; sha256: string; bytes: number }[] };
  const entry = manifest.artifacts.find((artifact) => artifact.name === name)!;
  entry.sha256 = sha(text); entry.bytes = Buffer.byteLength(text);
  const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
  fs.writeFileSync(manifestPath, manifestText);
  const sums = fs.readFileSync(path.join(evidence, "SHA256SUMS"), "utf8").trim().split("\n").map((line) => (line.endsWith(`  ${name}`) ? `${sha(text)}  ${name}` : line.endsWith("  manifest.json") ? `${sha(manifestText)}  manifest.json` : line));
  fs.writeFileSync(path.join(evidence, "SHA256SUMS"), `${sums.join("\n")}\n`);
}
const cleanup = (w: World): void => fs.rmSync(w.root, { recursive: true, force: true });
const read = (file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;

test("honest package and retained records: consistent, and the verifier still claims neither authenticity nor independence", () => {
  const w = world();
  try {
    const report = verifyProvenance(w.evidence, w.retained.directory);
    assert.deepEqual(report.problems, []);
    assert.equal(report.overall, "CONSISTENT_WITH_RECORDS");
    assert.deepEqual(report.levels, { byteIntegrity: "VERIFIED", artifactCompleteness: "VERIFIED", runBinding: "VERIFIED", producerIdentity: "CLAIMED_UNVERIFIED", independentCorroboration: "CONSISTENT", authenticity: "UNVERIFIED" });
    assert.deepEqual(report.claims, { authenticated: false, independent: false });
    assert.equal(report.claimedProducer.gitSha, gitSha, "producer identity is reported as a claim only");
  } finally { cleanup(w); }
});

test("evidence substitution: replacing an artifact and consistently re-hashing the package keeps byte integrity VERIFIED but fails corroboration against the retained finalization digest", () => {
  const w = world();
  try {
    const original = read(path.join(w.evidence, "kind-ledger.json"));
    substitute(w.evidence, "kind-ledger.json", { ...original, total: (original.total as number) + 1 });
    const report = verifyProvenance(w.evidence, w.retained.directory);
    assert.equal(report.levels.byteIntegrity, "VERIFIED", "the package is self-consistent: a checksum cannot tell");
    assert.equal(report.levels.independentCorroboration, "FAILED");
    assert.ok(report.problems.includes("independentCorroboration:finalization_digest_mismatch"));
    assert.equal(report.overall, "FAILED");
  } finally { cleanup(w); }
});

test("modified finalization artifacts: SHA256SUMS or manifest.json edited, an artifact edited without re-hashing, an unlisted artifact added", () => {
  const edits: [string, (w: World) => void, string][] = [
    ["sums line removed", (w) => { const p = path.join(w.evidence, "SHA256SUMS"); fs.writeFileSync(p, fs.readFileSync(p, "utf8").split("\n").filter((line) => !line.endsWith("  connections.json")).join("\n")); }, "byteIntegrity"],
    ["manifest edited", (w) => fs.appendFileSync(path.join(w.evidence, "manifest.json"), " "), "byteIntegrity"],
    ["artifact edited", (w) => fs.appendFileSync(path.join(w.evidence, "external.json"), " "), "byteIntegrity"],
    ["unlisted artifact", (w) => fs.writeFileSync(path.join(w.evidence, "kind-ledger-extra.json"), "{}"), "byteIntegrity"],
    ["artifact removed", (w) => fs.rmSync(path.join(w.evidence, "connections.json")), "byteIntegrity"],
  ];
  for (const [label, edit, level] of edits) {
    const w = world();
    try {
      edit(w);
      const report = verifyProvenance(w.evidence, w.retained.directory);
      assert.equal(report.overall, "FAILED", label);
      assert.equal(report.levels[level as "byteIntegrity"], "FAILED", label);
    } finally { cleanup(w); }
  }
});

test("replay: records retained for another run cannot vouch for this package (run id, commitment time, parameters)", () => {
  const a = world(); const b = world();
  try {
    const wrongRun = verifyProvenance(b.evidence, a.retained.directory);
    assert.equal(wrongRun.overall, "FAILED");
    assert.ok(wrongRun.problems.some((problem) => problem.startsWith("runBinding:beacon_run_id_mismatch") || problem.startsWith("runBinding:final_run_id_mismatch")), wrongRun.problems.join(","));
    // a commitment made AFTER the run started cannot have been made before it
    const late = world({}, { committedAt: new Date(Date.now() + 3_600_000).toISOString() });
    try { assert.ok(verifyProvenance(late.evidence, late.retained.directory).problems.includes("runBinding:commitment_not_before_run")); } finally { cleanup(late); }
  } finally { cleanup(a); cleanup(b); }
});

test("mismatched run identities: campaign, level, parameters and source revision must equal the pre-run commitment", () => {
  const cases: [string, Partial<CommitmentFields>, string][] = [
    ["campaign", { campaignId: "campaign-b" }, "runBinding:campaign_mismatch"], ["level", { levelId: "ba0-l7-c2" }, "runBinding:level_mismatch"],
    ["parameters", { paramsSha256: "d".repeat(64) }, "runBinding:parameters_mismatch"], ["git", { gitSha: "e".repeat(40) }, "runBinding:git_mismatch"],
  ];
  for (const [label, fields, problem] of cases) {
    const w = world({}, fields);
    try { const report = verifyProvenance(w.evidence, w.retained.directory); assert.ok(report.problems.includes(problem), `${label}: ${report.problems.join(",")}`); assert.equal(report.overall, "FAILED", label); } finally { cleanup(w); }
  }
  // a commitment edited after the fact no longer matches its seal
  const w = world();
  try {
    const file = path.join(w.retained.directory, "commitment.json");
    const commitment = read(file); commitment.campaignId = "campaign-b";
    fs.writeFileSync(file, JSON.stringify(commitment));
    assert.ok(verifyProvenance(w.evidence, w.retained.directory).problems.includes("runBinding:commitment_seal_mismatch"));
    assert.equal(commitmentSeal({ campaignId: "x", levelId: "y", paramsSha256: "z", gitSha: "g", committedAt: "t", nonce: "n" }).length, 64);
  } finally { cleanup(w); }
});

test("beacon chain: truncation, alteration, reordering, a rewritten journal and a missing store are all detected; absence never reads as consistent", () => {
  const lines = (w: World): string[] => fs.readFileSync(path.join(w.retained.directory, "beacons.ndjson"), "utf8").split("\n").filter(Boolean);
  const write = (w: World, items: string[]): void => fs.writeFileSync(path.join(w.retained.directory, "beacons.ndjson"), `${items.join("\n")}\n`);
  const run = (label: string, change: (w: World) => void, expected: string): void => {
    const w = world();
    try { change(w); const report = verifyProvenance(w.evidence, w.retained.directory); assert.equal(report.overall, "FAILED", label); assert.ok(report.problems.some((problem) => problem.startsWith(expected)), `${label}: ${report.problems.join(",")}`); } finally { cleanup(w); }
  };
  run("truncated chain", (w) => write(w, lines(w).slice(0, 2)), "independentCorroboration:final_beacon_count");
  run("altered digest", (w) => { const items = lines(w); const beacon = JSON.parse(items[0]) as { journalDigest: string }; beacon.journalDigest = "0".repeat(64); items[0] = JSON.stringify(beacon); write(w, items); }, "independentCorroboration:chain_broken");
  run("reordered", (w) => { const items = lines(w); write(w, [items[1], items[0], items[2]]); }, "independentCorroboration:beacon_sequence");
  run("journal rewritten after the beacons (accounting digest and package re-hashed consistently)", (w) => {
    const file = path.join(w.evidence, "ledger-journal-field.ndjson");
    const text = fs.readFileSync(file, "utf8").replace(/INGRESS_ACCEPTED/u, "INGRESS_ABORTED");
    fs.writeFileSync(file, text);
    const accounting = read(path.join(w.evidence, "accounting.json")) as { journal: { journalSha256: string } };
    accounting.journal.journalSha256 = sha(text);
    substitute(w.evidence, "accounting.json", accounting);
  }, "independentCorroboration:journal_prefix_mismatch");
  run("journal extended after the last beacon", (w) => {
    const file = path.join(w.evidence, "ledger-journal-field.ndjson");
    const text = `${fs.readFileSync(file, "utf8")}{"src":"p","rid":"x","seq":99,"k":"INGRESS_ACCEPTED"}\n`;
    fs.writeFileSync(file, text);
    const accounting = read(path.join(w.evidence, "accounting.json")) as { journal: { journalSha256: string; lines: number } };
    accounting.journal.journalSha256 = sha(text);
    substitute(w.evidence, "accounting.json", accounting);
  }, "independentCorroboration:");
  const none = world();
  try {
    fs.rmSync(none.retained.directory, { recursive: true, force: true });
    const report = verifyProvenance(none.evidence, none.retained.directory);
    assert.notEqual(report.overall, "CONSISTENT_WITH_RECORDS");
    assert.equal(report.overall, "INCOMPLETE");
    assert.equal(report.levels.independentCorroboration, "ABSENT");
  } finally { cleanup(none); }
});

test("a fully forged package whose actor also controls the retained records is CONSISTENT but is never described as authenticated or independent", () => {
  const w = world();
  try {
    // the same actor rewrites an artifact AND rebuilds the commitment, the beacon chain and the final record around the forgery
    const original = read(path.join(w.evidence, "kind-ledger.json"));
    substitute(w.evidence, "kind-ledger.json", { ...original, total: (original.total as number) + 7 });
    const forgedStore = new RetainedRecords(path.join(w.root, "forged-retained-store"));
    forgedStore.commit({ campaignId: "campaign-a", levelId: "ba0-l7-c1", paramsSha256: pinned, gitSha, committedAt: new Date(Date.now() - 3_600_000).toISOString(), nonce: "f".repeat(16) });
    announce(forgedStore, w.evidence, w.runId, 4);
    const report = verifyProvenance(w.evidence, forgedStore.directory);
    assert.equal(report.overall, "CONSISTENT_WITH_RECORDS", "the verifier cannot tell a same-actor forgery from an honest package");
    assert.equal(report.levels.authenticity, "UNVERIFIED");
    assert.equal(report.levels.producerIdentity, "CLAIMED_UNVERIFIED");
    assert.deepEqual(report.claims, { authenticated: false, independent: false });
    // and the honest store, which the forger did NOT control, exposes the same forgery
    assert.equal(verifyProvenance(w.evidence, w.retained.directory).overall, "FAILED");
  } finally { cleanup(w); }
});

test("the prototype is offline: no network, no process spawn, no key material, no signing", () => {
  const text = fs.readFileSync(path.join(REPOSITORY_ROOT, "lab/provenance/prototype.ts"), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
  assert.equal(/node:(?:http|https|net|child_process|dgram|tls)|createSign|createPrivateKey|generateKeyPair|createHmac|sign\(/u.test(text), false);
});
