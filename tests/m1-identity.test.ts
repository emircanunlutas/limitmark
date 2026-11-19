import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { m1TallyCheck } from "../lab/defense/ba0-m1-tally-check";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { IDENTITY_FIELDS, identityBlock, identityDifferences, identityDigest, identityFromPackage, parseIdentity } from "../lab/m1/identity";
import { writeFieldLikeEvidence } from "./support/m1-evidence-dir";
import { testRoot } from "./support/m1-world";

// The canonical identity is derived from the finalized package's verified bytes; nothing is taken from a directory name or from the result being bound.

const roots: string[] = [];
const fresh = (): string => { const root = testRoot("identity"); roots.push(root); return root; };
test.after(() => { for (const root of roots) fs.rmSync(root, { recursive: true, force: true }); });

test("a finalized package yields one nine-field identity; the finalization digest is the digest of SHA256SUMS", () => {
  const root = fresh(); const id = writeFieldLikeEvidence(root);
  const { identity, problems } = identityFromPackage(path.join(root, id));
  assert.deepEqual(problems, []);
  assert.deepEqual(Object.keys(identity!).sort(), [...IDENTITY_FIELDS].sort());
  assert.equal(identity!.runId, id);
  assert.equal(identity!.paramsId, "ba0-field-v1");
  assert.equal(identityDifferences(identity!, identity!).length, 0);
  assert.equal(identityDigest(identity!).length, 64);
  assert.deepEqual(parseIdentity(JSON.parse(JSON.stringify(identity))), identity);
});

test("fail closed: missing, tampered, unlisted or self-contradicting packages have no identity", () => {
  const cases: [string, (root: string) => string][] = [
    ["server-level missing", (root) => writeFieldLikeEvidence(root, { artifacts: { "server-level.json": null } })],
    ["core missing", (root) => writeFieldLikeEvidence(root, { artifacts: { "core.json": null } })],
    ["campaign disagrees across artifacts", (root) => writeFieldLikeEvidence(root, { mutate: { "core.json": (c) => { (c.level as { campaignId: string }).campaignId = "campaign-x"; } } })],
    ["level disagrees", (root) => writeFieldLikeEvidence(root, { mutate: { "core.json": (c) => { (c.level as { id: string }).id = "ba0-l7-c2"; } } })],
    ["parameters disagree", (root) => writeFieldLikeEvidence(root, { mutate: { "core.json": (c) => { (c.parameters as { sha256: string }).sha256 = "d".repeat(64); } } })],
    ["fixture disagrees", (root) => writeFieldLikeEvidence(root, { mutate: { "core.json": (c) => { c.workloadSha256 = "e".repeat(64); } } })],
    ["git disagrees", (root) => writeFieldLikeEvidence(root, { mutate: { "server-level.json": (c) => { c.gitSha = "f".repeat(40); } } })],
    ["unlisted artifact", (root) => writeFieldLikeEvidence(root, { unlisted: { "server-level-extra.json": "{}" } })],
    ["malformed server-level", (root) => writeFieldLikeEvidence(root, { rawArtifacts: { "server-level.json": "{" } })],
  ];
  for (const [label, build] of cases) {
    const root = fresh(); const id = build(root);
    const { identity, problems } = identityFromPackage(path.join(root, id));
    assert.equal(identity, null, label);
    assert.ok(problems.length > 0, label);
  }
});

test("the directory name is a consistency check, never the source: a renamed package has no identity", () => {
  const root = fresh(); const id = writeFieldLikeEvidence(root);
  const renamed = path.join(root, "20260101T000000Z-renamed-abcdef");
  fs.renameSync(path.join(root, id), renamed);
  const { identity, problems } = identityFromPackage(renamed);
  assert.equal(identity, null);
  assert.ok(problems.includes("directory_name_is_not_the_manifest_run_id"));
});

test("tampered bytes after finalization give no identity", () => {
  const root = fresh(); const id = writeFieldLikeEvidence(root);
  fs.appendFileSync(path.join(root, id, "core.json"), " ");
  assert.equal(identityFromPackage(path.join(root, id)).identity, null);
});

test("parseIdentity is strict: wrong keys, extra keys, bad hex, bad version", () => {
  const root = fresh(); const id = writeFieldLikeEvidence(root);
  const good = identityFromPackage(path.join(root, id)).identity!;
  const bad = (change: (value: Record<string, unknown>) => void): unknown => { const copy = { ...good } as Record<string, unknown>; change(copy); return parseIdentity(copy); };
  assert.equal(bad((v) => { v.extra = 1; }), null);
  assert.equal(bad((v) => { delete v.gitSha; }), null);
  assert.equal(bad((v) => { v.gitSha = "xyz"; }), null);
  assert.equal(bad((v) => { v.paramsSha256 = "A".repeat(64); }), null);
  assert.equal(bad((v) => { v.paramsVersion = 0; }), null);
  assert.equal(bad((v) => { v.runId = "has space"; }), null);
  assert.equal(parseIdentity(null), null);
  assert.equal(parseIdentity([]), null);
});

test("the existing result CLIs now carry the identity block of the package they evaluated (additive); a package without identity is reported, not guessed", () => {
  const root = fresh(); const id = writeFieldLikeEvidence(root);
  const outcome = m1TallyCheck({ serverId: id }, root);
  const artifact = JSON.parse(fs.readFileSync(path.join(root, outcome.evidenceId!, "m1-tally-check.json"), "utf8")) as { identity: unknown; identitySha256: string; tallyCheck: { outcome: string } };
  assert.deepEqual(artifact.identity, identityFromPackage(path.join(root, id)).identity);
  assert.equal(artifact.identitySha256, identityDigest(parseIdentity(artifact.identity)!));
  assert.equal(artifact.tallyCheck.outcome, "PASS", "the historical result is unchanged");
  const block = identityBlock(resolveEvidenceDirectory(id, root));
  assert.equal(block.identity !== null && block.identityProblems.length === 0, true);
  const broken = writeFieldLikeEvidence(root, { artifacts: { "core.json": null } });
  const missing = identityBlock(path.join(root, broken));
  assert.deepEqual([missing.identity, missing.identitySha256], [null, null]);
  assert.ok(missing.identityProblems.length > 0);
});
