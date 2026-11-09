import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { COMPONENT_FILES, COMPONENT_NAMES, evaluateAcceptance, m1AcceptRun, type AcceptanceInput, type ComponentName, type LoadedComponent } from "../lab/m1/acceptance";
import { identityBlock, identityDigest, identityFromPackage, type M1Identity } from "../lab/m1/identity";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { buildWorld, disposeWorld, syntheticResult, testRoot, type World } from "./support/m1-world";

// ADVERSARIAL REVIEW of the unified acceptance evaluator (review cycle; the evaluator is NOT modified).
// Tests named CONFIRMED_FALSE_PASS assert the CURRENT (defective) behavior so that a future correction flips them deliberately. Tests named HOLDS assert behavior that is correct today.
// Disposable local fixtures only. QUALIFIED must stay unreachable in every probe.

const read = (root: string, id: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(resolveEvidenceDirectory(id, root), file), "utf8")) as Record<string, unknown>;
type Loaded = Record<ComponentName, Record<string, unknown>>;
const inputOf = (world: World, artifacts: Loaded): AcceptanceInput => {
  const { identity, problems } = identityFromPackage(resolveEvidenceDirectory(world.serverId, world.root));
  return { packageIdentity: identity, packageProblems: problems, components: Object.fromEntries(COMPONENT_NAMES.map((name) => [name, { state: "loaded", artifact: artifacts[name] } satisfies LoadedComponent])) as AcceptanceInput["components"] };
};
const artifactsOf = (world: World): Loaded => Object.fromEntries(COMPONENT_NAMES.map((name) => [name, read(world.root, world.ids[name]!, COMPONENT_FILES[name])])) as Loaded;
const run = (input: AcceptanceInput) => { const result = evaluateAcceptance(input); assert.notEqual(result.outcome as string, "QUALIFIED"); assert.equal(result.qualification.reachable, false); return result; };

let GOOD: World; let BAD: World; let good: Loaded;
test.before(async () => {
  GOOD = await buildWorld(testRoot("adv-good")); good = artifactsOf(GOOD);
  // a world whose REAL observer evidence fails (the stand-in dropped a form submission) and whose package journal was rewritten after its digest was recorded
  BAD = await buildWorld(testRoot("adv-bad"), { faults: { drop: ["window.2.submit"] }, evidence: { journalMutator: (text) => text + "\n" } });
});
test.after(() => { for (const w of [GOOD, BAD]) { if (!w) continue; disposeWorld(w); fs.rmSync(w.root, { recursive: true, force: true }); } });

const forge = (world: World, name: ComponentName, body: Record<string, unknown>): string => syntheticResult(world.root, world.serverId, COMPONENT_FILES[name], body);

test("control: the genuine bad world is not accepted through the IO path (observer evidence really failed)", () => {
  assert.equal(m1AcceptRun({ serverId: BAD.serverId, resultIds: BAD.ids }, BAD.root).result.outcome === "LOCALLY_CONSISTENT", false);
});

test("CONFIRMED_FALSE_PASS 1-2: a forged PASS result carrying the (public) package identity and a correctly recomputed or copied identity hash is accepted; the evaluator trusts identity fields and never re-derives the verdict", () => {
  // the forger needs only the package identity, which is readable from the package itself
  const forged = { ...BAD.ids };
  forged.observation = forge(BAD, "observation", { observation: { outcome: "PASS", reasons: [] }, summary: null, limitations: [], inputs: {}, claims: {} });
  forged.provenance = forge(BAD, "provenance", { provenance: { overall: "CONSISTENT_WITH_RECORDS", levels: { byteIntegrity: "VERIFIED", artifactCompleteness: "VERIFIED", runBinding: "VERIFIED", producerIdentity: "CLAIMED_UNVERIFIED", independentCorroboration: "CONSISTENT", authenticity: "UNVERIFIED" } }, claims: { authenticated: false, independent: false } });
  forged.tally = forge(BAD, "tally", { tallyCheck: { outcome: "PASS", reasons: [] } });
  forged.receipts = forge(BAD, "receipts", { receiptCheck: { outcome: "PASS", reasons: [] } });
  const outcome = m1AcceptRun({ serverId: BAD.serverId, resultIds: forged }, BAD.root);
  assert.equal(outcome.result.outcome, "LOCALLY_CONSISTENT", "known gap: forged component results are accepted when they carry the package identity");
  // copied identity hash: the digest is a pure function of public fields, so copying it adds no protection
  const block = identityBlock(resolveEvidenceDirectory(BAD.serverId, BAD.root));
  assert.equal(block.identitySha256, identityDigest(block.identity as M1Identity));
});

test("CONFIRMED_FALSE_PASS 3: a genuine result with substituted payload fields (outcome flipped, reasons cleared, identity untouched) is accepted when presented as an artifact", () => {
  const tampered: Loaded = structuredClone(good);
  (tampered.observation.observation as Record<string, unknown>) = { outcome: "PASS", reasons: [] };
  (tampered.observation.summary as unknown) = { journeys: 0 };
  assert.equal(run(inputOf(GOOD, tampered)).outcome, "LOCALLY_CONSISTENT", "payload is not cross-checked against the recorded input digests");
});

test("HOLDS 4: a stale result replayed against a re-finalized package (same run id, different SHA256SUMS bytes) is rejected by the finalization digest", () => {
  const dir = resolveEvidenceDirectory(GOOD.serverId, GOOD.root);
  const sums = path.join(dir, "SHA256SUMS");
  const original = fs.readFileSync(sums);
  const lines = original.toString("utf8").split("\n").filter((l) => l.length > 0);
  try {
    fs.writeFileSync(sums, lines.reverse().join("\n") + "\n");
    const result = run(inputOf(GOOD, good));
    if (identityFromPackage(dir).identity === null) assert.equal(result.outcome, "ERROR", "reordering is itself refused");
    else { assert.equal(result.outcome, "REJECT"); assert.ok(result.reasons.some((r) => r.endsWith("identity_differs.finalizationSha256"))); }
  } finally { fs.writeFileSync(sums, original); }
});

test("CONFIRMED_FALSE_PASS 5: one forged result among genuine ones is enough; nothing cross-checks components against each other", () => {
  const mixed: Loaded = structuredClone(good);
  mixed.receipts = { ...mixed.receipts, receiptCheck: { outcome: "PASS", reasons: [] }, summary: "contradicts the tally" } as Record<string, unknown>;
  assert.equal(run(inputOf(GOOD, mixed)).outcome, "LOCALLY_CONSISTENT");
});

test("6a HOLDS: the package modified after evaluation gives no identity, so every previously written result is ERROR", () => {
  const dir = resolveEvidenceDirectory(GOOD.serverId, GOOD.root);
  const core = path.join(dir, "core.json"); const original = fs.readFileSync(core);
  try { fs.appendFileSync(core, " "); assert.equal(run(inputOf(GOOD, good)).outcome, "ERROR"); } finally { fs.writeFileSync(core, original); }
});

test("6b CONFIRMED_FALSE_PASS: observer and retained records modified after their result was written are not revalidated (the recorded input digests are never compared)", () => {
  const files = ["canary-results.json", "observation-meta.json"].map((f) => path.join(GOOD.observerDirectory, f));
  const originals = files.map((f) => fs.readFileSync(f));
  try {
    fs.writeFileSync(files[0], "{}");
    assert.equal(m1AcceptRun({ serverId: GOOD.serverId, resultIds: GOOD.ids }, GOOD.root).result.outcome, "LOCALLY_CONSISTENT", "inputs digests exist in the result but nothing re-reads the observer directory");
  } finally { files.forEach((f, i) => fs.writeFileSync(f, originals[i])); }
});

test("7 CONFIRMED_FALSE_PASS (minor): contradictory producer metadata (top-level runId of another run, empty inputs, missing claims) is ignored", () => {
  const odd: Loaded = structuredClone(good);
  odd.observation = { ...odd.observation, runId: "some-other-run", inputs: {} };
  delete (odd.provenance as Record<string, unknown>).claims;
  delete (odd.provenance as Record<string, unknown>).announcementSource;
  assert.equal(run(inputOf(GOOD, odd)).outcome, "LOCALLY_CONSISTENT");
});

test("8 HOLDS: a result with no identity block, a malformed block, a wrong digest or a wrong shape is ERROR; a missing result is INCOMPLETE", () => {
  for (const mutate of [(a: Record<string, unknown>) => { delete a.identity; }, (a: Record<string, unknown>) => { a.identity = { runId: "x" }; }, (a: Record<string, unknown>) => { a.identitySha256 = "0".repeat(64); }]) {
    const broken: Loaded = structuredClone(good); mutate(broken.tally); assert.equal(run(inputOf(GOOD, broken)).outcome, "ERROR");
  }
  const shaped: Loaded = structuredClone(good); shaped.receipts = { ...shaped.receipts, receiptCheck: "PASS" } as Record<string, unknown>;
  assert.equal(run(inputOf(GOOD, shaped)).outcome, "ERROR");
  const missing = inputOf(GOOD, good); delete missing.components.observation; assert.equal(run(missing).outcome, "INCOMPLETE");
});
