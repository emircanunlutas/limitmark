import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { COMPONENT_FILES, COMPONENT_NAMES, evaluateAcceptance, gatherAuthority, loadComponent, m1AcceptRun, type AcceptanceInput, type ComponentName, type LoadedComponent } from "../lab/m1/acceptance";
import { identityDigest, identityFromPackage, type M1Identity } from "../lab/m1/identity";
import { evaluatorSources, observedInputs, outputDigest, type InputSources } from "../lab/m1/result-provenance";
import { writeObservationResult, writeProvenanceResult } from "../lab/m1/results";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { buildWorld, disposeWorld, testRoot, type World } from "./support/m1-world";

// ADVERSARIAL REGRESSION for the unified acceptance evaluator after the false-PASS closure. The five paths confirmed in the previous review (forged PASS with a correct or copied identity,
// outcome/reasons changed after evaluation, one forged result among genuine ones, observer/retained records modified after evaluation, contradictory or missing metadata) must now
// be ERROR, REJECT or INCOMPLETE. A forger here is assumed to know the package identity AND the whole artifact format, and to re-seal every digest it can compute.

type Loaded = Record<ComponentName, Record<string, unknown>>;
const clone = <T,>(value: T): T => structuredClone(value);
const read = (root: string, id: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(resolveEvidenceDirectory(id, root), file), "utf8")) as Record<string, unknown>;
const artifactsOf = (world: World): Loaded => Object.fromEntries(COMPONENT_NAMES.map((name) => [name, read(world.root, world.ids[name]!, COMPONENT_FILES[name])])) as Loaded;
const identityOf = (world: World): { identity: M1Identity | null; problems: string[] } => identityFromPackage(resolveEvidenceDirectory(world.serverId, world.root));
function inputOf(world: World, artifacts: Partial<Loaded>, sources: InputSources = world.sources): AcceptanceInput {
  const { identity, problems } = identityOf(world);
  return { packageIdentity: identity, packageProblems: problems, authority: gatherAuthority(identity, sources), components: Object.fromEntries(COMPONENT_NAMES.filter((name) => artifacts[name] !== undefined).map((name) => [name, { state: "loaded", artifact: artifacts[name] } satisfies LoadedComponent])) as AcceptanceInput["components"] };
}
const run = (input: AcceptanceInput) => { const result = evaluateAcceptance(input); assert.notEqual(result.outcome as string, "QUALIFIED"); assert.equal(result.qualification.reachable, false); return result; };
const notAccepted = (outcome: string): void => assert.ok(["ERROR", "REJECT", "INCOMPLETE"].includes(outcome), outcome);
/** The most capable forger: recomputes every digest it can (output digest, identity digest) and rewrites the declared inputs to the bytes of `world`. */
function reseal(world: World, name: ComponentName, artifact: Record<string, unknown>): Record<string, unknown> {
  const out = clone(artifact); const { identity } = identityOf(world);
  out.identity = identity; out.identitySha256 = identityDigest(identity!);
  if ("runId" in out) out.runId = world.serverId;
  const block = out.resultProvenance as Record<string, unknown>;
  block.inputs = observedInputs(name, world.sources); block.evaluator = { contract: (block.evaluator as { contract: string }).contract, sources: evaluatorSources(name) };
  block.outputSha256 = outputDigest(out);
  return out;
}
const resealOnly = (artifact: Record<string, unknown>): Record<string, unknown> => { const out = clone(artifact); (out.resultProvenance as Record<string, unknown>).outputSha256 = outputDigest(out); return out; };

let GOOD: World; let BAD: World; let OTHER: World; let good: Loaded; let bad: Loaded;
test.before(async () => {
  GOOD = await buildWorld(testRoot("adv-good")); good = artifactsOf(GOOD);
  OTHER = await buildWorld(testRoot("adv-other"));
  // a world whose REAL observer evidence fails and whose journal was rewritten after its digest was recorded
  BAD = await buildWorld(testRoot("adv-bad"), { faults: { drop: ["window.2.submit"] }, evidence: { journalMutator: (text) => text + "\n" } }); bad = artifactsOf(BAD);
});
test.after(() => { for (const w of [GOOD, BAD, OTHER]) { if (!w) continue; disposeWorld(w); fs.rmSync(w.root, { recursive: true, force: true }); } });

test("positive control: genuine evidence with every authoritative input available is LOCALLY_CONSISTENT through the IO path, and QUALIFIED stays unreachable", () => {
  const direct = run(inputOf(GOOD, good));
  assert.deepEqual([direct.outcome, direct.reasons], ["LOCALLY_CONSISTENT", []]);
  const outcome = m1AcceptRun({ serverId: GOOD.serverId, resultIds: GOOD.ids, generatorReportPath: GOOD.reportPath, observerDirectory: GOOD.observerDirectory, retainedDirectory: GOOD.retainedDirectory }, GOOD.root);
  assert.equal(outcome.result.outcome, "LOCALLY_CONSISTENT");
  assert.equal(run(inputOf(GOOD, good)).provenanceLevels!.authenticity, "UNVERIFIED");
});

test("control: the bad world really fails (observer and ledger evidence) and is not accepted", () => {
  const result = run(inputOf(BAD, bad));
  assert.notEqual(result.outcome, "LOCALLY_CONSISTENT");
  assert.ok(result.reasons.includes("m1.accept.observation.not_passed"), result.reasons.join(","));
});

test("FIXED 1-2: forged PASS results with the correct identity, a recomputed or copied identity hash, and re-sealed digests are not accepted", () => {
  // the forger takes the GOOD world's genuine artifacts and rebinds every one of them to the BAD package, re-sealing all digests it can compute
  const forged = Object.fromEntries(COMPONENT_NAMES.map((name) => [name, reseal(BAD, name, good[name])])) as Loaded;
  const result = run(inputOf(BAD, forged));
  notAccepted(result.outcome);
  assert.ok(result.reasons.some((reason) => reason.endsWith("supplied_result_disagrees_with_recomputation")), result.reasons.join(","));
  // the identity hash is an unkeyed function of public fields: a copied hash binds nothing
  const { identity } = identityOf(BAD);
  assert.equal(forged.observation.identitySha256, identityDigest(identity!));
  // a forged observation PASS that also declares BAD's real observer bytes still disagrees with the recomputed REJECT
  assert.equal(run(inputOf(BAD, { ...bad, observation: forged.observation })).components.observation, "ERROR");
});

test("FIXED 3: a genuine result with substituted payload fields (outcome flipped, reasons cleared) is ERROR whether or not the output digest is re-sealed", () => {
  const flipped = clone(bad); const block = flipped.observation.observation as Record<string, unknown>; block.outcome = "PASS"; block.reasons = [];
  const unsealed = run(inputOf(BAD, flipped));
  assert.ok(unsealed.reasons.includes("m1.accept.observation.result_provenance.output_digest"));
  flipped.observation = resealOnly(flipped.observation);
  const sealed = run(inputOf(BAD, flipped));
  assert.deepEqual([sealed.outcome, sealed.reasons.includes("m1.accept.observation.supplied_result_disagrees_with_recomputation")], ["ERROR", true]);
});

test("FIXED 4: a stale result replayed against a re-finalized package (same run id, different SHA256SUMS bytes) is not accepted", () => {
  const dir = resolveEvidenceDirectory(GOOD.serverId, GOOD.root); const sums = path.join(dir, "SHA256SUMS"); const original = fs.readFileSync(sums);
  try {
    fs.writeFileSync(sums, original.toString("utf8").split("\n").filter((line) => line.length > 0).reverse().join("\n") + "\n");
    const result = run(inputOf(GOOD, good));
    notAccepted(result.outcome);
    if (identityOf(GOOD).identity !== null) assert.ok(result.reasons.some((reason) => reason.endsWith("identity_differs.finalizationSha256")));
  } finally { fs.writeFileSync(sums, original); }
  // results of another run (another finalization) in the right slots
  for (const name of COMPONENT_NAMES) { const swapped = clone(good); swapped[name] = artifactsOf(OTHER)[name]; assert.equal(run(inputOf(GOOD, swapped)).outcome, "REJECT", name); }
});

test("FIXED 5: one forged component among genuine ones makes the whole set ERROR; nothing is averaged or tolerated", () => {
  for (const name of COMPONENT_NAMES) {
    const mixed = clone(bad); mixed[name] = reseal(BAD, name, good[name]);
    if (JSON.stringify(mixed[name]) === JSON.stringify(bad[name])) continue; // a component that is genuinely identical needs no forgery
    notAccepted(run(inputOf(BAD, mixed)).outcome);
  }
  const mixed = clone(good); (mixed.receipts.receiptCheck as Record<string, unknown>).reasons = ["m1.receipt.x"];
  assert.notEqual(run(inputOf(GOOD, mixed)).outcome, "LOCALLY_CONSISTENT");
});

test("FIXED 6: result tampering after evaluation, and observer/retained records modified after evaluation, are detected", () => {
  // 6a package bytes
  const dir = resolveEvidenceDirectory(GOOD.serverId, GOOD.root); const core = path.join(dir, "core.json"); const originalCore = fs.readFileSync(core);
  try { fs.appendFileSync(core, " "); assert.equal(run(inputOf(GOOD, good)).outcome, "ERROR"); } finally { fs.writeFileSync(core, originalCore); }
  // 6b observer records
  const canary = path.join(GOOD.observerDirectory, "canary-results.json"); const originalCanary = fs.readFileSync(canary);
  try {
    fs.writeFileSync(canary, "{}");
    const result = run(inputOf(GOOD, good)); notAccepted(result.outcome);
    assert.ok(result.reasons.includes("m1.accept.observation.result_provenance.inputs_not_the_bytes_read"), result.reasons.join(","));
    assert.notEqual(m1AcceptRun({ serverId: GOOD.serverId, resultIds: GOOD.ids, generatorReportPath: GOOD.reportPath, observerDirectory: GOOD.observerDirectory, retainedDirectory: GOOD.retainedDirectory }, GOOD.root).result.outcome, "LOCALLY_CONSISTENT");
  } finally { fs.writeFileSync(canary, originalCanary); }
  // 6c retained provenance records
  const beacons = path.join(GOOD.retainedDirectory, "beacons.ndjson"); const originalBeacons = fs.readFileSync(beacons);
  try { fs.writeFileSync(beacons, ""); const result = run(inputOf(GOOD, good)); notAccepted(result.outcome); assert.ok(result.reasons.includes("m1.accept.provenance.result_provenance.inputs_not_the_bytes_read")); } finally { fs.writeFileSync(beacons, originalBeacons); }
  // 6d the result file itself, through the strict loader
  const target = path.join(resolveEvidenceDirectory(GOOD.ids.tally!, GOOD.root), COMPONENT_FILES.tally); const originalTally = fs.readFileSync(target);
  try { fs.appendFileSync(target, " "); assert.equal(loadComponent(GOOD.root, GOOD.ids.tally, "tally").state, "unreadable"); } finally { fs.writeFileSync(target, originalTally); }
  assert.equal(run(inputOf(GOOD, good)).outcome, "LOCALLY_CONSISTENT", "the originals were restored");
});

test("FIXED 6e-f: replaced observer evidence and replaced provenance records: stale results fail on the bytes; genuine results over the replacements are REJECT", () => {
  const swappedObserver: InputSources = { ...GOOD.sources, observerDirectory: OTHER.observerDirectory };
  assert.ok(run(inputOf(GOOD, good, swappedObserver)).reasons.includes("m1.accept.observation.result_provenance.inputs_not_the_bytes_read"));
  const rerun = { ...good, observation: read(GOOD.root, writeObservationResult(GOOD.serverId, OTHER.observerDirectory, GOOD.root).evidenceId, COMPONENT_FILES.observation) };
  assert.equal(run(inputOf(GOOD, rerun, swappedObserver)).outcome, "REJECT", "another run's observer records: foreign run and campaign receipts");
  const swappedRetained: InputSources = { ...GOOD.sources, retainedDirectory: OTHER.retainedDirectory };
  assert.ok(run(inputOf(GOOD, good, swappedRetained)).reasons.includes("m1.accept.provenance.result_provenance.inputs_not_the_bytes_read"));
  const rerunProvenance = { ...good, provenance: read(GOOD.root, writeProvenanceResult(GOOD.serverId, OTHER.retainedDirectory, GOOD.root).evidenceId, COMPONENT_FILES.provenance) };
  assert.equal(run(inputOf(GOOD, rerunProvenance, swappedRetained)).outcome, "REJECT", "another run's retained records: run binding fails");
});

test("FIXED 7-9: contradictory or missing metadata, missing or empty input declarations, changed evaluator metadata and forged output digests are ERROR", () => {
  const mutated = (name: ComponentName, change: (a: Record<string, unknown>) => void, seal = true): Loaded => { const copy = clone(good); change(copy[name]); if (seal) copy[name] = resealOnly(copy[name]); return copy; };
  const block = (a: Record<string, unknown>): Record<string, unknown> => a.resultProvenance as Record<string, unknown>;
  const cases: [string, ComponentName, (a: Record<string, unknown>) => void, string][] = [
    ["top-level runId of another run", "tally", (a) => { a.runId = "some-other-run"; }, "schema.run_id_not_bound"],
    ["claims removed", "receipts", (a) => { delete a.claims; }, "schema.keys_not_closed"],
    ["claims overclaim", "observation", (a) => { (a.claims as Record<string, unknown>).independentCustody = "established"; }, "schema.claims_overclaim"],
    ["unexpected extra key", "tally", (a) => { a.extra = 1; }, "schema.keys_not_closed"],
    ["contract string", "receipts", (a) => { a.contract = "m1-receipt-check-v2"; }, "schema.contract_unexpected"],
    ["overlay run binding", "overlay", (a) => { (a.inputs as { server: { runId: string } }).server.runId = "other"; }, "schema.run_id_not_bound"],
    ["inputs removed", "tally", (a) => { delete block(a).inputs; }, "schema.result_provenance_missing_or_open"],
    ["inputs empty", "tally", (a) => { block(a).inputs = []; }, "result_provenance.inputs_empty"],
    ["one input digest missing", "observation", (a) => { block(a).inputs = (block(a).inputs as unknown[]).slice(1); }, "result_provenance.inputs_not_the_bytes_read"],
    ["one input digest changed", "receipts", (a) => { (block(a).inputs as { sha256: string }[])[0].sha256 = "0".repeat(64); }, "result_provenance.inputs_not_the_bytes_read"],
    ["evaluator contract changed", "tally", (a) => { (block(a).evaluator as { contract: string }).contract = "m1-tally-check-v2"; }, "result_provenance.evaluator_contract"],
    ["evaluator source changed", "overlay", (a) => { (block(a).evaluator as { sources: { gitBlobId: string }[] }).sources[0].gitBlobId = "git.blob." + "1".repeat(40); }, "result_provenance.evaluator_source_changed"],
    ["producer claim verified", "provenance", (a) => { block(a).producerClaim = { claimed: "local.evaluator.process", verified: true }; }, "result_provenance.producer_claim"],
    ["component label", "tally", (a) => { block(a).component = "receipts"; }, "result_provenance.component"],
    ["timestamp malformed", "tally", (a) => { block(a).evaluatedAt = "yesterday"; }, "result_provenance.evaluated_at"],
  ];
  for (const [label, name, change, reason] of cases) {
    const result = run(inputOf(GOOD, mutated(name, change)));
    assert.equal(result.outcome, "ERROR", label);
    assert.ok(result.reasons.includes(`m1.accept.${name}.${reason}`), `${label}: ${result.reasons.join(",")}`);
  }
  const forgedDigest = mutated("tally", (a) => { block(a).outputSha256 = "f".repeat(64); }, false);
  assert.ok(run(inputOf(GOOD, forgedDigest)).reasons.includes("m1.accept.tally.result_provenance.output_digest"));
  // the digest covers the artifact without its own block: editing any other field breaks it
  const edited = clone(good); edited.tally.scope = "edited"; assert.ok(run(inputOf(GOOD, edited)).reasons.includes("m1.accept.tally.result_provenance.output_digest"));
});

test("FIXED 13: contradictory outcome and reasons (re-sealed) disagree with the recomputation", () => {
  const contradictory = clone(good); const check = contradictory.tally.tallyCheck as Record<string, unknown>; check.reasons = ["m1.tally.x"]; contradictory.tally = resealOnly(contradictory.tally);
  assert.ok(run(inputOf(GOOD, contradictory)).reasons.includes("m1.accept.tally.supplied_result_disagrees_with_recomputation"));
  const rejectNoReasons = clone(good); (rejectNoReasons.receipts.receiptCheck as Record<string, unknown>).outcome = "REJECT"; rejectNoReasons.receipts = resealOnly(rejectNoReasons.receipts);
  assert.ok(run(inputOf(GOOD, rejectNoReasons)).reasons.includes("m1.accept.receipts.supplied_result_disagrees_with_recomputation"));
  const material = clone(good); (material.receipts.identities as { ok: boolean }[])[0].ok = false; material.receipts = resealOnly(material.receipts);
  assert.ok(run(inputOf(GOOD, material)).reasons.includes("m1.accept.receipts.supplied_result_disagrees_with_recomputation"), "material claims (identities) are compared, not just the verdict");
});

test("FIXED 14: missing authoritative inputs make the component INCOMPLETE; nothing is fabricated", () => {
  const noReport = run(inputOf(GOOD, good, { ...GOOD.sources, generatorReportPath: null }));
  assert.equal(noReport.outcome, "INCOMPLETE");
  assert.ok(noReport.reasons.includes("m1.accept.overlay.recomputation_inputs_unavailable"), noReport.reasons.join(","));
  assert.equal(run(inputOf(GOOD, good, { ...GOOD.sources, observerDirectory: null })).outcome, "INCOMPLETE");
  assert.equal(run(inputOf(GOOD, good, { ...GOOD.sources, retainedDirectory: null })).outcome, "INCOMPLETE");
  const unreadable = run(inputOf(GOOD, good, { ...GOOD.sources, generatorReportPath: path.join(GOOD.reportDirectory, "absent", "generator-report.json") }));
  assert.equal(unreadable.outcome, "INCOMPLETE");
  const absentAuthority = { ...inputOf(GOOD, good), authority: undefined };
  assert.equal(run(absentAuthority).outcome, "INCOMPLETE", "no authority at all: nothing can be accepted");
});

test("a forged result-provenance block cannot substitute for recomputation: a complete, resealed block over a lie still disagrees", () => {
  const lie = clone(bad); lie.observation = reseal(BAD, "observation", good.observation);
  const result = run(inputOf(BAD, lie));
  assert.equal(result.components.observation, "ERROR");
  assert.ok(result.reasons.includes("m1.accept.observation.supplied_result_disagrees_with_recomputation"));
});
