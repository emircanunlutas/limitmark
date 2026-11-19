import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { COMPONENT_FILES, COMPONENT_NAMES, QUALIFICATION_BLOCKERS, evaluateAcceptance, gatherAuthority, loadComponent, m1AcceptRun, type AcceptanceInput, type ComponentName, type LoadedComponent } from "../lab/m1/acceptance";
import { IDENTITY_FIELDS, identityDigest, identityFromPackage, parseIdentity, type M1Identity } from "../lab/m1/identity";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { outputDigest } from "../lab/m1/result-provenance";
import { writeProvenanceResult } from "../lab/m1/results";
import { buildWorld, disposeWorld, syntheticResult, testRoot, type World } from "./support/m1-world";

// Unified M1 acceptance prototype: identity binding across every component, fail-closed behavior, and QUALIFIED unreachable.

const clone = <T,>(value: T): T => structuredClone(value);
const read = (root: string, id: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(resolveEvidenceDirectory(id, root), file), "utf8")) as Record<string, unknown>;

type Loaded = Record<ComponentName, Record<string, unknown>>;
function inputOf(world: World, artifacts: Loaded): AcceptanceInput {
  const { identity, problems } = identityFromPackage(resolveEvidenceDirectory(world.serverId, world.root));
  return { packageIdentity: identity, packageProblems: problems, authority: gatherAuthority(identity, world.sources), components: Object.fromEntries(COMPONENT_NAMES.map((name) => [name, { state: "loaded", artifact: artifacts[name] } satisfies LoadedComponent])) as AcceptanceInput["components"] };
}
const artifactsOf = (world: World): Loaded => Object.fromEntries(COMPONENT_NAMES.map((name) => [name, read(world.root, world.ids[name]!, COMPONENT_FILES[name])])) as Loaded;
/** Re-seals an identity edit exactly as a careful forger would (digest recomputed). */
function reidentify(artifact: Record<string, unknown>, change: (identity: M1Identity) => void): Record<string, unknown> {
  const copy = clone(artifact); const identity = parseIdentity(copy.identity)!; change(identity); copy.identity = identity; copy.identitySha256 = identityDigest(identity); return copy;
}

let A: World; let B: World; let artifactsA: Loaded; let artifactsB: Loaded;
test.before(async () => { A = await buildWorld(testRoot("accept-a")); B = await buildWorld(testRoot("accept-b")); artifactsA = artifactsOf(A); artifactsB = artifactsOf(B); });
test.after(() => { for (const w of [A, B]) { if (!w) continue; disposeWorld(w); fs.rmSync(w.root, { recursive: true, force: true }); } });

const never = (outcome: string): void => assert.notEqual(outcome, "QUALIFIED");
const run = (input: AcceptanceInput) => { const result = evaluateAcceptance(input); never(result.outcome); assert.equal(result.qualification.reachable, false); return result; };

test("genuine local evidence for one run is LOCALLY_CONSISTENT, bound to one nine-field identity, and is not represented as authenticated, independent or qualified", () => {
  const result = run(inputOf(A, artifactsA));
  assert.deepEqual([result.outcome, result.reasons], ["LOCALLY_CONSISTENT", []]);
  assert.deepEqual(Object.values(result.components), ["PASS", "PASS", "PASS", "PASS", "PASS"]);
  assert.deepEqual(Object.keys(result.identity!).sort(), [...IDENTITY_FIELDS].sort());
  assert.equal(result.provenanceLevels!.authenticity, "UNVERIFIED");
  assert.equal(result.provenanceLevels!.producerIdentity, "CLAIMED_UNVERIFIED");
  assert.ok(QUALIFICATION_BLOCKERS.includes("independent_custody_not_established") && QUALIFICATION_BLOCKERS.includes("authorized_external_lane_qualification_absent"));
  assert.deepEqual(result.qualification.blockers, QUALIFICATION_BLOCKERS);
});

test("the same result through the IO path writes an additive artifact that claims neither authenticity nor custody", () => {
  const outcome = m1AcceptRun({ serverId: A.serverId, resultIds: A.ids, generatorReportPath: A.reportPath, observerDirectory: A.observerDirectory, retainedDirectory: A.retainedDirectory }, A.root);
  assert.equal(outcome.result.outcome, "LOCALLY_CONSISTENT");
  const written = read(A.root, outcome.evidenceId, "m1-acceptance.json") as { acceptance: { outcome: string }; claims: Record<string, string>; qualification: { reachable: boolean }; identity: M1Identity };
  assert.deepEqual([written.acceptance.outcome, written.qualification.reachable, written.claims.authenticity, written.claims.independentCustody], ["LOCALLY_CONSISTENT", false, "not_claimed", "not_established"]);
  assert.equal(written.identity.runId, A.serverId);
});

test("mixed evidence: a component of another run, campaign, commit, parameter set, fixture or finalization is never accepted (even with a recomputed identity digest)", () => {
  for (const name of COMPONENT_NAMES) {
    const mixed = clone(artifactsA); mixed[name] = artifactsB[name];
    const result = run(inputOf(A, mixed));
    assert.equal(result.outcome, "REJECT", name);
    assert.ok(result.reasons.includes(`m1.accept.${name}.identity_mismatch`) && result.reasons.includes(`m1.accept.${name}.identity_differs.runId`), `${name}: ${result.reasons.join(",")}`);
  }
  const fields: [string, (identity: M1Identity) => void][] = [
    ["campaignId", (i) => { i.campaignId = "campaign-b"; }], ["levelId", (i) => { i.levelId = "ba0-l7-c2"; }], ["gitSha", (i) => { i.gitSha = "e".repeat(40); }], ["paramsSha256", (i) => { i.paramsSha256 = "d".repeat(64); }],
    ["paramsVersion", (i) => { i.paramsVersion = 2; }], ["paramsId", (i) => { i.paramsId = "ba0-field-v2"; }], ["workloadSha256", (i) => { i.workloadSha256 = "9".repeat(64); }], ["finalizationSha256", (i) => { i.finalizationSha256 = "f".repeat(64); }], ["runId", (i) => { i.runId = "run-b"; }],
  ];
  for (const [field, change] of fields) {
    for (const name of COMPONENT_NAMES) {
      const forged = clone(artifactsA); forged[name] = reidentify(artifactsA[name], change);
      const result = run(inputOf(A, forged));
      assert.equal(result.outcome, "REJECT", `${name}/${field}`);
      assert.ok(result.reasons.includes(`m1.accept.${name}.identity_differs.${field}`), `${name}/${field}: ${result.reasons.join(",")}`);
    }
  }
  // an identity edited WITHOUT recomputing the digest is an inconsistent block, not a mismatch to be argued about
  const sloppy = clone(artifactsA); (sloppy.tally.identity as M1Identity).campaignId = "campaign-b";
  assert.deepEqual([run(inputOf(A, sloppy)).outcome, run(inputOf(A, sloppy)).reasons.includes("m1.accept.tally.identity_digest_inconsistent")], ["ERROR", true]);
});

test("missing producer contract: a result without an identity block, or with a malformed one, is ERROR and is named", () => {
  for (const name of COMPONENT_NAMES) {
    const without = clone(artifactsA); delete without[name].identity; delete without[name].identitySha256;
    const result = run(inputOf(A, without));
    assert.equal(result.outcome, "ERROR", name);
    assert.ok(result.reasons.includes(`m1.accept.${name}.identity_missing.producer_contract`), name);
    const malformed = clone(artifactsA); malformed[name].identity = { runId: "x" };
    assert.equal(run(inputOf(A, malformed)).outcome, "ERROR", name);
  }
  const noPackage = run({ ...inputOf(A, artifactsA), packageIdentity: null, packageProblems: ["missing:core.json"] });
  assert.equal(noPackage.outcome, "ERROR");
});

test("missing components are INCOMPLETE and named; nothing is defaulted", () => {
  for (const name of COMPONENT_NAMES) {
    const input = inputOf(A, artifactsA); delete input.components[name];
    const result = run(input);
    assert.equal(result.outcome, "INCOMPLETE", name);
    assert.deepEqual(result.reasons, [`m1.accept.${name}.absent`]);
    assert.equal(result.components[name], "ABSENT");
  }
  const none = run({ ...inputOf(A, artifactsA), components: {} });
  assert.equal(none.outcome, "INCOMPLETE");
  assert.equal(none.reasons.length, 5);
});

test("a component that genuinely did not pass is REJECT: failed overlay, criterion 9 rejection, receipt reconciliation, failed origin observation, failed or replayed provenance (each produced by the REAL writers on altered evidence)", async () => {
  const worlds: [ComponentName, Parameters<typeof buildWorld>[1]][] = [
    ["overlay", { evidence: { mutate: { "server-level.json": (c) => { (c.reconcileInput as Record<string, number>).externalAccepted += 1; } } } }],
    ["tally", { evidence: { mutate: { "kind-ledger.json": (c) => { (c.counts as Record<string, number>).INGRESS_ACCEPTED += 1; } } } }],
    ["receipts", { evidence: { mutate: { "processes.json": (c) => { ((c.app as { stats: { counters: Record<string, number> } }).stats.counters).executed += 1; } } } }],
    ["observation", { faults: { drop: ["window.2.submit"] } }],
  ];
  for (const [name, options] of worlds) {
    const world = await buildWorld(testRoot("accept-fail-" + name), options);
    try {
      const result = run(inputOf(world, artifactsOf(world)));
      assert.equal(result.outcome, "REJECT", `${name}: ${result.reasons.join(",")}`);
      assert.ok(result.reasons.includes(`m1.accept.${name}.not_passed`), `${name}: ${result.reasons.join(",")}`);
    } finally { disposeWorld(world); fs.rmSync(world.root, { recursive: true, force: true }); }
  }
  // failed provenance: the retained commitment names another commit; the REAL verifier and writer record FAILED, and acceptance recomputes the same
  const world = await buildWorld(testRoot("accept-fail-provenance"));
  try {
    const commitmentFile = path.join(world.retainedDirectory, "commitment.json");
    const commitment = JSON.parse(fs.readFileSync(commitmentFile, "utf8")) as Record<string, unknown>; commitment.gitSha = "e".repeat(40); fs.writeFileSync(commitmentFile, JSON.stringify(commitment));
    const ids = { ...world.ids, provenance: writeProvenanceResult(world.serverId, world.retainedDirectory, world.root).evidenceId };
    const result = run(inputOf(world, Object.fromEntries(COMPONENT_NAMES.map((name) => [name, read(world.root, ids[name]!, COMPONENT_FILES[name])])) as Loaded));
    assert.equal(result.outcome, "REJECT"); assert.ok(result.reasons.includes("m1.accept.provenance.not_passed"));
  } finally { disposeWorld(world); fs.rmSync(world.root, { recursive: true, force: true }); }
  // provenance carried over from another run (a replay) is bound to the wrong package
  const replayed = clone(artifactsA); replayed.provenance = artifactsB.provenance;
  assert.equal(run(inputOf(A, replayed)).outcome, "REJECT");
});

test("a provenance result may never claim authenticity or independence: an unsealed edit fails the output digest, a re-sealed one disagrees with the recomputation, a claim edit fails the closed claims", () => {
  const reseal = (a: Record<string, unknown>): Record<string, unknown> => { (a.resultProvenance as Record<string, unknown>).outputSha256 = outputDigest(a); return a; };
  const over = clone(artifactsA); (over.provenance.provenance as { levels: Record<string, string> }).levels.authenticity = "VERIFIED";
  assert.ok(run(inputOf(A, over)).reasons.includes("m1.accept.provenance.result_provenance.output_digest"));
  const resealed = clone(artifactsA); (resealed.provenance.provenance as { levels: Record<string, string> }).levels.authenticity = "VERIFIED"; reseal(resealed.provenance);
  assert.deepEqual([run(inputOf(A, resealed)).outcome, run(inputOf(A, resealed)).reasons.includes("m1.accept.provenance.supplied_result_disagrees_with_recomputation")], ["ERROR", true]);
  for (const key of ["independent", "authenticated"]) {
    const claimed = clone(artifactsA); (claimed.provenance.claims as Record<string, unknown>)[key] = true; reseal(claimed.provenance);
    const result = run(inputOf(A, claimed)); assert.equal(result.outcome, "ERROR"); assert.ok(result.reasons.includes("m1.accept.provenance.schema.claims_overclaim"));
  }
});

test("malformed or untrusted result artifacts are ERROR: tampered bytes, unlisted files, duplicate keys, wrong shape", () => {
  // bytes changed after finalization: the strict loader refuses them
  const tampered = syntheticResult(A.root, A.serverId, COMPONENT_FILES.receipts, { receiptCheck: { outcome: "PASS", reasons: [] } });
  fs.appendFileSync(path.join(resolveEvidenceDirectory(tampered, A.root), COMPONENT_FILES.receipts), " ");
  assert.equal(loadComponent(A.root, tampered, "receipts").state, "unreadable");
  const viaCli = m1AcceptRun({ serverId: A.serverId, resultIds: { ...A.ids, receipts: tampered }, generatorReportPath: A.reportPath, observerDirectory: A.observerDirectory, retainedDirectory: A.retainedDirectory }, A.root);
  assert.equal(viaCli.result.outcome, "ERROR");
  never(viaCli.result.outcome);
  // an unlisted extra artifact next to a result
  const extra = syntheticResult(A.root, A.serverId, COMPONENT_FILES.receipts, { receiptCheck: { outcome: "PASS", reasons: [] } });
  fs.writeFileSync(path.join(resolveEvidenceDirectory(extra, A.root), "replacement.json"), "{}");
  assert.equal(loadComponent(A.root, extra, "receipts").state, "unreadable");
  // wrong shapes
  for (const name of COMPONENT_NAMES) {
    const shapeless = clone(artifactsA);
    for (const key of Object.keys(shapeless[name])) if (!["identity", "identitySha256", "runId"].includes(key)) delete shapeless[name][key];
    assert.equal(run(inputOf(A, shapeless)).outcome, "ERROR", name);
  }
  assert.equal(evaluateAcceptance(null as unknown as AcceptanceInput).outcome, "ERROR");
  assert.equal(run({ ...inputOf(A, artifactsA), components: { tally: { state: "unreadable", problems: ["x"] } } }).outcome, "ERROR");
});

test("QUALIFIED is unreachable: no code path, no flag, no input; exhaustive over every component state combination", () => {
  const text = fs.readFileSync(path.join(__dirname, "..", "lab", "m1", "acceptance.ts"), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "").replace(/\/\/.*$/gmu, "");
  assert.equal([...text.matchAll(/"QUALIFIED"/gu)].length, 1, "the only mention is the member of the outcome type");
  assert.equal(/return finish\("QUALIFIED"|outcome\s*=\s*"QUALIFIED"|independent\s*[:=]\s*true|bypass|override|force/iu.test(text), false);
  assert.equal(/export type AcceptCli = \{ serverId: string; resultIds: Partial<Record<ComponentName, string>>; generatorReportPath\?: string \| null; observerDirectory\?: string \| null; retainedDirectory\?: string \| null \}/u.test(text), true, "the CLI takes ids and input LOCATIONS only: no assertion flags");
  const states: LoadedComponent[] = [{ state: "absent" }, { state: "unreadable", problems: [] }, { state: "loaded", artifact: null }, { state: "loaded", artifact: {} }];
  let combinations = 0;
  const walk = (index: number, current: Partial<Record<ComponentName, LoadedComponent>>): void => {
    if (index === COMPONENT_NAMES.length) { combinations++; never(evaluateAcceptance({ ...inputOf(A, artifactsA), components: current }).outcome); return; }
    for (const state of states) walk(index + 1, { ...current, [COMPONENT_NAMES[index]]: state });
    walk(index + 1, { ...current, [COMPONENT_NAMES[index]]: { state: "loaded", artifact: artifactsA[COMPONENT_NAMES[index]] } });
  };
  walk(0, {});
  assert.equal(combinations, 5 ** 5);
});
