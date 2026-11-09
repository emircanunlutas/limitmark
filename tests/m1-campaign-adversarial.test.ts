import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { BA0_FIELD_V1, ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { COMPONENT_FILES, COMPONENT_NAMES, m1AcceptRun, type ComponentName } from "../lab/m1/acceptance";
import { m1LocalCampaign } from "../lab/m1/campaign";
import { identityBlock, identityDigest, type M1Identity } from "../lab/m1/identity";
import { evaluatorSources, observedInputs, outputDigest } from "../lab/m1/result-provenance";
import { EvidenceRun, collectEnvironment, collectGitState, resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { buildWorld, disposeWorld, testRoot, type World } from "./support/m1-world";

// ADVERSARIAL REGRESSION for the campaign wrapper. Reproduced before the fix (recorded in M1-CAMPAIGN-TRUST-CLOSURE.md): a forged stored `m1-acceptance.json` with the correct
// identity made a campaign whose run 2 had FAILING observer evidence report LOCAL_REPEATABILITY_PASS. Now the stored artifact is an audit record only: acceptance is recomputed per
// run from the authoritative evidence and the stored artifact must agree with it. Every invalid case below must prevent LOCAL_REPEATABILITY_PASS; QUALIFIED stays unreachable.

const root = testRoot("campaign-adv");
const worlds: Record<string, World> = {}; const accepted: Record<string, string> = {};
const read = (id: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(resolveEvidenceDirectory(id, root), file), "utf8")) as Record<string, unknown>;
const acceptCli = (w: World) => ({ serverId: w.serverId, resultIds: w.ids, generatorReportPath: w.reportPath, observerDirectory: w.observerDirectory, retainedDirectory: w.retainedDirectory });
type RunOverride = Partial<{ acceptanceId: string | undefined; resultIds: Partial<Record<ComponentName, string>>; observerDirectory: string | undefined; retainedDirectory: string | undefined; reportPath: string }>;
const runOf = (w: World, override: RunOverride = {}) => ({ ...acceptCli(w), acceptanceId: accepted[w.serverId], reportPath: w.reportPath, ...override });
function campaign(runs: ReturnType<typeof runOf>[]) {
  const outcome = m1LocalCampaign({ runs }, root);
  assert.notEqual(outcome.result.outcome as string, "QUALIFIED"); assert.equal(outcome.result.qualification.reachable, false);
  const artifact = read(outcome.evidenceId, "m1-campaign.json") as { qualification: { reachable: boolean }; claims: Record<string, string> };
  assert.deepEqual([artifact.qualification.reachable, artifact.claims.machineFreshness], [false, "not_provable_from_evidence"]);
  return outcome.result;
}
const notPass = (runs: ReturnType<typeof runOf>[], expectedOutcome: string, reason?: string) => {
  const result = campaign(runs);
  assert.notEqual(result.outcome, "LOCAL_REPEATABILITY_PASS");
  assert.equal(result.outcome, expectedOutcome, result.reasons.join(","));
  if (reason !== undefined) assert.ok(result.reasons.includes(reason), result.reasons.join(","));
  return result;
};
/** Writes an acceptance-shaped evidence run (a forger's audit record). */
function writeAcceptance(body: Record<string, unknown>): string {
  const run = new EvidenceRun("m1-acceptance", "m1-acceptance", new Date(), root);
  run.addJsonArtifact("m1-acceptance.json", body);
  run.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "test", result: "PASS", resultReasons: [], metrics: {} });
  return run.id;
}
const rewritten = (w: World, edit: (artifact: Record<string, unknown>) => void): string => { const copy = structuredClone(read(accepted[w.serverId], "m1-acceptance.json")); edit(copy); return writeAcceptance(copy); };
const claimsConsistent = (w: World): string => rewritten(w, (a) => { a.acceptance = { outcome: "LOCALLY_CONSISTENT", reasons: [] }; a.components = Object.fromEntries(COMPONENT_NAMES.map((n) => [n, "PASS"])); });

test.before(async () => {
  for (const slot of [1, 2, 3]) worlds[`g${slot}`] = await buildWorld(root, { slot });
  worlds.tally = await buildWorld(root, { slot: 2, evidence: { mutate: { "kind-ledger.json": (c) => { (c.counts as Record<string, number>).INGRESS_ACCEPTED += 1; } } } });
  worlds.receipt = await buildWorld(root, { slot: 2, evidence: { mutate: { "processes.json": (c) => { ((c.app as { stats: { counters: Record<string, number> } }).stats.counters).executed += 1; } } } });
  worlds.observation = await buildWorld(root, { slot: 2, faults: { drop: ["window.2.submit"] } });
  // a process that was NOT fresh: its counters carry surplus from an earlier run, so the receipt identities cannot reconcile from zero
  worlds.stale = await buildWorld(root, { slot: 2, evidence: { mutate: { "processes.json": (c) => {
    const b = (c.boundary as { stats: Record<string, number> }).stats; for (const key of ["arrived", "admitted", "appProofsIssued", "relayed", "forwardResponded", "responded"]) b[key] += 10;
    const a = (c.app as { stats: { counters: Record<string, number>; served: Record<string, number> } }).stats; a.counters.admitted += 10; a.counters.executed += 10; a.served.received += 10; a.served.completed += 10;
  } } } });
  worlds.sameCampaign = await buildWorld(root, { slot: 2, fields: { campaignId: "campaign-slot-1" }, evidence: { mutate: {
    "server-level.json": (c) => { c.campaignId = "campaign-slot-1"; }, "core.json": (c) => { (c.level as { campaignId: string }).campaignId = "campaign-slot-1"; } } } });
  worlds.overlap = await buildWorld(root, { slot: 2, window: { startedAt: "2026-11-08T11:00:35.000Z", endedAt: "2026-11-08T11:01:05.000Z" }, evidence: { mutate: {
    "server-level.json": (c) => { c.window = { openedAt: "2026-11-08T11:00:30.000Z", closedAt: "2026-11-08T11:01:30.000Z", elapsedMs: 60_000 }; } } } });
  for (const w of Object.values(worlds)) accepted[w.serverId] = m1AcceptRun(acceptCli(w), root).evidenceId;
});
test.after(() => { for (const w of Object.values(worlds)) disposeWorld(w); fs.rmSync(root, { recursive: true, force: true }); });

const G = (): World[] => [worlds.g1, worlds.g2, worlds.g3];
const withSecond = (replacement: ReturnType<typeof runOf>) => [runOf(worlds.g1), replacement, runOf(worlds.g3)];

test("POSITIVE: a genuine three-run local fixture with every locally required input produces LOCAL_REPEATABILITY_PASS (and nothing more)", () => {
  const result = campaign(G().map((w) => runOf(w)));
  assert.deepEqual([result.outcome, result.reasons], ["LOCAL_REPEATABILITY_PASS", []]);
  assert.equal(result.repeatability?.outcome, "PASS");
  assert.equal(result.freshState, "process_counters_reconciled_from_zero_per_run");
  for (const w of G()) assert.equal(read(accepted[w.serverId], "m1-acceptance.json").runId, w.serverId);
});

test("REPRODUCED AND CLOSED: a forged acceptance artifact with the correct identity cannot lift a run whose observer evidence fails", () => {
  const bad = worlds.observation;
  assert.equal(m1AcceptRun(acceptCli(bad), root).result.outcome, "REJECT", "the genuine acceptance of the bad run is REJECT");
  const forged = claimsConsistent(bad);
  // the unforged baseline: the genuine record for the bad run gives REJECT
  notPass(withSecond(runOf(bad)), "REJECT", "m1.campaign.run2.not_accepted");
  // the reported defect: previously LOCAL_REPEATABILITY_PASS; now the recomputed acceptance is REJECT and the stored record disagrees
  const result = notPass(withSecond(runOf(bad, { acceptanceId: forged })), "ERROR", "m1.campaign.run2.stored_acceptance_not_verified");
  assert.equal(result.repeatability, null, "repeatability is not consulted");
});

test("a genuine acceptance record whose outcome was modified, in either direction, is not trusted", () => {
  const upgraded = rewritten(worlds.observation, (a) => { (a.acceptance as { outcome: string }).outcome = "LOCALLY_CONSISTENT"; });
  notPass(withSecond(runOf(worlds.observation, { acceptanceId: upgraded })), "ERROR");
  const downgraded = rewritten(worlds.g2, (a) => { (a.acceptance as { outcome: string }).outcome = "REJECT"; });
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: downgraded })), "ERROR", "m1.campaign.run2.stored_acceptance_not_verified");
  // a record whose reasons or components were edited
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: rewritten(worlds.g2, (a) => { (a.components as Record<string, string>).observation = "FAIL"; }) })), "ERROR");
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: rewritten(worlds.g2, (a) => { (a.inputs as Record<string, unknown>).overlaySha256 = "0".repeat(64); }) })), "ERROR");
});

test("copied identity hash plus forged component results (all digests re-sealed) cannot make a failing run pass", () => {
  const bad = worlds.observation; const template = read(worlds.g2.ids.observation!, COMPONENT_FILES.observation);
  const identity = identityBlock(resolveEvidenceDirectory(bad.serverId, root)).identity as M1Identity;
  const forgedResult = structuredClone(template);
  forgedResult.identity = identity; forgedResult.identitySha256 = identityDigest(identity); forgedResult.runId = bad.serverId;
  const block = forgedResult.resultProvenance as Record<string, unknown>;
  block.inputs = observedInputs("observation", { packageDirectory: resolveEvidenceDirectory(bad.serverId, root), observerDirectory: bad.observerDirectory });
  block.evaluator = { contract: (block.evaluator as { contract: string }).contract, sources: evaluatorSources("observation") }; block.outputSha256 = outputDigest(forgedResult);
  const run = new EvidenceRun("m1-synthetic", "m1-synthetic", new Date(), root);
  run.addJsonArtifact(COMPONENT_FILES.observation, forgedResult);
  run.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: ba0FieldFingerprint(BA0_FIELD_V1), engine: "test", result: "PASS", resultReasons: [], metrics: {} });
  const resultIds = { ...bad.ids, observation: run.id };
  notPass(withSecond(runOf(bad, { resultIds, acceptanceId: claimsConsistent(bad) })), "ERROR");
});

test("observer evidence and retained provenance records modified after acceptance prevent a pass", () => {
  const canary = path.join(worlds.g2.observerDirectory, "canary-results.json"); const originalCanary = fs.readFileSync(canary);
  try { fs.writeFileSync(canary, "{}"); notPass(withSecond(runOf(worlds.g2)), "ERROR"); } finally { fs.writeFileSync(canary, originalCanary); }
  const beacons = path.join(worlds.g2.retainedDirectory, "beacons.ndjson"); const originalBeacons = fs.readFileSync(beacons);
  try { fs.writeFileSync(beacons, ""); notPass(withSecond(runOf(worlds.g2)), "ERROR"); } finally { fs.writeFileSync(beacons, originalBeacons); }
  assert.equal(campaign(G().map((w) => runOf(w))).outcome, "LOCAL_REPEATABILITY_PASS", "originals restored");
});

test("a run whose Criterion 9, receipt reconciliation or canary observation now rejects is REJECT, with the failing component named", () => {
  for (const [key, component] of [["tally", "tally"], ["receipt", "receipts"], ["observation", "observation"]] as const) {
    const result = notPass(withSecond(runOf(worlds[key])), "REJECT", "m1.campaign.run2.not_accepted");
    assert.equal(result.repeatability, null, key);
    assert.equal(m1AcceptRun(acceptCli(worlds[key]), root).result.components[component], "FAIL", key);
  }
});

test("a substituted finalization digest, or an acceptance record of another run, is not accepted", () => {
  const substituted = rewritten(worlds.g2, (a) => { const identity = a.identity as M1Identity; identity.finalizationSha256 = "9".repeat(64); a.identitySha256 = identityDigest(identity); });
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: substituted })), "ERROR", "m1.campaign.run2.stored_acceptance_not_verified");
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: accepted[worlds.g1.serverId] })), "ERROR");
  // the same package submitted twice
  notPass([runOf(worlds.g1), runOf(worlds.g1), runOf(worlds.g3)], "REJECT");
});

test("matching configuration but invalid freshness evidence: a run whose process counters do not reconcile from zero (a reused process) prevents the pass", () => {
  const result = notPass(withSecond(runOf(worlds.stale)), "REJECT", "m1.campaign.run2.not_accepted");
  assert.equal(result.repeatability, null);
  assert.equal(m1AcceptRun(acceptCli(worlds.stale), root).result.components.receipts, "FAIL");
});

test("missing independently retained evidence makes the campaign INCOMPLETE or ERROR, never a pass", () => {
  notPass(withSecond(runOf(worlds.g2, { retainedDirectory: undefined })), "INCOMPLETE");
  notPass(withSecond(runOf(worlds.g2, { observerDirectory: undefined })), "INCOMPLETE");
  notPass(withSecond(runOf(worlds.g2, { acceptanceId: undefined })), "INCOMPLETE", "m1.campaign.run2.stored_acceptance_missing");
  notPass(withSecond(runOf(worlds.g2, { resultIds: {} })), "INCOMPLETE");
  const missingReport = notPass(withSecond(runOf(worlds.g2, { reportPath: path.join(worlds.g2.reportDirectory, "absent", "generator-report.json") })), "ERROR");
  assert.ok(missingReport.reasons.some((reason) => reason.includes("repeatability_facts_missing") || reason.includes("acceptance")));
});

test("repeatability rules are preserved through the recomputed path: reused campaign ids and overlapping windows are REJECT even though each run is individually consistent", () => {
  for (const key of ["sameCampaign", "overlap"]) assert.equal(m1AcceptRun(acceptCli(worlds[key]), root).result.outcome, "LOCALLY_CONSISTENT", `${key}: individually consistent`);
  notPass(withSecond(runOf(worlds.sameCampaign)), "REJECT", "m1.repeat.campaign_ids_not_distinct");
  notPass(withSecond(runOf(worlds.overlap)), "REJECT", "m1.repeat.windows_overlap");
  // wrong number of runs
  notPass([runOf(worlds.g1), runOf(worlds.g2)], "INCOMPLETE");
  notPass([...G().map((w) => runOf(w)), runOf(worlds.g1)], "ERROR");
});
