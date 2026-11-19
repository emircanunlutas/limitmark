import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { runCli } from "../lab/m1/cli";
import { PARAMETERS_DIGEST, buildCommitment, evaluateFreshness, expectedObservationFrom, type Commitment, type CommitmentInput } from "../lab/m1/commitment";
import { evaluateRunFromEvidence } from "../lab/m1/acceptance";
import { identityFromPackage } from "../lab/m1/identity";
import { evaluateObservationFiles } from "../lab/m1/observation-bundle";
import { LOCAL_EXPECTATION, type ExpectedObservation } from "../lab/m1/observation-profile";
import { buildMeta, runLauncher } from "../lab/m1/observation/launch";
import { writeObservationResult } from "../lab/m1/results";
import { exportAndSeal, verifySeal } from "../lab/m1/seal";
import { buildWorld, disposeWorld, testRoot, type World } from "./support/m1-world";

// Observation PROFILES. LOCAL_LOOPBACK keeps every existing requirement. REMOTE_PRIVATE replaces "five local process ids" with distinct observer ROLES whose deployment identities
// and private addresses must equal what the pre-run environment commitment declared. The verifier selects the profile from the verified commitment; a result file can only agree.
// The "remote" evidence below is SIMULATED from real local evidence (there is no private address to bind locally): it proves the structural contract, NOT a real off-host
// deployment, and every identity in it is self-reported.

const root = testRoot("profiles");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "m1-profiles-"));
let world: World; let identity: { runId: string; campaignId: string; gitSha: string };
const H = 3_600_000; const T0 = 1_800_000_000_000;
const CANARY = { deploymentId: "gce/obs-project/canary-1", address: "10.30.0.10" }; const COLLECTOR = { deploymentId: "gce/obs-project/collector-1", address: "10.30.0.11" };
test.before(async () => { world = await buildWorld(root, { slot: 1 }); const id = identityFromPackage(resolveEvidenceDirectory(world.serverId, root)).identity!; identity = { runId: id.runId, campaignId: id.campaignId, gitSha: id.gitSha }; });
test.after(() => { disposeWorld(world); fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(scratch, { recursive: true, force: true }); });

function commitmentInput(observation?: CommitmentInput["observation"], over: Partial<CommitmentInput> = {}): CommitmentInput {
  return {
    campaignId: identity.campaignId, runId: identity.runId, commit: identity.gitSha, treeClean: true, parametersId: "ba0-field-v1", parametersDigest: PARAMETERS_DIGEST, fixtureDigest: "e".repeat(64),
    target: { ipv4: "10.10.0.5", authorizedFromMs: T0 - H, authorizedUntilMs: T0 + 2 * H }, window: { startMs: T0, endMs: T0 + 300_000 },
    instance: { id: "target-instance-1", createdMs: T0 - 30 * 60_000, imageId: "image-1", bootId: "boot-1" }, counters: { admitted: 0 }, canaryThresholdsFixed: true, retentionDays: 30, previousTeardownMs: null,
    ...(observation ? { observation } : {}), ...over,
  };
}
const remoteObservation = { profile: "REMOTE_PRIVATE" as const, canary: CANARY, collector: COLLECTOR };
function built(input: CommitmentInput): { commitment: Commitment; digest: string } { const r = buildCommitment(input); assert.equal(r.outcome, "VALID", r.reasons.join(",")); return { commitment: r.commitment!, digest: r.digest! }; }
const remoteExpected = (): ExpectedObservation => { const b = built(commitmentInput(remoteObservation)); return expectedObservationFrom(b.commitment, b.digest); };

const json = (dir: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(dir, file), "utf8")) as Record<string, unknown>;
const write = (dir: string, file: string, value: unknown): void => fs.writeFileSync(path.join(dir, file), `${JSON.stringify(value)}\n`);
const edit = (dir: string, file: string, change: (v: Record<string, unknown>) => void): void => { const v = json(dir, file); change(v); write(dir, file, v); };
let counter = 0;
const copy = (label: string, change?: (dir: string) => void): string => { const dir = path.join(scratch, `${label}-${++counter}`); fs.cpSync(world.observerDirectory, dir, { recursive: true }); change?.(dir); return dir; };
/** SIMULATED off-host evidence: the real local evidence rewritten to the shape an off-host canary and collector would write. Not a deployment. */
function simulatedRemote(label: string, change?: (dir: string) => void): string {
  return copy(label, (dir) => {
    edit(dir, "observation-meta.json", (m) => { m.profile = "REMOTE_PRIVATE"; m.loopbackOnly = false; m.topology = "private-lane"; m.observers = { canary: CANARY }; delete m.processes; });
    edit(dir, "canary-results.json", (c) => { c.observer = CANARY; });
    edit(dir, "collector-declaration.json", (d) => { d.observer = COLLECTOR; });
    change?.(dir);
  });
}
const judge = (dir: string, expected: ExpectedObservation | null, limit: number | null = 1_000, who = identity) => evaluateObservationFiles({ runId: who.runId, campaignId: who.campaignId }, dir, limit, expected);
const has = (r: ReturnType<typeof judge>, reason: string): void => assert.ok(r.result.reasons.includes(reason), `${reason} not in ${r.result.reasons.join(",")}`);

test("1. genuine local loopback evidence is still accepted, with no commitment and with a local commitment; the local limitations are unchanged", () => {
  const none = judge(world.observerDirectory, null); assert.equal(none.result.outcome, "PASS", none.result.reasons.join(","));
  assert.ok(none.result.limitations.includes("separate_local_processes_not_independent_custody"));
  const local = built(commitmentInput()); const expected = expectedObservationFrom(local.commitment, local.digest);
  assert.equal(expected.profile, "LOCAL_LOOPBACK"); assert.equal(judge(world.observerDirectory, expected).result.outcome, "PASS");
  const explicit = built(commitmentInput({ profile: "LOCAL_LOOPBACK" })); assert.equal(judge(world.observerDirectory, expectedObservationFrom(explicit.commitment, explicit.digest)).result.outcome, "PASS");
});

test("2. simulated off-host evidence passes the structural contract under REMOTE_PRIVATE and carries the remote limitations; process ids are not needed and not accepted as proof", () => {
  const dir = simulatedRemote("pass"); const r = judge(dir, remoteExpected());
  assert.equal(r.result.outcome, "PASS", r.result.reasons.join(",")); assert.equal(r.result.profile, "REMOTE_PRIVATE");
  for (const l of ["observer_identities_self_reported_not_authenticated", "independent_custody_not_established_by_this_check", "producer_authenticity_not_established"]) assert.ok(r.result.limitations.includes(l), l);
  assert.ok(!r.result.limitations.includes("separate_local_processes_not_independent_custody"));
  // five fabricated distinct process ids do not substitute for the identities
  const fake = simulatedRemote("fake-pids", (d) => { edit(d, "observation-meta.json", (m) => { m.processes = { a: 11, b: 22, c: 33, d: 44, e: 55 }; }); edit(d, "collector-declaration.json", (x) => { delete x.observer; }); });
  const f = judge(fake, remoteExpected()); assert.notEqual(f.result.outcome, "PASS"); has(f, "m1.obs.remote.collector_identity_missing");
});

test("3. forged profile substitution fails: a file never selects its own profile, in either direction, and an unknown profile is an error", () => {
  const localAsRemote = copy("local-claims-remote", (d) => edit(d, "observation-meta.json", (m) => { m.profile = "REMOTE_PRIVATE"; }));
  const a = judge(localAsRemote, null); assert.equal(a.result.outcome, "ERROR"); has(a, "m1.obs.remote_profile_without_environment_commitment");
  const b = judge(localAsRemote, LOCAL_EXPECTATION); assert.equal(b.result.outcome, "REJECT"); has(b, "m1.obs.profile_mismatch");
  const remoteUnderLocal = judge(simulatedRemote("remote-under-local"), LOCAL_EXPECTATION); assert.notEqual(remoteUnderLocal.result.outcome, "PASS");
  const claimsLocal = simulatedRemote("remote-claims-local", (d) => edit(d, "observation-meta.json", (m) => { m.profile = "LOCAL_LOOPBACK"; }));
  const c = judge(claimsLocal, remoteExpected()); assert.equal(c.result.outcome, "REJECT"); has(c, "m1.obs.profile_mismatch");
  const unknown = simulatedRemote("unknown", (d) => edit(d, "observation-meta.json", (m) => { m.profile = "REMOTE_PUBLIC"; }));
  const u = judge(unknown, remoteExpected()); assert.equal(u.result.outcome, "ERROR"); has(u, "m1.obs.profile_unknown");
  // local evidence judged under a remote expectation is a mismatch, not a pass
  const d = judge(world.observerDirectory, remoteExpected()); assert.equal(d.result.outcome, "REJECT"); has(d, "m1.obs.profile_mismatch");
});

test("4-5. missing or duplicated collector and canary identities fail; identities that differ from the commitment fail; the commitment itself refuses duplicates", () => {
  const noCollector = judge(simulatedRemote("no-collector", (d) => edit(d, "collector-declaration.json", (x) => { delete x.observer; })), remoteExpected()); assert.equal(noCollector.result.outcome, "ERROR"); has(noCollector, "m1.obs.remote.collector_identity_missing");
  const noCanary = judge(simulatedRemote("no-canary", (d) => edit(d, "canary-results.json", (x) => { delete x.observer; })), remoteExpected()); assert.equal(noCanary.result.outcome, "ERROR"); has(noCanary, "m1.obs.remote.canary_identity_missing");
  const noMeta = judge(simulatedRemote("no-meta-observers", (d) => edit(d, "observation-meta.json", (x) => { delete x.observers; })), remoteExpected()); assert.equal(noMeta.result.outcome, "ERROR");
  const same = judge(simulatedRemote("duplicate", (d) => edit(d, "collector-declaration.json", (x) => { x.observer = CANARY; })), remoteExpected()); assert.equal(same.result.outcome, "REJECT");
  has(same, "m1.obs.remote.canary_and_collector_not_distinct"); has(same, "m1.obs.remote.collector_identity_differs_from_commitment");
  const swapped = judge(simulatedRemote("swapped", (d) => { edit(d, "collector-declaration.json", (x) => { x.observer = CANARY; }); edit(d, "canary-results.json", (x) => { x.observer = COLLECTOR; }); edit(d, "observation-meta.json", (m) => { m.observers = { canary: COLLECTOR }; }); }), remoteExpected());
  assert.equal(swapped.result.outcome, "REJECT"); has(swapped, "m1.obs.remote.canary_identity_differs_from_commitment");
  const inconsistent = judge(simulatedRemote("inconsistent", (d) => edit(d, "observation-meta.json", (m) => { m.observers = { canary: { ...CANARY, deploymentId: "gce/other" } }; })), remoteExpected()); has(inconsistent, "m1.obs.remote.canary_identity_inconsistent_between_results_and_metadata");
  const publicAddress = judge(simulatedRemote("public-address", (d) => edit(d, "collector-declaration.json", (x) => { x.observer = { ...COLLECTOR, address: "8.8.8.8" }; })), remoteExpected()); assert.equal(publicAddress.result.outcome, "ERROR");
  const notRemoteMeta = judge(simulatedRemote("loopback-claim", (d) => edit(d, "observation-meta.json", (m) => { m.loopbackOnly = true; })), remoteExpected()); has(notRemoteMeta, "m1.obs.remote.metadata_contradicts_remote_profile");
  for (const o of [{ profile: "REMOTE_PRIVATE" as const, canary: CANARY, collector: CANARY }, { profile: "REMOTE_PRIVATE" as const, canary: CANARY, collector: { deploymentId: "x/other", address: CANARY.address } }, { profile: "REMOTE_PRIVATE" as const, canary: CANARY }, { profile: "REMOTE_PRIVATE" as const, canary: CANARY, collector: { ...COLLECTOR, address: "8.8.8.8" } }, { profile: "REMOTE_PRIVATE" as const, canary: CANARY, collector: { ...COLLECTOR, address: "10.10.0.5" } }, { profile: "LOCAL_LOOPBACK" as const, canary: CANARY }])
    assert.equal(buildCommitment(commitmentInput(o)).outcome, "INVALID", JSON.stringify(o));
  assert.equal(buildCommitment(commitmentInput(remoteObservation, { instance: { id: CANARY.deploymentId, createdMs: T0 - 1800_000, imageId: "i", bootId: "b" } })).outcome, "INVALID", "an observer identity equal to the target instance");
});

test("6-7. missing heartbeat evidence and missing origin receipts fail under REMOTE_PRIVATE as they do locally", () => {
  const noBeats = judge(simulatedRemote("no-beats", (d) => edit(d, "collector-declaration.json", (x) => { x.heartbeatsMs = []; })), remoteExpected()); assert.notEqual(noBeats.result.outcome, "PASS"); has(noBeats, "m1.complete.no_heartbeats");
  const strict = judge(simulatedRemote("strict"), remoteExpected(), 1); assert.notEqual(strict.result.outcome, "PASS"); has(strict, "m1.complete.heartbeat_gap_exceeded");
  const noLimit = judge(simulatedRemote("no-limit", (d) => edit(d, "observation-meta.json", (m) => { delete m.completeness; })), remoteExpected(), null); assert.equal(noLimit.limitMissing, true);
  const empty = judge(simulatedRemote("no-receipts", (d) => { fs.writeFileSync(path.join(d, "origin-receipts.ndjson"), ""); edit(d, "collector-declaration.json", (x) => { x.receiptCount = 0; x.lastSeq = 0; }); }), remoteExpected());
  assert.notEqual(empty.result.outcome, "PASS"); has(empty, "m1.obs.canary_success_without_origin_receipt");
  const gone = judge(simulatedRemote("receipts-absent", (d) => fs.rmSync(path.join(d, "origin-receipts.ndjson"))), remoteExpected()); assert.notEqual(gone.result.outcome, "PASS");
  const noDeclaration = judge(simulatedRemote("no-declaration", (d) => fs.rmSync(path.join(d, "collector-declaration.json"))), remoteExpected()); assert.notEqual(noDeclaration.result.outcome, "PASS");
});

test("8. cross-run and cross-campaign substitution fails in the remote profile", () => {
  const dir = simulatedRemote("cross");
  assert.notEqual(judge(dir, remoteExpected(), 1_000, { ...identity, runId: "another-run" }).result.outcome, "PASS");
  assert.notEqual(judge(dir, remoteExpected(), 1_000, { ...identity, campaignId: "another-campaign" }).result.outcome, "PASS");
  const foreignDeclaration = judge(simulatedRemote("foreign-declaration", (d) => edit(d, "collector-declaration.json", (x) => { x.runId = "another-run"; })), remoteExpected()); assert.notEqual(foreignDeclaration.result.outcome, "PASS");
  const foreignMeta = judge(simulatedRemote("foreign-meta", (d) => edit(d, "observation-meta.json", (m) => { m.campaignId = "another-campaign"; })), remoteExpected()); assert.notEqual(foreignMeta.result.outcome, "PASS");
  // the commitment is bound to a run too: a commitment for another run cannot supply the expectation through the CLI (see test 10)
});

test("9. modification after finalization is detected: a sealed remote-profile evidence set fails verification once any byte changes or a file is replaced", () => {
  const source = simulatedRemote("to-seal"); const b = built(commitmentInput(remoteObservation)); const destination = path.join(scratch, "sealed-remote");
  const sealed = exportAndSeal({ source, destination, runId: identity.runId, campaignId: identity.campaignId, commitmentDigest: b.digest }); assert.deepEqual(sealed.problems, []);
  const expected = { runId: identity.runId, campaignId: identity.campaignId, commitmentDigest: b.digest };
  assert.equal(verifySeal(destination, expected).outcome, "VERIFIED");
  edit(destination, "collector-declaration.json", (x) => { x.observer = CANARY; });
  const after = verifySeal(destination, expected); assert.notEqual(after.outcome, "VERIFIED");
  assert.notEqual(verifySeal(destination, { ...expected, commitmentDigest: "0".repeat(64) }).outcome, "VERIFIED", "another commitment");
});

test("10. a missing, foreign or invalid environment commitment fails; with the right commitment the CLI records PASS and states the profile; a local commitment cannot excuse remote evidence", async () => {
  const dir = simulatedRemote("cli"); const b = built(commitmentInput(remoteObservation));
  const file = path.join(scratch, "commitment-remote.json"); fs.writeFileSync(file, JSON.stringify({ commitment: b.commitment, digest: b.digest }));
  const local = built(commitmentInput()); const localFile = path.join(scratch, "commitment-local.json"); fs.writeFileSync(localFile, JSON.stringify({ commitment: local.commitment, digest: local.digest }));
  const foreign = built(commitmentInput(remoteObservation, { runId: "another-run" })); const foreignFile = path.join(scratch, "commitment-foreign.json"); fs.writeFileSync(foreignFile, JSON.stringify({ commitment: foreign.commitment, digest: foreign.digest }));
  const badDigestFile = path.join(scratch, "commitment-bad-digest.json"); fs.writeFileSync(badDigestFile, JSON.stringify({ commitment: b.commitment, digest: "1".repeat(64) }));
  const run = async (args: string[]) => { const lines: string[] = []; const code = await runCli(args, { stdout: (l) => lines.push(l), evidenceRoot: root }); return { code, out: JSON.parse(lines[lines.length - 1]!) as { outcome: string; reasons: string[]; details: Record<string, unknown> } }; };
  const base = ["--server", world.serverId, "--observer-dir", dir, "--max-heartbeat-gap-ms", "1000"];
  const missing = await run(["observe", ...base]); assert.equal(missing.code, 30); assert.ok(missing.out.reasons.includes("m1.obs.remote_profile_without_environment_commitment"));
  { const r = await run(["observe", ...base, "--commitment", localFile]); assert.equal(r.code, 10, JSON.stringify(r.out)); }
  assert.equal((await run(["observe", ...base, "--commitment", foreignFile])).code, 10, "a commitment for another run");
  assert.equal((await run(["observe", ...base, "--commitment", badDigestFile])).code, 10);
  assert.equal((await run(["observe", ...base, "--commitment", path.join(scratch, "absent.json")])).code, 30);
  const ok = await run(["observe", ...base, "--commitment", file]); assert.equal(ok.code, 0, JSON.stringify(ok.out)); assert.equal(ok.out.details.observationProfile, "REMOTE_PRIVATE");
  const localRun = await run(["observe", "--server", world.serverId, "--observer-dir", world.observerDirectory, "--max-heartbeat-gap-ms", "1000"]); assert.equal(localRun.code, 0); assert.equal(localRun.out.details.observationProfile, "LOCAL_LOOPBACK");
});

test("11. self-reported independence is not authenticated custody: claims of it are rejected and the limitations always say so", () => {
  for (const [label, change] of [
    ["meta", (d: string) => edit(d, "observation-meta.json", (m) => { m.independentCustody = true; })], ["declaration", (d: string) => edit(d, "collector-declaration.json", (x) => { x.authenticated = true; })],
    ["canary", (d: string) => edit(d, "canary-results.json", (c) => { c.authenticatedCustody = true; })],
  ] as [string, (d: string) => void][]) { const r = judge(simulatedRemote(`claim-${label}`, change), remoteExpected()); assert.equal(r.result.outcome, "REJECT", label); has(r, "m1.obs.remote.custody_claim_cannot_be_verified_here"); }
  const ok = judge(simulatedRemote("limits"), remoteExpected());
  assert.ok(ok.result.limitations.includes("observer_identities_self_reported_not_authenticated") && ok.result.limitations.includes("remote_profile_simulated_evidence_does_not_prove_real_off_host_deployment_unless_the_commitment_and_custody_are_real"));
});

test("12. the local anti-forgery and process-isolation checks are still enforced", () => {
  const dupPids = copy("dup-pids", (d) => edit(d, "observation-meta.json", (m) => { const p = m.processes as Record<string, number>; const keys = Object.keys(p); p[keys[1]!] = p[keys[0]!]!; }));
  const a = judge(dupPids, null); assert.equal(a.result.outcome, "REJECT"); has(a, "m1.obs.processes_not_separate");
  const fewer = copy("few-pids", (d) => edit(d, "observation-meta.json", (m) => { const p = m.processes as Record<string, number>; delete p[Object.keys(p)[0]!]; }));
  has(judge(fewer, null), "m1.obs.processes_not_separate");
  const notLoopback = copy("not-loopback", (d) => edit(d, "observation-meta.json", (m) => { m.loopbackOnly = false; })); has(judge(notLoopback, null), "m1.obs.meta_identity_mismatch");
  const noProcesses = copy("no-processes", (d) => edit(d, "observation-meta.json", (m) => { delete m.processes; })); assert.equal(judge(noProcesses, null).result.outcome, "ERROR");
  const pinned = copy("timeout", (d) => edit(d, "canary-results.json", (c) => { c.timeoutMs = 60_000; })); has(judge(pinned, null), "m1.obs.canary_timeout_not_pinned");
  const replay = copy("replay", (d) => edit(d, "canary-results.json", (c) => { const s = c.steps as { requestId: string }[]; s[1]!.requestId = s[0]!.requestId; })); assert.notEqual(judge(replay, null).result.outcome, "PASS");
  const foreignReceipt = copy("foreign-receipt", (d) => { const f = path.join(d, "origin-receipts.ndjson"); const l = fs.readFileSync(f, "utf8").split("\n").filter(Boolean); l[0] = JSON.stringify({ ...(JSON.parse(l[0]!) as object), runId: "another" }); fs.writeFileSync(f, `${l.join("\n")}\n`); }); assert.notEqual(judge(foreignReceipt, null).result.outcome, "PASS");
});

test("profile binding through the unified acceptance chain: the same function recomputes under the verifier's expected profile, a stored result recorded under one profile disagrees under another, and a function form selects per run", () => {
  const dir = simulatedRemote("chain"); const expected = remoteExpected();
  const stored = writeObservationResult(world.serverId, dir, root, new Date(), 1_000, expected); assert.equal(stored.result.outcome, "PASS");
  const cli = { serverId: world.serverId, resultIds: { ...world.ids, observation: stored.evidenceId }, generatorReportPath: world.reportPath, observerDirectory: dir, retainedDirectory: world.retainedDirectory };
  const under = (e: ExpectedObservation | null | ((id: string) => ExpectedObservation | null)) => evaluateRunFromEvidence(cli, root, { maxHeartbeatGapMs: 1_000, expectedObservation: e }).result.components.observation;
  const remoteOk = under(expected); assert.equal(remoteOk, "PASS", "recomputed under the committed remote profile and agreeing with the stored result");
  const seen: string[] = []; under((id) => { seen.push(id); return expected; }); assert.deepEqual(seen, [world.serverId]);
  assert.notEqual(under(LOCAL_EXPECTATION), "PASS", "the same bytes under the local profile"); assert.notEqual(under(null), "PASS", "and with no commitment at all");
  // a result recorded for LOCAL evidence cannot vouch for the remote copy, nor the reverse
  const localStored = writeObservationResult(world.serverId, world.observerDirectory, root, new Date(), 1_000, null);
  const crossed = evaluateRunFromEvidence({ ...cli, resultIds: { ...cli.resultIds, observation: localStored.evidenceId } }, root, { maxHeartbeatGapMs: 1_000, expectedObservation: expected }).result.components.observation;
  assert.notEqual(crossed, "PASS", "a result recorded for the local evidence cannot vouch for the remote copy");
});

test("freshness: a campaign cannot mix observation profiles across its runs; the commitment without an observation block keeps its local meaning", () => {
  const a = built(commitmentInput()); const b = built(commitmentInput(remoteObservation, { runId: "r2", campaignId: "c2", instance: { id: "i2", createdMs: T0 + 400_000, imageId: "i", bootId: "b2" }, window: { startMs: T0 + 500_000, endMs: T0 + 800_000 }, previousTeardownMs: T0 + 350_000 }));
  const mixed = evaluateFreshness([a, b]); assert.ok(mixed.reasons.includes("m1.fresh.observation_profile_changed"));
  assert.deepEqual(expectedObservationFrom(a.commitment, a.digest), { ...LOCAL_EXPECTATION, commitmentDigest: a.digest });
  assert.deepEqual(expectedObservationFrom(null, null), LOCAL_EXPECTATION);
});

test("launcher: the remote profile needs a declared private identity and private addresses, the local profile refuses one, and the metadata states profile and identity truthfully", async () => {
  const out: string[] = []; const run = (args: string[]) => runLauncher(args, { stdout: (l) => out.push(l) });
  const dir = path.join(scratch, "launch-flags"); const id = ["--run-id", "r1", "--campaign-id", "c1", "--output-dir", dir];
  const canary = ["canary", ...id, "--target-port", "9"];
  assert.equal(await run([...canary, "--target-host", "10.10.0.5", "--allow-private-network", "--profile", "REMOTE_PRIVATE"]), 64, "no observer identity");
  assert.equal(await run([...canary, "--target-host", "10.10.0.5", "--profile", "REMOTE_PRIVATE", "--observer-id", "gce/x", "--observer-address", "10.30.0.10"]), 64, "no --allow-private-network");
  assert.equal(await run([...canary, "--target-host", "127.0.0.1", "--allow-private-network", "--profile", "REMOTE_PRIVATE", "--observer-id", "gce/x", "--observer-address", "10.30.0.10"]), 64, "loopback target under the remote profile");
  assert.equal(await run([...canary, "--target-host", "10.10.0.5", "--allow-private-network", "--profile", "REMOTE_PRIVATE", "--observer-id", "gce/x", "--observer-address", "8.8.8.8"]), 64, "public observer address");
  assert.equal(await run([...canary, "--target-host", "127.0.0.1", "--observer-id", "gce/x", "--observer-address", "10.30.0.10"]), 64, "identity flags under the local profile");
  assert.equal(await run([...canary, "--target-host", "10.10.0.5", "--allow-private-network"]), 64, "private target under the local profile");
  assert.equal(await run(["collector", ...id, "--listen-host", "10.30.0.99", "--listen-port", "0", "--upstream-host", "10.10.0.5", "--upstream-port", "9", "--allow-private-network", "--profile", "REMOTE_PRIVATE", "--observer-id", "gce/c", "--observer-address", "10.30.0.11"]), 64, "collector must listen on its own observer address");
  assert.equal(await run(["canary", ...id, "--target-host", "127.0.0.1", "--target-port", "9", "--profile", "SOMETHING"]), 64);
  assert.ok(!fs.existsSync(path.join(dir, "canary-results.json")));
  const remoteMeta = buildMeta({ runId: "r1", campaignId: "c1", windowStartMs: 1, windowEndMs: 2, hosts: ["10.10.0.5"], processes: { canary: 1 }, profile: "REMOTE_PRIVATE", observer: CANARY });
  assert.deepEqual([remoteMeta.profile, remoteMeta.loopbackOnly, remoteMeta.topology, remoteMeta.observers], ["REMOTE_PRIVATE", false, "private-lane", { canary: CANARY }]);
  assert.equal(buildMeta({ runId: "r1", campaignId: "c1", windowStartMs: 1, windowEndMs: 2, hosts: ["127.0.0.1"], processes: { canary: 1 } }).profile, "LOCAL_LOOPBACK");
});
