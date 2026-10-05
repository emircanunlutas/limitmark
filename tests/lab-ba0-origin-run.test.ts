import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { REPOSITORY_ROOT, verifyEvidenceDirectory, type EvidenceManifest } from "../lab/evidence/manifest";
import { Collector, DEFAULT_COLLECTOR_LIMITS } from "../lab/defense/collector";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { BoundaryProcess } from "../lab/defense/origin-processes";
import { BA0_ORIGIN_LOCAL_V1, ba0OriginFingerprint, type Ba0OriginThresholds } from "../lab/defense/origin-thresholds";
import { DIRECT_CORPUS_FIXED_COUNT, DIRECT_POSITIVE_CONTROLS } from "../lab/defense/direct-corpus";
import { NOT_CLAIMED, NOT_MEASURED, SCOPE_STATEMENT, runBa0Origin, type Ba0OriginOutcome } from "../lab/defense/ba0-origin-run";
import { CORPUS_FIXED_COUNT } from "../lab/defense/hostile-corpus";

const SMALL: Ba0OriginThresholds = { ...BA0_ORIGIN_LOCAL_V1, journeys: { baselinePerLane: 3, postDirectPerLane: 2 } };
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const json = <T>(outcome: Ba0OriginOutcome, name: string): T => JSON.parse(readFileSync(path.join(outcome.evidenceDirectory, name), "utf8")) as T;
const cleanup = (outcome: Ba0OriginOutcome) => rmSync(outcome.evidenceDirectory, { recursive: true, force: true });
const codes = (outcome: Ba0OriginOutcome) => new Set(outcome.anomalies.map((anomaly) => anomaly.code));

/**
 * A crash can lose the dying process's last events (still in its bounded flush window). A PROTECTED request that completed just before the
 * kill then has surviving app events but an incomplete record for the dead process, so the ledger cannot PROVE its lineage and fails closed.
 * That is the ONLY way a lineage anomaly may appear after a crash: never on a direct lane, and only where the dead process's stream is the gap.
 */
function assertLineageGapsAreCrashTailsOnly(outcome: Ba0OriginOutcome, dead: "plane" | "boundary"): number {
  const byRid = new Map(outcome.records.map((record) => [record.rid, record]));
  const gaps = outcome.anomalies.filter((anomaly) => /^app_(admit|execution|mutation)_without_lineage$/.test(anomaly.code));
  for (const anomaly of gaps) {
    const record = byRid.get(anomaly.nonce ?? "");
    assert.equal(record?.meta.lane, "protected", `${anomaly.code} is only ever about a protected request`);
    assert.ok(record!.app.some((event) => event.kind === "APP_ADMITTED"), "the application's own surviving events are what expose the gap");
    if (dead === "boundary") assert.equal(record!.boundary.length, 0, `${anomaly.code}: its boundary events died with the process`);
    else assert.ok(!record!.plane.some((event) => event.kind === "INGRESS_RESPONDED" || event.kind === "INGRESS_ABORTED"), `${anomaly.code}: its plane stream is incomplete because the plane died`);
  }
  assert.ok(gaps.length <= 6, `at most the in-flight tail of requests (saw ${gaps.length})`);
  return gaps.length;
}

function strings(value: unknown, into: string[] = []): string[] {
  if (typeof value === "string") into.push(value);
  else if (Array.isArray(value)) for (const child of value) strings(child, into);
  else if (value !== null && typeof value === "object") for (const child of Object.values(value as Record<string, unknown>)) strings(child, into);
  return into;
}

test("a clean local run is APP-NON-BYPASS-VALID: JCR 100%, full lineage, 110 direct requests refused or controlled, three-way mutation, and network non-bypass NOT measured", { timeout: 240_000 }, async () => {
  const outcome = await runBa0Origin({ thresholds: SMALL });
  try {
    assert.deepEqual(outcome.reasons, []);
    assert.equal(outcome.verdict, "APP-NON-BYPASS-VALID");
    assert.equal(outcome.anomalyTotal, 0, JSON.stringify(outcome.anomalies.slice(0, 5)));
    assert.equal(outcome.accounting.identitiesOk, true, JSON.stringify(outcome.accounting.identities.filter((identity) => !identity.ok)));
    assert.equal(outcome.origin.identitiesOk, true, JSON.stringify(outcome.origin.identities.filter((identity) => !identity.ok)));

    const manifest = json<EvidenceManifest>(outcome, "manifest.json");
    assert.equal(manifest.result, "APP-NON-BYPASS-VALID");
    assert.notEqual(manifest.result as string, "PASS");
    const metrics = manifest.metrics as Record<string, unknown>;
    assert.equal(metrics.defenseQualification, "not_claimed");
    assert.equal(metrics.networkNonBypass, "not_measured");
    assert.equal(metrics.originNetworkIsolation, "not_measured");
    assert.equal(metrics.appNonBypass, "measured_loopback_fixed_count");
    assert.equal(metrics.originFailureDomain, "process_only_same_host");
    assert.deepEqual(metrics.notClaimed, [...NOT_CLAIMED]);
    assert.deepEqual((metrics.namespaces as Record<string, string>)["n3.volumetric"], "not_measured");
    assert.deepEqual((metrics.namespaces as Record<string, string>)["t4.transport"], "not_measured");
    assert.deepEqual(manifest.thresholds, ba0OriginFingerprint(SMALL));
    assert.deepEqual(manifest.ceilings, { fixedCounts: { baselineJourneysPerLane: 3, postDirectJourneysPerLane: 2, corpusCases: CORPUS_FIXED_COUNT, semanticCases: 18, directCases: 110 }, loadRamp: "none", externalTraffic: "none" });
    assert.deepEqual(verifyEvidenceDirectory(outcome.evidenceDirectory), []);

    // canary: JCR 100% on every lane and phase, protected identical to control
    const canary = json<{ journeyCompletionRate: { lane: string; phase: string; attempted: number; completed: number; rate: number }[]; parity: { mismatches: unknown[]; compared: number }; latency: { ok: boolean; addedP95Ms: number; addedP99Ms: number } }>(outcome, "canary.json");
    assert.equal(canary.journeyCompletionRate.length, 4);
    for (const entry of canary.journeyCompletionRate) { assert.equal(entry.rate, 1); assert.equal(entry.completed, entry.attempted); }
    assert.deepEqual(canary.parity.mismatches, []);
    assert.equal(canary.latency.ok, true);

    // the plane semantic corpus
    const semantic = json<{ fixedCount: number; executed: number; violations: number; cases: { id: string; expected: string; reason: string; ok: boolean }[] }>(outcome, "semantic-corpus.json");
    assert.deepEqual([semantic.fixedCount, semantic.executed, semantic.violations], [18, 18, 0]);
    assert.ok(semantic.cases.every((entry) => entry.ok));
    assert.equal(semantic.cases.filter((entry) => entry.expected === "pass").length, 4);

    // the direct known-address corpus
    const direct = json<{ fixedCount: number; executed: number; violations: number; mustBeRefused: number; positiveControls: string[]; cases: { id: string; target: string; lane: string; expected: string; observed: string; ok: boolean }[] }>(outcome, "direct-corpus.json");
    assert.deepEqual([direct.fixedCount, direct.executed, direct.violations, direct.mustBeRefused], [110, 110, 0, 107]);
    assert.deepEqual([...direct.positiveControls].sort(), [...DIRECT_POSITIVE_CONTROLS].sort());
    assert.ok(direct.cases.every((entry) => entry.ok));
    for (const entry of direct.cases) if (entry.expected !== "admit_once" && entry.expected !== "parser") assert.equal(entry.observed, entry.expected, `${entry.id}: the ledger recorded exactly the expected reason`);
    assert.equal(direct.cases.filter((entry) => entry.observed === "admitted").length, 3);

    // the three hops reconcile, with no application execution or mutation on any refused lane
    const origin = outcome.origin;
    assert.equal(origin.lineage.complete, origin.app.admitted);
    assert.ok(origin.app.admitted > 0);
    assert.equal(origin.lineage.appAdmitsWithoutLineage, 0);
    assert.deepEqual([origin.direct.appAdmissionsOnRejectedLanes, origin.direct.appExecutionsOnRejectedLanes, origin.direct.appMutationsOnRejectedLanes], [0, 0, 0]);
    assert.equal(origin.direct.boundarySent, 87);
    assert.equal(origin.direct.appSent, 20);
    assert.deepEqual(origin.positiveControls, { sent: 3, admitted: 3, executed: 3, mutated: 0 });
    assert.equal(origin.mutation.clientObserved, SMALL.journeys.baselinePerLane + SMALL.journeys.postDirectPerLane);
    assert.deepEqual([origin.mutation.clientObserved, origin.mutation.ledgerCorrelated, origin.mutation.appAuthoritative], [5, 5, 5]);
    assert.equal(origin.mutation.perRecordViolations, 0);
    assert.equal(origin.plane.attempted, origin.plane.proofIssued);
    assert.equal(origin.boundary.admitted, origin.plane.proofIssued);
    assert.equal(origin.app.admitted, origin.boundary.appProofIssued);

    // evidence audit: no key material or proof ever reaches disk, and nothing over-claims
    const files = readdirSync(outcome.evidenceDirectory);
    assert.ok(files.includes("ledger-journal.ndjson") && files.includes("app-boundary.json") && files.includes("direct-corpus.json"));
    const keys = Object.values(outcome.keyMaterial);
    const proofPrefixes = ['["ba0-pb-v2"', '["ba0-ba-v2"'].map((prefix) => Buffer.from(prefix).toString("base64url"));
    for (const name of files) {
      const text = readFileSync(path.join(outcome.evidenceDirectory, name), "utf8");
      for (const key of keys) assert.ok(!text.includes(key), `${name} contains key material`);
      for (const prefix of proofPrefixes) assert.ok(!text.includes(prefix), `${name} contains a proof`);
      assert.doesNotMatch(text, /x-ba0-hop|BEGIN [A-Z ]*PRIVATE KEY/i, name);
    }
    const allowed = new Set<string>([...NOT_CLAIMED, ...NOT_MEASURED, SCOPE_STATEMENT]);
    const overclaim = /isolat|volumetric|ddos|bandwidth|\bsyn\b|exhaustion|bypass-proof|secure origin|origin is protected|protected from/i;
    for (const name of files.filter((file) => file.endsWith(".json"))) {
      for (const value of strings(JSON.parse(readFileSync(path.join(outcome.evidenceDirectory, name), "utf8")))) {
        if (overclaim.test(value)) assert.ok(allowed.has(value), `${name}: "${value.slice(0, 80)}" is a claim outside the declared not-claimed / not-measured lists`);
      }
    }
    const boundaryDoc = json<{ keyCustody: Record<string, string>; hopSeparation: Record<string, unknown>; boundaryStats: Record<string, unknown>; appStats: { guard: Record<string, unknown> } }>(outcome, "app-boundary.json");
    assert.match(boundaryDoc.keyCustody.app, /no private key/);
    assert.equal(boundaryDoc.hopSeparation.keys, "distinct");
    assert.equal((boundaryDoc.boundaryStats as { contentReadsStarted: number }).contentReadsStarted <= (boundaryDoc.boundaryStats as { replay: { reserved: number } }).replay.reserved, true);
    const accounting = json<{ scope: string; eventChannels: { plane: { planeCrashed: string }; boundary: { crashed: string; fin: { drained: boolean } }; app: { crashed: string; fin: { drained: boolean } } } }>(outcome, "accounting.json");
    assert.equal(accounting.scope, SCOPE_STATEMENT);
    assert.deepEqual([accounting.eventChannels.plane.planeCrashed, accounting.eventChannels.boundary.crashed, accounting.eventChannels.app.crashed], ["no", "no", "no"]);
    assert.deepEqual([accounting.eventChannels.boundary.fin.drained, accounting.eventChannels.app.fin.drained], [true, true]);
    assert.ok(DIRECT_CORPUS_FIXED_COUNT === 110);
  } finally { cleanup(outcome); }
});

test("the Defense Plane crashing is INVALID, but it changes nothing at the origin: every direct request is still refused and nothing executes or mutates", { timeout: 240_000 }, async () => {
  const outcome = await runBa0Origin({ thresholds: SMALL, hooks: { beforePhase: async (phase, handles) => { if (phase === "direct") { handles.plane.crash(); await sleep(250); } } } });
  try {
    assert.equal(outcome.verdict, "INVALID");
    assert.ok(codes(outcome).has("plane_crashed"));
    assert.deepEqual(outcome.directViolations, [], "the direct corpus is independent of the plane: every case behaved exactly as specified with the plane dead");
    assert.deepEqual([outcome.origin.direct.appAdmissionsOnRejectedLanes, outcome.origin.direct.appExecutionsOnRejectedLanes, outcome.origin.direct.appMutationsOnRejectedLanes], [0, 0, 0]);
    assert.equal(outcome.origin.positiveControls.admitted, 3, "the labelled controls still work: the boundary neither tightened nor loosened");
    for (const code of ["direct_app_execution", "direct_app_mutation", "direct_not_rejected"]) assert.ok(!codes(outcome).has(code as never), code);
    assertLineageGapsAreCrashTailsOnly(outcome, "plane");
    assert.ok(outcome.reasons.includes("ledger_anomalies_present"));
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.post_direct"), "legitimate traffic failed because the plane was dead");
  } finally { cleanup(outcome); }
});

test("the Origin Boundary crashing is INVALID with no restart and no fallback: the plane's egress fails, and the application's own port still refuses everything", { timeout: 240_000 }, async () => {
  const outcome = await runBa0Origin({ thresholds: SMALL, hooks: { beforePhase: async (phase, handles) => { if (phase === "direct") { handles.boundary.crash(); await sleep(250); } } } });
  try {
    assert.equal(outcome.verdict, "INVALID");
    assert.ok(codes(outcome).has("boundary_crashed"));
    assert.ok(outcome.directViolations.length > 0, "the boundary cases cannot be refused by a dead boundary: that is a recorded violation, never a silent pass");
    assert.ok(outcome.directViolations.every((problem) => /^(?:np_|sp_|mf_|bd_|hp_|tm_|fg_|sc_|xh_|rp_)/.test(problem)), "only boundary-targeted cases fail");
    assert.equal(outcome.origin.direct.appRefused, outcome.origin.direct.appSent, "every app-port attempt was still refused by the app's own guard");
    assert.deepEqual([outcome.origin.direct.appAdmissionsOnRejectedLanes, outcome.origin.direct.appExecutionsOnRejectedLanes, outcome.origin.direct.appMutationsOnRejectedLanes], [0, 0, 0]);
    assert.equal(outcome.accounting.egress.failedByKind.refused > 0 || outcome.accounting.egress.failed > 0, true, "plane egress to the dead boundary is attributed (refused/reset), never rerouted");
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.post_direct"));
    assertLineageGapsAreCrashTailsOnly(outcome, "boundary");
    for (const code of ["direct_app_execution", "direct_app_mutation", "direct_not_rejected"]) assert.ok(!codes(outcome).has(code as never), code);
  } finally { cleanup(outcome); }
});

test("an application failure behind the boundary is attributed to the forward and fails the run; the failed requests keep their lineage up to the failure", { timeout: 240_000 }, async () => {
  const outcome = await runBa0Origin({ thresholds: SMALL, hooks: { beforePhase: (phase, handles) => { if (phase === "baseline") handles.app.injectFault({ kind: "reset", remaining: 2 }); } } });
  try {
    assert.equal(outcome.verdict, "INVALID");
    assert.equal(outcome.origin.boundary.forwardFailed, 2);
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.baseline"));
    assert.ok(!codes(outcome).has("direct_app_execution"));
    assert.ok(!codes(outcome).has("app_admit_without_lineage"), "an admission that later failed still had complete lineage");
  } finally { cleanup(outcome); }
});

test("an injected signer failure fails closed at the plane: nothing is sent unsigned, the boundary sees nothing, and the run is INVALID", { timeout: 240_000 }, async () => {
  const outcome = await runBa0Origin({ thresholds: SMALL, hooks: { beforePhase: async (phase, handles) => { if (phase === "baseline") { handles.plane.injectFault("sign", 2); await sleep(150); } } } });
  try {
    assert.equal(outcome.verdict, "INVALID");
    assert.equal(outcome.origin.plane.signFailures, 2);
    assert.equal(outcome.origin.plane.attempted, outcome.origin.plane.proofIssued + 2);
    assert.equal(outcome.origin.boundary.admitted, outcome.origin.plane.proofIssued, "the two unsigned attempts never reached the boundary");
    assert.equal(outcome.accounting.egress.failedByKind.error, 2);
    assert.ok(outcome.reasons.includes("jcr_below_minimum:protected.baseline"));
    assert.ok(!codes(outcome).has("boundary_rejected_plane_egress"));
  } finally { cleanup(outcome); }
});

test("a boundary started without usable key material never becomes ready: there is no unauthenticated mode to fall back to", { timeout: 120_000 }, async () => {
  const root = new HopTrustRoot();
  const collector = new Collector(null, DEFAULT_COLLECTOR_LIMITS);
  const init = root.boundaryInit(9, { replayCapacity: 8, bodyDeadlineMs: 100, forwardTimeoutMs: 100, baLifetimeMs: 1_000 });
  await assert.rejects(BoundaryProcess.start(collector, { ...init, publicKeyP: "not-a-key" }, 20_000), /exited before it was ready|did not become ready/);
  await assert.rejects(BoundaryProcess.start(collector, { ...init, privateKeyB: "AAAA" }, 20_000), /exited before it was ready|did not become ready/);
});

test("lab:ba0:origin takes no arguments: anything is REFUSED before any socket is opened", () => {
  const result = spawnSync(process.execPath, [...process.execArgv, path.join(REPOSITORY_ROOT, "lab", "defense", "ba0-origin-run.ts"), "--target", "x"], { cwd: REPOSITORY_ROOT, encoding: "utf8", timeout: 60_000 });
  assert.equal(result.status, 2, result.stderr);
  assert.match(result.stderr, /REFUSED/);
});
