/**
 * BA0 Slice 3 runner: layer diversity and predecessor-collapse qualification of L2 `a7.journey-lanes`. Loopback only.
 *
 *   npm run lab:ba0:collapse
 *
 * The CLI accepts NO arguments: counts, ports and targets are fixed by the `ba0-collapse-local-v1` threshold set and every socket is a
 * 127.0.0.1 listener this process (or one of its child processes) created. Each arm is an independent topology with its own keys:
 *
 *   C0r  the unchanged Slice-2 composition (`defense/plane/main.ts`): L2 is ABSENT from its module graph, not disabled by any flag
 *   C0   the normal Slice-3 composition (`defense/plane/main-l2.ts`): L1 + L2 + canonicalization + PB + Boundary + BA + App. No collapse capability
 *   C1   the harness-only collapse entry: real L1 evaluation delivered as a simulated false-negative (basis=simulated); real L2
 *   C2   the harness-only collapse entry: real shadow L1 and L2 evaluations, both delivered as simulated passes; characterization only.
 *        Canonicalization, PB, Boundary, BA, replay guards and the App guard stay real
 *   C2p  the harness-only collapse entry with REAL L1/L2 faults (no forced verdict): the failure policy end to end
 *
 * Conclusions: LAYER-DIVERSITY-VALID or INVALID. Never a defense-qualification PASS. LAYER-DIVERSITY-VALID means ONLY that, under these local,
 * fixed-count conditions and for the reviewed fixture set, a second application-plane mechanism using a different signal (journey provenance
 * plus budgeted mutation lanes) bounded residual mutation while preserving the declared legitimate journeys. It does not imply DDoS
 * resistance, bot detection, read-flood protection, per-user fairness, L1/L2 process independence, network or transport protection, or
 * production readiness.
 * Exit codes: 0 LAYER-DIVERSITY-VALID, 1 INVALID, 2 REFUSED, 4 ERROR.
 */
import path from "node:path";
import { createSyntheticOrigin, type SyntheticOrigin } from "../../defense/origin/synthetic-origin";
import { JourneyLanes, UNIT } from "../../defense/core/lanes";
import { terminalOutcome, terminalOutcomeL2, type PlaneEvent } from "../../defense/core/ledger";
import type { L2Params, PlaneL2Advisory } from "../../defense/plane/l2-protocol";
import { EvidenceRun, collectEnvironment, collectGitState, type EvidenceResult } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { deriveAccounting, type AccountingReport } from "./accounting";
import { compareParity, journeyCompletionRates, latenciesByLane, runJourney, type JourneyResult } from "./canary";
import { trackedRaw, type Exchange } from "./client";
import { CollapseController } from "./collapse/controller";
import { forcedIdentity, forcedRequestBytes, FORCED_FIXTURES, FORCED_FIXTURE_SET_DIGEST, RENDER_SCENARIOS, isRedirect, newToken, render, runF1, runF2, runF3, runF4Renders, postFabricated, tokenFrom, validFormBody, type FloodResult, type ForcedFixture } from "./collapse-corpus";
import { BA0_COLLAPSE_LOCAL_V1, ba0CollapseFingerprint, decideCollapseVerdict, type Ba0CollapseThresholds, type CollapseVerdict, type Gate } from "./collapse-thresholds";
import { Collector, DEFAULT_COLLECTOR_LIMITS, type LedgerRecord, type PlaneFin, type RequestMeta } from "./collector";
import { HopTrustRoot } from "./hop-keys";
import { deriveLaneAccounting, penetrationTable, realDecision, type LaneAccountingReport, type PenetrationRow } from "./lane-accounting";
import { deriveOriginAccounting, type OriginAccountingReport } from "./origin-accounting";
import { AppProcess, BoundaryProcess } from "./origin-processes";
import { PLANE_L2_ENTRY, PlaneProcess } from "./plane-process";
import { compareLatency } from "./thresholds";

const REPOSITORY_ROOT_ENTRY = (relative: string) => path.join(__dirname, "..", "..", relative);
const LEGACY_ENTRY = REPOSITORY_ROOT_ENTRY(path.join("defense", "plane", "main.ts"));
const COLLAPSE_ENTRY = path.join(__dirname, "collapse", "plane-collapse-main.ts");

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const round = (value: number) => Math.round(value * 1000) / 1000;

export type ArmName = "C0r" | "C0" | "C1" | "C2" | "C2p";
export const ALL_ARMS: readonly ArmName[] = ["C0r", "C0", "C1", "C2", "C2p"];

export type Ba0CollapseOptions = { thresholds?: Ba0CollapseThresholds; arms?: readonly ArmName[]; log?: (line: string) => void };

/** Exact strings the evidence carries about what is NOT claimed; a test pins that no other string over-claims. */
export const NOT_CLAIMED: readonly string[] = Object.freeze([
  "DDoS resistance",
  "bot detection",
  "read-flood resistance",
  "per-user fairness",
  "L1/L2 process independence: both layers run in one Defense Plane process and share its failure domain",
  "network or transport protection",
  "production readiness",
  "calibrated limits: every number is provisional and uncalibrated",
  "protection against a stateful automation that renders and then posts, beyond the stated credited-lane bound",
  "behaviour with more than one plane instance",
  "fidelity to the real application's idempotency, challenge verification or budgets",
]);
export const SCOPE_STATEMENT = "application-plane layer diversity only: a second mechanism with a different signal behind L1, measured on loopback with fixed counts; no volumetric, network or transport behaviour is measured";
export const SCALE_STATEMENT = "lab constants: the credit filter is scaled down and generation lengths are compressed so fixed-count experiments can walk the whole curve; semantics are identical and unit-tested on an injected clock";

// ---------------------------------------------------------------------------
// Arm infrastructure
// ---------------------------------------------------------------------------

type ArmSpec = { name: ArmName; entry: string; l2: boolean; collapse: boolean; l2Params?: L2Params };

type ArmContext = {
  spec: ArmSpec;
  thresholds: Ba0CollapseThresholds;
  collector: Collector;
  control: SyntheticOrigin;
  controlPort: number;
  plane: PlaneProcess;
  planePort: number;
  controller: CollapseController | null;
  journeys: JourneyResult[];
  gates: Gate[];
  log: (line: string) => void;
  clientMutations: Record<string, number>;
  notes: Record<string, unknown>;
};

export type ArmReport = {
  name: ArmName;
  spec: ArmSpec;
  records: LedgerRecord[];
  anomalies: { code: string; nonce: string | null; detail: string }[];
  anomalyTotal: number;
  fin: PlaneFin | null;
  journeys: JourneyResult[];
  lane: LaneAccountingReport | null;
  legacy: AccountingReport | null;
  origin: OriginAccountingReport;
  gates: Gate[];
  notes: Record<string, unknown>;
  controllerRecords: { armTag: string; layer: string; granted: boolean }[];
  journalFile: string;
  journal: { lines: number; bytes: number; sha256: string; overflow: boolean } | null;
  thresholds: Ba0CollapseThresholds;
};

/** Gate details are free text that ends up in evidence: the evidence scanner refuses name/value shapes, so none is ever written. */
const safeDetail = (detail: string): string => detail.replace(/=/g, ":").replace(/%/g, " pct").slice(0, 400);
const gate = (ctx: { spec: ArmSpec; gates: Gate[] }, id: string, ok: boolean, detail: string): void => { ctx.gates.push({ id: `${ctx.spec.name}.${id}`, ok, detail: safeDetail(detail) }); };

async function runArm(spec: ArmSpec, thresholds: Ba0CollapseThresholds, directory: string, log: (line: string) => void, body: (ctx: ArmContext) => Promise<void>, evaluate: (report: ArmReport) => void): Promise<ArmReport> {
  const journalFile = `ledger-journal-${spec.name.toLowerCase()}.ndjson`;
  const collector = new Collector(path.join(directory, journalFile), { ...DEFAULT_COLLECTOR_LIMITS, ...thresholds.collector });
  collector.enableOriginStreams();
  if (spec.l2) collector.enableLaneStreams();
  const root = new HopTrustRoot();
  const control = createSyntheticOrigin({ instance: "control", onObservation: (event) => collector.ingestOrigin(event) });
  let plane: PlaneProcess | null = null;
  let boundary: BoundaryProcess | null = null;
  let app: AppProcess | null = null;
  try {
    const controlPort = await control.listen();
    app = await AppProcess.start(collector, root.appInit({ replayCapacity: thresholds.hop.replayCapacity, bodyDeadlineMs: thresholds.hop.bodyDeadlineMs }, thresholds.channel));
    boundary = await BoundaryProcess.start(collector, root.boundaryInit(app.port, {
      replayCapacity: thresholds.hop.replayCapacity, bodyDeadlineMs: thresholds.hop.bodyDeadlineMs, forwardTimeoutMs: thresholds.hop.forwardTimeoutMs, baLifetimeMs: thresholds.hop.baLifetimeMs,
    }, thresholds.channel));
    plane = await PlaneProcess.start(collector, {
      upstreamPort: boundary.port, bodyDeadlineMs: thresholds.timing.stallDeadlineMs, egressTimeoutMs: thresholds.timing.clientTimeoutMs,
      composer: { timeoutMs: thresholds.composer.timeoutMs, maxConcurrent: thresholds.composer.maxConcurrent, failurePolicy: "fail_closed" }, channel: thresholds.channel,
      hop: root.planeInit(thresholds.hop.pbLifetimeMs), ...(spec.l2 ? { l2: spec.l2Params ?? thresholds.l2 } : {}),
    }, 20_000, spec.entry);
    const ctx: ArmContext = {
      spec, thresholds, collector, control, controlPort, plane, planePort: plane.port, controller: spec.collapse ? new CollapseController(plane) : null,
      journeys: [], gates: [], log, clientMutations: {}, notes: {},
    };
    log(`arm ${spec.name} started`);
    await body(ctx);

    const fin = await plane.finish(thresholds.timing.finTimeoutMs);
    const boundaryFin = await boundary.finish(thresholds.timing.finTimeoutMs);
    const appFin = await app.finish(thresholds.timing.finTimeoutMs);
    void boundaryFin; void appFin;
    collector.freeze();
    await sleep(thresholds.timing.settleMs);
    await Promise.all([plane.stop(), boundary.stop(), app.stop()]);
    await control.close();

    const { anomalies, anomalyTotal } = collector.finalize();
    const records = [...collector.allRecords()];
    const origin = deriveOriginAccounting({
      records, journeys: ctx.journeys, boundary: collector.boundaryInfo.fin, app: collector.appInfo.fin, controlCounters: control.appStats(),
      boundaryAnonymous: collector.boundaryInfo.anonymous, appAnonymous: collector.appInfo.anonymous, hop: fin?.advisory.hop,
      expected: { positiveControls: 0, parserCases: 0, droppedUnbound: 0 },
    });
    // The Slice-2 identity "client-observed mutations equal ledger mutations" counts only the canary; this run's hostile fixtures mutate too, and
    // that is reconciled below (client, ledger and the application's own counter, per family).
    origin.identities = origin.identities.filter((identity) => identity.id !== "o2.mutation_client_equals_ledger");
    origin.identitiesOk = origin.identities.every((identity) => identity.ok);
    const advisory = fin?.advisory as PlaneL2Advisory | undefined;
    const lane = spec.l2 ? deriveLaneAccounting({ records, fin: advisory && "l2" in advisory ? advisory : null, l2: spec.l2Params ?? thresholds.l2, renderScenarios: RENDER_SCENARIOS, maxUses: (spec.l2Params ?? thresholds.l2).maxUses }) : null;
    const legacy = spec.l2 ? null : deriveAccounting(records.filter((record) => record.meta.lane === "protected" || record.meta.lane === "control" || record.meta.lane === "pre_ingress"), collector.parserRejectedTotal());
    const journal = await collector.closeJournal();
    const report: ArmReport = {
      name: spec.name, spec, records, anomalies, anomalyTotal, fin, journeys: ctx.journeys, lane, legacy, origin, gates: ctx.gates, notes: ctx.notes,
      controllerRecords: ctx.controller?.records ?? [], journalFile, journal, thresholds,
    };
    // mutation reconciled three ways per run: client-observed (canary + hostile) = ledger = the application's own counter
    const canaryClient = ctx.journeys.filter((journey) => journey.lane === "protected" && journey.steps[3]?.ok === true).length;
    const hostileClient = Object.values(ctx.clientMutations).reduce((total, value) => total + value, 0);
    gate(report, "mutation_reconciled", canaryClient + hostileClient === origin.mutation.ledgerCorrelated && origin.mutation.ledgerCorrelated === origin.mutation.appAuthoritative,
      `client ${canaryClient + hostileClient}, ledger ${origin.mutation.ledgerCorrelated}, application ${origin.mutation.appAuthoritative}`);
    evaluate(report);
    return report;
  } finally {
    await Promise.allSettled([plane?.stop(), boundary?.stop(), app?.stop(), control.close()]);
  }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function canary(ctx: ArmContext, phase: string, count: number): Promise<void> {
  const { gapMs } = ctx.thresholds.journeys;
  for (let index = 0; index < count; index++) {
    const started = performance.now();
    const order = index % 2 === 0 ? (["control", "protected"] as const) : (["protected", "control"] as const);
    for (const lane of order) {
      ctx.journeys.push(await runJourney(ctx.collector, { lane, port: lane === "control" ? ctx.controlPort : ctx.planePort, phase, journey: index + 1, timeoutMs: ctx.thresholds.timing.clientTimeoutMs }));
    }
    const rest = gapMs - (performance.now() - started);
    if (rest > 0 && index < count - 1) await sleep(rest);
  }
}

const tally = (ctx: ArmContext, scenario: string, results: readonly FloodResult[]): void => {
  ctx.clientMutations[scenario] = (ctx.clientMutations[scenario] ?? 0) + results.filter((result) => result.mutatedByClient).length;
};

/** The forced fixture, delivered on a connection the harness opened, after the arms were granted over IPC. Nothing about the request enables a bypass. */
async function sendForced(ctx: ArmContext, fixture: ForcedFixture, arms: { l1: boolean; l2: boolean }, phase: string): Promise<Exchange> {
  const meta: RequestMeta = { lane: "protected", phase, cls: "hostile", scenario: fixture.id, journey: null, step: null, method: fixture.method };
  const identity = forcedIdentity(fixture);
  return trackedRaw(ctx.collector, ctx.planePort, meta, (nonce) => ({ head: forcedRequestBytes(fixture, ctx.planePort, nonce) }), ctx.thresholds.timing.clientTimeoutMs, async (socket, nonce) => {
    if (ctx.controller === null) throw new Error("no collapse controller");
    const port = socket.localPort;
    if (port === undefined) throw new Error("no local port");
    if (arms.l1 && !(await ctx.controller.arm("l1", nonce, identity, port))) throw new Error("l1 arm refused");
    if (arms.l2 && !(await ctx.controller.arm("l2", nonce, identity, port))) throw new Error("l2 arm refused");
  });
}

/** A request the normal plane must NOT treat specially even though the harness tries to arm it: used as the negative control. */
async function sendUnderArmAttempt(ctx: ArmContext, fixture: ForcedFixture, phase: string): Promise<Exchange> {
  const meta: RequestMeta = { lane: "protected", phase, cls: "hostile", scenario: `${fixture.id}_armattempt`, journey: null, step: null, method: fixture.method };
  return trackedRaw(ctx.collector, ctx.planePort, meta, (nonce) => ({ head: forcedRequestBytes(fixture, ctx.planePort, nonce) }), ctx.thresholds.timing.clientTimeoutMs, async (socket, nonce) => {
    // The control message is sent; a normal plane has no handler and no ack ever comes, so this never waits for one.
    ctx.plane.sendControl({ type: "collapse:arm", armId: "attempt-without-a-handler", layer: "l1", nonce, fixtureDigest: "0".repeat(64), remotePort: socket.localPort ?? 1, ttlMs: 1000 });
    await sleep(50);
  });
}

const dec = (record: LedgerRecord): PlaneEvent | undefined => record.plane.find((event) => event.kind === "L2_DECIDED");
const hostile = (records: readonly LedgerRecord[], scenarioPrefix: string, phase?: string): LedgerRecord[] =>
  records.filter((record) => record.meta.cls === "hostile" && record.meta.lane === "protected" && record.meta.scenario.startsWith(scenarioPrefix) && (phase === undefined || record.meta.phase === phase));
const mutations = (records: readonly LedgerRecord[]): number => records.reduce((total, record) => total + record.app.filter((event) => event.kind === "APP_MUTATED").length, 0);
const realOutcome = (record: LedgerRecord): { outcome: string; lane: string } => { const d = dec(record); return d ? realDecision(d) : { outcome: "none", lane: "none" }; };

/** Admitted decisions on one bucket within a set of records, against the bound the bucket itself allows over the span those decisions cover. */
function laneBound(records: readonly LedgerRecord[], lane: "credited" | "unverified", bucket: { capacity: number; refillPerSecond: number }): { admitted: number; bound: number; span: number } {
  const decisions = records.map(dec).filter((event): event is PlaneEvent => event !== undefined && event.dt !== undefined && realDecision(event).lane === lane);
  if (decisions.length === 0) return { admitted: 0, bound: bucket.capacity, span: 0 };
  const dts = decisions.map((event) => event.dt as number);
  const span = Math.max(...dts) - Math.min(...dts);
  return { admitted: decisions.filter((event) => realDecision(event).outcome === "admitted").length, bound: Math.floor(bucket.capacity + (bucket.refillPerSecond * span) / 1000), span };
}

type PhaseSummary = { phase: string; lane: string; attempted: number; completed: number; rate: number };
function canaryByPhase(report: ArmReport): { jcr: PhaseSummary[]; refused: Record<string, { falseRejects: number; legit503: number; legit429: number; requests: number }> } {
  const jcr = journeyCompletionRates(report.journeys).map((entry) => ({ phase: entry.phase, lane: entry.lane, attempted: entry.attempted, completed: entry.completed, rate: entry.rate }));
  const refused: Record<string, { falseRejects: number; legit503: number; legit429: number; requests: number }> = {};
  for (const record of report.records) {
    if (record.meta.cls !== "canary" || record.meta.lane !== "protected") continue;
    const row = refused[record.meta.phase] ?? { falseRejects: 0, legit503: 0, legit429: 0, requests: 0 };
    row.requests++;
    const outcome = report.spec.l2 ? terminalOutcomeL2(record.plane) : terminalOutcome(record.plane);
    if (outcome === "rejected" || outcome === "shed" || outcome === "error" || outcome === "l2_shed" || outcome === "l2_error") row.falseRejects++;
    const client = record.harness.find((event) => event.kind === "CLIENT_COMPLETED");
    if (client?.status === 503) row.legit503++;
    if (client?.status === 429) row.legit429++;
    refused[record.meta.phase] = row;
  }
  return { jcr, refused };
}

const gated = (phase: string): boolean => !phase.startsWith("farm");
const pressurePhase = (phase: string): boolean => phase.startsWith("pressure") || phase.startsWith("after") || phase === "poison";

/** JCR, refusals, parity and latency gates over every canary phase of an arm (the farmer phases are reported, never gated). */
function continuityGates(report: ArmReport): void {
  const { jcr, refused } = canaryByPhase(report);
  const thresholds = report.thresholds;
  const protectedGated = jcr.filter((entry) => entry.lane === "protected" && gated(entry.phase));
  gate(report, "canary_jcr", protectedGated.length > 0 && protectedGated.every((entry) => entry.rate >= thresholds.jcr.minimum), protectedGated.map((entry) => `${entry.phase}:${entry.completed}/${entry.attempted}`).join(" "));
  const controlJcr = jcr.filter((entry) => entry.lane === "control");
  gate(report, "control_jcr", controlJcr.length > 0 && controlJcr.every((entry) => entry.rate >= thresholds.jcr.minimum), "the unprotected control completes every journey");
  const bad = Object.entries(refused).filter(([phase, row]) => gated(phase) && (row.falseRejects > 0 || row.legit503 > 0 || row.legit429 > 0));
  gate(report, "legitimate_refusals_zero", bad.length === 0, bad.map(([phase, row]) => `${phase}:rej${row.falseRejects}/503:${row.legit503}/429:${row.legit429}`).join(" ") || "no canary request was refused or answered 429/503 in a gated phase");
  gate(report, "parity", compareParity(report.journeys.filter((journey) => gated(journey.phase))).mismatches.length === 0, "status, body digest and header names match the control");
  const split = (predicate: (phase: string) => boolean) => latenciesByLane(report.journeys.filter((journey) => predicate(journey.phase)));
  const calm = split((phase) => phase === "baseline" || phase.startsWith("recovery") || phase === "final");
  const stressed = split(pressurePhase);
  const calmComparison = compareLatency(thresholds.latencyEnvelope, calm.control, calm.protected);
  gate(report, "latency_calm", calmComparison.ok, `added p95 ${calmComparison.addedP95Ms} ms, p99 ${calmComparison.addedP99Ms} ms`);
  if (stressed.protected.length > 0) {
    const stressedComparison = compareLatency(thresholds.pressureLatencyEnvelope, stressed.control, stressed.protected);
    gate(report, "latency_pressure_provisional", stressedComparison.ok, `added p95 ${stressedComparison.addedP95Ms} ms, p99 ${stressedComparison.addedP99Ms} ms (provisional envelope)`);
  }
}

function identityGates(report: ArmReport): void {
  gate(report, "ledger_anomalies_zero", report.anomalyTotal === 0, JSON.stringify(report.anomalies.slice(0, 3)));
  if (report.lane) gate(report, "lane_identities", report.lane.identitiesOk, report.lane.identities.filter((identity) => !identity.ok).map((identity) => `${identity.id}:${identity.left}/${identity.right}`).join(" "));
  if (report.legacy) gate(report, "plane_identities", report.legacy.identitiesOk, report.legacy.identities.filter((identity) => !identity.ok).map((identity) => `${identity.id}:${identity.left}/${identity.right}`).join(" "));
  gate(report, "origin_identities", report.origin.identitiesOk, report.origin.identities.filter((identity) => !identity.ok).map((identity) => `${identity.id}:${identity.left}/${identity.right}`).join(" "));
  gate(report, "journal_not_overflowed", report.journal?.overflow !== true, "the bounded journal did not overflow");
}

// ---------------------------------------------------------------------------
// C0r: the unchanged Slice-2 composition
// ---------------------------------------------------------------------------

async function bodyC0r(ctx: ArmContext): Promise<void> {
  const { thresholds } = ctx;
  await canary(ctx, "baseline", thresholds.journeys.baselinePerLane);
  const f1Run = (async () => tally(ctx, "f1_fabricated", await runF1(ctx.collector, ctx.planePort, "pressure_c1", thresholds.fixtures.f1.count, thresholds.fixtures.f1.concurrency, thresholds.timing.clientTimeoutMs)))();
  const f2Run = (async () => tally(ctx, "f2_post", await runF2(ctx.collector, ctx.planePort, "pressure_c1", thresholds.fixtures.f2.credits, thresholds.fixtures.f2.postsPerCredit, thresholds.timing.clientTimeoutMs)))();
  await Promise.all([f1Run, f2Run, canary(ctx, "pressure_c1", thresholds.journeys.pressurePerCycle)]);
  tally(ctx, "f3_post", await runF3(ctx.collector, ctx.planePort, "farm_c1", thresholds.fixtures.f3.journeys, thresholds.fixtures.f3.postsPerCredit, thresholds.timing.clientTimeoutMs));
  // The negative control: a harness arm attempt against a plane that has no handler for it changes nothing.
  const refused = await sendUnderArmAttempt(ctx, FORCED_FIXTURES.find((fixture) => fixture.id === "fx_path_admin") as ForcedFixture, "negative_control");
  ctx.notes.negativeControlStatus = refused.status;
  await canary(ctx, "recovery_c1", thresholds.journeys.recovery);
}

function evaluateC0r(report: ArmReport): void {
  identityGates(report);
  continuityGates(report);
  const { thresholds } = report;
  const f1 = hostile(report.records, "f1_fabricated");
  const f2 = hostile(report.records, "f2_post");
  const f3 = hostile(report.records, "f3_post");
  const residual = { f1: mutations(f1), f2: mutations(f2), f3: mutations(f3) };
  report.notes.residualMutations = { ...residual, f1Sent: thresholds.fixtures.f1.count };
  gate(report, "reference_residual_observed", residual.f1 >= Math.floor(thresholds.fixtures.f1.count * 0.98), `reference arm: ${residual.f1} of ${thresholds.fixtures.f1.count} fabricated valid mutations reached APP_MUTATED (no L2)`);
  gate(report, "reference_has_no_l2_and_no_override", report.fin !== null && !("l2" in (report.fin.advisory as object)) && report.records.every((record) => record.plane.every((event) => event.basis === undefined && !event.kind.startsWith("L2_"))), "the legacy composition produced no L2 event and no simulated label");
  gate(report, "negative_control_normal_plane", report.notes.negativeControlStatus === 404 && hostile(report.records, "fx_path_admin_armattempt").every((record) => record.plane.some((event) => event.kind === "L1_REJECTED") && !record.plane.some((event) => event.kind === "EGRESS_ATTEMPTED")), "a harness arm attempt against a plane without a handler leaves L1's refusal in force");
}

// ---------------------------------------------------------------------------
// C0: the normal Slice-3 composition, repeated pressure -> recovery cycles
// ---------------------------------------------------------------------------

async function bodyC0(ctx: ArmContext): Promise<void> {
  const { thresholds } = ctx;
  const staleTokens: (string | null)[] = [];
  await canary(ctx, "baseline", thresholds.journeys.baselinePerLane);
  for (let cycle = 1; cycle <= thresholds.cycles.count; cycle++) {
    ctx.log(`C0 cycle ${cycle}: pressure`);
    const stale = await render(ctx.collector, ctx.planePort, `stalefetch_c${cycle}`, "stale_render", thresholds.timing.clientTimeoutMs);
    staleTokens.push(tokenFrom(stale));
    const f1Run = (async () => tally(ctx, "f1_fabricated", await runF1(ctx.collector, ctx.planePort, `pressure_c${cycle}`, thresholds.fixtures.f1.count, thresholds.fixtures.f1.concurrency, thresholds.timing.clientTimeoutMs)))();
    const f2Run = (async () => tally(ctx, "f2_post", await runF2(ctx.collector, ctx.planePort, `pressure_c${cycle}`, thresholds.fixtures.f2.credits, thresholds.fixtures.f2.postsPerCredit, thresholds.timing.clientTimeoutMs)))();
    await Promise.all([f1Run, f2Run, canary(ctx, `pressure_c${cycle}`, thresholds.journeys.pressurePerCycle)]);
    await canary(ctx, `after_c${cycle}`, thresholds.journeys.afterPressure);
    const farmRun = (async () => tally(ctx, "f3_post", await runF3(ctx.collector, ctx.planePort, `farm_c${cycle}`, thresholds.fixtures.f3.journeys, thresholds.fixtures.f3.postsPerCredit, thresholds.timing.clientTimeoutMs)))();
    await Promise.all([farmRun, canary(ctx, `farm_c${cycle}`, 3)]);
    ctx.log(`C0 cycle ${cycle}: recovery`);
    await sleep(thresholds.cycles.recoverySettleMs);
    // A credit enrolled before the idle period is gone: its POST is unverified (generations aged out, the use record is purgeable, nothing was reopened).
    const stalePost = staleTokens[cycle - 1];
    if (stalePost !== null) {
      const exchange = await postFabricated(ctx.collector, ctx.planePort, `recovery_c${cycle}`, thresholds.timing.clientTimeoutMs, "stale_post", stalePost);
      tally(ctx, "stale_post", [{ exchange, mutatedByClient: isRedirect(exchange) }]);
      // the one unverified token that probe took must have time to come back before the next pressure phase starts
      await sleep(Math.ceil(1000 / thresholds.l2.unverified.refillPerSecond) + 100);
    }
    await canary(ctx, `recovery_c${cycle}`, thresholds.journeys.recovery);
  }
  // render/filter poisoning characterization: a bounded render flood, with the canary running, then a fabricated probe against the poisoned filter
  ctx.log("C0 poison");
  const poisonFlood = runF4Renders(ctx.collector, ctx.planePort, "poison", thresholds.fixtures.f4.renders, thresholds.fixtures.f4.concurrency, thresholds.timing.clientTimeoutMs);
  await Promise.all([poisonFlood, canary(ctx, "poison", thresholds.journeys.pressurePerCycle)]);
  tally(ctx, "f4_fabricated", await runF1(ctx.collector, ctx.planePort, "poison", thresholds.fixtures.f4.fabricatedProbe, thresholds.fixtures.f1.concurrency, thresholds.timing.clientTimeoutMs, "f4_fabricated"));
  await sleep(thresholds.cycles.recoverySettleMs);
  await canary(ctx, "final", thresholds.journeys.recovery);
  await sleep(thresholds.cycles.recoverySettleMs);
  // The negative control: a harness arm attempt against the normal Slice-3 plane has no effect.
  const refused = await sendUnderArmAttempt(ctx, FORCED_FIXTURES.find((fixture) => fixture.id === "fx_path_admin") as ForcedFixture, "negative_control");
  ctx.notes.negativeControlStatus = refused.status;
}

function evaluateC0(report: ArmReport): void {
  identityGates(report);
  continuityGates(report);
  const { thresholds, lane, records } = report;
  const l2 = thresholds.l2;
  gate(report, "normal_arm_has_no_collapse_capability", report.fin !== null && (report.fin.advisory as PlaneL2Advisory).overrideInjected === false && records.every((record) => record.plane.every((event) => event.basis === undefined)), "overrideInjected is false and no event carries a simulated label");
  gate(report, "negative_control_normal_plane", report.notes.negativeControlStatus === 404 && hostile(records, "fx_path_admin_armattempt").every((record) => record.plane.some((event) => event.kind === "L1_REJECTED") && !record.plane.some((event) => event.kind === "EGRESS_ATTEMPTED")), "a harness arm attempt against the normal plane leaves L1's refusal in force");
  if (lane === null) return;

  // ---- per cycle: bounded hostile mutation, replay beyond K, recovery equivalence
  const cycleRows: Record<string, unknown>[] = [];
  const attenuations: number[] = [];
  for (let cycle = 1; cycle <= thresholds.cycles.count; cycle++) {
    const phase = `pressure_c${cycle}`;
    const f1 = hostile(records, "f1_fabricated", phase);
    const f2 = hostile(records, "f2_post", phase);
    const f1Bound = laneBound(f1, "unverified", l2.unverified);
    const f1Credited = f1.filter((record) => realOutcome(record).lane === "credited").length;
    const f1Mutated = mutations(f1);
    const attenuation = f1.length === 0 ? 0 : round(1 - f1Mutated / f1.length);
    attenuations.push(attenuation);
    const f2Credited = f2.filter((record) => realOutcome(record).lane === "credited" && realOutcome(record).outcome === "admitted").length;
    gate(report, `c${cycle}_f1_bounded`, f1Bound.admitted <= f1Bound.bound && f1Mutated <= f1Bound.admitted, `admitted ${f1Bound.admitted} within the unverified bound ${f1Bound.bound} (span ${f1Bound.span} ms); mutated ${f1Mutated} of ${f1.length}`);
    gate(report, `c${cycle}_f1_bucket_was_full`, f1Bound.admitted >= l2.unverified.capacity, `the first ${l2.unverified.capacity} fabricated posts were admitted: the bucket was full when pressure began (admitted ${f1Bound.admitted})`);
    gate(report, `c${cycle}_f1_never_credited`, f1Credited === 0, `${f1Credited} fabricated posts were classified credited`);
    gate(report, `c${cycle}_f2_replay_capped`, f2Credited === thresholds.fixtures.f2.credits * l2.maxUses, `credited admissions for replayed tokens: ${f2Credited} (K ${l2.maxUses} per token, ${thresholds.fixtures.f2.credits} tokens)`);
    cycleRows.push({ cycle, f1Sent: f1.length, f1AdmittedUnverified: f1Bound.admitted, f1Bound: f1Bound.bound, f1Mutated, attenuation, f2CreditedAdmitted: f2Credited });
  }
  gate(report, "cycles_equivalent_attenuation", attenuations.length > 0 && Math.max(...attenuations) - Math.min(...attenuations) <= thresholds.cycles.attenuationTolerance, `attenuation per cycle ${attenuations.join(", ")} within ${thresholds.cycles.attenuationTolerance}`);
  report.notes.cycles = cycleRows;

  // ---- farmer: bounded, never defeated: reported
  const farm = hostile(records, "f3_post");
  const farmCredited = farm.filter((record) => realOutcome(record).lane === "credited" && realOutcome(record).outcome === "admitted").length;
  const farmRenders = hostile(records, "f3_render").length;
  gate(report, "f3_farmer_bounded_by_k_per_render", farmCredited <= farmRenders * l2.maxUses, `credited farmer admissions ${farmCredited} within K x renders ${farmRenders * l2.maxUses}`);
  report.notes.farmer = { renders: farmRenders, posts: farm.length, creditedAdmitted: farmCredited, mutated: mutations(farm), note: "reported: a stateful render-then-post automation contends for the credited lane; it is bounded, not defeated" };

  // ---- recovery: stale credit, generation reset, final quiescence
  for (let cycle = 1; cycle <= thresholds.cycles.count; cycle++) {
    const stale = hostile(records, "stale_post", `recovery_c${cycle}`);
    gate(report, `c${cycle}_stale_credit_gone`, stale.length === 1 && realOutcome(stale[0]).lane === "unverified", `a credit enrolled before the idle period is classified ${stale.length === 1 ? realOutcome(stale[0]).lane : "missing"} after it`);
    const firstForm = records.find((record) => record.meta.cls === "canary" && record.meta.lane === "protected" && record.meta.scenario === "journey_form" && record.meta.phase === `recovery_c${cycle}`);
    const enrolled = firstForm?.plane.find((event) => event.kind === "L2_ENROLLED");
    gate(report, `c${cycle}_filter_generations_cleared`, enrolled?.fill !== undefined && enrolled.fill[1] === 0 && enrolled.fill[0] <= l2.filterHashes, `first enrollment after idle: popcount (active, previous) ${enrolled?.fill?.join(",") ?? "missing"}`);
  }
  const fprEstimate = Math.max(0, ...records.flatMap((record) => record.plane.filter((event) => event.kind === "L2_ENROLLED" && event.fill !== undefined).map((event) => {
    const [active, previous] = event.fill as [number, number];
    return 1 - (1 - Math.pow(active / l2.filterBits, l2.filterHashes)) * (1 - Math.pow(previous / l2.filterBits, l2.filterHashes));
  })));
  const poisonCanary = canaryByPhase(report);
  gate(report, "f4_filter_poisoned_by_renders", fprEstimate > 0.01, `estimated false-positive rate under the render flood reached ${round(fprEstimate)}`);
  gate(report, "f4_render_never_denied", hostile(records, "f4_render").every((record) => record.harness.some((event) => event.kind === "CLIENT_COMPLETED" && event.status === 200)), "every flooded render was served: form-page availability is untouched");
  gate(report, "f4_legit_credit_unaffected", (poisonCanary.jcr.find((entry) => entry.lane === "protected" && entry.phase === "poison")?.rate ?? 0) >= 1, "legitimate journeys during the render flood all completed: no genuine credit was lost");
  const probe = hostile(records, "f4_fabricated", "poison");
  const probeCredited = probe.filter((record) => realOutcome(record).lane === "credited" && realOutcome(record).outcome === "admitted").length;
  const probeBound = laneBound(probe, "credited", l2.credited);
  // the MEASURED false-positive rate: how many never-enrolled tokens the poisoned filter classified credited (admitted or shed by the credited bucket)
  const probeClassifiedCredited = probe.filter((record) => realOutcome(record).lane === "credited").length;
  gate(report, "f4_false_positive_credit_bounded", probeCredited <= probeBound.bound, `fabricated posts admitted credited (false positives): ${probeCredited} of ${probe.length}, within the credited bound ${probeBound.bound}`);
  report.notes.poison = {
    estimatedFalsePositiveRate: round(fprEstimate), fabricatedProbe: probe.length, measuredClassifiedCredited: probeClassifiedCredited,
    measuredFalsePositiveRate: probe.length === 0 ? 0 : round(probeClassifiedCredited / probe.length), falsePositiveCreditedAdmissions: probeCredited, falsePositiveByPhase: lane.credit.falsePositiveByPhase,
  };
  const outsidePoison = Object.entries(lane.credit.falsePositiveByPhase).filter(([phase]) => phase !== "poison");
  gate(report, "false_positive_credit_only_under_poison", outsidePoison.length === 0, `false-positive credited admissions outside the poison phase: ${outsidePoison.map(([phase, count]) => `${phase}:${count}`).join(" ") || "none"}`);
  const gatedPosts = records.filter((record) => record.meta.cls === "canary" && record.meta.lane === "protected" && record.meta.scenario === "journey_valid_post" && gated(record.meta.phase));
  const creditedPosts = gatedPosts.filter((record) => realOutcome(record).lane === "credited" && realOutcome(record).outcome === "admitted").length;
  gate(report, "canary_post_always_credited", gatedPosts.length > 0 && creditedPosts === gatedPosts.length, `legitimate POSTs credited ${creditedPosts} of ${gatedPosts.length} outside the farmer phases`);
  gate(report, "enrollment_precedes_decision_g2", lane.ordering.creditedWithEnrollment > 0 && lane.ordering.violations === 0, `${lane.ordering.creditedWithEnrollment} credited decisions checked, ${lane.ordering.violations} inversions`);

  const fin = report.fin?.advisory as PlaneL2Advisory | undefined;
  const snapshot = fin?.l2.lanes;
  const initial = new JourneyLanes({ filterBits: l2.filterBits, filterHashes: l2.filterHashes, epochMs: l2.epochMs, credited: l2.credited, unverified: l2.unverified, maxUses: l2.maxUses, ledgerCapacity: l2.ledgerCapacity, mono: () => 0 }).snapshot();
  const quiet = snapshot !== undefined && fin !== undefined && report.fin !== null
    && snapshot.credited.levelUnits === l2.credited.capacity * UNIT && snapshot.unverified.levelUnits === l2.unverified.capacity * UNIT
    && snapshot.filter.popcount[0] === 0 && snapshot.filter.popcount[1] === 0 && snapshot.ledger.size === 0 && snapshot.ledger.stateViolations === 0
    && fin.l2.occupancy === 0 && fin.front.inFlight === 0 && fin.channelNow.queued === 0 && fin.channelNow.unacknowledged === 0 && fin.channelNow.dropped === 0
    && snapshot.digest === initial.digest;
  gate(report, "final_quiescence", quiet, snapshot ? `buckets ${snapshot.credited.levelUnits / UNIT}/${snapshot.unverified.levelUnits / UNIT}, popcount ${snapshot.filter.popcount.join(",")}, ledger ${snapshot.ledger.size}, evaluator ${fin?.l2.occupancy}, front in-flight ${fin?.front.inFlight}, digest ${snapshot.digest === initial.digest ? "equals initial" : "DIFFERS"}` : "no final snapshot");
  report.notes.finalState = snapshot ? { digest: snapshot.digest, initialDigest: initial.digest, creditedLevel: snapshot.credited.levelUnits / UNIT, unverifiedLevel: snapshot.unverified.levelUnits / UNIT, popcount: snapshot.filter.popcount, ledgerSize: snapshot.ledger.size, stateViolations: snapshot.ledger.stateViolations, evaluatorOccupancy: fin?.l2.occupancy, frontInFlight: fin?.front.inFlight } : null;
  const residual = { f1: mutations(hostile(records, "f1_fabricated")), f2: mutations(hostile(records, "f2_post")), f3: mutations(farm) };
  report.notes.residualMutations = { ...residual, f1Sent: thresholds.fixtures.f1.count * thresholds.cycles.count };
}

// ---------------------------------------------------------------------------
// C1 / C2: simulated predecessor collapse
// ---------------------------------------------------------------------------

async function bodyCollapse(ctx: ArmContext, both: boolean): Promise<void> {
  const { thresholds } = ctx;
  const controller = ctx.controller as CollapseController;
  const initial = await controller.probe();
  ctx.notes.initialDigest = initial?.lanes.digest ?? null;
  await canary(ctx, "baseline", Math.max(2, Math.floor(thresholds.journeys.baselinePerLane / 3)));
  // single-flight, one armed request at a time; the canary never shares an armed window
  for (const fixture of FORCED_FIXTURES) await sendForced(ctx, fixture, { l1: true, l2: both }, "collapse");
  if (!both) {
    const burst = FORCED_FIXTURES.find((fixture) => fixture.id === "fx_unknown_field") as ForcedFixture;
    for (let index = 0; index < thresholds.fixtures.forcedBurst; index++) await sendForced(ctx, { ...burst, id: "fx_unknown_field_burst" }, { l1: true, l2: false }, "collapse_burst");
    // natural fabricated traffic alongside the canary: L1 passes it by design, L2 is real. The unverified bucket the forced fixtures drained refills first.
    await sleep(Math.ceil((thresholds.l2.unverified.capacity / thresholds.l2.unverified.refillPerSecond) * 1000) + 200);
    const f1Run = (async () => tally(ctx, "f1_fabricated", await runF1(ctx.collector, ctx.planePort, "pressure_c1", thresholds.fixtures.f1.count, thresholds.fixtures.f1.concurrency, thresholds.timing.clientTimeoutMs)))();
    await Promise.all([f1Run, canary(ctx, "pressure_c1", thresholds.journeys.pressurePerCycle)]);
  } else {
    // fabricated valid mutations with BOTH layers' verdicts simulated: the deepest the request can go when both predecessors are wrong
    for (let index = 0; index < thresholds.fixtures.c2Fabricated; index++) {
      const fixture: ForcedFixture = {
        id: "c2_fabricated", method: "POST", rawMethod: "POST", target: "/api/public-inquiries", headers: [`Content-Type: application/x-www-form-urlencoded`, "Origin: http://127.0.0.1:{PORT}"],
        body: validFormBody(newToken()), l1Reason: "none", terminals: ["app_mutated"],
      };
      const exchange = await sendForced(ctx, fixture, { l1: false, l2: true }, "collapse");
      // a raw exchange keeps no body: a valid submission answered 200 is the client's evidence that the application committed it
      ctx.clientMutations.c2_fabricated = (ctx.clientMutations.c2_fabricated ?? 0) + (exchange.result === "response" && exchange.status === 200 ? 1 : 0);
    }
  }
  await sleep(thresholds.cycles.recoverySettleMs);
  const quiet = await controller.probe();
  ctx.notes.quiescentProbe = quiet === null ? null : {
    digest: quiet.lanes.digest, initialDigest: ctx.notes.initialDigest, creditedLevel: quiet.lanes.credited.levelUnits / UNIT, unverifiedLevel: quiet.lanes.unverified.levelUnits / UNIT,
    popcount: quiet.lanes.filter.popcount, ledgerSize: quiet.lanes.ledger.size, stateViolations: quiet.lanes.ledger.stateViolations, l2Occupancy: quiet.l2Occupancy, l1Occupancy: quiet.l1Occupancy,
    frontInFlight: quiet.front.inFlight, channelQueued: quiet.channel.queued, channelUnacknowledged: quiet.channel.unacknowledged, channelDropped: quiet.channel.dropped, arms: quiet.arms,
  };
  await canary(ctx, "recovery_c1", thresholds.journeys.recovery);
}

function evaluateCollapse(report: ArmReport, both: boolean): void {
  identityGates(report);
  continuityGates(report);
  const { thresholds, lane, records } = report;
  const forced = records.filter((record) => record.meta.cls === "hostile" && record.meta.lane === "protected" && (record.meta.phase === "collapse" || record.meta.phase === "collapse_burst"));
  const fixtureOf = (record: LedgerRecord) => FORCED_FIXTURES.find((fixture) => fixture.id === record.meta.scenario || `${fixture.id}_burst` === record.meta.scenario);
  const table = penetrationTable(records, (record) => (record.meta.cls === "hostile" ? (record.meta.scenario.startsWith("f1_") ? "f1_natural" : record.meta.scenario.startsWith("c2_") ? "c2_fabricated" : "forced") : null));
  report.notes.penetration = table.rows;

  const explained = forced.every((record) => (table.perRecord.get(record.rid)?.terminal ?? "").length > 0);
  gate(report, "every_fixture_has_terminal_explanation", explained && forced.length > 0, `${forced.length} forced requests, each with exactly one terminal explanation`);
  const simulated = forced.filter((record) => table.perRecord.get(record.rid)?.basis === "simulated").length;
  gate(report, "every_forced_request_labelled_simulated", forced.length > 0 && simulated === forced.length, `${simulated} of ${forced.length} forced requests carry basis=simulated`);
  const shadowsOk = forced.filter((record) => {
    const fixture = fixtureOf(record);
    const passed = record.plane.find((event) => event.kind === "L1_PASSED");
    return fixture !== undefined && passed?.basis === "simulated" && passed.shadow === `reject:${fixture.l1Reason}`;
  }).length;
  const forcedWithFixture = forced.filter((record) => fixtureOf(record) !== undefined).length;
  gate(report, "l1_really_evaluated_shadow_matches", forcedWithFixture > 0 && shadowsOk === forcedWithFixture, `the shadow of each simulated L1 pass equals the reject reason L1 really computed (${shadowsOk} of ${forcedWithFixture})`);
  const terminalsOk = forced.filter((record) => { const fixture = fixtureOf(record); const terminal = table.perRecord.get(record.rid)?.terminal ?? ""; return fixture !== undefined && fixture.terminals.includes(terminal); }).length;
  gate(report, "forced_terminals_as_reviewed", terminalsOk === forcedWithFixture, `${terminalsOk} of ${forcedWithFixture} ended in a reviewed terminal explanation`);
  gate(report, "natural_and_simulated_never_merged", table.rows.filter((row) => row.family === "forced" || row.family === "c2_fabricated").every((row) => row.basis === "simulated") && table.rows.filter((row) => row.family === "f1_natural").every((row) => row.basis === "natural"), "forced rows are all simulated and natural rows all natural: nothing was summarized across the two");
  gate(report, "boundary_never_rejects_plane_approved", !records.some((record) => record.boundary.some((event) => event.kind === "BOUNDARY_REJECTED")), "no Boundary rejection of plane-approved traffic");
  const reachedApp = records.filter((record) => record.app.some((event) => event.kind === "APP_ADMITTED"));
  gate(report, "app_admissions_have_complete_lineage", report.origin.lineage.appAdmitsWithoutLineage === 0 && report.origin.lineage.complete === report.origin.app.admitted, `${reachedApp.length} requests reached the application, every one with the complete PB and BA lineage`);

  const controls = report.controllerRecords;
  const arms = (report.notes.quiescentProbe as { arms?: { armed: number; consumed: number; refused: number; expired: number; outstanding: number } } | null)?.arms;
  gate(report, "every_arm_granted_and_consumed", controls.every((entry) => entry.granted) && arms !== undefined && arms.armed === controls.length && arms.consumed === controls.length && arms.refused === 0 && arms.expired === 0 && arms.outstanding === 0, `arms ${arms?.armed}, consumed ${arms?.consumed}, refused ${arms?.refused}, expired ${arms?.expired}, outstanding ${arms?.outstanding}`);
  gate(report, "collapse_capable_entry_reported", report.fin !== null && (report.fin.advisory as PlaneL2Advisory).overrideInjected === true, "the harness entry reports overrideInjected; a normal entry always reports false");
  const quiet = report.notes.quiescentProbe as Record<string, unknown> | null;
  gate(report, "quiescence_digest_returns_to_initial", quiet !== null && quiet.digest === quiet.initialDigest && quiet.creditedLevel === thresholds.l2.credited.capacity && quiet.unverifiedLevel === thresholds.l2.unverified.capacity
    && JSON.stringify(quiet.popcount) === "[0,0]" && quiet.ledgerSize === 0 && quiet.stateViolations === 0 && quiet.l2Occupancy === 0 && quiet.l1Occupancy === 0 && quiet.frontInFlight === 0
    && quiet.channelQueued === 0 && quiet.channelUnacknowledged === 0 && quiet.channelDropped === 0, quiet ? `digest ${quiet.digest === quiet.initialDigest ? "equals initial" : "DIFFERS"}, popcount ${JSON.stringify(quiet.popcount)}, evaluator ${quiet.l2Occupancy}` : "no probe");
  if (lane === null) return;

  if (!both) {
    // C1: L1 was simulated-wrong; did L2 independently attenuate?
    const burst = forced.filter((record) => record.meta.phase === "collapse_burst");
    const shed = burst.filter((record) => realOutcome(record).outcome === "shed").length;
    const bound = laneBound(forced, "unverified", thresholds.l2.unverified);
    gate(report, "c1_l2_independently_attenuated", shed >= 1, `of ${burst.length} simulated-L1 false negatives in the burst, L2 shed ${shed}`);
    gate(report, "c1_forced_admissions_bounded", bound.admitted <= bound.bound, `forced requests admitted by the unverified lane: ${bound.admitted}, bound ${bound.bound}`);
    gate(report, "c1_forced_mutations_zero", mutations(forced) === 0, "none of the reviewed predecessor-collapse fixtures mutated application state");
    const f1 = hostile(records, "f1_fabricated");
    const f1Bound = laneBound(f1, "unverified", thresholds.l2.unverified);
    gate(report, "c1_natural_f1_bounded", f1Bound.admitted <= f1Bound.bound && mutations(f1) <= f1Bound.admitted, `natural fabricated posts: admitted ${f1Bound.admitted} within ${f1Bound.bound}, mutated ${mutations(f1)} of ${f1.length}`);
    report.notes.residualMutations = { forced: mutations(forced), f1: mutations(f1), f1Sent: f1.length };
  } else {
    // C2: characterization only; the number that matters is how deep each reviewed request went when both predecessors were wrong
    const fabricated = records.filter((record) => record.meta.scenario === "c2_fabricated");
    report.notes.residualMutations = { forced: mutations(forced), c2Fabricated: mutations(fabricated), c2FabricatedSent: fabricated.length };
    gate(report, "c2_characterized", fabricated.length === thresholds.fixtures.c2Fabricated && fabricated.every((record) => (table.perRecord.get(record.rid)?.terminal ?? "") !== ""), `${fabricated.length} fabricated valid mutations with both verdicts simulated: ${mutations(fabricated)} reached APP_MUTATED (characterization only, not a defense claim)`);
  }
}

// ---------------------------------------------------------------------------
// C2': real L1/L2 faults, no forced verdict
// ---------------------------------------------------------------------------

async function bodyC2p(ctx: ArmContext): Promise<void> {
  const { thresholds } = ctx;
  const controller = ctx.controller as CollapseController;
  const timeout = thresholds.timing.clientTimeoutMs;
  await canary(ctx, "baseline", 2);
  // a real L2 failure: mutation fails closed, browsing continues (degraded), nothing is enrolled
  controller.fault("l2", "throw", 3);
  await sleep(100);
  await postFabricated(ctx.collector, ctx.planePort, "fault_error", timeout, "c2p_mutation_error");
  const degraded = await render(ctx.collector, ctx.planePort, "fault_error", "c2p_degraded_render", timeout);
  const degradedToken = tokenFrom(degraded);
  await postFabricated(ctx.collector, ctx.planePort, "fault_error", timeout, "c2p_mutation_error");
  // the real L2 hangs: two timeouts, then the evaluator bulkhead is full: saturation
  controller.fault("l2", "hang", 2);
  await sleep(100);
  for (let index = 0; index < 3; index++) await postFabricated(ctx.collector, ctx.planePort, "fault_hang", timeout, "c2p_mutation_hang");
  await sleep(600);
  // a real L1 failure
  controller.fault("l1", "throw", 1);
  await sleep(100);
  await postFabricated(ctx.collector, ctx.planePort, "fault_l1", timeout, "c2p_l1_error");
  // L2 healthy again: the token the degraded render delivered earned no credit, and journeys complete again
  if (degradedToken !== null) {
    const exchange = await postFabricated(ctx.collector, ctx.planePort, "fault_recovered", timeout, "c2p_degraded_token_post", degradedToken);
    tally(ctx, "c2p_degraded_token_post", [{ exchange, mutatedByClient: isRedirect(exchange) }]);
  }
  await sleep(thresholds.cycles.recoverySettleMs);
  await canary(ctx, "recovery_c1", thresholds.journeys.recovery);
}

function evaluateC2p(report: ArmReport): void {
  identityGates(report);
  continuityGates(report);
  const { records } = report;
  const byScenario = (prefix: string) => hostile(records, prefix);
  const errors = byScenario("c2p_mutation_error");
  gate(report, "c2p_mutation_fails_closed_on_l2_error", errors.length === 2 && errors.every((record) => { const d = dec(record); return d?.outcome === "error" && d.lane === null && d.l2ErrorKind === "throw" && !record.plane.some((event) => event.kind === "EGRESS_ATTEMPTED") && record.app.length === 0; }), "an L2 internal error refused the mutation (503), nothing reached the origin");
  const degraded = byScenario("c2p_degraded_render");
  gate(report, "c2p_open_get_degrades_explicitly", degraded.length === 1 && degraded.every((record) => { const d = dec(record); return d?.outcome === "degraded" && d.lane === "open" && record.plane.some((event) => event.kind === "EGRESS_ATTEMPTED") && record.plane.some((event) => event.kind === "L2_ENROLL_SKIPPED" && event.skipReason === "degraded") && !record.plane.some((event) => event.kind === "L2_ENROLLED"); }), "an open GET proceeded with outcome=degraded and enrolled no credit");
  const hang = byScenario("c2p_mutation_hang");
  const hangKinds = hang.map((record) => { const d = dec(record); return d?.outcome === "error" ? `error:${d.l2ErrorKind}` : d?.outcome === "shed" ? `shed:${d.shedReason}` : `${d?.outcome}`; });
  gate(report, "c2p_timeout_then_saturation_fail_closed", hang.length === 3 && hangKinds.filter((kind) => kind === "error:timeout").length === 2 && hangKinds.filter((kind) => kind === "shed:evaluator_saturation").length === 1 && hang.every((record) => record.app.length === 0), `outcomes ${hangKinds.join(", ")}: refused, nothing reached the application`);
  const l1Fault = byScenario("c2p_l1_error");
  gate(report, "c2p_l1_error_fails_closed", l1Fault.length === 1 && l1Fault.every((record) => record.plane.some((event) => event.kind === "L1_ERROR") && record.app.length === 0), "an injected L1 error refused the request");
  const after = byScenario("c2p_degraded_token_post");
  gate(report, "c2p_degraded_render_earned_no_credit", after.length === 1 && realOutcome(after[0]).lane === "unverified", `the token delivered by a degraded render is classified ${after.length === 1 ? realOutcome(after[0]).lane : "missing"} afterwards`);
  const mutating = hostile(records, "c2p_").filter((record) => record.app.some((event) => event.kind === "APP_MUTATED"));
  gate(report, "c2p_no_failure_became_pass", mutating.every((record) => record.meta.scenario === "c2p_degraded_token_post"), `mutations during failures: ${mutating.length}; only the post-recovery unverified request may have mutated`);
  gate(report, "c2p_no_simulated_label", records.every((record) => record.plane.every((event) => event.basis === undefined)), "no forced verdict participated: every outcome is the layers' own");
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

export type Ba0CollapseOutcome = {
  verdict: CollapseVerdict;
  reasons: string[];
  evidenceId: string;
  evidenceDirectory: string;
  arms: ArmReport[];
  gates: Gate[];
  anomalyTotal: number;
};

const SPECS: Record<ArmName, (thresholds: Ba0CollapseThresholds) => ArmSpec> = {
  C0r: () => ({ name: "C0r", entry: LEGACY_ENTRY, l2: false, collapse: false }),
  C0: () => ({ name: "C0", entry: PLANE_L2_ENTRY, l2: true, collapse: false }),
  C1: () => ({ name: "C1", entry: COLLAPSE_ENTRY, l2: true, collapse: true }),
  C2: () => ({ name: "C2", entry: COLLAPSE_ENTRY, l2: true, collapse: true }),
  C2p: (thresholds) => ({ name: "C2p", entry: COLLAPSE_ENTRY, l2: true, collapse: true, l2Params: { ...thresholds.l2, stage: { timeoutMs: 50, maxConcurrent: 2 } } }),
};

export async function runBa0Collapse(options: Ba0CollapseOptions = {}): Promise<Ba0CollapseOutcome> {
  const thresholds = options.thresholds ?? BA0_COLLAPSE_LOCAL_V1;
  const log = options.log ?? (() => undefined);
  const wanted = options.arms ?? ALL_ARMS;
  const startedAt = new Date();
  const evidence = new EvidenceRun("ba0-slice3-journey-lanes", "ba0-collapse", startedAt);
  const git = collectGitState();
  const reports: ArmReport[] = [];
  let finalized = false;
  try {
    for (const name of ALL_ARMS) {
      if (!wanted.includes(name)) continue;
      const spec = SPECS[name](thresholds);
      const body = name === "C0r" ? bodyC0r : name === "C0" ? bodyC0 : name === "C1" ? (ctx: ArmContext) => bodyCollapse(ctx, false) : name === "C2" ? (ctx: ArmContext) => bodyCollapse(ctx, true) : bodyC2p;
      const evaluate = name === "C0r" ? evaluateC0r : name === "C0" ? evaluateC0 : name === "C1" ? (report: ArmReport) => evaluateCollapse(report, false) : name === "C2" ? (report: ArmReport) => evaluateCollapse(report, true) : evaluateC2p;
      reports.push(await runArm(spec, thresholds, evidence.directory, log, body, evaluate));
    }

    // ---- cross-arm gate: the reference residual against the normal arm's bounded residual
    const c0r = reports.find((report) => report.name === "C0r");
    const c0 = reports.find((report) => report.name === "C0");
    const crossGates: Gate[] = [];
    if (c0r && c0) {
      const reference = (c0r.notes.residualMutations as { f1: number }).f1;
      const normal = (c0.notes.residualMutations as { f1: number; f1Sent: number }).f1;
      const referencePerCycle = reference;
      const normalPerCycle = normal / thresholds.cycles.count;
      crossGates.push({ id: "cross.l2_reduced_residual_mutation", ok: normalPerCycle < referencePerCycle, detail: `fabricated valid mutations reaching APP_MUTATED per ${thresholds.fixtures.f1.count} sent: reference ${referencePerCycle}, with L2 ${round(normalPerCycle)}` });
    }
    const gates = [...reports.flatMap((report) => report.gates), ...crossGates];
    const anomalyTotal = reports.reduce((total, report) => total + report.anomalyTotal, 0);
    const decision = decideCollapseVerdict({ gates, anomalyTotal });

    const rowsFor = (report: ArmReport): PenetrationRow[] => penetrationTable(report.records, (record) => (record.meta.cls === "hostile" ? record.meta.scenario.replace(/_burst$/, "") : null), report.spec.l2).rows;
    evidence.addJsonArtifact("collapse.json", {
      scope: SCOPE_STATEMENT, scale: SCALE_STATEMENT,
      arms: reports.map((report) => ({
        arm: report.name, plane: report.spec.collapse ? "harness-only collapse entry" : report.spec.l2 ? "normal slice-3 entry (L2 always present)" : "unchanged slice-2 entry (no L2 code)",
        l2Composition: report.spec.l2, overrideInjected: report.fin ? (report.fin.advisory as { overrideInjected?: boolean }).overrideInjected ?? false : "no_fin",
        requests: report.records.length, anomalyTotal: report.anomalyTotal, residualMutations: report.notes.residualMutations ?? null, cycles: report.notes.cycles ?? null,
        farmer: report.notes.farmer ?? null, poison: report.notes.poison ?? null, finalState: report.notes.finalState ?? null, quiescentProbe: report.notes.quiescentProbe ?? null,
      })),
      crossArm: crossGates,
    });
    evidence.addJsonArtifact("gates.json", { gates, verdict: decision.verdict, reasons: decision.reasons });
    evidence.addJsonArtifact("lanes.json", {
      scope: SCOPE_STATEMENT, configuration: { ...thresholds.l2, scale: SCALE_STATEMENT, productionSizing: { filterBitsPerGeneration: 2 ** 23, note: "computed, not measured here" } },
      arms: reports.filter((report) => report.lane !== null).map((report) => ({
        arm: report.name, ...report.lane, identities: report.lane?.identities,
        // the plane's own final L2 state at finish: bucket levels, the filter's fill and estimated false-positive rate, the use ledger, the aggregate counters
        finalState: report.fin && "l2" in report.fin.advisory ? (report.fin.advisory as PlaneL2Advisory).l2.lanes : "no_fin",
      })),
    });
    evidence.addJsonArtifact("penetration.json", {
      vocabulary: ["l1 natural_pass | simulated_pass | rejected | shed | error | skipped", "l2 admitted | quarantined | shed | error | degraded | skipped", "canon_refused", "boundary_rejected", "app_admitted", "app_executed", "app_mutated"],
      note: "natural and simulated rows are never merged; a simulated pass is never summarized as a natural bypass",
      arms: reports.map((report) => ({ arm: report.name, rows: rowsFor(report) })),
    });
    evidence.addJsonArtifact("canary.json", {
      journey: { steps: ["homepage", "navigation_privacy", "form", "valid_post", "thank_you"], completeFlowRequired: true },
      arms: reports.map((report) => { const summary = canaryByPhase(report); return { arm: report.name, journeyCompletionRate: summary.jcr, legitimateRefusals: summary.refused, parityMismatches: compareParity(report.journeys.filter((journey) => gated(journey.phase))).mismatches.length, latencyPhasesCalm: compareLatency(thresholds.latencyEnvelope, latenciesByLane(report.journeys.filter((journey) => journey.phase === "baseline" || journey.phase.startsWith("recovery") || journey.phase === "final")).control, latenciesByLane(report.journeys.filter((journey) => journey.phase === "baseline" || journey.phase.startsWith("recovery") || journey.phase === "final")).protected) }; }),
      canaryPostLanes: reports.filter((report) => report.lane).map((report) => ({ arm: report.name, ...report.lane?.canaryPost })),
    });
    evidence.addJsonArtifact("accounting.json", {
      scope: SCOPE_STATEMENT,
      arms: reports.map((report) => ({
        arm: report.name, anomalyTotal: report.anomalyTotal, anomalies: report.anomalies,
        plane: report.legacy ? { identities: report.legacy.identities, identitiesOk: report.legacy.identitiesOk } : "see lanes.json",
        hopPath: { identities: report.origin.identities, identitiesOk: report.origin.identitiesOk, lineage: report.origin.lineage, app: report.origin.app, boundary: report.origin.boundary, mutation: report.origin.mutation },
        journal: report.journal ? { file: report.journalFile, lines: report.journal.lines, bytes: report.journal.bytes, sha256: report.journal.sha256, overflow: report.journal.overflow } : "none",
      })),
    });
    evidence.addJsonArtifact("testcontrols.json", {
      statement: "force-pass exists only in the harness-only entry under lab/; it is armed one-shot over IPC with a CSPRNG id, bound to nonce, fixture digest and connection; every simulated verdict is permanently labelled",
      arms: reports.map((report) => ({
        arm: report.name, entry: report.spec.collapse ? "lab collapse entry" : report.spec.l2 ? "defense main-l2 (no injected dependency)" : "defense main (legacy)", overrideInjected: report.fin ? (report.fin.advisory as { overrideInjected?: boolean }).overrideInjected ?? false : "no_fin",
        arms: report.controllerRecords, normalRuntimeNegativeControl: report.notes.negativeControlStatus ?? "not_applicable",
      })),
      forcedFixtureSetSha256: FORCED_FIXTURE_SET_DIGEST, forcedFixtureCount: FORCED_FIXTURES.length,
    });
    evidence.addJsonArtifact("resources.json", {
      scope: "bounded self-reported samples; the child figures are advisory, the ledger is authoritative",
      arms: reports.map((report) => ({ arm: report.name, plane: report.fin ? { rssMaxMb: report.fin.advisory.rssMaxMb, eventLoopDelayP99Ms: report.fin.advisory.eventLoopDelayP99Ms, eventLoopDelayMaxMs: report.fin.advisory.eventLoopDelayMaxMs, cpuUserMs: report.fin.advisory.cpuUserMs, eventQueueHighWater: report.fin.channel.queueHighWater, eventsDropped: report.fin.channel.dropped } : "not_measured" })),
      notMeasured: ["n3.volumetric", "t4.transport", "pre_socket_loss", "tcp_backlog", "file_descriptors", "origin.network_isolation"],
    });
    evidence.finalize({
      git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null,
      ceilings: { fixedCounts: thresholds.fixtures, cycles: thresholds.cycles.count, loadRamp: "none", externalTraffic: "none", boundedConcurrency: Math.max(thresholds.fixtures.f1.concurrency, thresholds.fixtures.f4.concurrency) },
      thresholds: ba0CollapseFingerprint(thresholds), engine: "node-http-loopback", result: decision.verdict as EvidenceResult,
      resultReasons: decision.reasons.map((reason) => `ba0.${reason}`.slice(0, 200)),
      metrics: {
        scope: SCOPE_STATEMENT, verdict: decision.verdict, defenseQualification: "not_claimed", arms: reports.map((report) => report.name), anomalyTotal,
        gatesPassed: gates.filter((entry) => entry.ok).length, gatesFailed: gates.filter((entry) => !entry.ok).length,
        layerDiversity: decision.verdict === "LAYER-DIVERSITY-VALID" ? "measured_loopback_fixed_count" : "not_established",
        networkNonBypass: "not_measured", failureDomain: "shared_plane_process",
        notClaimed: [...NOT_CLAIMED],
        namespaces: { "a7.application": "measured", "n3.volumetric": "not_measured", "t4.transport": "not_measured" },
      },
    });
    finalized = true;
    return { verdict: decision.verdict, reasons: decision.reasons, evidenceId: evidence.id, evidenceDirectory: evidence.directory, arms: reports, gates, anomalyTotal };
  } catch (error) {
    if (!finalized) {
      try {
        evidence.finalize({
          git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null, ceilings: null,
          thresholds: ba0CollapseFingerprint(thresholds), engine: "node-http-loopback", result: "ERROR", resultReasons: [`ba0.${evidenceSafeError(error)}`.slice(0, 200)],
          metrics: { verdict: "ERROR", defenseQualification: "not_claimed" },
        });
      } catch { /* the original error is what matters */ }
    }
    throw error;
  }
}

const EXIT: Record<string, number> = { "LAYER-DIVERSITY-VALID": 0, INVALID: 1, REFUSED: 2, ERROR: 4 };

async function main(argv: readonly string[]): Promise<number> {
  if (argv.length > 0) { console.error("REFUSED  lab:ba0:collapse accepts no arguments; counts and targets are fixed by ba0-collapse-local-v1"); return EXIT.REFUSED; }
  const outcome = await runBa0Collapse({ log: (line) => console.log(line) });
  console.log(`${outcome.verdict}  ba0 slice 3 layer diversity (DDoS, bot detection, read-flood, per-user fairness, L1/L2 process independence, network/transport and production readiness are NOT claimed)`);
  for (const reason of outcome.reasons) console.log(`  - ${reason}`);
  for (const entry of outcome.gates) console.log(`  ${entry.ok ? "ok  " : "FAIL"} ${entry.id}: ${entry.detail}`);
  console.log(`evidence=${outcome.evidenceId}`);
  return EXIT[outcome.verdict];
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(EXIT.ERROR); });
}
