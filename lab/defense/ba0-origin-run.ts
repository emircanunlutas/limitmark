/**
 * BA0 Slice 2 runner: independent origin boundary, application non-bypass only, loopback only.
 *
 *   npm run lab:ba0:origin
 *
 * The CLI accepts NO arguments: counts, ports and targets are fixed by the `ba0-origin-local-v1` threshold set and every socket is a
 * 127.0.0.1 listener this process (or one of its three children) created. Topology:
 *
 *   canary / corpora -> Defense Plane (L1 + semantic gate + PB issuer) -> Origin Boundary (PB verifier, BA issuer) -> Protected App
 *   known-address direct tests -> Origin Boundary, and (stricter) the Protected App's own port
 *
 * Phases: startup fence probe, baseline canary, Slice-1 hostile corpus, semantic corpus, direct corpus, post-direct canary.
 *
 * Conclusions: APP-NON-BYPASS-VALID or INVALID. Never a defense-qualification PASS. APP-NON-BYPASS-VALID means ONLY that, under these
 * local fixed-count conditions, a request without a valid, request-bound, fresh, single-use proof chain never reached application
 * semantics or state. It says NOTHING about network or transport isolation: answering 403 on an open socket is not L3/L4 isolation, and
 * no result here speaks to bandwidth, PPS, SYN, TLS-handshake or connection-state exhaustion (all `not_measured`).
 * Exit codes: 0 APP-NON-BYPASS-VALID, 1 INVALID, 2 REFUSED, 4 ERROR.
 */
import path from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { createSyntheticOrigin, type SyntheticOrigin } from "../../defense/origin/synthetic-origin";
import { EvidenceRun, collectEnvironment, collectGitState, type EvidenceResult } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { deriveAccounting, type AccountingReport } from "./accounting";
import { compareParity, journeyCompletionRates, latenciesByLane, runJourney, type JourneyResult } from "./canary";
import { Collector, DEFAULT_COLLECTOR_LIMITS, type LedgerRecord } from "./collector";
import { DIRECT_CORPUS_FIXED_COUNT, DIRECT_ENTRIES, DIRECT_POSITIVE_CONTROLS, runDirectCorpus, verifyDirect, type DirectExecuted } from "./direct-corpus";
import { CORPUS, CORPUS_FIXED_COUNT, runCorpus, verifyCase } from "./hostile-corpus";
import { HopTrustRoot } from "./hop-keys";
import { deriveOriginAccounting, type OriginAccountingReport } from "./origin-accounting";
import { BoundaryProcess, AppProcess } from "./origin-processes";
import { BA0_ORIGIN_LOCAL_V1, ba0OriginFingerprint, decideOriginVerdict, type Ba0OriginThresholds, type OriginVerdict } from "./origin-thresholds";
import { PlaneProcess } from "./plane-process";
import { SEMANTIC_CORPUS, SEMANTIC_CORPUS_FIXED_COUNT, SEMANTIC_EXPECTED_DROPPED, runSemanticCorpus, verifySemantic } from "./semantic-corpus";
import { compareLatency } from "./thresholds";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const round = (value: number) => Math.round(value * 100) / 100;
const rows = (map: Record<string, number>) => Object.entries(map).map(([name, count]) => ({ name, count }));

export type OriginPhase = "baseline" | "corpus" | "semantic" | "direct" | "post_direct";
export type OriginHandles = { plane: PlaneProcess; boundary: BoundaryProcess; app: AppProcess; control: SyntheticOrigin; collector: Collector; root: HopTrustRoot };
export type Ba0OriginHooks = { beforePhase?: (phase: OriginPhase, handles: OriginHandles) => Promise<void> | void };
export type Ba0OriginOptions = { thresholds?: Ba0OriginThresholds; hooks?: Ba0OriginHooks; log?: (line: string) => void };

export type Ba0OriginOutcome = {
  verdict: OriginVerdict;
  reasons: string[];
  evidenceId: string;
  evidenceDirectory: string;
  accounting: AccountingReport;
  origin: OriginAccountingReport;
  anomalyTotal: number;
  anomalies: { code: string; nonce: string | null; detail: string }[];
  journeys: JourneyResult[];
  records: LedgerRecord[];
  semanticViolations: string[];
  directViolations: string[];
  /** Held only in memory, so a test can prove none of it reached evidence. Never written. */
  keyMaterial: ReturnType<HopTrustRoot["keyMaterial"]>;
};

/** Exact strings the evidence may carry about what is NOT claimed; a test pins that no other string over-claims. */
export const NOT_CLAIMED: readonly string[] = Object.freeze([
  "network or transport isolation of the origin",
  "any protection against bandwidth, PPS, SYN, TLS-handshake or connection-state exhaustion",
  "CPU or memory isolation of the boundary under load",
  "resistance to an on-path attacker or integrity of responses",
  "integrity of any request header outside the closed bound set",
  "key custody beyond a disposable run, rotation or revocation",
  "replay protection across a verifier restart beyond the start fence",
  "independence of verifier code: the boundary and the app share one implementation",
  "compromise independence from process separation alone",
  "defense qualification",
]);
export const NOT_MEASURED: readonly string[] = Object.freeze(["n3.volumetric", "t4.transport", "pre_socket_loss", "tcp_backlog", "file_descriptors", "origin.network_isolation", "origin.cpu_isolated"]);
export const SCOPE_STATEMENT = "application non-bypass only: a refused request is answered on an open socket, which is not network or transport isolation; loss before the socket is invisible to this ledger";

class HarnessSampler {
  private readonly loop = monitorEventLoopDelay({ resolution: 10 });
  private rssMax = 0;
  private timer: NodeJS.Timeout | null = null;
  private cpuStart = process.cpuUsage();
  start(): void { this.cpuStart = process.cpuUsage(); this.loop.enable(); this.timer = setInterval(() => { this.rssMax = Math.max(this.rssMax, process.memoryUsage.rss()); }, 250); this.timer.unref(); }
  stop() {
    if (this.timer) clearInterval(this.timer);
    this.loop.disable();
    this.rssMax = Math.max(this.rssMax, process.memoryUsage.rss());
    const cpu = process.cpuUsage(this.cpuStart);
    return { rssMaxMb: Math.round(this.rssMax / 1_048_576), eventLoopDelayP99Ms: round(this.loop.percentile(99) / 1e6), eventLoopDelayMaxMs: round(this.loop.max / 1e6), cpuUserMs: Math.round(cpu.user / 1000), cpuSystemMs: Math.round(cpu.system / 1000) };
  }
}

const SLICE1_LANES: ReadonlySet<string> = new Set(["protected", "control", "pre_ingress"]);

export async function runBa0Origin(options: Ba0OriginOptions = {}): Promise<Ba0OriginOutcome> {
  const thresholds = options.thresholds ?? BA0_ORIGIN_LOCAL_V1;
  const log = options.log ?? (() => undefined);
  const startedAt = new Date();
  const evidence = new EvidenceRun("ba0-slice2-app-boundary", "ba0-origin", startedAt);
  const git = collectGitState();
  const collector = new Collector(path.join(evidence.directory, "ledger-journal.ndjson"), { ...DEFAULT_COLLECTOR_LIMITS, ...thresholds.collector });
  collector.enableOriginStreams();
  const sampler = new HarnessSampler();
  sampler.start();
  const root = new HopTrustRoot();

  // The unguarded baseline: reached directly, NOT the protected origin. Its address provides a path by design (it is the control).
  const control = createSyntheticOrigin({ instance: "control", onObservation: (event) => collector.ingestOrigin(event) });
  let plane: PlaneProcess | null = null;
  let boundary: BoundaryProcess | null = null;
  let app: AppProcess | null = null;
  const journeys: JourneyResult[] = [];
  const reasons: string[] = [];
  let finalized = false;

  try {
    const controlPort = await control.listen();
    app = await AppProcess.start(collector, root.appInit({ replayCapacity: thresholds.hop.replayCapacity, bodyDeadlineMs: thresholds.hop.bodyDeadlineMs }, thresholds.channel));
    boundary = await BoundaryProcess.start(collector, root.boundaryInit(app.port, {
      replayCapacity: thresholds.hop.replayCapacity, bodyDeadlineMs: thresholds.hop.bodyDeadlineMs, forwardTimeoutMs: thresholds.hop.forwardTimeoutMs, baLifetimeMs: thresholds.hop.baLifetimeMs,
    }, thresholds.channel));
    const directContext = { boundaryPort: boundary.port, appPort: app.port, root, collector, timeoutMs: thresholds.timing.clientTimeoutMs, boundarySpawnedAtMs: boundary.spawnedAtMs };

    // Startup probe: a proof issued before the verifier started can only be a replay across a restart, and it is only distinguishable from an
    // expired one in the first seconds of the verifier's life, so it runs now, before the plane exists.
    log("phase startup");
    const startupExecuted = await runDirectCorpus(directContext, "startup");

    plane = await PlaneProcess.start(collector, {
      upstreamPort: boundary.port, bodyDeadlineMs: thresholds.timing.stallDeadlineMs, egressTimeoutMs: thresholds.timing.clientTimeoutMs,
      composer: { timeoutMs: thresholds.composer.timeoutMs, maxConcurrent: thresholds.composer.maxConcurrent, failurePolicy: "fail_closed" }, channel: thresholds.channel,
      hop: root.planeInit(thresholds.hop.pbLifetimeMs),
    });
    const handles: OriginHandles = { plane, boundary, app, control, collector, root };
    const planePort = plane.port;

    const canaryPhase = async (phase: "baseline" | "post_direct", count: number) => {
      await options.hooks?.beforePhase?.(phase, handles);
      for (let index = 0; index < count; index++) {
        const lanes = index % 2 === 0 ? (["control", "protected"] as const) : (["protected", "control"] as const);
        for (const lane of lanes) {
          journeys.push(await runJourney(collector, { lane, port: lane === "control" ? controlPort : planePort, phase, journey: index + 1, timeoutMs: thresholds.timing.clientTimeoutMs }));
        }
      }
    };

    log("phase baseline");
    await canaryPhase("baseline", thresholds.journeys.baselinePerLane);
    log("phase corpus");
    await options.hooks?.beforePhase?.("corpus", handles);
    const corpusRun = await runCorpus(collector, planePort, thresholds.timing.clientTimeoutMs);
    log("phase semantic");
    await options.hooks?.beforePhase?.("semantic", handles);
    const semanticRun = await runSemanticCorpus(collector, planePort, thresholds.timing.clientTimeoutMs);
    log("phase direct");
    await options.hooks?.beforePhase?.("direct", handles);
    const directExecuted: DirectExecuted[] = [...startupExecuted, ...(await runDirectCorpus(directContext, "main"))];
    log("phase post_direct");
    await canaryPhase("post_direct", thresholds.journeys.postDirectPerLane);

    // ---- finalization: nothing is in flight (every client call has completed); each child drains and reports, the ledger freezes,
    // stragglers show up as LATE events, then everything is shut down before judging.
    const fin = await plane.finish(thresholds.timing.finTimeoutMs);
    await boundary.finish(thresholds.timing.finTimeoutMs);
    await app.finish(thresholds.timing.finTimeoutMs);
    collector.freeze();
    await sleep(thresholds.timing.settleMs);
    await Promise.all([plane.stop(), boundary.stop(), app.stop()]);
    await control.close();

    // ---- Slice-1 corpus (unchanged expectations), semantic corpus, direct corpus: each verified against the LEDGER
    let corpusViolations = 0;
    const slice1ById = new Map(CORPUS.map((entry) => [entry.id, entry]));
    const observedReasons: Record<string, number> = {};
    const corpusRows: { id: string; family: string; expected: string; terminal: string; reason: string; ok: boolean }[] = [];
    for (const executed of corpusRun.cases) {
      const entry = slice1ById.get(executed.id)!;
      const record = collector.recordFor(executed.nonce);
      if (!record) { corpusViolations++; collector.anomaly("corpus_expectation_violated", null, `${entry.id}: no ledger record`); continue; }
      const problem = verifyCase(entry, record, executed.exchange);
      const verdictEvent = record.plane.find((event) => event.kind === "L1_REJECTED");
      const reason = verdictEvent?.reason ?? (entry.expect.kind === "parser" ? "parser_lane" : "passed_l1");
      observedReasons[reason] = (observedReasons[reason] ?? 0) + 1;
      if (problem) { corpusViolations++; collector.anomaly("corpus_expectation_violated", executed.nonce, `${entry.id}: ${problem}`); }
      corpusRows.push({ id: entry.id, family: entry.family, expected: entry.expect.kind, terminal: Collector.terminalOf(record) ?? "none", reason, ok: problem === null });
    }

    const semanticViolations: string[] = [];
    const semanticById = new Map(SEMANTIC_CORPUS.map((entry) => [entry.id, entry]));
    const semanticRows: { id: string; expected: string; terminal: string; reason: string; clientStatus: number | null; ok: boolean }[] = [];
    for (const executed of semanticRun.cases) {
      const entry = semanticById.get(executed.id)!;
      const record = collector.recordFor(executed.nonce);
      if (!record) { semanticViolations.push(`${entry.id}: no ledger record`); collector.anomaly("corpus_expectation_violated", null, `${entry.id}: no ledger record`); continue; }
      const problem = verifySemantic(entry, record, executed.exchange);
      if (problem) { semanticViolations.push(`${entry.id}: ${problem}`); collector.anomaly("corpus_expectation_violated", executed.nonce, `${entry.id}: ${problem}`); }
      semanticRows.push({
        id: entry.id, expected: entry.expect.kind === "reject" ? entry.expect.reason : "pass", terminal: Collector.terminalOf(record) ?? "none",
        reason: record.plane.find((event) => event.kind === "L1_REJECTED")?.reason ?? "passed", clientStatus: executed.exchange.status, ok: problem === null,
      });
    }

    const directViolations: string[] = [];
    const directById = new Map(DIRECT_ENTRIES.map((entry) => [entry.id, entry]));
    const directRows: { id: string; family: string; target: string; lane: string; expected: string; observed: string; clientResult: string; ok: boolean }[] = [];
    for (const executed of directExecuted) {
      const entry = directById.get(executed.id)!;
      const record = collector.recordFor(executed.nonce);
      if (!record) { directViolations.push(`${entry.id}: no ledger record`); collector.anomaly("corpus_expectation_violated", null, `${entry.id}: no ledger record`); continue; }
      const problem = verifyDirect(entry, record, executed.exchange);
      if (problem) { directViolations.push(`${entry.id}: ${problem}`); collector.anomaly("corpus_expectation_violated", executed.nonce, `${entry.id}: ${problem}`); }
      const observed = record.boundary.find((event) => event.kind === "BOUNDARY_REJECTED")?.reason ?? record.app.find((event) => event.kind === "APP_REFUSED")?.reason
        ?? (record.app.some((event) => event.kind === "APP_ADMITTED") ? "admitted" : "none");
      directRows.push({
        id: entry.id, family: entry.family, target: entry.target, lane: entry.lane,
        expected: entry.expect.kind === "reject" ? entry.expect.reason : entry.expect.kind, observed, clientResult: executed.exchange.result, ok: problem === null,
      });
    }

    // Event-loop safety proof: the grammar parser ran only for bodies that passed every pre-parse bound (a semantic reject follows the shape gate).
    const records = [...collector.allRecords()];
    const expectedParses = records.filter((record) => record.meta.lane === "protected" && (record.plane.some((event) => event.kind === "L1_REJECTED" && (event.stage === "grammar" || event.reason?.startsWith("a7.semantic_"))) || record.plane.some((event) => event.kind === "L1_PASSED")) && record.meta.method === "POST").length;
    if (fin && fin.advisory.l1.grammarParses !== expectedParses) { corpusViolations++; collector.anomaly("corpus_expectation_violated", null, `grammar parser ran ${fin.advisory.l1.grammarParses} times, ledger expects ${expectedParses}`); }

    const { anomalies, anomalyTotal } = collector.finalize();
    const slice1Records = records.filter((record) => SLICE1_LANES.has(record.meta.lane));
    const accounting = deriveAccounting(slice1Records, collector.parserRejectedTotal());
    const parserCases = DIRECT_ENTRIES.filter((entry) => entry.expect.kind === "parser").length;
    const origin = deriveOriginAccounting({
      records, journeys, boundary: collector.boundaryInfo.fin, app: collector.appInfo.fin, controlCounters: control.appStats(),
      boundaryAnonymous: collector.boundaryInfo.anonymous, appAnonymous: collector.appInfo.anonymous, hop: fin?.advisory.hop,
      expected: { positiveControls: DIRECT_POSITIVE_CONTROLS.length, parserCases, droppedUnbound: SEMANTIC_EXPECTED_DROPPED },
    });
    const idsOk = (prefixes: string[]) => origin.identities.filter((identity) => prefixes.some((prefix) => identity.id.startsWith(prefix))).every((identity) => identity.ok);
    const jcr = journeyCompletionRates(journeys);
    const parity = compareParity(journeys);
    const latencies = latenciesByLane(journeys);
    const latency = compareLatency(thresholds.latencyEnvelope, latencies.control, latencies.protected);
    const positiveRows = directRows.filter((row) => DIRECT_POSITIVE_CONTROLS.includes(row.id));
    const decision = decideOriginVerdict(thresholds, {
      anomalyTotal, identitiesOk: accounting.identitiesOk, originIdentitiesOk: origin.identitiesOk,
      jcr: jcr.map((entry) => ({ phase: entry.phase, lane: entry.lane, rate: entry.rate })), latencyOk: latency.ok, parityMismatches: parity.mismatches.length,
      corpusViolations, semanticViolations: semanticViolations.length, directViolations: directViolations.length,
      corpusCount: corpusRun.cases.length, expectedCorpusCount: CORPUS_FIXED_COUNT, semanticCount: semanticRun.cases.length, directCount: directExecuted.length,
      positiveControlsOk: positiveRows.length === DIRECT_POSITIVE_CONTROLS.length && positiveRows.every((row) => row.ok) && idsOk(["o2.positive_controls"]),
      lineageComplete: origin.app.admitted > 0 && origin.lineage.complete === origin.app.admitted && origin.lineage.appAdmitsWithoutLineage === 0 && idsOk(["o2.lineage", "o2.app_admits_without_lineage"]),
      mutationReconciled: idsOk(["o2.mutation", "o2.control_mutation"]) && origin.mutation.clientObserved > 0,
      countersReconciled: idsOk(["o2.boundary_counters", "o2.app_counters", "o2.app_executions", "o2.app_mutations", "o2.boundary_replay", "o2.app_replay", "o2.replay_state", "o2.no_anonymous", "o2.body_reads", "o2.clock_step"]),
    });
    reasons.push(...decision.reasons, ...latency.reasons);
    const journal = await collector.closeJournal();
    const harness = sampler.stop();

    const planeChannel = collector.channel;
    const boundaryInfo = collector.boundaryInfo;
    const appInfo = collector.appInfo;
    const channelRow = (info: { received: number; lastSeq: number; droppedReported: number; fin: { drained: boolean; channel: object } | null; crashed: string | null }) => ({
      receivedByCollector: info.received, lastSeq: info.lastSeq, droppedReported: info.droppedReported, fin: info.fin ? { drained: info.fin.drained, ...info.fin.channel } : "no_fin", crashed: info.crashed ?? "no",
    });
    evidence.addJsonArtifact("accounting.json", {
      scope: SCOPE_STATEMENT,
      identities: accounting.identities, identitiesOk: accounting.identitiesOk, sent: accounting.sent, ingress: accounting.ingress,
      l1: { entered: accounting.l1.entered, passed: accounting.l1.passed, rejected: accounting.l1.rejected, shed: accounting.l1.shed, error: accounting.l1.error, rejectedByReason: rows(accounting.l1.rejectedByReason), errorByKind: rows(accounting.l1.errorByKind) },
      egress: { attempted: accounting.egress.attempted, responded: accounting.egress.responded, failed: accounting.egress.failed, failedByKind: rows(accounting.egress.failedByKind) },
      synthetic_origins: accounting.origin, delivery: accounting.delivery, parser: accounting.parser, client: { completed: accounting.client.completed, byResult: rows(accounting.client.byResult) },
      eventChannels: { plane: { receivedByCollector: planeChannel.received, lastSeq: planeChannel.lastSeq, droppedReported: planeChannel.droppedReported, planeFin: planeChannel.fin ? { drained: planeChannel.fin.drained, ...planeChannel.fin.channel } : "no_fin", planeCrashed: planeChannel.crashed ?? "no", lateEvents: planeChannel.late }, boundary: channelRow(boundaryInfo), app: channelRow(appInfo) },
      anomalyTotal, anomalies,
    });
    evidence.addJsonArtifact("app-boundary.json", {
      scope: SCOPE_STATEMENT,
      topology: ["canary and corpora -> defense plane -> origin boundary -> protected app", "known-address direct tests -> origin boundary and protected app own port"],
      keyCustody: {
        plane: "holds the plane-to-boundary private key only",
        boundary: "holds the plane public key and the boundary-to-app private key; never the plane private key",
        app: "holds public keys only; no private key",
        harness: "lab trust root: generated both keypairs, holds both for labelled misuse and positive-control cases only",
      },
      hopSeparation: { roles: ["pb", "ba"], domains: "distinct", keys: "distinct", audiences: "distinct", proofHeaderNames: "distinct", replaySets: "distinct", lifetimes: { pbMs: thresholds.hop.pbLifetimeMs, baMs: thresholds.hop.baLifetimeMs } },
      identities: origin.identities, identitiesOk: origin.identitiesOk,
      plane: origin.plane, boundary: origin.boundary, app: origin.app, lineage: origin.lineage, mutation: origin.mutation, direct: origin.direct, positiveControls: origin.positiveControls,
      refusedByReason: rows(origin.refusedByReason),
      boundaryStats: boundaryInfo.fin ? boundaryInfo.fin.stats : "no_fin",
      appStats: appInfo.fin ? appInfo.fin.stats : "no_fin",
      planeHopStats: fin?.advisory.hop ?? "not_measured",
    });
    evidence.addJsonArtifact("canary.json", {
      journey: { steps: ["homepage", "navigation_privacy", "form", "valid_post", "thank_you"], completeFlowRequired: true },
      journeyCompletionRate: jcr, parity: { compared: parity.compared, mismatches: parity.mismatches }, latency: { envelope: thresholds.latencyEnvelope, ...latency },
    });
    evidence.addJsonArtifact("corpus.json", { fixedCount: CORPUS_FIXED_COUNT, executed: corpusRun.cases.length, violations: corpusViolations, outcomesByReason: rows(observedReasons), cases: corpusRows });
    evidence.addJsonArtifact("semantic-corpus.json", { fixedCount: SEMANTIC_CORPUS_FIXED_COUNT, executed: semanticRun.cases.length, violations: semanticViolations.length, cases: semanticRows });
    evidence.addJsonArtifact("direct-corpus.json", {
      fixedCount: DIRECT_CORPUS_FIXED_COUNT, executed: directExecuted.length, violations: directViolations.length, mustBeRefused: directExecuted.length - DIRECT_POSITIVE_CONTROLS.length,
      positiveControls: DIRECT_POSITIVE_CONTROLS, cases: directRows,
    });
    evidence.addJsonArtifact("resources.json", {
      scope: "bounded self-reported samples; the child figures are advisory, the ledger is authoritative",
      plane: fin ? { ...fin.advisory.front, rssMaxMb: fin.advisory.rssMaxMb, eventLoopDelayP99Ms: fin.advisory.eventLoopDelayP99Ms, eventLoopDelayMaxMs: fin.advisory.eventLoopDelayMaxMs, cpuUserMs: fin.advisory.cpuUserMs, cpuSystemMs: fin.advisory.cpuSystemMs, eventQueueHighWater: fin.channel.queueHighWater, eventsDropped: fin.channel.dropped } : "not_measured",
      harness: { ...harness, note: "the unguarded control origin and the collector share the harness process; the boundary and the protected app are their own processes" },
      control_origin: control.stats(),
      not_measured: [...NOT_MEASURED],
    });
    evidence.finalize({
      git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null,
      ceilings: { fixedCounts: { baselineJourneysPerLane: thresholds.journeys.baselinePerLane, postDirectJourneysPerLane: thresholds.journeys.postDirectPerLane, corpusCases: CORPUS_FIXED_COUNT, semanticCases: SEMANTIC_CORPUS_FIXED_COUNT, directCases: DIRECT_CORPUS_FIXED_COUNT }, loadRamp: "none", externalTraffic: "none" },
      thresholds: ba0OriginFingerprint(thresholds), engine: "node-http-loopback", result: decision.verdict as EvidenceResult,
      resultReasons: reasons.map((reason) => `ba0.${reason}`),
      metrics: {
        scope: SCOPE_STATEMENT, verdict: decision.verdict, defenseQualification: "not_claimed",
        appNonBypass: decision.verdict === "APP-NON-BYPASS-VALID" ? "measured_loopback_fixed_count" : "not_established",
        networkNonBypass: "not_measured", originNetworkIsolation: "not_measured", originFailureDomain: "process_only_same_host",
        requests: accounting.sent.total + directExecuted.length, anomalyTotal, identitiesOk: accounting.identitiesOk, originIdentitiesOk: origin.identitiesOk,
        journeyCompletionRate: jcr.map((entry) => ({ lane: entry.lane, phase: entry.phase, rate: entry.rate })), latencyAddedP95Ms: latency.addedP95Ms, latencyAddedP99Ms: latency.addedP99Ms,
        lineageComplete: origin.lineage.complete, appAdmitted: origin.app.admitted, directRefusedWithZeroExecution: directExecuted.length - DIRECT_POSITIVE_CONTROLS.length - directViolations.length,
        positiveControlsAdmitted: origin.positiveControls.admitted,
        mutation: { clientObserved: origin.mutation.clientObserved, ledgerCorrelated: origin.mutation.ledgerCorrelated, appAuthoritative: origin.mutation.appAuthoritative },
        journal: journal ? { file: "ledger-journal.ndjson", lines: journal.lines, bytes: journal.bytes, sha256: journal.sha256, overflow: journal.overflow } : "none",
        namespaces: { "a7.application": "measured", "ob.origin_hop_gate": "measured_application_only", "n3.volumetric": "not_measured", "t4.transport": "not_measured" },
        notClaimed: [...NOT_CLAIMED],
      },
    });
    finalized = true;
    return {
      verdict: decision.verdict, reasons, evidenceId: evidence.id, evidenceDirectory: evidence.directory, accounting, origin, anomalyTotal, anomalies, journeys, records,
      semanticViolations, directViolations, keyMaterial: root.keyMaterial(),
    };
  } catch (error) {
    // Anything unexpected is an ERROR run with its reason recorded, never a silent success and never a verdict.
    reasons.push(evidenceSafeError(error));
    if (!finalized) {
      try {
        await collector.closeJournal().catch(() => null);
        evidence.finalize({
          git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null, ceilings: null,
          thresholds: ba0OriginFingerprint(thresholds), engine: "node-http-loopback", result: "ERROR", resultReasons: reasons.map((reason) => `ba0.${reason}`.slice(0, 200)),
          metrics: { verdict: "ERROR", defenseQualification: "not_claimed", networkNonBypass: "not_measured", originNetworkIsolation: "not_measured" },
        });
      } catch { /* the original error is what matters */ }
    }
    throw error;
  } finally {
    await Promise.allSettled([plane?.stop(), boundary?.stop(), app?.stop(), control.close()]);
  }
}

const EXIT: Record<string, number> = { "APP-NON-BYPASS-VALID": 0, INVALID: 1, REFUSED: 2, ERROR: 4 };

async function main(argv: readonly string[]): Promise<number> {
  if (argv.length > 0) { console.error("REFUSED  lab:ba0:origin accepts no arguments; counts and targets are fixed by ba0-origin-local-v1"); return EXIT.REFUSED; }
  const outcome = await runBa0Origin({ log: (line) => console.log(line) });
  const jcr = journeyCompletionRates(outcome.journeys);
  console.log(`${outcome.verdict}  ba0 slice 2 application non-bypass (network non-bypass not_measured; defense qualification not claimed)`);
  for (const reason of outcome.reasons) console.log(`  - ${reason}`);
  for (const entry of jcr) console.log(`  JCR ${entry.phase}/${entry.lane}: ${entry.completed}/${entry.attempted}`);
  for (const identity of outcome.accounting.identities) console.log(`  ${identity.ok ? "ok  " : "FAIL"} ${identity.id}: ${identity.left} vs ${identity.right}`);
  for (const identity of outcome.origin.identities) console.log(`  ${identity.ok ? "ok  " : "FAIL"} ${identity.id}: ${identity.left} vs ${identity.right}`);
  for (const problem of [...outcome.semanticViolations, ...outcome.directViolations].slice(0, 20)) console.log(`  case ${problem}`);
  for (const anomaly of outcome.anomalies.slice(0, 20)) console.log(`  anomaly ${anomaly.code} ${anomaly.nonce ?? "-"} ${anomaly.detail}`);
  console.log(`evidence=${outcome.evidenceId}`);
  return EXIT[outcome.verdict];
}

// Run as a script only when this file is the entry point (a test importing runBa0Origin must not start a run).
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(EXIT.ERROR); });
}
