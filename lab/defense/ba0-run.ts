/**
 * BA0 Slice 1 runner: skeleton + L1 + the complete measurement path, loopback only.
 *
 *   npm run lab:ba0
 *
 * The CLI accepts NO arguments: counts, ports and targets are fixed by the `ba0-local-v1` threshold set and every socket is a
 * 127.0.0.1 listener this process (or its plane child) created. Phases: baseline canary, hostile corpus, post-corpus canary.
 *
 * Conclusions: BASELINE-VALID or INVALID. Slice 1 never claims a defense-qualification PASS. Scope: application plane only; an L7
 * success says nothing about network or transport health (n3.* and t4.* are reserved and reported not_measured).
 * Exit codes: 0 BASELINE-VALID, 1 INVALID, 2 REFUSED, 4 ERROR.
 */
import path from "node:path";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { createSyntheticOrigin, type SyntheticOrigin } from "../../defense/origin/synthetic-origin";
import { IMPLEMENTED_NAMESPACES, LAYER_NAMESPACES } from "../../defense/core/types";
import { EvidenceRun, collectEnvironment, collectGitState, type EvidenceResult } from "../evidence/manifest";
import { evidenceSafeError } from "../evidence/redact";
import { deriveAccounting, type AccountingReport } from "./accounting";
import { compareParity, journeyCompletionRates, latenciesByLane, runJourney, type JourneyResult } from "./canary";
import { Collector, DEFAULT_COLLECTOR_LIMITS } from "./collector";
import { CORPUS, CORPUS_FIXED_COUNT, runCorpus, verifyCase } from "./hostile-corpus";
import { PlaneProcess } from "./plane-process";
import { BA0_LOCAL_V1, ba0Fingerprint, compareLatency, decideVerdict, type Ba0Thresholds, type Ba0Verdict } from "./thresholds";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const round = (value: number) => Math.round(value * 100) / 100;
const rows = (map: Record<string, number>) => Object.entries(map).map(([name, count]) => ({ name, count }));

export type Ba0Hooks = {
  /** Called before each phase with handles for fault injection in tests. */
  beforePhase?: (phase: "baseline" | "corpus" | "post_corpus", handles: { plane: PlaneProcess; control: SyntheticOrigin; protectedOrigin: SyntheticOrigin; collector: Collector }) => Promise<void> | void;
};

export type Ba0Options = { thresholds?: Ba0Thresholds; hooks?: Ba0Hooks; log?: (line: string) => void };

export type Ba0Outcome = {
  verdict: Ba0Verdict;
  reasons: string[];
  evidenceId: string;
  evidenceDirectory: string;
  accounting: AccountingReport;
  anomalyTotal: number;
  anomalies: { code: string; nonce: string | null; detail: string }[];
  journeys: JourneyResult[];
};

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

export async function runBa0(options: Ba0Options = {}): Promise<Ba0Outcome> {
  const thresholds = options.thresholds ?? BA0_LOCAL_V1;
  const log = options.log ?? (() => undefined);
  const startedAt = new Date();
  const evidence = new EvidenceRun("ba0-slice1-baseline", "ba0-baseline", startedAt);
  const git = collectGitState();
  const collector = new Collector(path.join(evidence.directory, "ledger-journal.ndjson"), { ...DEFAULT_COLLECTOR_LIMITS, ...thresholds.collector });
  const sampler = new HarnessSampler();
  sampler.start();

  const control = createSyntheticOrigin({ instance: "control", onObservation: (event) => collector.ingestOrigin(event) });
  const protectedOrigin = createSyntheticOrigin({ instance: "protected", onObservation: (event) => collector.ingestOrigin(event) });
  let plane: PlaneProcess | null = null;
  const journeys: JourneyResult[] = [];
  let corpusRun: Awaited<ReturnType<typeof runCorpus>> | null = null;
  const reasons: string[] = [];
  let finalized = false;

  try {
    const controlPort = await control.listen();
    const protectedPort = await protectedOrigin.listen();
    plane = await PlaneProcess.start(collector, {
      upstreamPort: protectedPort, bodyDeadlineMs: thresholds.timing.stallDeadlineMs, egressTimeoutMs: thresholds.timing.clientTimeoutMs,
      composer: { timeoutMs: thresholds.composer.timeoutMs, maxConcurrent: thresholds.composer.maxConcurrent, failurePolicy: "fail_closed" }, channel: thresholds.channel,
    });
    const handles = { plane, control, protectedOrigin, collector };
    const planePort = plane.port;

    const canaryPhase = async (phase: "baseline" | "post_corpus", count: number) => {
      await options.hooks?.beforePhase?.(phase, handles);
      for (let index = 0; index < count; index++) {
        // Alternate which lane goes first so drift and warm-up fall on both lanes equally.
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
    corpusRun = await runCorpus(collector, planePort, thresholds.timing.clientTimeoutMs);
    log("phase post_corpus");
    await canaryPhase("post_corpus", thresholds.journeys.postCorpusPerLane);

    // ---- finalization: nothing is in flight (every client call has completed); ask the plane to drain and report, freeze the
    // ledger, let any straggling work show up as a LATE event, then shut everything down before judging.
    const fin = await plane.finish(thresholds.timing.finTimeoutMs);
    collector.freeze();
    await sleep(thresholds.timing.settleMs);
    await plane.stop();
    await Promise.all([control.close(), protectedOrigin.close()]);

    // ---- corpus verification against the ledger (the client's view is only a cross-check)
    const byId = new Map(CORPUS.map((entry) => [entry.id, entry]));
    const corpusRows: { id: string; family: string; expected: string; terminal: string; reason: string; clientResult: string; clientStatus: number | null; ok: boolean }[] = [];
    let violations = 0;
    const observedReasons: Record<string, number> = {};
    for (const executed of corpusRun.cases) {
      const entry = byId.get(executed.id)!;
      const record = collector.recordFor(executed.nonce);
      if (!record) { violations++; collector.anomaly("corpus_expectation_violated", null, `${entry.id}: no ledger record`); continue; }
      const problem = verifyCase(entry, record, executed.exchange);
      const verdictEvent = record.plane.find((event) => event.kind === "L1_REJECTED");
      const terminal = Collector.terminalOf(record) ?? "none";
      const reason = verdictEvent?.reason ?? (entry.expect.kind === "parser" ? "parser_lane" : "passed_l1");
      observedReasons[reason] = (observedReasons[reason] ?? 0) + 1;
      if (problem) { violations++; collector.anomaly("corpus_expectation_violated", executed.nonce, `${entry.id}: ${problem}`); }
      corpusRows.push({ id: entry.id, family: entry.family, expected: entry.expect.kind, terminal, reason, clientResult: executed.exchange.result, clientStatus: executed.exchange.status, ok: problem === null });
    }
    // Event-loop safety proof: the form grammar parser must have run ONLY for bodies that passed every pre-parse bound.
    const records = [...collector.allRecords()];
    const expectedParses = records.filter((record) => record.meta.lane === "protected" && (record.plane.some((event) => event.kind === "L1_REJECTED" && event.stage === "grammar") || (record.meta.method === "POST" && record.plane.some((event) => event.kind === "L1_PASSED")))).length;
    if (fin && fin.advisory.l1.grammarParses !== expectedParses) { violations++; collector.anomaly("corpus_expectation_violated", null, `grammar parser ran ${fin.advisory.l1.grammarParses} times, ledger expects ${expectedParses}`); }

    const { anomalies, anomalyTotal } = collector.finalize();
    const accounting = deriveAccounting(records, collector.parserRejectedTotal());
    const jcr = journeyCompletionRates(journeys);
    const parity = compareParity(journeys);
    const latencies = latenciesByLane(journeys);
    const latency = compareLatency(thresholds.latencyEnvelope, latencies.control, latencies.protected);
    const decision = decideVerdict(thresholds, {
      anomalyTotal, identitiesOk: accounting.identitiesOk, jcr: jcr.map((entry) => ({ phase: entry.phase, lane: entry.lane, rate: entry.rate })), latencyOk: latency.ok,
      parityMismatches: parity.mismatches.length, corpusViolations: violations, corpusCount: corpusRun.cases.length, expectedCorpusCount: CORPUS_FIXED_COUNT,
    });
    reasons.push(...decision.reasons, ...latency.reasons);
    const journal = await collector.closeJournal();
    const harness = sampler.stop();

    const channel = collector.channel;
    evidence.addJsonArtifact("accounting.json", {
      scope: scopeStatement(),
      identities: accounting.identities, identitiesOk: accounting.identitiesOk,
      sent: accounting.sent,
      ingress: accounting.ingress,
      l1: { entered: accounting.l1.entered, passed: accounting.l1.passed, rejected: accounting.l1.rejected, shed: accounting.l1.shed, error: accounting.l1.error, rejectedByReason: rows(accounting.l1.rejectedByReason), errorByKind: rows(accounting.l1.errorByKind) },
      egress: { attempted: accounting.egress.attempted, responded: accounting.egress.responded, failed: accounting.egress.failed, failedByKind: rows(accounting.egress.failedByKind) },
      synthetic_origins: accounting.origin, delivery: accounting.delivery, parser: accounting.parser, client: { completed: accounting.client.completed, byResult: rows(accounting.client.byResult) },
      residualHostileAtOrigin: rows(accounting.residualHostileAtOrigin),
      eventChannel: { receivedByCollector: channel.received, lastSeq: channel.lastSeq, droppedReported: channel.droppedReported, planeFin: channel.fin ? { drained: channel.fin.drained, ...channel.fin.channel } : "no_fin", planeCrashed: channel.crashed ?? "no", lateEvents: channel.late },
      anomalyTotal, anomalies,
    });
    evidence.addJsonArtifact("canary.json", {
      journey: { steps: ["homepage", "navigation_privacy", "form", "valid_post", "thank_you"], completeFlowRequired: true },
      journeyCompletionRate: jcr, parity: { compared: parity.compared, mismatches: parity.mismatches },
      latency: { envelope: thresholds.latencyEnvelope, ...latency },
    });
    evidence.addJsonArtifact("corpus.json", { fixedCount: CORPUS_FIXED_COUNT, executed: corpusRun.cases.length, violations, outcomesByReason: rows(observedReasons), cases: corpusRows });
    evidence.addJsonArtifact("resources.json", {
      scope: "bounded self-reported samples; the plane figures are advisory, the ledger is authoritative",
      plane: fin ? { ...fin.advisory.front, rssMaxMb: fin.advisory.rssMaxMb, eventLoopDelayP99Ms: fin.advisory.eventLoopDelayP99Ms, eventLoopDelayMaxMs: fin.advisory.eventLoopDelayMaxMs, cpuUserMs: fin.advisory.cpuUserMs, cpuSystemMs: fin.advisory.cpuSystemMs, bulkheadOccupancyHighWater: fin.advisory.composer.inFlightHighWater, shedTotal: fin.advisory.composer.shed, lateVerdictsDiscarded: fin.advisory.composer.lateVerdictsDiscarded, eventQueueHighWater: fin.channel.queueHighWater, eventsDropped: fin.channel.dropped } : "not_measured",
      harness: { ...harness, note: "the synthetic origins and the collector share the harness process" },
      synthetic_origins: { control: control.stats(), protected: protectedOrigin.stats() },
      not_measured: ["host.cpu_total", "host.memory_total", "origin.cpu_isolated", "n3.volumetric", "t4.transport", "pre_socket_loss", "tcp_backlog", "file_descriptors"],
    });
    evidence.finalize({
      git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null,
      ceilings: { fixedCounts: { baselineJourneysPerLane: thresholds.journeys.baselinePerLane, postCorpusJourneysPerLane: thresholds.journeys.postCorpusPerLane, corpusCases: CORPUS_FIXED_COUNT }, loadRamp: "none", externalTraffic: "none" },
      thresholds: ba0Fingerprint(thresholds), engine: "node-http-loopback", result: decision.verdict as EvidenceResult,
      // The `ba0.` prefix keeps a long snake_case reason from being mistaken for a token by the evidence scanner.
      resultReasons: reasons.map((reason) => `ba0.${reason}`),
      metrics: {
        scope: scopeStatement(), verdict: decision.verdict, defenseQualification: "not_claimed",
        requests: accounting.sent.total, anomalyTotal, identitiesOk: accounting.identitiesOk,
        journeyCompletionRate: jcr.map((entry) => ({ lane: entry.lane, phase: entry.phase, rate: entry.rate })),
        latencyAddedP95Ms: latency.addedP95Ms, latencyAddedP99Ms: latency.addedP99Ms,
        journal: journal ? { file: "ledger-journal.ndjson", lines: journal.lines, bytes: journal.bytes, sha256: journal.sha256, overflow: journal.overflow } : "none",
        namespaces: { "a7.application": "measured", "n3.volumetric": "not_measured", "t4.transport": "not_measured" },
      },
    });
    finalized = true;
    return { verdict: decision.verdict, reasons, evidenceId: evidence.id, evidenceDirectory: evidence.directory, accounting, anomalyTotal, anomalies, journeys };
  } catch (error) {
    // Anything unexpected is an ERROR run with its reason recorded, never a silent success and never a PASS.
    reasons.push(evidenceSafeError(error));
    if (!finalized) {
      try {
        await collector.closeJournal().catch(() => null);
        evidence.finalize({
          git, environment: collectEnvironment(), target: { id: "ba0-loopback-synthetic", class: "lab-local", scheme: "http" }, workload: null, ceilings: null,
          thresholds: ba0Fingerprint(thresholds), engine: "node-http-loopback", result: "ERROR", resultReasons: reasons.map((reason) => `ba0.${reason}`.slice(0, 200)),
          metrics: { verdict: "ERROR", defenseQualification: "not_claimed" },
        });
      } catch { /* the original error is what matters */ }
    }
    throw error;
  } finally {
    await Promise.allSettled([plane?.stop(), control.close(), protectedOrigin.close()]);
  }
}

function scopeStatement(): string {
  return `application plane only (${IMPLEMENTED_NAMESPACES.join(",")} of ${Object.keys(LAYER_NAMESPACES).join(",")}); an L7 success implies nothing about network or transport health; loss before the socket is invisible to this ledger`;
}

const EXIT: Record<string, number> = { "BASELINE-VALID": 0, INVALID: 1, REFUSED: 2, ERROR: 4 };

async function main(argv: readonly string[]): Promise<number> {
  if (argv.length > 0) { console.error("REFUSED  lab:ba0 accepts no arguments; counts and targets are fixed by ba0-local-v1"); return EXIT.REFUSED; }
  const outcome = await runBa0({ log: (line) => console.log(line) });
  const jcr = journeyCompletionRates(outcome.journeys);
  console.log(`${outcome.verdict}  ba0 slice 1 baseline (defense qualification not claimed)`);
  for (const reason of outcome.reasons) console.log(`  - ${reason}`);
  for (const entry of jcr) console.log(`  JCR ${entry.phase}/${entry.lane}: ${entry.completed}/${entry.attempted}`);
  for (const identity of outcome.accounting.identities) console.log(`  ${identity.ok ? "ok  " : "FAIL"} ${identity.id}: ${identity.left} vs ${identity.right}`);
  for (const anomaly of outcome.anomalies.slice(0, 20)) console.log(`  anomaly ${anomaly.code} ${anomaly.nonce ?? "-"} ${anomaly.detail}`);
  console.log(`evidence=${outcome.evidenceId}`);
  return EXIT[outcome.verdict];
}

// Run as a script only when this file is the entry point (a test importing runBa0 must not start a run).
if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (error) => { console.error(error instanceof Error ? evidenceSafeError(error) : "ERROR"); process.exit(EXIT.ERROR); });
}
