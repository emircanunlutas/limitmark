/**
 * Field qualification: serializes one level's evidence. The CORE artifact (what the level was, what it concluded, why, and the STOP/finalize
 * sequence) is written FIRST and from enums and numbers only; every richer artifact is then written in isolation, so a single artifact the
 * evidence scanner refuses (a key or value it forbids) is recorded in the manifest and never loses the core or the others. A selftest pushes
 * a synthetic level through this exact writer (`field-selftest.ts`) so a shape problem is found before a field run, not at its end.
 *
 * Nothing here writes an address, a nonce, a token, a header, a body, a key or a path; the redactor refuses them anyway.
 */
import type { Anomaly, PlaneEvent } from "../../defense/core/ledger";
import type { Tick, TickRole } from "../../defense/core/telemetry";
import type { EvidenceRun, GitState } from "../evidence/manifest";
import type { JournalSummary, PlaneFin, BoundaryFin, AppFin } from "./collector";
import type { ExternalAccountingReport } from "./external-accounting";
import type { ExternalCounters, ExternalTrace } from "./external-reducer";
import type { ExposureResult } from "./exposure-proof";
import type { LatchedReason, StepResult } from "./field-state";
import type { PreflightResult } from "./field-preflight";
import type { Ba0FieldThresholds } from "./field-thresholds";
import type { ServerSideDecision } from "./field-verdict";
import { SERVER_LEVEL_SCHEMA, type ServerLevelEvidence } from "./reconcile";
import { EXPOSURE_STATEMENT } from "./exposure-proof";

/** Exact strings the evidence carries about what is NOT claimed. A test pins that no other string over-claims. */
export const NOT_CLAIMED_FIELD: readonly string[] = Object.freeze([
  "DDoS resistance or capacity: one level of ordinary HTTP pressure from one source is measured, nothing above it",
  "bot detection",
  "read-flood resistance: the open lane has no budget by design",
  "per-user fairness",
  "network, transport, TLS or origin-network isolation: the exposure proof reads host listener state only",
  "cloud firewall or NAT behaviour",
  "the real application: the protected application is the synthetic stand-in origin",
  "multi-source, distributed or mixed L4/L7 traffic",
  "behaviour at any level above the tested one",
  "L1/L2 process independence: both layers run in one Defense Plane process",
  "production readiness",
  "calibrated limits: every number is provisional and uncalibrated",
]);

export const SCOPE_STATEMENT_FIELD = "application-plane behaviour under one reviewed level of ordinary HTTP request pressure, from one authorized source, against one reviewed Defense Plane ingress on a disposable host; plain HTTP";

export type CanarySummary = {
  jcr: { lane: string; phase: string; attempted: number; completed: number; rate: number }[];
  journeys: number;
  legitimateRefusals: number;
  l1FalseRejects: number;
  l2NonAdmits: number;
  parityMismatches: number;
  parityCompared: number;
  scheduleLagMs: { count: number; p50: number; p95: number; p99: number; max: number };
  latencyMs: Record<string, { count: number; p50: number; p95: number; p99: number; max: number }>;
  windowLatencyOk: boolean | null;
  stepFailures: Record<string, number>;
  clientObservedMutations: number;
  /** Journeys a STOP interrupted (their later requests were refused by the STOP's own ingress close): excluded from the rates, counted here. */
  interruptedJourneys: number;
};

export type FieldEvidenceBundle = {
  level: { id: string; campaignId: string; workers: number };
  parameters: { id: string; version: number; sha256: string };
  workloadSha256: string;
  thresholds: Ba0FieldThresholds;
  git: GitState;
  serverSide: ServerSideDecision;
  firstReason: LatchedReason | null;
  reasons: readonly LatchedReason[];
  machine: { transitions: readonly { state: string; atMs: number }[]; phasesCompleted: boolean };
  sequence: readonly StepResult[];
  preflight: PreflightResult | null;
  exposure: { running: { checks: number; violations: string[] }; final: ExposureResult | null };
  window: { openedAt: string; closedAt: string; elapsedMs: number } | null;
  external: ExternalCounters;
  accounting: ExternalAccountingReport | null;
  traces: readonly ExternalTrace[];
  canary: CanarySummary;
  telemetry: {
    gaps: number; gapDetails: readonly string[]; finalTicks: Record<TickRole, boolean>; ring: Record<TickRole, readonly Tick<unknown>[]>;
    harnessEld: { highTicks: number; max: number; ticks: number }; peaks: Record<string, number>;
  };
  connections: Record<string, number> | null;
  externalInFlightMax: number;
  processes: { plane: PlaneFin | null; boundary: BoundaryFin | null; app: AppFin | null };
  collector: { anomalyTotal: number; anomalies: readonly Anomaly[]; records: number; journal: JournalSummary | null };
  recovery: { quietMs: number; checked: boolean; ok: boolean; detail: string };
  reconcileInput: ServerLevelEvidence["reconcileInput"] | null;
  anonymousRefusals: Record<string, number>;
};

const round = (value: number): number => Math.round(value * 100) / 100;

/** The parameter set as evidence: a few key names the scanner reserves (for example anything containing the word body) are renamed, values untouched. */
export function evidenceView(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(evidenceView);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key.replace(/body/gi, "read"), evidenceView(child)]));
  return value;
}

/** A compact, identifier-free trace: kinds and the few facts that explain a request. The nonce never appears; the evidence id does. */
export function compactTrace(trace: ExternalTrace): Record<string, unknown> {
  const plane = trace.plane.map((event: PlaneEvent) => [event.seq, event.kind, event.reason ?? event.outcome ?? event.status ?? event.egressError ?? event.shedReason ?? ""].join(":"));
  return { rid: trace.rid, reason: trace.reason, plane, boundary: trace.boundary.map((event) => event.kind), app: trace.app.map((event) => event.kind) };
}

export type WriteResult = { written: string[]; failed: { artifact: string; rule: string }[] };

/** Writes every artifact; the core first, then the rest each in isolation. Never throws for an artifact the scanner refuses. */
export function writeFieldEvidence(evidence: EvidenceRun, bundle: FieldEvidenceBundle): WriteResult {
  const result: WriteResult = { written: [], failed: [] };
  const put = (name: string, value: unknown): void => {
    try { evidence.addJsonArtifact(name, value); result.written.push(name); }
    catch (error) { result.failed.push({ artifact: name, rule: error instanceof Error ? error.message.replace(/=/g, ":").slice(0, 160) : "refused" }); }
  };

  // ---- the core: enums and numbers only
  put("core.json", {
    scope: SCOPE_STATEMENT_FIELD,
    level: bundle.level, parameters: bundle.parameters, workloadSha256: bundle.workloadSha256,
    serverSide: { status: bundle.serverSide.status, failureClass: bundle.serverSide.failureClass, reasons: bundle.serverSide.reasons.map((reason) => ({ code: reason.code, detail: reason.detail ?? null })) },
    finalVerdict: "not_decided_here",
    firstReason: bundle.firstReason === null ? null : { code: bundle.firstReason.code, cls: bundle.firstReason.cls, atMs: round(bundle.firstReason.atMs) },
    machine: { phasesCompleted: bundle.machine.phasesCompleted, transitions: bundle.machine.transitions.map((entry) => ({ state: entry.state, atMs: round(entry.atMs) })) },
    sequence: bundle.sequence,
    sequenceNote: "the finalization steps that had completed when this artifact was written; the evidence step and the termination that follows it cannot record themselves",
    claims: { defenseQualification: "not_claimed", networkNonBypass: "not_measured", originNetworkIsolation: "not_measured", notClaimed: [...NOT_CLAIMED_FIELD] },
  });

  put("server-level.json", {
    schema: SERVER_LEVEL_SCHEMA, campaignId: bundle.level.campaignId, levelId: bundle.level.id, gitSha: bundle.git.gitSha,
    paramsFingerprintSha256: bundle.parameters.sha256, workloadFingerprintSha256: bundle.workloadSha256, workers: bundle.level.workers,
    serverSide: { status: bundle.serverSide.status, failureClass: bundle.serverSide.failureClass, reasons: bundle.serverSide.reasons.map((reason) => ({ code: reason.code })) },
    window: bundle.window, reconcileInput: bundle.reconcileInput,
  });
  put("external.json", {
    scope: SCOPE_STATEMENT_FIELD, counters: bundle.external, anonymousRefusals: bundle.anonymousRefusals,
    accounting: bundle.accounting === null ? "not_derived" : { identities: bundle.accounting.identities, identitiesOk: bundle.accounting.identitiesOk, mutationBound: bundle.accounting.mutationBound, buckets: bundle.accounting.buckets, summary: bundle.accounting.summary },
  });
  put("canary.json", { journey: { steps: ["homepage", "navigation_privacy", "form", "valid_post", "thank_you"], completeFlowRequired: true }, ...bundle.canary });
  put("exposure.json", {
    statement: EXPOSURE_STATEMENT,
    preBind: bundle.preflight?.exposure ?? "not_run", running: bundle.exposure.running, final: bundle.exposure.final ?? "not_run",
    firewall: bundle.preflight?.firewall ?? "not_read",
  });
  put("preflight.json", { ok: bundle.preflight?.ok ?? false, checks: bundle.preflight?.checks ?? [], ambientNonLoopbackPorts: bundle.preflight?.ambientNonLoopbackPorts ?? [] });
  put("telemetry.json", {
    scope: "1-second observation-only ticks; the last ticks per process are kept (bounded ring); the ledger is authoritative, these are for attribution",
    tickMs: bundle.thresholds.telemetry.tickMs, gaps: bundle.telemetry.gaps, gapDetails: bundle.telemetry.gapDetails, finalTicks: bundle.telemetry.finalTicks,
    harnessEventLoop: bundle.telemetry.harnessEld, peaks: bundle.telemetry.peaks, ring: bundle.telemetry.ring,
    kernelCounters: "advisory: they count events the application never saw and cannot be attributed to a connection",
  });
  put("connections.json", { scope: "exact monotonic counters from the plane's listener", final: bundle.connections ?? "not_available", externalInFlightMax: bundle.externalInFlightMax });
  put("traces.json", { scope: "a bounded sample: every anomaly, every mutation, the first of each kind, a head sample; never every request", retained: bundle.traces.length, traces: bundle.traces.map(compactTrace) });
  put("processes.json", {
    plane: bundle.processes.plane === null ? "no_fin" : { drained: bundle.processes.plane.drained, channel: bundle.processes.plane.channel },
    boundary: bundle.processes.boundary === null ? "no_fin" : { drained: bundle.processes.boundary.drained, channel: bundle.processes.boundary.channel, stats: bundle.processes.boundary.stats },
    app: bundle.processes.app === null ? "no_fin" : { drained: bundle.processes.app.drained, channel: bundle.processes.app.channel, stats: bundle.processes.app.stats },
  });
  put("accounting.json", {
    anomalyTotal: bundle.collector.anomalyTotal, anomalies: bundle.collector.anomalies, registeredRecords: bundle.collector.records,
    journal: bundle.collector.journal ? { lines: bundle.collector.journal.lines, bytes: bundle.collector.journal.bytes, journalSha256: bundle.collector.journal.sha256, overflow: bundle.collector.journal.overflow } : "none",
  });
  put("recovery.json", { quietMs: bundle.recovery.quietMs, derivation: "2 x epoch + settle margin, from the parameter set", checked: bundle.recovery.checked, ok: bundle.recovery.ok, detail: bundle.recovery.detail });
  put("parameters.json", { fingerprint: bundle.parameters, status: bundle.thresholds.status, calibration: bundle.thresholds.calibration, values: evidenceView(bundle.thresholds) });
  return result;
}
