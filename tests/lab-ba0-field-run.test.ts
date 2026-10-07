import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { test } from "node:test";
import { ba0FieldFingerprint, BA0_FIELD_V1, type Ba0FieldThresholds } from "../lab/defense/field-thresholds";
import { FIELD_LEVELS, parseFieldArguments, runFieldLevel, type AuthorizationLike, type FieldRunOutcome, type FieldRunSeams } from "../lab/defense/ba0-field-run";
import { DISPOSABLE_MARKER_CONTENT, type FieldEnvironment } from "../lab/defense/field-preflight";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { FakeProc, SSHD } from "./support/fake-proc";
import { workloadFingerprint } from "../lab/defense/generator-report";
import { WORKLOADS } from "../lab/policy/workloads";

/**
 * The REAL field runner end to end on loopback: real Defense Plane, Boundary and App child processes (the field entries, with ticks), the real
 * collector, canary, tick loop, exposure proof (over a fake /proc, since this machine is not Linux), state machine, STOP path and evidence writer.
 *
 * What a loopback run can and cannot show: every peer here is LOCAL (there is no second host), so no request enters the external lane; the window
 * is driven by a timer (the `manualWindow` seam) instead of a remote generator. The external lane itself is proven end to end in-process in
 * `lab-ba0-external-e2e.test.ts`. A run against a real remote generator is the authorized campaign and is NOT performed here.
 */
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const MARKER = DISPOSABLE_MARKER_CONTENT;
const NOT_LISTENING = Symbol("not listening");

async function freePort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
  const port = (probe.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/** A level that runs in seconds: the same shape and the same gates, scaled down. Fingerprinted differently on purpose. */
function fast(overrides: (copy: Ba0FieldThresholds) => void = () => undefined): Ba0FieldThresholds {
  const copy = structuredClone(BA0_FIELD_V1) as Ba0FieldThresholds;
  (copy.level as { durationSeconds: number }).durationSeconds = 1;
  (copy.level as { maxTotalRequests: number }).maxTotalRequests = 25;
  copy.l2.epochMs = 1_000;
  (copy.hop as { pbLifetimeMs: number }).pbLifetimeMs = 600;
  (copy.hop as { baLifetimeMs: number }).baLifetimeMs = 500;
  copy.plane.egressTimeoutMs = 600;
  copy.recovery = { epochMs: 1_000, settleMarginMs: 1_500, quietMs: 3_500 };
  // The starvation limits are relaxed so a busy test machine does not turn scheduling noise into a verdict; one test below tightens them to prove the check.
  copy.canary = { ...copy.canary, baselineJourneys: 2, gapMs: 250, residualJourneys: 1, residualGapMs: 100, recoveryJourneys: 2, timeoutMs: 3_000, scheduleLagP99Ms: 2_000, harnessEldP99Ms: 2_000 };
  copy.window = { startSlackMs: 4_000, hardDeadlineMs: 12_000, quiescenceMs: 300, setupAllowanceMs: 2_000, drainAllowanceMs: 2_000 };
  copy.telemetry = { tickMs: 200, ringTicks: 120, gapToleranceMs: 700 };
  overrides(copy);
  return copy;
}

/** A /proc whose plane socket disappears when the real listener does, and whose host CPU can be driven high. */
class LiveProc extends FakeProc {
  planeOpen = true;
  planeInode = -1;
  hostBusy = 0;
  private statReads = 0;
  override readText(file: string): string | null {
    if (file === "/proc/stat" && this.hostBusy > 0) {
      this.statReads++;
      const total = this.statReads * 1_000;
      const busy = Math.round(total * this.hostBusy);
      return `cpu  ${busy} 0 0 ${total - busy} 0 0 0 0 0 0\n`;
    }
    if (file === "/proc/net/tcp" && !this.planeOpen && this.planeInode > 0) {
      const text = super.readText(file);
      return text === null ? null : text.split("\n").filter((line) => !line.includes(` ${this.planeInode} `)).join("\n");
    }
    return super.readText(file);
  }
}

type Rig = {
  proc: LiveProc;
  port: number;
  thresholds: Ba0FieldThresholds;
  seams: FieldRunSeams;
  topology: { pids: Record<string, number | undefined> };
  evidenceRoot: string;
  lockFile: string;
  cleanup: () => void;
};

async function rig(options: { thresholds?: Ba0FieldThresholds; env?: Partial<FieldEnvironment>; seams?: Partial<FieldRunSeams>; manualWindow?: boolean } = {}): Promise<Rig> {
  const port = await freePort();
  const proc = new LiveProc();
  proc.addProcess(process.pid).addProcess(SSHD);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  const thresholds = options.thresholds ?? fast();
  const evidenceRoot = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${process.pid}-${Math.random().toString(16).slice(2, 8)}`);
  fs.mkdirSync(evidenceRoot, { recursive: true });
  const lockFile = path.join(evidenceRoot, "field-run.lock");
  const topology: Rig["topology"] = { pids: {} };
  const ufw = ["Status: active", "", `[ 1] 22/tcp                     ALLOW IN    198.51.100.7`, `[ 2] ${port}/tcp                  ALLOW IN    203.0.113.9`, ""].join("\n");
  const env: FieldEnvironment = {
    platform: "linux", reader: proc, pid: process.pid, readMarker: () => MARKER, unitState: async () => "inactive", ufwStatus: async () => ufw, localIpv4Addresses: () => ["127.0.0.1"], ...options.env,
  };
  const authorization: AuthorizationLike = {
    target: { id: "sut-test", class: "lab-remote", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/"], allowedMethods: ["GET", "POST"], origin: `http://127.0.0.1:${port}` },
    authorizedUntilMs: null, assertStillAuthorized: () => undefined,
  };
  const seams: FieldRunSeams = {
    env, thresholds, authorization, git: { gitSha: "a".repeat(40), dirty: false, dirtyFileCount: 0, untrackedFileCount: 0 }, treeIsClean: true, allowLoopbackIngress: true, skipPlatformCheck: true,
    evidenceRoot, lockFile,
    // the fake /proc follows the real listener: when the plane acknowledges its ingress is closed, its socket leaves the table
    onIngressClosed: () => { proc.planeOpen = false; },
    ...(options.manualWindow === false ? {} : { manualWindow: { openAfterMs: 300, closeAfterMs: 1_500 } }),
    onTopology: (info) => {
      topology.pids = { ...info.pids };
      const { plane, boundary, app } = info.pids;
      for (const pid of [plane, boundary, app]) if (pid !== undefined) proc.addProcess(pid);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.control, inode: 11 }, [process.pid]);
      proc.planeInode = 12;
      proc.addSocket({ family: 4, ip: info.ingress.ip, port: info.ingress.port, inode: 12 }, [plane!]);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.boundary, inode: 13 }, [boundary!]);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.app, inode: 14 }, [app!]);
      options.seams?.onTopology?.(info);
    },
    ...Object.fromEntries(Object.entries(options.seams ?? {}).filter(([key]) => key !== "onTopology")),
  };
  return { proc, port, thresholds, seams, topology, evidenceRoot, lockFile, cleanup: () => { fs.rmSync(evidenceRoot, { recursive: true, force: true }); } };
}

const run = (r: Rig): Promise<FieldRunOutcome> => runFieldLevel({ targetId: "sut-test", levelId: "ba0-l7-c1", campaignId: "selftest-campaign" }, r.seams);

const alive = (pid: number | undefined): boolean => { if (pid === undefined) return false; try { process.kill(pid, 0); return true; } catch { return false; } };
const states = (outcome: FieldRunOutcome): string[] => outcome.bundle!.machine.transitions.map((entry) => entry.state);
const codes = (outcome: FieldRunOutcome): string[] => outcome.serverSide?.reasons.map((reason) => reason.code) ?? [];
const readJson = (outcome: FieldRunOutcome, name: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(outcome.evidenceDirectory!, name), "utf8")) as Record<string, unknown>;

async function assertTornDown(r: Rig): Promise<void> {
  await sleep(300);
  for (const [role, pid] of Object.entries(r.topology.pids)) if (role !== "runner") assert.equal(alive(pid), false, `${role} (${pid}) must be gone`);
  await assert.rejects(() => new Promise((resolve, reject) => { const probe = net.connect({ host: "127.0.0.1", port: r.port }, () => { probe.destroy(); resolve(true); }); probe.on("error", reject); }), /ECONNREFUSED/, "the public ingress is closed");
  assert.equal(fs.existsSync(r.lockFile), false, "the single-instance lock is released");
}

// ------------------------------------------------------------------------------------------------ the happy path
test("a full level runs PREFLIGHT -> ... -> DONE: ordered states, every finalization step ok, evidence complete, ingress closed, every process gone", { timeout: 120_000 }, async () => {
  const r = await rig();
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "complete", JSON.stringify(outcome.serverSide?.reasons));
    assert.equal(outcome.exit, 0);
    assert.deepEqual(states(outcome), ["CREATED", "PREFLIGHT", "TOPOLOGY_UP", "BASELINE", "ARMED", "WINDOW", "RESIDUAL", "QUIET", "RECOVERY", "FINALIZING", "DONE"]);
    assert.deepEqual(outcome.bundle!.sequence.map((step) => [step.name, step.ok]), [["close_ingress", true], ["drain", true], ["final_telemetry", true], ["snapshot", true], ["finalize_evidence", true], ["terminate", true]]);
    assert.equal(outcome.bundle!.machine.phasesCompleted, true);
    assert.equal(outcome.bundle!.firstReason, null);
    assert.deepEqual(outcome.write!.failed, [], "every artifact, built from REAL ticks, passed the evidence scanner");
    assert.equal(outcome.write!.written.length, 13);
    assert.equal(outcome.bundle!.collector.anomalyTotal, 0);
    assert.deepEqual(outcome.bundle!.accounting!.identities.filter((entry) => !entry.ok), []);
    assert.ok(outcome.bundle!.exposure.running.checks >= 10, `the exposure proof ran every tick: ${outcome.bundle!.exposure.running.checks}`);
    assert.deepEqual(outcome.bundle!.exposure.running.violations, []);
    assert.equal(outcome.bundle!.exposure.final?.ok, true);
    assert.equal(outcome.bundle!.exposure.final?.planeSocket, "absent", "after the close the plane has no listener");
    assert.deepEqual(outcome.bundle!.telemetry.finalTicks, { plane: true, boundary: true, app: true });
    assert.equal(outcome.bundle!.telemetry.gaps, 0);
    assert.ok(outcome.bundle!.telemetry.ring.plane.length >= 10 && outcome.bundle!.telemetry.ring.boundary.length >= 10 && outcome.bundle!.telemetry.ring.app.length >= 10, "1-second-style ticks from all three processes");
    assert.equal(outcome.bundle!.canary.jcr.every((entry) => entry.rate === 1), true);
    assert.deepEqual(outcome.bundle!.canary.jcr.map((entry) => `${entry.lane}.${entry.phase}`).sort(), ["control.baseline", "control.recovery", "protected.baseline", "protected.recovery", "protected.residual", "protected.window"]);
    assert.equal(outcome.bundle!.canary.parityMismatches, 0);
    assert.equal(outcome.bundle!.recovery.ok, true, outcome.bundle!.recovery.detail);
    assert.equal(outcome.bundle!.recovery.quietMs, 3_500, "derived: 2 x epoch + settle margin");
    assert.ok(outcome.bundle!.window !== null);
    assert.equal(outcome.bundle!.external.accepted, 0, "a loopback run has no remote peer");
    assert.equal(outcome.bundle!.connections!.acceptedRemote, 0);
    assert.ok(outcome.bundle!.connections!.acceptedLocal >= 25, "the canary's own connections");
    assert.equal(outcome.bundle!.connections!.active, 0);
    assert.equal(outcome.bundle!.connections!.dropped, 0);
    const core = readJson(outcome, "core.json") as { finalVerdict: string; serverSide: { status: string } };
    assert.equal(core.finalVerdict, "not_decided_here");
    assert.equal(core.serverSide.status, "complete");
    const level = readJson(outcome, "server-level.json") as { schema: string; paramsFingerprintSha256: string; reconcileInput: { externalAccepted: number } };
    assert.equal(Object.hasOwn(level, "n2"), false, "historical N=1 evidence shape is unchanged");
    assert.equal(level.schema, "ba0-server-level-v1");
    assert.equal(level.paramsFingerprintSha256, ba0FieldFingerprint(r.thresholds).sha256);
    const manifest = readJson(outcome, "manifest.json") as { result: string };
    assert.equal(manifest.result, "SERVER-COMPLETE", "never a final verdict");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ STOP: forensic freeze
test("N=2 runner uses its own workload binding and preserves complete journeys, accounting, parity and derived recovery", { timeout: 120_000 }, async () => {
  const r = await rig({ thresholds: fast((t) => { t.id = "ba0-field-c2-v1"; t.level.id = "ba0-l7-c2"; t.level.workers = 2; }) });
  try {
    const outcome = await runFieldLevel({ targetId: "sut-test", levelId: "ba0-l7-c2", campaignId: "selftest-campaign" }, r.seams);
    assert.equal(outcome.status, "complete", JSON.stringify(outcome.serverSide?.reasons));
    assert.deepEqual(outcome.write!.failed, []);
    assert.equal(outcome.bundle!.collector.anomalyTotal, 0);
    assert.deepEqual(outcome.bundle!.accounting!.identities.filter((entry) => !entry.ok), []);
    assert.equal(outcome.bundle!.canary.jcr.length, 6);
    assert.ok(outcome.bundle!.canary.jcr.every((entry) => entry.rate === 1));
    assert.equal(outcome.bundle!.canary.legitimateRefusals, 0);
    assert.equal(outcome.bundle!.canary.l1FalseRejects, 0);
    assert.equal(outcome.bundle!.canary.l2NonAdmits, 0);
    assert.equal(outcome.bundle!.canary.parityMismatches, 0);
    assert.equal(outcome.bundle!.recovery.ok, true);
    assert.equal(outcome.bundle!.recovery.quietMs, 2 * r.thresholds.l2.epochMs + r.thresholds.recovery.settleMarginMs);
    const level = readJson(outcome, "server-level.json");
    assert.equal(level.levelId, "ba0-l7-c2");
    assert.equal(level.workers, 2);
    assert.equal(level.paramsFingerprintSha256, ba0FieldFingerprint(r.thresholds).sha256);
    assert.equal(level.workloadFingerprintSha256, workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]));
    assert.deepEqual(level.n2, outcome.bundle!.n2, "the real writer preserves the source barriers and bounded exposure");
    assert.equal(outcome.bundle!.n2!.armed!.phase, "armed");
    assert.equal(outcome.bundle!.n2!.closed!.phase, "closed");
    assert.equal(outcome.bundle!.n2!.armed!.acceptedExternal, 0);
    assert.equal(outcome.bundle!.n2!.closed!.inFlightExternal, 0);
    assert.ok(outcome.bundle!.n2!.closed!.seq > outcome.bundle!.n2!.armed!.seq, "watermark includes intervening canary events");
    assert.equal(outcome.bundle!.n2!.exposure.overlapMs.length, 5, "scaled test seam; production has 60 intervals");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("D5: a STOP latches the FIRST reason, closes the ingress at once, blocks new work, drains, snapshots and finalizes BEFORE any process is terminated", { timeout: 120_000 }, async () => {
  let armedAt = 0;
  const r = await rig({
    manualWindow: false,
    seams: {
      onArmed: ({ ingress }) => {
        armedAt = performance.now();
        // a stray LOCAL request that no harness registered: an unexplained request, which must stop the level
        const request = net.connect({ host: ingress.ip, port: ingress.port }, () => { request.write("GET /gizlilik HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); });
        request.on("error", () => undefined);
        request.on("data", () => undefined);
      },
    },
  });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "invalid");
    assert.equal(outcome.serverSide?.failureClass, "measurement");
    assert.equal(outcome.bundle!.firstReason?.code, "ledger_anomaly", "the first latched reason is the one that began the STOP");
    assert.deepEqual(states(outcome).slice(-5), ["STOPPING", "DRAINING", "SNAPSHOT", "FINALIZING", "DONE"]);
    assert.ok(!states(outcome).includes("WINDOW"), "no window opened after the STOP");
    assert.deepEqual(outcome.bundle!.sequence.map((step) => step.name), ["close_ingress", "drain", "final_telemetry", "snapshot", "finalize_evidence", "terminate"]);
    assert.ok(outcome.bundle!.sequence.every((step) => step.ok), JSON.stringify(outcome.bundle!.sequence));
    assert.ok(performance.now() - armedAt < 20_000, "bounded");
    assert.equal(outcome.bundle!.machine.phasesCompleted, false);
    assert.deepEqual(outcome.write!.failed, []);
    assert.ok(outcome.bundle!.telemetry.ring.plane.length > 0, "the ticks that led to the STOP are preserved");
    assert.deepEqual(outcome.bundle!.telemetry.finalTicks, { plane: true, boundary: true, app: true }, "final telemetry was collected AFTER the STOP");
    assert.ok(outcome.bundle!.collector.anomalies.some((anomaly) => anomaly.code === "uncorrelated_ingress"), "the evidence explains the STOP");
    assert.equal(readJson(outcome, "manifest.json").result, "INVALID");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("a generator that never starts is an OPERATIONAL end (aborted), not a defense or measurement failure", { timeout: 120_000 }, async () => {
  const r = await rig({ manualWindow: false, thresholds: fast((t) => { t.window.startSlackMs = 1_200; }) });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "aborted");
    assert.equal(outcome.serverSide?.failureClass, "operational");
    assert.deepEqual(codes(outcome).slice(0, 1), ["generator_not_started"]);
    assert.equal(outcome.exit, 3);
    assert.equal(outcome.bundle!.firstReason?.code, "generator_not_started");
    assert.equal(readJson(outcome, "manifest.json").result, "ABORTED");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("an operator abort (the abort signal, as SIGINT would) ends the level orderly: ABORTED, finalized, nothing killed first", { timeout: 120_000 }, async () => {
  const controller = new AbortController();
  const r = await rig({ seams: { abort: controller.signal, onArmed: () => { setTimeout(() => controller.abort(), 400); } } });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "aborted");
    assert.equal(outcome.bundle!.firstReason?.code, "operator_abort");
    assert.deepEqual(states(outcome).slice(-5), ["STOPPING", "DRAINING", "SNAPSHOT", "FINALIZING", "DONE"]);
    assert.ok(outcome.bundle!.sequence.every((step) => step.ok));
    assert.equal(outcome.bundle!.machine.phasesCompleted, false);
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("the target authorization lapsing mid-run is an operational end: the watchdog latches target_expired and the level stops orderly", { timeout: 120_000 }, async () => {
  let calls = 0;
  const r = await rig();
  r.seams.authorization = { ...r.seams.authorization!, assertStillAuthorized: () => { if (++calls > 6) throw new Error("expired"); } };
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "aborted");
    assert.equal(outcome.bundle!.firstReason?.code, "target_expired");
    assert.equal(outcome.serverSide?.failureClass, "operational");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ D1: continuous exposure
test("D1: an unexpected non-loopback listener appearing DURING the run is a STOP (measurement failure) detected within a tick, and the evidence records it", { timeout: 120_000 }, async () => {
  const r = await rig({
    seams: {
      onTopology: () => {
        setTimeout(() => {
          const pid = r.topology.pids.boundary!;
          r.proc.addSocket({ family: 4, ip: "0.0.0.0", port: 41_999, inode: 99 }, [pid]);
        }, 900);
      },
    },
  });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "invalid");
    assert.equal(outcome.serverSide?.failureClass, "measurement");
    assert.equal(outcome.bundle!.firstReason?.code, "exposure_violation");
    assert.ok(outcome.bundle!.exposure.running.violations.includes("topology_wildcard_v4"));
    assert.deepEqual(states(outcome).slice(-5), ["STOPPING", "DRAINING", "SNAPSHOT", "FINALIZING", "DONE"]);
    const exposure = readJson(outcome, "exposure.json") as { statement: string; running: { violations: string[] } };
    assert.match(exposure.statement, /host listener state only/);
    assert.ok(exposure.running.violations.includes("topology_wildcard_v4"));
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("D1: an unreadable /proc during the run is exposure_unproven (fail closed), never a pass", { timeout: 120_000 }, async () => {
  const r = await rig({ seams: { onTopology: () => { setTimeout(() => { r.proc.tcpUnreadable = true; }, 700); } } });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "invalid");
    assert.equal(outcome.bundle!.firstReason?.code, "exposure_unproven");
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ a measured defense failure is its own class
test("a host CPU ceiling held for the pinned number of ticks is a STOP of class DEFENSE (a measured resource limit), not a measurement failure", { timeout: 120_000 }, async () => {
  const r = await rig({ seams: { onTopology: () => { r.proc.files.set("/proc/meminfo", "MemTotal:       8000000 kB\nMemAvailable:   4000000 kB\n"); r.proc.hostBusy = 0.95; } } });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "invalid");
    assert.equal(outcome.serverSide?.failureClass, "defense", JSON.stringify(outcome.serverSide?.reasons));
    assert.equal(outcome.bundle!.firstReason?.code, "resource_ceiling");
    assert.match(outcome.bundle!.firstReason?.detail ?? "", /host cpu/);
    assert.ok(outcome.bundle!.telemetry.peaks.hostCpuBusyPct >= 80);
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

test("canary starvation is a MEASUREMENT failure, told apart from a slow server: a canary whose scheduler lagged is not evidence about the defense", { timeout: 120_000 }, async () => {
  const r = await rig({ thresholds: fast((t) => { t.canary.scheduleLagP99Ms = 0; }) });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "invalid");
    assert.equal(outcome.serverSide?.failureClass, "measurement");
    assert.ok(codes(outcome).includes("canary_starved"), codes(outcome).join(","));
    assert.equal(outcome.bundle!.machine.phasesCompleted, true, "the level itself ran to the end");
    assert.ok(outcome.bundle!.canary.scheduleLagMs.count > 0);
    await assertTornDown(r);
  } finally { r.cleanup(); }
});

// ------------------------------------------------------------------------------------------------ preflight refusals bind nothing
test("a preflight refusal starts NOTHING: no process, no listener, no lock, minimal evidence, exit code 2", { timeout: 60_000 }, async () => {
  let topologyStarted = false;
  const r = await rig({ env: { unitState: async () => "active" }, seams: { onTopology: () => { topologyStarted = true; } } });
  try {
    const outcome = await run(r);
    assert.equal(outcome.status, "refused");
    assert.equal(outcome.exit, 2);
    assert.deepEqual(outcome.refusals, ["old_service.inactive"]);
    assert.equal(topologyStarted, false, "no child process was started");
    assert.equal(fs.existsSync(r.lockFile), false);
    await assert.rejects(() => new Promise((resolve, reject) => { const probe = net.connect({ host: "127.0.0.1", port: r.port }, () => { probe.destroy(); resolve(true); }); probe.on("error", reject); }), /ECONNREFUSED/, "nothing listens on the reviewed port");
    const manifest = JSON.parse(fs.readFileSync(path.join(outcome.evidenceDirectory!, "manifest.json"), "utf8")) as { result: string; metrics: { networkActivity: boolean } };
    assert.equal(manifest.result, "REFUSED");
    assert.equal(manifest.metrics.networkActivity, false);
  } finally { r.cleanup(); }
});

test("every preflight refusal path is fail-closed: a bad level, an unauthorized target, a failing budget gate, an old 3000 listener, a held lock", { timeout: 120_000 }, async () => {
  const refused = async (label: string, setup: (r: Rig) => void | Promise<void>, expected: string, level = "ba0-l7-c1") => {
    const r = await rig();
    try {
      await setup(r);
      const outcome = await runFieldLevel({ targetId: "sut-test", levelId: level, campaignId: "selftest-campaign" }, r.seams);
      assert.equal(outcome.status, "refused", label);
      assert.ok(outcome.refusals.includes(expected), `${label}: ${outcome.refusals.join(",")}`);
      assert.equal(Object.keys(r.topology.pids).length, 0, `${label}: nothing was started`);
    } finally { r.cleanup(); }
  };
  await refused("an unreviewed level", () => undefined, "level_not_reviewed", "ba0-l7-c9");
  await refused("an unauthorized target", (r) => { r.seams.authorization = undefined; r.seams.registry = new Map(); }, "policy_target-unknown");
  await refused("a failing budget gate", (r) => { r.seams.thresholds = fast((t) => { t.l2.ledgerCapacity = 5; }); }, "budget.l2.ledger_capacity");
  await refused("an exposed old application port", (r) => { r.proc.addProcess(600); r.proc.addSocket({ family: 4, ip: "0.0.0.0", port: 3000, inode: 70 }, [600]); }, "exposure.pre_bind_clean");
  await refused("a lock that is already held", (r) => { fs.writeFileSync(r.lockFile, "1\n"); }, "lock_held_or_stale");
  await refused("a loopback bind in a real run", (r) => { r.seams.allowLoopbackIngress = false; }, "bind.not_loopback");
  await refused("a missing disposable marker", (r) => { r.seams.env = { ...r.seams.env!, readMarker: () => null }; }, "host.disposable_marker");
});

// ------------------------------------------------------------------------------------------------ the command line
test("the field command line accepts exactly --target, --level and --campaign (plus --dry-run and --selftest); no URL, host, port or path", () => {
  assert.deepEqual(parseFieldArguments(["--target", "sut-test", "--level", "ba0-l7-c1", "--campaign", "first-campaign"]), { targetId: "sut-test", levelId: "ba0-l7-c1", campaignId: "first-campaign", dryRun: false, selftest: false });
  assert.equal(parseFieldArguments(["--target", "sut-test", "--level", "ba0-l7-c1", "--campaign", "first-campaign", "--dry-run"]).dryRun, true);
  assert.equal(parseFieldArguments(["--selftest"]).selftest, true);
  for (const argv of [[], ["--target", "sut-test"], ["--target", "sut-test", "--level", "ba0-l7-c1"], ["--url", "http://x"], ["--host", "10.0.0.1"], ["--port", "8080"], ["--target", "http://x", "--level", "ba0-l7-c1", "--campaign", "first-campaign"],
    ["--target", "sut-test", "--level", "ba0-l7-c1", "--campaign", "first-campaign", "--target", "other"], ["--target=sut-test", "--level", "ba0-l7-c1", "--campaign", "first-campaign"], ["--target", "sut-test", "--level", "ba0-l7-c1", "--campaign", "x"]]) {
    assert.throws(() => parseFieldArguments(argv), Error, JSON.stringify(argv));
  }
  assert.deepEqual(Object.keys(FIELD_LEVELS), ["ba0-l7-c1", "ba0-l7-c2"], "only the two reviewed levels exist");
});

void NOT_LISTENING;
