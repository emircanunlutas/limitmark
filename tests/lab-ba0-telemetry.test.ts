import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { createAppGuard } from "../defense/origin/app-guard";
import { createBoundary } from "../defense/boundary/boundary";
import { JourneyLanes, type LaneDecision } from "../defense/core/lanes";
import { importPrivateKey, importPublicKey } from "../defense/core/hop-proof";
import { ProcessSampler, TickSource, type Tick } from "../defense/core/telemetry";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import type { PlaneTick } from "../defense/plane/l2-protocol";
import { TickMonitor } from "../lab/defense/field-monitor";
import { buildSelftestBundle } from "../lab/defense/field-selftest";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { ProcSampler, type ProcSnapshot } from "../lab/defense/proc-sampler";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { FakeProc } from "./support/fake-proc";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// ------------------------------------------------------------------------------------------------ the per-process sampler and the tick source
test("the sampler reports the interval just ended and resets: an idle loop is quiet, a blocked loop shows its delay, then it is quiet again", async () => {
  const sampler = new ProcessSampler();
  try {
    await sleep(120);
    const idle = sampler.sample();
    assert.ok(idle.eldP99Ms < 50, `idle p99 ${idle.eldP99Ms}`);
    assert.ok(idle.rssMb > 10);
    assert.ok(idle.cpuUserMs >= 0 && idle.cpuSystemMs >= 0);
    const until = Date.now() + 150;
    while (Date.now() < until) { /* hold the event loop */ }
    await sleep(60);
    const blocked = sampler.sample();
    assert.ok(blocked.eldMaxMs >= 100, `blocked max ${blocked.eldMaxMs}`);
    assert.ok(blocked.eldMaxMs >= blocked.eldP99Ms && blocked.eldP99Ms >= blocked.eldP50Ms);
    await sleep(150);
    const after = sampler.sample();
    assert.ok(after.eldMaxMs < blocked.eldMaxMs, "the histogram was reset at the previous sample");
  } finally { sampler.stop(); }
});

test("ticks carry a gapless sequence, mark the final one, and are small and bounded", () => {
  const sampler = new ProcessSampler();
  try {
    const source = new TickSource("plane", sampler, () => ({ counter: 1 }));
    const ticks = [source.next(), source.next(), source.next(true)];
    assert.deepEqual(ticks.map((tick) => tick.tickSeq), [1, 2, 3]);
    assert.deepEqual(ticks.map((tick) => tick.final), [false, false, true]);
    assert.ok(ticks.every((tick) => tick.type === "tick" && tick.role === "plane"));
    assert.ok(JSON.stringify(ticks[0]).length < 1_000);
    const bundle = buildSelftestBundle();
    const realistic = bundle.telemetry.ring.plane[0] as PlaneTick;
    assert.ok(JSON.stringify(realistic).length < 4_000, `a plane tick is ${JSON.stringify(realistic).length} bytes`);
  } finally { sampler.stop(); }
});

test("a tick that fails to build changes nothing: the source throws to its caller (the runtime's timer swallows it), and its sequence is not advanced by a failure", () => {
  const sampler = new ProcessSampler();
  try {
    let fail = true;
    const source = new TickSource("boundary", sampler, () => { if (fail) throw new Error("collect failed"); return { ok: true }; });
    assert.throws(() => source.next(), /collect failed/);
    fail = false;
    assert.equal(source.next().tickSeq, 2, "a sequence number was spent: the gap is detectable");
  } finally { sampler.stop(); }
});

// ------------------------------------------------------------------------------------------------ telemetry never influences an enforcement verdict
test("reading the L2 state (the tick's snapshot) is state-neutral: decisions with a snapshot between every call equal decisions with none, on the same clock", () => {
  const run = (observe: boolean): LaneDecision[] => {
    let now = 0;
    const lanes = new JourneyLanes({
      filterBits: 2 ** 13, filterHashes: 7, epochMs: 1_000, credited: { capacity: 4, refillPerSecond: 2 }, unverified: { capacity: 2, refillPerSecond: 1 }, maxUses: 3, ledgerCapacity: 64,
      mono: () => now, key: Buffer.alloc(32, 7),
    });
    const decisions: LaneDecision[] = [];
    const render = (token: string): void => { lanes.enroll(token); };
    const post = (token: string): LaneDecision => lanes.decide({
      method: "POST", target: "/api/public-inquiries", headers: [], bodyStatus: "complete", body: new TextEncoder().encode(`name=a&submissionToken=${token}`),
    });
    const tokens = Array.from({ length: 6 }, (_, index) => `${String.fromCharCode(65 + index)}`.repeat(43));
    for (let step = 0; step < 60; step++) {
      now += 137;
      if (observe) lanes.snapshot();
      if (step % 7 === 0) render(tokens[step % tokens.length]);
      if (observe) lanes.snapshot();
      const decision = post(step % 3 === 0 ? tokens[step % tokens.length] : `${"z".repeat(42)}${step % 10}`);
      lanes.record(decision);
      decisions.push(decision);
      if (observe) { lanes.snapshot(); lanes.filter.stats(); }
      if (step === 30) now += 3_500;
    }
    return decisions;
  };
  assert.deepEqual(run(true), run(false));
});

test("the tick and monitor modules are imported by nothing that decides: no layer, composer, lane, gate or guard reads telemetry", async () => {
  const { readFileSync } = await import("node:fs");
  const path = await import("node:path");
  const root = path.join(__dirname, "..");
  for (const file of ["defense/core/composer.ts", "defense/core/lanes.ts", "defense/core/credit-filter.ts", "defense/layers/a7-shape-gate.ts", "defense/layers/a7-journey-lanes.ts", "defense/plane/semantic-gate.ts", "defense/plane/l2-stage.ts", "defense/origin/app-guard.ts", "defense/core/hop-admission.ts", "defense/core/replay-guard.ts"]) {
    assert.doesNotMatch(readFileSync(path.join(root, file), "utf8"), /telemetry|TickSource|ProcessSampler|\bTick\b/, file);
  }
  const front = readFileSync(path.join(root, "defense", "plane", "front.ts"), "utf8");
  assert.doesNotMatch(front, /telemetry|TickSource|ProcessSampler/, "the front only keeps counters; it neither builds nor sends ticks");
});

// ------------------------------------------------------------------------------------------------ the tick monitor
// Built once: the bundle runs git and the whole accounting, far too heavy to repeat per tick.
const BASE_PLANE_TICK = buildSelftestBundle().telemetry.ring.plane[0] as PlaneTick;
const plane = (seq: number, overrides: { eld?: number; rss?: number; dropped?: number; final?: boolean } = {}): PlaneTick => {
  const base = BASE_PLANE_TICK;
  return { ...base, tickSeq: seq, final: overrides.final ?? false, sample: { ...base.sample, eldP99Ms: overrides.eld ?? 1, rssMb: overrides.rss ?? 90 }, data: { ...base.data, channel: { ...base.data.channel, dropped: overrides.dropped ?? 0 } } };
};
const child = (role: "boundary" | "app", seq: number, final = false): Tick<unknown> => ({ type: "tick", role, tickSeq: seq, tMonoMs: seq * 1000, final, sample: { eldP50Ms: 0, eldP99Ms: 1, eldMaxMs: 2, rssMb: 60, cpuUserMs: 1, cpuSystemMs: 1 }, data: {} });
const clock = () => { let now = 0; return { now: () => now, advance: (ms: number) => { now += ms; } }; };
const snapshot = (overrides: { cpu?: number; mem?: number; roles?: ProcSnapshot["perRole"] } = {}): ProcSnapshot => ({
  perRole: overrides.roles ?? {},
  host: { cpuBusyPct: overrides.cpu ?? 5, memAvailablePct: overrides.mem ?? 60, memAvailableMb: 4000, rxBytesDelta: 0, txBytesDelta: 0, tcpInUse: 1, tcpTimeWait: 0, tcpOrphan: 0, kernelAdvisory: null },
});

test("a missing sequence number while the window is open is a tick gap (a measurement failure); outside the window it is counted, not stopped on", () => {
  const t = clock();
  const monitor = new TickMonitor(BA0_FIELD_V1, t.now);
  assert.deepEqual(monitor.observe(plane(1)), []);
  assert.deepEqual(monitor.observe(plane(2)), []);
  assert.deepEqual(monitor.observe(plane(4)), [], "outside the window");
  assert.equal(monitor.tickGaps, 1);
  monitor.setWindowActive(true);
  const reasons = monitor.observe(plane(7));
  assert.deepEqual(reasons.map((reason) => reason.code), ["tick_gap"]);
  assert.equal(monitor.tickGaps, 2);
  assert.deepEqual(monitor.gapDetails(), ["plane 2>4", "plane 4>7"]);
});

test("silence longer than the tolerance while the window is open is a gap even when no number was skipped, and it is reported once", () => {
  const t = clock();
  const monitor = new TickMonitor(BA0_FIELD_V1, t.now);
  monitor.setWindowActive(true);
  monitor.observe(plane(1));
  monitor.observe(child("boundary", 1));
  monitor.observe(child("app", 1));
  t.advance(2_000);
  assert.deepEqual(monitor.checkSilence(), []);
  t.advance(600);
  assert.deepEqual(monitor.checkSilence().map((reason) => reason.code), ["tick_gap", "tick_gap", "tick_gap"]);
  assert.deepEqual(monitor.checkSilence(), [], "re-armed: one long silence is one report per process");
  monitor.setWindowActive(false);
  t.advance(60_000);
  assert.deepEqual(monitor.checkSilence(), [], "no window, no silence rule");
});

test("every process must deliver a FINAL tick: a missing one is telemetry_incomplete at finalization", () => {
  const monitor = new TickMonitor(BA0_FIELD_V1, clock().now);
  monitor.observe(plane(1, { final: true }));
  monitor.observe(child("boundary", 1, true));
  assert.deepEqual(monitor.finalReasons().map((reason) => [reason.code, reason.detail]), [["telemetry_incomplete", "no final tick from app"]]);
  monitor.observe(child("app", 1, true));
  assert.deepEqual(monitor.finalReasons(), []);
  assert.deepEqual(monitor.finalTicks(), { plane: true, boundary: true, app: true });
});

test("the ring of recent ticks is bounded per process", () => {
  const monitor = new TickMonitor(BA0_FIELD_V1, clock().now);
  for (let seq = 1; seq <= 500; seq++) { monitor.observe(plane(seq)); monitor.observe(child("app", seq)); }
  assert.equal(monitor.ring().plane.length, BA0_FIELD_V1.telemetry.ringTicks);
  assert.equal(monitor.ring().app.length, BA0_FIELD_V1.telemetry.ringTicks);
  assert.equal(monitor.ring().plane.at(-1)?.tickSeq, 500);
  assert.equal(monitor.ring().boundary.length, 0);
});

test("resource ceilings: a process over its memory ceiling, the plane's event loop slow for the pinned number of consecutive ticks, and a dropped event all raise reasons", () => {
  const monitor = new TickMonitor(BA0_FIELD_V1, clock().now);
  assert.deepEqual(monitor.observe(plane(1, { rss: 600 })).map((reason) => reason.code), ["resource_ceiling"]);
  const slow = new TickMonitor(BA0_FIELD_V1, clock().now);
  assert.deepEqual(slow.observe(plane(1, { eld: 300 })), []);
  assert.deepEqual(slow.observe(plane(2, { eld: 300 })), []);
  assert.deepEqual(slow.observe(plane(3, { eld: 300 })).map((reason) => reason.code), ["resource_ceiling"], "the third consecutive slow tick");
  const recovering = new TickMonitor(BA0_FIELD_V1, clock().now);
  recovering.observe(plane(1, { eld: 300 }));
  recovering.observe(plane(2, { eld: 300 }));
  recovering.observe(plane(3, { eld: 5 }));
  assert.deepEqual(recovering.observe(plane(4, { eld: 300 })), [], "the run of slow ticks was broken");
  assert.deepEqual(new TickMonitor(BA0_FIELD_V1, clock().now).observe(plane(1, { dropped: 3 })).map((reason) => reason.code), ["evidence_gap"]);
});

test("the harness sample: host CPU for the pinned consecutive ticks, low available memory, a process over memory, and file descriptors near their limit", () => {
  const monitor = new TickMonitor(BA0_FIELD_V1, clock().now);
  assert.deepEqual(monitor.observeHarness({ eldP99Ms: 1, eldMaxMs: 2, proc: snapshot({ cpu: 90 }) }), []);
  assert.deepEqual(monitor.observeHarness({ eldP99Ms: 1, eldMaxMs: 2, proc: snapshot({ cpu: 90 }) }), []);
  assert.deepEqual(monitor.observeHarness({ eldP99Ms: 1, eldMaxMs: 2, proc: snapshot({ cpu: 90 }) }).map((reason) => reason.code), ["resource_ceiling"]);
  assert.deepEqual(new TickMonitor(BA0_FIELD_V1, clock().now).observeHarness({ eldP99Ms: 1, eldMaxMs: 2, proc: snapshot({ mem: 10 }) }).map((reason) => reason.code), ["resource_ceiling"]);
  const roles = { plane: { alive: true, cpuMsDelta: 0, rssMb: 600, threads: 8, fds: 10, fdLimit: 1024 }, app: { alive: true, cpuMsDelta: 0, rssMb: 50, threads: 8, fds: 900, fdLimit: 1024 }, boundary: { alive: false, cpuMsDelta: 0, rssMb: 0, threads: 0, fds: 0, fdLimit: null } };
  const reasons = new TickMonitor(BA0_FIELD_V1, clock().now).observeHarness({ eldP99Ms: 1, eldMaxMs: 2, proc: snapshot({ roles }) });
  assert.equal(reasons.length, 2);
  assert.ok(reasons.every((reason) => reason.code === "resource_ceiling"));
});

test("the harness's own event-loop delay is counted so canary starvation can be told from a slow server", () => {
  const monitor = new TickMonitor(BA0_FIELD_V1, clock().now);
  monitor.observeHarness({ eldP99Ms: 20, eldMaxMs: 25, proc: snapshot() });
  monitor.observeHarness({ eldP99Ms: 400, eldMaxMs: 900, proc: snapshot() });
  monitor.observeHarness({ eldP99Ms: 30, eldMaxMs: 40, proc: snapshot() });
  assert.deepEqual(monitor.harnessEld(), { highTicks: 1, max: 900, ticks: 3 });
});

// ------------------------------------------------------------------------------------------------ the /proc sampler on kernel-format text
function hostProc(options: { busy: number; total: number; rx: number; listenOverflows: number } = { busy: 100, total: 1_000, rx: 5_000, listenOverflows: 0 }): FakeProc {
  const proc = new FakeProc();
  const idle = options.total - options.busy;
  proc.files.set("/proc/stat", `cpu  ${options.busy} 0 0 ${idle} 0 0 0 0 0 0\ncpu0 1 1 1 1 0 0 0 0 0 0\n`);
  proc.files.set("/proc/meminfo", "MemTotal:       8000000 kB\nMemFree:        1000000 kB\nMemAvailable:   4000000 kB\n");
  proc.files.set("/proc/net/dev", `Inter-|   Receive\n face |bytes    packets\n    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n  eth0: ${options.rx} 10 0 0 0 0 0 0 ${options.rx * 2} 10 0 0 0 0 0 0\n`);
  proc.files.set("/proc/net/sockstat", "sockets: used 100\nTCP: inuse 7 orphan 1 tw 3 alloc 9 mem 2\nUDP: inuse 0 mem 0\n");
  proc.files.set("/proc/net/netstat", `TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPTimeouts\nTcpExt: 0 ${options.listenOverflows} ${options.listenOverflows * 2} 4\nIpExt: InNoRoutes\nIpExt: 0\n`);
  proc.files.set("/proc/net/snmp", "Tcp: RtoAlgorithm RetransSegs EstabResets AttemptFails CurrEstab\nTcp: 1 5 2 1 4\n");
  proc.addProcess(4242, {
    stat: "4242 (node (worker) x) S 1 4242 4242 0 -1 4194560 1000 0 0 0 150 50 0 0 20 0 9 0 12345 123456789 25600 18446744073709551615 0 0 0 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0\n",
    limits: "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 1048576              files\n",
  });
  proc.addSocket({ family: 4, ip: "127.0.0.1", port: 1, inode: 1 }, [4242]);
  return proc;
}

test("the sampler reads the kernel's own text: per-process CPU deltas (a comm with spaces and parentheses), RSS, threads, fds and the fd limit; host CPU, memory, network and TCP counts", () => {
  const proc = hostProc();
  const sampler = new ProcSampler(proc);
  const first = sampler.sample({ plane: 4242 });
  assert.deepEqual(first.perRole.plane, { alive: true, cpuMsDelta: 0, rssMb: 100, threads: 9, fds: 1, fdLimit: 1024 }, "the first sample has no delta");
  assert.equal(first.host?.memAvailablePct, 50);
  assert.equal(first.host?.memAvailableMb, 3906);
  assert.equal(first.host?.tcpInUse, 7);
  assert.equal(first.host?.tcpTimeWait, 3);
  assert.equal(first.host?.tcpOrphan, 1);
  assert.equal(first.host?.rxBytesDelta, 0);
  proc.files.set("/proc/stat", "cpu  600 0 0 1400 0 0 0 0 0 0\n");
  proc.files.set("/proc/net/dev", "  eth0: 9000 10 0 0 0 0 0 0 18000 10 0 0 0 0 0 0\n    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n");
  proc.files.set("/proc/net/netstat", "TcpExt: SyncookiesSent ListenOverflows ListenDrops TCPTimeouts\nTcpExt: 0 3 6 9\n");
  proc.files.set("/proc/4242/stat", "4242 (node (worker) x) S 1 4242 4242 0 -1 4194560 1000 0 0 0 250 80 0 0 20 0 9 0 12345 123456789 25600 18446744073709551615 0 0 0 0 0 0 0 4096 0 0 0 0 17 0 0 0 0 0 0\n");
  const second = sampler.sample({ plane: 4242 });
  assert.equal(second.perRole.plane.cpuMsDelta, 1_300, "(250+80) - (150+50) clock ticks at 100 per second");
  assert.equal(second.host?.cpuBusyPct, 100 * 500 / 1000 > 0 ? 100 * 500 / (1000) : 0, "busy ticks 500 of total 1000 elapsed");
  assert.equal(second.host?.rxBytesDelta, 4_000);
  assert.equal(second.host?.txBytesDelta, 8_000);
  assert.deepEqual(second.host?.kernelAdvisory, { listenOverflows: 3, listenDrops: 6, retransSegs: 0, estabResets: 0, attemptFails: 0 }, "kernel counters are deltas and labelled advisory");
});

test("a process that is gone is reported not alive; a host that cannot be read yields no host sample rather than zeros", () => {
  const sampler = new ProcSampler(new FakeProc());
  const snapshot = sampler.sample({ plane: 9999 });
  assert.equal(snapshot.perRole.plane.alive, false);
  assert.equal(snapshot.host, null);
});

// ------------------------------------------------------------------------------------------------ evidence safety of every tick shape
test("every process's tick payload, built from the REAL components' own counters, passes the evidence scanner", async () => {
  const root = new HopTrustRoot();
  const hop = BA0_ORIGIN_LOCAL_V1.hop;
  const appInit = root.appInit({ replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs });
  const built = createAppGuard({ keyB: importPublicKey(appInit.publicKeyB), kidB: appInit.kidB, keyP: importPublicKey(appInit.publicKeyP), kidP: appInit.kidP, appId: appInit.appId, boundaryId: appInit.boundaryId, replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs });
  const app = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined, guard: built.guard, onApp: () => undefined });
  const appPort = await app.listen();
  const init = root.boundaryInit(appPort, { replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs, forwardTimeoutMs: hop.forwardTimeoutMs, baLifetimeMs: hop.baLifetimeMs });
  const boundary = createBoundary({ appPort, keyP: importPublicKey(init.publicKeyP), kidP: init.kidP, boundaryId: init.boundaryId, keyB: importPrivateKey(init.privateKeyB), kidB: init.kidB, appId: init.appId, limits: init.limits, emit: () => 1 });
  await boundary.listen();
  const sampler = new ProcessSampler();
  try {
    const channel = { emitted: 0, dropped: 0, sent: 0, received: 0, queued: 0, unacknowledged: 0, queueHighWater: 0, lastSeq: 0 };
    const boundaryTick = new TickSource("boundary", sampler, () => ({ inFlight: 0, stats: boundary.stats(), channel })).next();
    const appTick = new TickSource("app", sampler, () => ({ inFlight: 0, counters: app.appStats(), served: app.stats(), guard: built.stats(), channel })).next();
    assert.doesNotThrow(() => assertEvidenceSafe(boundaryTick, "$boundaryTick"));
    assert.doesNotThrow(() => assertEvidenceSafe(appTick, "$appTick"));
    assert.doesNotThrow(() => assertEvidenceSafe(buildSelftestBundle().telemetry.ring.plane, "$planeTicks"));
  } finally { sampler.stop(); await boundary.close(); await app.close(); randomBytes(1); }
});
