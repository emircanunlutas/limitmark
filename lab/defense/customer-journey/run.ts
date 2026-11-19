import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { AppEvent, BoundaryEvent, EventFrame, PlaneEvent } from "../../../defense/core/ledger";
import { ProcessSampler, type Tick } from "../../../defense/core/telemetry";
import { REPOSITORY_ROOT } from "../../evidence/manifest";
import { trackedHttp } from "../client";
import { Collector } from "../collector";
import { FieldAppProcess, FieldBoundaryProcess } from "../field-processes";
import { BA0_FIELD_V1 as config } from "../field-thresholds";
import { HopTrustRoot } from "../hop-keys";
import { PLANE_L2_ENTRY, PlaneProcess } from "../plane-process";
import { addressClass, fsProcReader, listeningOnly, parseTcpTable } from "../proc-net";
import { ProcSampler } from "../proc-sampler";
import { clientRecords, plan, type CanaryResult } from "./canary";
import { evaluate, type Evidence } from "./evaluate";
import { fixturePlan, runFixture, type FixtureEvidence } from "./adverse";

// The independent canary owns SENT and CLIENT_COMPLETED. Retain each server stream in its
// original order and acknowledge receipt over IPC. Join by request ID only after all FINs.
function stream<E extends PlaneEvent | BoundaryEvent | AppEvent>(): EventFrame<E> {
  return { type: "events", events: [], dropped: 0 };
}
function append<E extends PlaneEvent | BoundaryEvent | AppEvent>(target: EventFrame<E>, frame: EventFrame<E>) {
  target.dropped = Math.max(target.dropped, frame.dropped);
  target.events.push(...frame.events);
  return target.events.length;
}
class Capture extends Collector {
  readonly plane = stream<PlaneEvent>();
  readonly boundary = stream<BoundaryEvent>();
  readonly app = stream<AppEvent>();
  override ingestFrame(frame: EventFrame) { return append(this.plane, frame); }
  override ingestBoundaryFrame(frame: EventFrame<BoundaryEvent>) { return append(this.boundary, frame); }
  override ingestAppFrame(frame: EventFrame<AppEvent>) { return append(this.app, frame); }
}

async function run() {
  const args = process.argv.slice(2);
  const adverseRun = args.length === 1 && args[0] === "--adverse";
  assert.ok(!args.length || adverseRun, "expected no arguments or --adverse");
  assert.equal(process.platform, "linux", "run in the local Linux lab container");
  assert.deepEqual(readdirSync("/sys/class/net"), ["lo"], "run with --network none");
  const gitSha = process.env.BA0_GIT_SHA;
  assert.ok(gitSha && /^[0-9a-f]{40}$/.test(gitSha), "supply the checkout commit in BA0_GIT_SHA");
  const runId = randomUUID();
  const directory = path.join(REPOSITORY_ROOT, "artifacts", "lab", adverseRun ? "adverse-continuity" : "customer-journey", runId);
  mkdirSync(directory, { recursive: true });
  const save = (file: string, data: unknown) => writeFileSync(path.join(directory, file), JSON.stringify(data) + "\n", { flag: "wx" });
  if (adverseRun) {
    const sourceSha256 = Object.fromEntries(["adverse.ts", "canary.ts", "evaluate.ts", "run.ts"].map(name =>
      [name, createHash("sha256").update(readFileSync(path.join(__dirname, name))).digest("hex")]));
    save("parameters.json", { runId, gitSha, sourceSha256, node: process.version, fixture: fixturePlan, customerJourneys: plan,
      requiredCreditedOverlapGroups: 4, requiredCustomerSteps: 150, requiredCustomerMutations: 30, requiredFixtureMutations: 0,
      customerGapMs: config.canary.gapMs, customerWindowLatency: config.canary.windowLatency, quietMs: config.recovery.quietMs,
      resourceCeilings: config.ceilings, telemetry: config.telemetry });
  }
  console.log(`run ${runId} at ${gitSha}`);
  const capture = new Capture(null);
  const keys = new HopTrustRoot();
  const { channel, hop, composer, telemetry, l2 } = config;
  const limits = { replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs };
  const ticks: Evidence["ticks"] = [];
  const onTick = (tick: Tick<unknown>) => ticks.push({ at: performance.now(), tick });
  const cleanup: (() => void | Promise<void>)[] = [];
  try {
    const app = await FieldAppProcess.start(capture, { ...keys.appInit(limits, channel), telemetry }, onTick);
    cleanup.push(() => app.stop());
    const boundary = await FieldBoundaryProcess.start(capture, {
      ...keys.boundaryInit(app.port, { ...limits, forwardTimeoutMs: hop.forwardTimeoutMs, baLifetimeMs: hop.baLifetimeMs }, channel), telemetry,
    }, onTick);
    cleanup.push(() => boundary.stop());
    const plane = await PlaneProcess.start(capture, {
      upstreamPort: boundary.port, ...config.plane, composer: { ...composer, failurePolicy: "fail_closed" }, channel,
      hop: keys.planeInit(hop.pbLifetimeMs), l2, telemetry,
    }, undefined, PLANE_L2_ENTRY);
    cleanup.push(() => plane.stop());
    plane.onExtra(message => { if (message.type === "tick") onTick(message as Tick<unknown>); });

    const canary = fork(path.join(__dirname, "canary.ts"), [], { execArgv: process.execArgv, stdio: ["ignore", "inherit", "inherit", "ipc"] });
    const exited = new Promise<void>(resolve => canary.once("exit", () => resolve()));
    cleanup.push(async () => { if (canary.connected) canary.disconnect(); if (canary.exitCode === null) canary.kill(); await exited; });
    const [ready] = await once(canary, "message", { signal: AbortSignal.timeout(20_000) });
    assert.equal(ready, "ready");
    assert.ok(plane.pid && boundary.pid && app.pid && canary.pid);
    const pids = { runner: process.pid, plane: plane.pid, boundary: boundary.pid, app: app.pid, canary: canary.pid };
    const ports = [plane.port, boundary.port, app.port];
    const host: Evidence["host"] = [];
    const reader = fsProcReader();
    const sampler = new ProcSampler(reader);
    const own = new ProcessSampler();
    cleanup.push(() => own.stop());
    function sampleHost() {
      const listeners = listeningOnly(([4, 6] as const).flatMap(family => parseTcpTable(
        readFileSync(family === 4 ? "/proc/net/tcp" : "/proc/net/tcp6", "utf8"), family)));
      const sample = { ...own.sample(), proc: sampler.sample(pids) };
      host.push({ at: performance.now(), sample, loopbackPorts: listeners.filter(v => addressClass(v) === "loopback").map(v => v.port),
        otherListeners: listeners.filter(v => addressClass(v) !== "loopback").length });
    }
    const startMs = performance.now();
    sampleHost();
    assert.ok(host[0].otherListeners === 0 && host[0].loopbackPorts.length === 3 && ports.every(p => host[0].loopbackPorts.includes(p)),
      "local topology must have exactly the three loopback listeners before dispatch");
    const timer = setInterval(sampleHost, telemetry.tickMs);
    cleanup.push(() => clearInterval(timer));
    const fixtureStop = new AbortController();
    cleanup.push(() => fixtureStop.abort());
    let fixtureWork: Promise<FixtureEvidence> | undefined;
    const result = await new Promise<CanaryResult>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("canary exceeded its bounded run time")), 7 * 60_000);
      canary.on("message", value => {
        if (value === "window-open") {
          if (!adverseRun || fixtureWork) { reject(new Error("unexpected or repeated window notice")); return; }
          fixtureWork = runFixture(plane.port, fixtureStop.signal);
          fixtureWork.catch(reject);
        } else {
          clearTimeout(timeout);
          resolve(value as CanaryResult);
        }
      });
      canary.once("error", error => { clearTimeout(timeout); reject(error); });
      canary.once("exit", (code, signal) => { clearTimeout(timeout); reject(new Error(`canary exited ${code ?? signal}`)); });
      canary.send({ port: plane.port, notifyWindow: adverseRun });
    });
    const fixture = await fixtureWork;
    const control = new Collector(null);
    await trackedHttp(control, app.port, { lane: "direct_app_rejected", cls: "canary", scenario: "unsigned", phase: "control",
      journey: null, step: null, method: "GET" }, { method: "GET", path: "/" }, config.canary.timeoutMs);
    const [planeFin, boundaryFin, appFin] = await Promise.all([plane.finish(config.stop.drainMs), boundary.finish(config.stop.drainMs), app.finish(config.stop.drainMs)]);
    assert.ok(planeFin && boundaryFin && appFin, "missing process FIN");
    clearInterval(timer);
    sampleHost();
    const endMs = performance.now();
    const direct = clientRecords(control);
    // Substitute stable local record IDs everywhere, preserving unknown and duplicate joins.
    const ids = new Map<string, string>();
    function id(value: string) {
      if (!ids.has(value)) ids.set(value, `r${ids.size + 1}`);
      return ids.get(value)!;
    }
    for (const r of [...result.requests, ...(fixture?.requests ?? []), ...direct]) r.nonce = id(r.nonce);
    for (const frame of [capture.plane, capture.boundary, capture.app]) {
      for (const event of frame.events) if (event.nonce !== null) event.nonce = id(event.nonce);
    }
    const evidence: Evidence = { runId, gitSha, platform: process.platform, pids, ports, startMs, endMs, canary: result, direct,
      plane: capture.plane, boundary: capture.boundary, app: capture.app, planeFin, boundaryFin, appFin, ticks, host, fixture };
    save("observations.json", evidence);
    const bytes = readFileSync(path.join(directory, "observations.json"));
    const observed = JSON.parse(bytes.toString()) as Evidence;
    const measured = evaluate(observed, adverseRun);
    const copy = structuredClone(observed);
    const first = copy.canary.requests[0]?.nonce;
    const missing = copy.app.events.findIndex(v => v.nonce === first && v.kind === "APP_EXECUTED");
    const removed = missing >= 0 ? copy.app.events.splice(missing, 1)[0] : null;
    const negative = evaluate(copy, adverseRun);
    const negativePassed = !!removed && negative.verdict === "FAIL" && negative.failures.includes("baseline/1/homepage APP_EXECUTED");
    const additionalControls = [];
    if (adverseRun) {
      const missingClient = structuredClone(observed);
      missingClient.canary.journeys[0].steps.pop();
      const clientCheck = evaluate(missingClient, true);
      additionalControls.push({ name: "missing customer confirmation", verdict: clientCheck.verdict, failures: clientCheck.failures,
        passed: clientCheck.verdict === "FAIL" && clientCheck.failures.includes("baseline/1/thank_you missing or mismatched step") });
      const missingDecision = structuredClone(observed);
      const shed = missingDecision.fixture?.requests[4]?.nonce;
      missingDecision.plane.events = missingDecision.plane.events.filter(v => v.nonce !== shed || v.kind !== "L2_DECIDED");
      const accountingCheck = evaluate(missingDecision, true);
      additionalControls.push({ name: "missing fixture refusal decision", verdict: accountingCheck.verdict, failures: accountingCheck.failures,
        passed: accountingCheck.verdict === "FAIL" && accountingCheck.failures.includes("fixture/1/5 L2 decision") });
    }
    const verdict = measured.verdict === "PASS" && negativePassed && additionalControls.every(c => c.passed) ? "PASS" : "FAIL";
    const report = { ...measured, verdict, runId, gitSha, platform: process.platform, pids, observationsSha256: createHash("sha256").update(bytes).digest("hex"),
      negativeControl: { passed: negativePassed, removed, verdict: negative.verdict, failures: negative.failures },
      ...(adverseRun ? { additionalControls } : {}) };
    save("result.json", report);
    console.log(JSON.stringify(report));
    process.exitCode = verdict === "PASS" ? 0 : 1;
  } catch (error) {
    save("failure.json", { runId, gitSha, verdict: "FAIL", reason: String(error) });
    throw error;
  } finally {
    for (const stop of cleanup.reverse()) await stop();
  }
}

void run().catch(error => { console.error(error); process.exitCode = 1; });
