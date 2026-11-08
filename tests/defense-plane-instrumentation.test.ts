import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { test } from "node:test";
import { OutcomeCounters, countingEmit, type OutcomeSnapshot } from "../lab/defense/outcome-counters";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import type { L2Params } from "../defense/plane/l2-protocol";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { BA0_ORIGIN_LOCAL_V1 } from "../lab/defense/origin-thresholds";
import { checkOutcomeIdentities, compareToLedger } from "../lab/defense/plane-outcome-check";

// The REAL plane entry (defense/plane/main-l2.ts -> runtime.ts) is started as a child process twice: without telemetry (no tally, no wrapper, no tick)
// and with telemetry (tally + ticks). The same workload must produce the same statuses and the same event stream, and the tally must equal what the
// plane actually emitted over IPC.

const L2: L2Params = {
  filterBits: 2 ** 13, filterHashes: 7, epochMs: 60_000, credited: { capacity: 10, refillPerSecond: 2 }, unverified: { capacity: 3, refillPerSecond: 1 },
  maxUses: 3, ledgerCapacity: 512, stage: { timeoutMs: 50, maxConcurrent: 64 },
};
const ENTRY = path.join(process.cwd(), "defense", "plane", "main-l2.ts");
const FORM = "application/x-www-form-urlencoded";
type Ev = { kind: string; reason?: string; status?: number; class?: string; lane?: string | null; outcome?: string; seq: number; egressError?: string };
type Tick = { type: "tick"; final: boolean; data: { outcomes?: OutcomeSnapshot | null } };

function get(port: number, method: string, target: string, headers: Record<string, string> = {}, body?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path: target, agent: false, headers: { ...headers, ...(body !== undefined ? { "content-length": String(Buffer.byteLength(body)) } : {}) } }, (response) => {
      response.resume(); response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject); request.end(body);
  });
}

async function run(telemetry: boolean): Promise<{ statuses: number[]; events: Ev[]; ticks: Tick[]; childStayedAlive: boolean }> {
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  const root = new HopTrustRoot();
  const child: ChildProcess = fork(ENTRY, [], { execArgv: process.execArgv, cwd: process.cwd(), stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json" });
  const events: Ev[] = []; const ticks: Tick[] = [];
  let exited = false; child.on("exit", () => { exited = true; });
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("plane not ready")), 20_000);
    child.on("message", (raw: { type: string; port?: number; events?: Ev[]; received?: number } & Record<string, unknown>) => {
      if (raw.type === "ready") { clearTimeout(timer); resolve(raw.port!); }
      else if (raw.type === "events") { events.push(...(raw.events as Ev[])); child.send({ type: "ack", received: (raw as { upTo?: number }).upTo ?? raw.received ?? events.length }); }
      else if (raw.type === "tick") ticks.push(raw as unknown as Tick);
    });
    child.send({
      type: "init", upstreamPort: originPort, composer: { timeoutMs: BA0_ORIGIN_LOCAL_V1.composer.timeoutMs, maxConcurrent: BA0_ORIGIN_LOCAL_V1.composer.maxConcurrent, failurePolicy: "fail_closed" },
      channel: { queueCap: 4_096, windowCap: 2_048 }, hop: root.planeInit(BA0_ORIGIN_LOCAL_V1.hop.pbLifetimeMs), l2: L2, ...(telemetry ? { telemetry: { tickMs: 100 } } : {}),
    });
  });
  const statuses: number[] = [];
  const workload: Array<[string, string, Record<string, string>, string?]> = [
    ["GET", "/", {}], ["GET", "/gizlilik", {}], ["GET", "/test-talep-et", {}], ["GET", "/nope", {}], ["DELETE", "/", {}], ["GET", "/?q=1", {}],
    ["POST", "/api/public-inquiries", { "content-type": "text/plain" }, "x"], ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=a&name=b"],
    ["POST", "/api/public-inquiries", { "content-type": FORM }, "bogus=1"], ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=Ada"],
    ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=Ada"], ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=Ada"],
    ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=Ada"], ["POST", "/api/public-inquiries", { "content-type": FORM }, "name=Ada"], ["GET", "/", {}],
  ];
  for (const [method, target, headers, body] of workload) statuses.push(await get(port, method, target, headers, body));
  await new Promise((resolve) => setTimeout(resolve, 450)); // let the last events and at least two ticks arrive
  const alive = !exited;
  child.send({ type: "stop" });
  await new Promise((resolve) => { child.once("exit", resolve); setTimeout(() => { child.kill("SIGKILL"); resolve(null); }, 5_000); });
  await origin.close();
  return { statuses, events, ticks, childStayedAlive: alive };
}
const shape = (events: Ev[]) => events.map((e) => [e.kind, e.reason, e.status, e.class, e.lane, e.outcome, e.egressError]);
const kinds = (events: Ev[]) => { const out: Record<string, number> = {}; for (const e of events) out[e.kind] = (out[e.kind] ?? 0) + 1; return out; };

test("equivalence: the real plane gives the same statuses and the same event stream with instrumentation off and on", async () => {
  const off = await run(false);
  const on = await run(true);
  assert.ok(off.childStayedAlive && on.childStayedAlive, "neither plane crashed");
  assert.deepEqual(on.statuses, off.statuses, "identical HTTP statuses");
  assert.deepEqual(shape(on.events), shape(off.events), "identical event order, kinds, reasons, statuses, lanes and outcomes");
  assert.equal(off.ticks.length, 0, "disabled: no tick at all");
  assert.ok(on.ticks.length >= 2, "enabled: ticks flow");
  assert.ok(off.statuses.includes(503) && off.statuses.includes(200), "the workload exercised sheds and pass-throughs");
});

test("enabled: the tally equals the events the plane emitted, satisfies every accounting identity and shows no unexplained difference", async () => {
  const on = await run(true);
  const last = [...on.ticks].reverse().find((t) => t.data.outcomes);
  assert.ok(last && last.data.outcomes, "a tick carries the tally");
  const snapshot = last.data.outcomes!;
  assert.deepEqual(checkOutcomeIdentities(snapshot, { l2: true }), []);
  assert.deepEqual(compareToLedger(snapshot, kinds(on.events)), [], "tally == events delivered over IPC");
  assert.equal(snapshot.unknown, 0);
  assert.equal(snapshot.faults, 0);
  assert.ok(JSON.stringify(snapshot).length < 8_000, "bounded tick payload");
});

test("failure isolation inside the plane wiring: a tally that throws on every event changes no emitted event or status", async () => {
  // In-process proof with the very wrapper the runtime installs (countingEmit): same emitter, healthy vs throwing tally.
  const seen = (tally: OutcomeCounters) => { const out: number[] = []; const emit = countingEmit(tally, (event: { kind: string }) => { out.push(out.length + 1); return out.length; }); const r = [emit({ kind: "L1_PASSED" }), emit({ kind: "x" }), emit({ kind: "L1_REJECTED" })]; return [out, r]; };
  assert.deepEqual(seen(new OutcomeCounters({ injectedFault: () => { throw new Error("boom"); } })), seen(new OutcomeCounters()));
});

import { readFileSync } from "node:fs";
test("the in-tree tally module and the lab copy used by the checks are the same code (import paths aside)", () => {
  const inTree = readFileSync(new URL("../defense/core/outcome-counters.ts", import.meta.url), "utf8");
  const lab = readFileSync(new URL("../lab/defense/outcome-counters.ts", import.meta.url), "utf8").replace('"../../defense/core/ledger"', '"./ledger"').replace('"../../defense/core/types"', '"./types"');
  assert.equal(inTree.replace(/\r\n/gu, "\n"), lab.replace(/\r\n/gu, "\n"));
});
