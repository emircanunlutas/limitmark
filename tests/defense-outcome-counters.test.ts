import assert from "node:assert/strict";
import http from "node:http";
import { test } from "node:test";
import type { PlaneEvent } from "../defense/core/ledger";
import { OutcomeCounters, countingEmit } from "../defense/core/outcome-counters";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";
import { checkOutcomeIdentities, compareToLedger } from "../lab/defense/plane-outcome-check";

let counter = 0;
const nonce = () => `${String(++counter).padStart(22, "C")}`;

async function rig(outcomeCounters?: OutcomeCounters) {
  const events: PlaneEvent[] = [];
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  let seq = 0;
  const record = (event: Parameters<Parameters<typeof createFront>[0]["emit"]>[0]) => { const next = ++seq; events.push({ ...event, seq: next, t: 0 }); return next; };
  const front = createFront({ upstream: { host: "127.0.0.1", port: originPort }, emit: outcomeCounters === undefined ? record : countingEmit(outcomeCounters, record) });
  const port = await front.listen();
  return { front, port, events, snapshot: () => outcomeCounters?.snapshot() ?? null, close: async () => { await front.close(500); await origin.close(); } };
}
function send(port: number, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path, agent: false, headers: { ...headers, ...(body !== undefined ? { "content-length": String(Buffer.byteLength(body)) } : {}) } }, (response) => {
      response.resume(); response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end(body);
  });
}
const WORKLOAD: Array<[string, string, Record<string, string>, string?]> = [
  ["GET", "/", {}], ["GET", "/gizlilik", {}], ["GET", "/test-talep-et", {}], ["GET", "/nope", {}], ["DELETE", "/", {}], ["GET", "/?q=1", {}],
  ["POST", "/api/public-inquiries", { "content-type": "text/plain" }, "x"], ["POST", "/api/public-inquiries", { "content-type": "application/x-www-form-urlencoded" }, "name=a&name=b"],
  ["POST", "/api/public-inquiries", { "content-type": "application/x-www-form-urlencoded" }, "bogus=1"], ["GET", "/", {}],
];
async function drive(port: number): Promise<number[]> {
  const out: number[] = [];
  for (const [method, path, headers, body] of WORKLOAD) out.push(await send(port, method, path, { ...headers, "x-ba0-nonce": nonce() }, body));
  return out;
}
const countKinds = (events: PlaneEvent[]) => { const out: Record<string, number> = {}; for (const e of events) out[e.kind] = (out[e.kind] ?? 0) + 1; return out; };

test("disabled by default: no counter means no snapshot, no wrapper, and the identical event stream and statuses", async () => {
  const plain = await rig();
  const counted = await rig(new OutcomeCounters());
  try {
    assert.equal(plain.snapshot(), null);
    const a = await drive(plain.port);
    const b = await drive(counted.port);
    assert.deepEqual(a, b, "the same statuses with and without the tally");
    assert.deepEqual(plain.events.map((e) => [e.kind, e.reason, e.status]), counted.events.map((e) => [e.kind, e.reason, e.status]), "the same event stream");
  } finally { await plain.close(); await counted.close(); }
});

test("counter consistency: the tally equals the emitted events, satisfies every identity, and differs from the ledger by exactly what the ledger lacks", async () => {
  const r = await rig(new OutcomeCounters());
  try {
    await drive(r.port);
    const snapshot = r.snapshot()!;
    assert.deepEqual(checkOutcomeIdentities(snapshot, { l2: false }), []);
    const kinds = countKinds(r.events);
    assert.deepEqual(compareToLedger(snapshot, kinds), [], "no unexplained difference when the ledger saw every event");
    assert.ok(snapshot.events.L1_REJECTED >= 6 && snapshot.events.EGRESS_RESPONDED >= 3, "the workload exercised rejects and proxied requests");
    assert.equal(Object.values(snapshot.rejectReasons).reduce((x, y) => x + y, 0), snapshot.events.L1_REJECTED);
    const lossy = { ...kinds, L1_REJECTED: kinds.L1_REJECTED - 2 };
    assert.deepEqual(compareToLedger(snapshot, lossy), [{ kind: "L1_REJECTED", plane: kinds.L1_REJECTED, ledger: kinds.L1_REJECTED - 2 }]);
  } finally { await r.close(); }
});

test("failure isolation: a tally that throws on every event changes no response, no event and no status; faults are counted", async () => {
  const healthy = await rig(new OutcomeCounters());
  const faulty = await rig(new OutcomeCounters({ injectedFault: () => { throw new Error("boom"); } }));
  try {
    const a = await drive(healthy.port);
    const b = await drive(faulty.port);
    assert.deepEqual(a, b);
    assert.deepEqual(healthy.events.map((e) => [e.kind, e.reason, e.status]), faulty.events.map((e) => [e.kind, e.reason, e.status]));
    const snapshot = faulty.snapshot()!;
    assert.equal(snapshot.faults, faulty.events.length, "every event's tally fault is counted");
    assert.ok(checkOutcomeIdentities(snapshot, { l2: false }).some((f) => f.id.startsWith("I12")), "the fault is visible to the cross-check");
  } finally { await healthy.close(); await faulty.close(); }
});

test("bounded and content-free: hostile values never create keys; the snapshot holds no nonce, address, header or path", async () => {
  const tally = new OutcomeCounters();
  const keys = (s: ReturnType<OutcomeCounters["snapshot"]>) => JSON.stringify([s.events, s.rejectReasons, s.l2Decisions, s.egressFailures, s.clientResponseStatus].map((t) => Object.keys(t)));
  const before = keys(tally.snapshot());
  for (let i = 0; i < 20_000; i++) {
    tally.observe({ kind: `KIND_${i}`, reason: `r${i}` });
    tally.observe({ kind: "L1_REJECTED", reason: `a7.hostile_${i}` });
    tally.observe({ kind: "INGRESS_RESPONDED", status: 1000 + i });
    tally.observe({ kind: "L2_DECIDED", class: `c${i}`, lane: `l${i}`, outcome: "x" });
    tally.observe({ kind: "EGRESS_FAILED", egressError: `e${i}` });
  }
  const after = tally.snapshot();
  assert.equal(keys(after), before, "key spaces are closed");
  assert.equal(after.clientResponseStatus.other, 20_000, "out-of-list statuses land in one bucket");
  assert.equal(after.unknown, 20_000 * 4);
  const r = await rig(new OutcomeCounters());
  try {
    const id = nonce();
    await send(r.port, "GET", "/gizlilik?secret=abc", { "x-ba0-nonce": id, "x-forwarded-for": "203.0.113.9" });
    const text = JSON.stringify(r.snapshot());
    for (const forbidden of [id, "203.0.113.9", "secret", "gizlilik", "127.0.0.1"]) assert.equal(text.includes(forbidden), false, forbidden);
    assert.ok(text.length < 8_000, `snapshot stays small (${text.length} bytes)`);
  } finally { await r.close(); }
});

test("overhead is measured and small: per-event tally cost and end-to-end request cost with and without the tally", async () => {
  const tally = new OutcomeCounters();
  const N = 200_000;
  const t0 = performance.now();
  for (let i = 0; i < N; i++) tally.observe({ kind: "L1_REJECTED", reason: "a7.path_not_allowed" });
  const perEventNs = ((performance.now() - t0) / N) * 1e6;
  const plain = await rig();
  const counted = await rig(new OutcomeCounters());
  const time = async (port: number) => { const t = performance.now(); for (let i = 0; i < 200; i++) await send(port, "GET", "/gizlilik", { "x-ba0-nonce": nonce() }); return (performance.now() - t) / 200; };
  try {
    await time(plain.port); await time(counted.port);
    const a = await time(plain.port); const b = await time(counted.port);
    console.log(`outcome-counters overhead: ${perEventNs.toFixed(0)} ns/event; request mean ${a.toFixed(3)} ms plain vs ${b.toFixed(3)} ms counted (delta ${(b - a).toFixed(3)} ms)`);
    assert.ok(perEventNs < 20_000, `per-event cost ${perEventNs} ns`);
    assert.ok(b - a < 1, `end-to-end delta ${(b - a).toFixed(3)} ms`);
  } finally { await plain.close(); await counted.close(); }
});

import { ALL_REJECT_REASONS } from "../defense/core/types";
import { L2_ERROR_KINDS, L2_OUTCOMES, LANES, OPERATION_CLASSES, SHED_REASONS } from "../defense/core/lanes";
import { COUNTED_CLASSES, COUNTED_L2_ERROR_KINDS, COUNTED_L2_OUTCOMES, COUNTED_LANES, COUNTED_SHED_REASONS, REJECT_REASON_KEY } from "../defense/core/outcome-counters";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { readFileSync } from "node:fs";

test("the restated closed lists equal the authoritative ones, and reject-reason keys are positional and unique", () => {
  assert.deepEqual([...COUNTED_CLASSES], [...OPERATION_CLASSES]);
  assert.deepEqual([...COUNTED_LANES], [...LANES, "none"]);
  assert.deepEqual([...COUNTED_L2_OUTCOMES], [...L2_OUTCOMES]);
  assert.deepEqual([...COUNTED_SHED_REASONS], [...SHED_REASONS]);
  assert.deepEqual([...COUNTED_L2_ERROR_KINDS], [...L2_ERROR_KINDS]);
  assert.deepEqual(Object.keys(REJECT_REASON_KEY), [...ALL_REJECT_REASONS]);
  assert.equal(new Set(Object.values(REJECT_REASON_KEY)).size, ALL_REJECT_REASONS.length);
  assert.equal(REJECT_REASON_KEY[ALL_REJECT_REASONS[0]], "r00");
});

test("a real snapshot passes the evidence scanner unchanged (no forbidden key or value shape)", async () => {
  const r = await rig(new OutcomeCounters());
  try {
    await drive(r.port);
    assert.doesNotThrow(() => assertEvidenceSafe(r.snapshot(), "$snapshot"));
  } finally { await r.close(); }
});

test("the legacy plane entry module graph has no L2 import through the counter module", () => {
  const source = readFileSync(new URL("../defense/core/outcome-counters.ts", import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//gu, "");
  assert.doesNotMatch(source, /from "\.\/(lanes|credit-filter|enrollment|replay-guard)"/u);
});
