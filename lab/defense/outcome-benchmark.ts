/**
 * Reproducible overhead benchmark for the plane outcome tally. LOCAL ONLY (loopback, in-process front + synthetic origin). No external traffic.
 *
 *   npx tsx lab/defense/outcome-benchmark.ts            # prints one JSON document
 *
 * Method: a fixed workload (REQUESTS sequential requests: a repeating mix of a proxied GET, an L1 reject and an unknown route), run
 * ROUNDS times in strictly alternating order OFF, ON, OFF, ON ... after one warm-up of each, so drift affects both arms equally. It reports the
 * per-arm median and the median of the paired ON-OFF differences, plus the per-event cost of the tally measured in isolation.
 * Nothing here is a verdict input; a noisy machine is reported as noise (the spread is printed), never hidden.
 */
import http from "node:http";
import { createSyntheticOrigin } from "../../defense/origin/synthetic-origin";
import { createFront } from "../../defense/plane/front";
import { OutcomeCounters, countingEmit } from "./outcome-counters";

const REQUESTS = 600;
const ROUNDS = 7;
const MIX: Array<[string, string]> = [["GET", "/gizlilik"], ["GET", "/nope"], ["DELETE", "/"], ["GET", "/"]];

function send(port: number, method: string, target: string, nonce: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, method, path: target, agent: false, headers: { "x-ba0-nonce": nonce } }, (response) => { response.resume(); response.on("end", () => resolve()); });
    request.on("error", reject); request.end();
  });
}
const median = (values: number[]): number => { const s = [...values].sort((a, b) => a - b); return s[Math.floor(s.length / 2)]; };

async function arm(withTally: boolean): Promise<{ ms: number; close: () => Promise<void>; port: number }> {
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  let seq = 0;
  const base = (): number => ++seq;
  const emit = withTally ? countingEmit(new OutcomeCounters(), base) : base;
  const front = createFront({ upstream: { host: "127.0.0.1", port: originPort }, emit });
  const port = await front.listen();
  return { ms: 0, port, close: async () => { await front.close(500); await origin.close(); } };
}

async function timed(withTally: boolean): Promise<number> {
  const a = await arm(withTally);
  try {
    for (let i = 0; i < 40; i++) await send(a.port, MIX[i % MIX.length][0], MIX[i % MIX.length][1], `W${String(i).padStart(21, "0")}`); // warm-up
    const t0 = performance.now();
    for (let i = 0; i < REQUESTS; i++) await send(a.port, MIX[i % MIX.length][0], MIX[i % MIX.length][1], `B${String(i).padStart(21, "0")}`);
    return (performance.now() - t0) / REQUESTS;
  } finally { await a.close(); }
}

async function main(): Promise<void> {
  const off: number[] = []; const on: number[] = [];
  await timed(false); await timed(true);
  for (let round = 0; round < ROUNDS; round++) { off.push(await timed(false)); on.push(await timed(true)); }
  const diffs = off.map((value, index) => on[index] - value);
  const tally = new OutcomeCounters();
  const N = 1_000_000;
  const t0 = performance.now();
  for (let i = 0; i < N; i++) tally.observe({ kind: "L1_REJECTED", reason: "a7.path_not_allowed" });
  const perEventNs = ((performance.now() - t0) / N) * 1e6;
  process.stdout.write(`${JSON.stringify({
    benchmark: "outcome-tally-overhead", requestsPerArm: REQUESTS, rounds: ROUNDS, order: "alternating OFF,ON after one warm-up each",
    meanMsPerRequest: { offMedian: +median(off).toFixed(4), onMedian: +median(on).toFixed(4), pairedDeltaMedian: +median(diffs).toFixed(4), pairedDeltaMin: +Math.min(...diffs).toFixed(4), pairedDeltaMax: +Math.max(...diffs).toFixed(4) },
    tallyNsPerEvent: Math.round(perEventNs), eventsPerRequestApprox: 4,
  }, null, 2)}\n`);
}
void main();
