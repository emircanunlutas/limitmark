import { setTimeout as sleep } from "node:timers/promises";
import { runJourney, type JourneyResult } from "../canary";
import { Collector, type LedgerRecord } from "../collector";
import { BA0_FIELD_V1 as config } from "../field-thresholds";

export const plan = { baseline: 12, window: 12, recovery: 6 } as const;
export type Phase = keyof typeof plan;
export type ClientRecord = Pick<LedgerRecord, "nonce" | "meta" | "harness" | "latencyMs">;
export type CanaryResult = {
  pid: number;
  journeys: JourneyResult[];
  requests: ClientRecord[];
  intervals: Record<Phase, { startMs: number; endMs: number }>;
};

export function clientRecords(collector: Collector): ClientRecord[] {
  return Array.from(collector.allRecords(), ({ nonce, meta, harness, latencyMs }) => ({ nonce, meta, harness, latencyMs }));
}

async function observe(port: number, notifyWindow: boolean): Promise<CanaryResult> {
  const collector = new Collector(null);
  const journeys: JourneyResult[] = [];
  const intervals = {} as CanaryResult["intervals"];
  for (const phase of Object.keys(plan) as Phase[]) {
    if (phase === "recovery") {
      const deadline = intervals.window.endMs + config.recovery.quietMs;
      while (performance.now() < deadline) await sleep(Math.ceil(deadline - performance.now()));
    }
    intervals[phase] = { startMs: performance.now(), endMs: 0 };
    if (phase === "window" && notifyWindow) process.send!("window-open");
    for (let journey = 1; journey <= plan[phase]; journey++) {
      if (journey > 1) await sleep(config.canary.gapMs);
      journeys.push(await runJourney(collector, { lane: "protected", port, phase, journey, timeoutMs: config.canary.timeoutMs }));
    }
    intervals[phase].endMs = performance.now();
    console.log(`canary completed ${phase}: ${plan[phase]} journeys`);
  }
  return { pid: process.pid, journeys, requests: clientRecords(collector), intervals };
}

if (process.argv[1]?.replaceAll("\\", "/").endsWith("/customer-journey/canary.ts") && process.send) {
  process.on("disconnect", () => process.exit());
  process.once("message", async ({ port, notifyWindow = false }: { port: number; notifyWindow?: boolean }) => {
    try {
      process.send!(await observe(port, notifyWindow));
    } catch (error) {
      console.error(error);
      process.exit(1);
    }
  });
  process.send("ready");
}
