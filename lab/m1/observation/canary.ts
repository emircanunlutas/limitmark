/**
 * Disposable independent CANARY: a separate process that walks the legitimate-user journey against the server under test and records, on its own clock, what it saw.
 * Journey: home, static asset, FAQ navigation, form page, valid form submission, thank-you. Every request carries the run id, campaign id and a unique request id.
 * Child process entry; config JSON in argv[2]: { frontPort, runId, campaignId, plan: { baseline, window, recovery }, timeoutMs, outFile }. Loopback only.
 */
import { writeFileSync } from "node:fs";

const STEPS: { name: string; method: "GET" | "POST"; path: string }[] = [
  { name: "home", method: "GET", path: "/" }, { name: "asset", method: "GET", path: "/assets/site.css" }, { name: "faq", method: "GET", path: "/sss" },
  { name: "form", method: "GET", path: "/test-talep-et" }, { name: "submit", method: "POST", path: "/api/talep" }, { name: "thanks", method: "GET", path: "/tesekkurler" },
];

async function main(): Promise<void> {
  const config = JSON.parse(process.argv[2] ?? "{}") as { frontPort: number; frontHost?: string; runId: string; campaignId: string; plan: { baseline: number; window: number; recovery: number }; timeoutMs: number; outFile: string };
  const steps: unknown[] = [];
  for (const phase of ["baseline", "window", "recovery"] as const) {
    for (let journey = 1; journey <= config.plan[phase]; journey++) {
      for (const step of STEPS) {
        const requestId = `${phase}.${journey}.${step.name}`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), config.timeoutMs);
        const started = performance.now(); const startedAtMs = Date.now();
        let status: number | null = null; let ok = false; let timedOut = false; let failed = false; let challenged = false;
        try {
          const response = await fetch(`http://${config.frontHost ?? "127.0.0.1"}:${config.frontPort}${step.path}`, {
            method: step.method, signal: controller.signal, headers: { "x-m1-run-id": config.runId, "x-m1-campaign-id": config.campaignId, "x-m1-request-id": requestId, ...(step.method === "POST" ? { "content-type": "application/json" } : {}) },
            ...(step.method === "POST" ? { body: JSON.stringify({ name: "Canary", email: "canary@example.invalid" }) } : {}),
          });
          status = response.status; challenged = response.headers.has("x-m1-challenge");
          const text = await response.text();
          ok = status === 200 && (step.method !== "POST" || (JSON.parse(text) as { ok?: unknown }).ok === true);
        } catch (error) { if ((error as { name?: string }).name === "AbortError") timedOut = true; else failed = true; }
        clearTimeout(timer);
        steps.push({ phase, journey, step: step.name, requestId, method: step.method, path: step.path, status, ok, timedOut, failed, challenged, latencyMs: Math.round((performance.now() - started) * 100) / 100, startedAtMs });
      }
    }
  }
  writeFileSync(config.outFile, `${JSON.stringify({ schema: "m1-canary-results-v1", runId: config.runId, campaignId: config.campaignId, pid: process.pid, timeoutMs: config.timeoutMs, plan: config.plan, steps })}\n`);
}

if (process.send) { main().then(() => { process.send?.({ type: "done" }); process.exit(0); }, () => process.exit(1)); }
