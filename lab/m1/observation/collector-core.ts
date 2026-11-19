/**
 * Origin receipt collector core, shared by the local fork entry (origin-collector.ts) and the standalone launcher (launch.ts). It records, at ARRIVAL, every request actually
 * received (method, path, run id, campaign id, request id, order) into its own file, then relays the bytes to the origin unchanged. It does not read the App's counters.
 *
 * Completeness evidence (independent of the defense plane's own telemetry): a heartbeat every `heartbeatMs` on its own clock and, when stopped, ONE closing declaration
 * (run/campaign binding, receipt count and last sequence, covered window, every heartbeat). A verifier recounts the receipts against it; a missing declaration is a failure.
 */
import { appendFileSync, renameSync, writeFileSync } from "node:fs";
import http from "node:http";

export type CollectorConfig = {
  upstreamPort: number; receiptsFile: string; runId?: string; campaignId?: string; declarationFile?: string; heartbeatMs?: number;
  listenHost?: string; listenPort?: number; upstreamHost?: string;
  /** optional append-only monitoring log of heartbeats (one JSON line each); the declaration remains the authoritative record */
  heartbeatLogFile?: string;
  /** self-reported deployment identity of this collector (REMOTE_PRIVATE profile); written into the closing declaration */
  observer?: { deploymentId: string; address: string };
};
export type Declaration = { schema: "m1-collector-declaration-v1"; runId: string | null; campaignId: string | null; receiptCount: number; lastSeq: number; coverageStartMs: number; coverageEndMs: number; heartbeatMs: number; heartbeatsMs: number[]; observer?: { deploymentId: string; address: string } };
export type RunningCollector = { port: number; host: string; pid: number; stop: () => Promise<Declaration> };

export function startCollector(config: CollectorConfig): Promise<RunningCollector> {
  writeFileSync(config.receiptsFile, "");
  let seq = 0;
  const coverageStartMs = Date.now(); const heartbeatsMs: number[] = [];
  const beat = setInterval(() => {
    const now = Date.now(); heartbeatsMs.push(now);
    if (config.heartbeatLogFile) appendFileSync(config.heartbeatLogFile, `${JSON.stringify({ t: now, runId: config.runId ?? null, receipts: seq })}\n`);
  }, config.heartbeatMs ?? 100);
  const header = (req: http.IncomingMessage, name: string): string | null => { const v = req.headers[name]; return typeof v === "string" ? v : null; };
  const server = http.createServer((req, res) => {
    appendFileSync(config.receiptsFile, `${JSON.stringify({ seq: ++seq, requestId: header(req, "x-m1-request-id"), runId: header(req, "x-m1-run-id"), campaignId: header(req, "x-m1-campaign-id"), method: req.method ?? null, path: req.url ?? null, receivedAtMs: Date.now() })}\n`);
    const upstream = http.request({ host: config.upstreamHost ?? "127.0.0.1", port: config.upstreamPort, method: req.method, path: req.url, headers: req.headers }, (answer) => { res.writeHead(answer.statusCode ?? 502, answer.headers); answer.pipe(res); });
    upstream.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
  const host = config.listenHost ?? "127.0.0.1";
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.listenPort ?? 0, host, () => {
      const port = (server.address() as { port: number }).port;
      let finished: Promise<Declaration> | null = null;
      const stop = (): Promise<Declaration> => {
        finished ??= new Promise<Declaration>((done) => {
          clearInterval(beat);
          server.close(() => {
            const declaration: Declaration = { schema: "m1-collector-declaration-v1", runId: config.runId ?? null, campaignId: config.campaignId ?? null, receiptCount: seq, lastSeq: seq, coverageStartMs, coverageEndMs: Date.now(), heartbeatMs: config.heartbeatMs ?? 100, heartbeatsMs, ...(config.observer ? { observer: config.observer } : {}) };
            if (config.declarationFile) { const temporary = `${config.declarationFile}.partial`; writeFileSync(temporary, `${JSON.stringify(declaration)}\n`); renameSync(temporary, config.declarationFile); }
            done(declaration);
          });
          // keep-alive sockets must not delay the declaration
          server.closeAllConnections?.();
        });
        return finished;
      };
      resolve({ port, host, pid: process.pid, stop });
    });
  });
}
