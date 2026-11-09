/**
 * Disposable ORIGIN RECEIPT COLLECTOR: a separate process in front of the origin fixture. It records, at ARRIVAL, every request actually received (method, path, run id, campaign
 * id, request id, order) into its own file, then relays the bytes to the origin unchanged. It does not read the App's counters and the App does not read its file.
 * Child process entry; config JSON in argv[2]: { upstreamPort, receiptsFile, runId, campaignId, declarationFile, heartbeatMs, listenHost?, listenPort?, upstreamHost? }.
 *
 * Completeness evidence (independent of the defense plane's own telemetry): it beats a heartbeat every `heartbeatMs` on its own clock and, when told to stop, writes ONE closing
 * declaration (run/campaign binding, the number of receipts and the last sequence it issued, the window it covered, every heartbeat). A verifier recounts the receipts against it;
 * a missing declaration is a failure, never a pass. Defaults are loopback only; a non-loopback `listenHost` is an explicit setting for a separately provisioned machine (not used here).
 */
import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";

if (process.send) {
  const config = JSON.parse(process.argv[2] ?? "{}") as { upstreamPort: number; receiptsFile: string; runId?: string; campaignId?: string; declarationFile?: string; heartbeatMs?: number; listenHost?: string; listenPort?: number; upstreamHost?: string };
  writeFileSync(config.receiptsFile, "");
  let seq = 0;
  const coverageStartMs = Date.now(); const heartbeatsMs: number[] = [];
  const beat = setInterval(() => { heartbeatsMs.push(Date.now()); }, config.heartbeatMs ?? 100);
  const header = (req: http.IncomingMessage, name: string): string | null => { const v = req.headers[name]; return typeof v === "string" ? v : null; };
  const server = http.createServer((req, res) => {
    appendFileSync(config.receiptsFile, `${JSON.stringify({ seq: ++seq, requestId: header(req, "x-m1-request-id"), runId: header(req, "x-m1-run-id"), campaignId: header(req, "x-m1-campaign-id"), method: req.method ?? null, path: req.url ?? null, receivedAtMs: Date.now() })}\n`);
    const upstream = http.request({ host: config.upstreamHost ?? "127.0.0.1", port: config.upstreamPort, method: req.method, path: req.url, headers: req.headers }, (answer) => { res.writeHead(answer.statusCode ?? 502, answer.headers); answer.pipe(res); });
    upstream.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
  server.listen(config.listenPort ?? 0, config.listenHost ?? "127.0.0.1", () => process.send?.({ type: "ready", port: (server.address() as { port: number }).port, pid: process.pid }));
  process.on("message", (message: { type?: string }) => {
    if (message.type !== "stop") return;
    clearInterval(beat);
    server.close(() => {
      if (config.declarationFile) {
        writeFileSync(config.declarationFile, `${JSON.stringify({
          schema: "m1-collector-declaration-v1", runId: config.runId ?? null, campaignId: config.campaignId ?? null, receiptCount: seq, lastSeq: seq,
          coverageStartMs, coverageEndMs: Date.now(), heartbeatMs: config.heartbeatMs ?? 100, heartbeatsMs,
        })}\n`);
      }
      process.exit(0);
    });
    // keep-alive sockets must not delay the declaration
    server.closeAllConnections?.();
  });
}
