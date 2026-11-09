/**
 * Disposable ORIGIN RECEIPT COLLECTOR: a separate process in front of the origin fixture. It records, at ARRIVAL, every request actually received (method, path, run id, campaign
 * id, request id, order) into its own file, then relays the bytes to the origin unchanged. It does not read the App's counters and the App does not read its file.
 * Child process entry; config JSON in argv[2]: { upstreamPort, receiptsFile }. Loopback only.
 */
import { appendFileSync, writeFileSync } from "node:fs";
import http from "node:http";

if (process.send) {
  const config = JSON.parse(process.argv[2] ?? "{}") as { upstreamPort: number; receiptsFile: string };
  writeFileSync(config.receiptsFile, "");
  let seq = 0;
  const header = (req: http.IncomingMessage, name: string): string | null => { const v = req.headers[name]; return typeof v === "string" ? v : null; };
  const server = http.createServer((req, res) => {
    appendFileSync(config.receiptsFile, `${JSON.stringify({ seq: ++seq, requestId: header(req, "x-m1-request-id"), runId: header(req, "x-m1-run-id"), campaignId: header(req, "x-m1-campaign-id"), method: req.method ?? null, path: req.url ?? null, receivedAtMs: Date.now() })}\n`);
    const upstream = http.request({ host: "127.0.0.1", port: config.upstreamPort, method: req.method, path: req.url, headers: req.headers }, (answer) => { res.writeHead(answer.statusCode ?? 502, answer.headers); answer.pipe(res); });
    upstream.on("error", () => { res.writeHead(502); res.end(); });
    req.pipe(upstream);
  });
  server.listen(0, "127.0.0.1", () => process.send?.({ type: "ready", port: (server.address() as { port: number }).port, pid: process.pid }));
  process.on("message", (message: { type?: string }) => { if (message.type === "stop") server.close(() => process.exit(0)); });
}
