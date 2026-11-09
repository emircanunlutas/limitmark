/**
 * Disposable stand-in for the SERVER UNDER TEST: a pass-through loopback proxy with optional, request-id-keyed faults. It is NOT the L1/L2 defense plane; it exists so the
 * independent canary and origin receipt collector have something separate to observe. Child process entry; config JSON in argv[2]:
 * { upstreamPort, faults: { drop?: string[]; fake?: string[]; duplicate?: string[]; rateLimit?: string[]; challenge?: string[]; slowMs?: Record<string, number> } }. Loopback only.
 */
import http from "node:http";

type Faults = { drop?: string[]; fake?: string[]; duplicate?: string[]; rateLimit?: string[]; challenge?: string[]; slowMs?: Record<string, number> };

if (process.send) {
  const config = JSON.parse(process.argv[2] ?? "{}") as { upstreamPort: number; faults?: Faults };
  const faults = config.faults ?? {};
  const relay = (req: http.IncomingMessage, body: Buffer, onResponse?: (answer: http.IncomingMessage) => void): void => {
    const upstream = http.request({ host: "127.0.0.1", port: config.upstreamPort, method: req.method, path: req.url, headers: req.headers }, (answer) => { if (onResponse) onResponse(answer); else answer.resume(); });
    upstream.on("error", () => undefined);
    upstream.end(body);
  };
  const server = http.createServer((req, res) => {
    const id = typeof req.headers["x-m1-request-id"] === "string" ? req.headers["x-m1-request-id"] : "";
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      const respond = (): void => {
        if (faults.drop?.includes(id)) { res.writeHead(503); res.end(); return; }
        if (faults.rateLimit?.includes(id)) { res.writeHead(429); res.end(); return; }
        if (faults.challenge?.includes(id)) { res.writeHead(403, { "x-m1-challenge": "required" }); res.end(); return; }
        if (faults.fake?.includes(id)) { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ ok: true })); return; } // success WITHOUT forwarding
        if (faults.duplicate?.includes(id)) relay(req, body);
        relay(req, body, (answer) => { res.writeHead(answer.statusCode ?? 502, answer.headers); answer.pipe(res); });
      };
      const delay = faults.slowMs?.[id];
      if (delay) setTimeout(respond, delay); else respond();
    });
  });
  server.listen(0, "127.0.0.1", () => process.send?.({ type: "ready", port: (server.address() as { port: number }).port, pid: process.pid }));
  process.on("message", (message: { type?: string }) => { if (message.type === "stop") server.close(() => process.exit(0)); });
}
