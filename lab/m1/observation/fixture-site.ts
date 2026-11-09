/**
 * Disposable ORIGIN fixture ("the App"): a tiny loopback site with the legitimate-user journey the canary exercises. It is NOT the defense plane and keeps no counters the
 * observation relies on. Child process entry; started by run.ts. Loopback only.
 *   GET / (home) | GET /assets/site.css (static asset) | GET /sss (FAQ / navigation) | GET /test-talep-et (form page) | POST /api/talep (valid form) | GET /tesekkurler (thank-you)
 * Actions this fixture cannot perform (login, payment, account changes, search backends, file upload) are NOT covered and are never reported as covered.
 */
import http from "node:http";

const page = (title: string): string => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><link rel="stylesheet" href="/assets/site.css"></head><body><h1>${title}</h1></body></html>`;

function handle(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = new URL(req.url ?? "/", "http://fixture.invalid");
  if (req.method === "GET" && url.pathname === "/") { res.writeHead(200, { "content-type": "text/html" }); res.end(page("home")); return; }
  if (req.method === "GET" && url.pathname === "/assets/site.css") { res.writeHead(200, { "content-type": "text/css" }); res.end("body{font-family:sans-serif}"); return; }
  if (req.method === "GET" && url.pathname === "/sss") { res.writeHead(200, { "content-type": "text/html" }); res.end(page("faq")); return; }
  if (req.method === "GET" && url.pathname === "/test-talep-et") { res.writeHead(200, { "content-type": "text/html" }); res.end(page("form")); return; }
  if (req.method === "GET" && url.pathname === "/tesekkurler") { res.writeHead(200, { "content-type": "text/html" }); res.end(page("thanks")); return; }
  if (req.method === "POST" && url.pathname === "/api/talep") {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => { if (chunks.reduce((n, c) => n + c.length, 0) < 8192) chunks.push(chunk); });
    req.on("end", () => {
      let ok = false;
      try { const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { name?: unknown; email?: unknown }; ok = typeof body.name === "string" && body.name.length > 0 && typeof body.email === "string" && body.email.includes("@"); } catch { ok = false; }
      res.writeHead(ok ? 200 : 400, { "content-type": "application/json" }); res.end(JSON.stringify({ ok }));
    });
    return;
  }
  res.writeHead(404); res.end();
}

if (process.send) {
  const server = http.createServer(handle);
  server.listen(0, "127.0.0.1", () => process.send?.({ type: "ready", port: (server.address() as { port: number }).port, pid: process.pid }));
  process.on("message", (message: { type?: string }) => { if (message.type === "stop") server.close(() => process.exit(0)); });
}
