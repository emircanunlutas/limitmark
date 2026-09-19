import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer as createTcpServer } from "node:net";
import { test } from "node:test";
import { nativeSend } from "../operator/r2-transport";
import { syntheticTlsCertificate } from "./workers/support/synthetic-tls";

const tls = syntheticTlsCertificate();
async function listen(server: HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test-listener");
  return address.port;
}
async function exercise(handler: Parameters<typeof createHttpsServer>[1],
  run: (port: number) => Promise<void>): Promise<void> {
  const server = createHttpsServer(tls, handler);
  try { await run(await listen(server)); }
  finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
function options(port: number, timeout: number) {
  return { protocol: "https:", hostname: "127.0.0.1", port, method: "GET", path: "/pinned-result",
    headers: { host: "127.0.0.1" }, ca: tls.cert, timeout };
}

test("actual native HTTPS transport ignores ambient proxies and directly reaches pinned synthetic TLS endpoint", async () => {
  let proxyHits = 0;
  const proxy = createTcpServer((socket) => { proxyHits++; socket.destroy(); });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  const address = proxy.address();
  if (!address || typeof address === "string") throw new Error("test-proxy");
  const proxyUrl = `http://127.0.0.1:${address.port}`;
  const names = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"] as const;
  const previous = names.map((name) => [name, process.env[name]] as const);
  try {
    for (const name of names) process.env[name] = name.toLowerCase().includes("no_proxy") ? "never-match.invalid" : proxyUrl;
    let directHits = 0;
    await exercise((_req, res) => { directHits++; res.end("direct"); }, async (port) => {
      const result = await nativeSend(options(port, 500), undefined, 100);
      assert.equal(result.statusCode, 200);
      assert.equal(new TextDecoder().decode(result.body), "direct");
    });
    assert.equal(directHits, 1);
    assert.equal(proxyHits, 0, "proxy must receive no connection");
  } finally {
    for (const [name, value] of previous) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
    await new Promise<void>((resolve) => proxy.close(() => resolve()));
  }
});

test("actual native HTTPS total deadline ends stalled and dribbling responses", async () => {
  for (const mode of ["stall", "dribble"] as const) {
    let hits = 0;
    await exercise((_req, res) => {
      hits++;
      res.writeHead(200);
      if (mode === "dribble") {
        const interval = setInterval(() => res.write("x"), 25);
        res.on("close", () => clearInterval(interval));
      }
    }, async (port) => {
      const start = Date.now();
      await assert.rejects(() => nativeSend(options(port, 180), undefined, 1_024), /r2-transport/u);
      assert.ok(Date.now() - start < 1_000, `${mode} must respect total deadline`);
    });
    assert.equal(hits, 1, `${mode} must use one network attempt`);
  }
});

test("actual native HTTPS does not follow redirects or retry 429, 5xx and reset", async () => {
  for (const mode of [302, 429, 500, 503, "reset"] as const) {
    let hits = 0;
    await exercise((_req, res) => {
      hits++;
      if (mode === "reset") { res.socket?.destroy(); return; }
      if (mode === 302) res.setHeader("location", "https://127.0.0.1/other");
      res.writeHead(mode); res.end("test");
    }, async (port) => {
      if (mode === "reset") await assert.rejects(() => nativeSend(options(port, 500), undefined, 100));
      else assert.equal((await nativeSend(options(port, 500), undefined, 100)).statusCode, mode);
    });
    assert.equal(hits, 1, String(mode));
  }
});
