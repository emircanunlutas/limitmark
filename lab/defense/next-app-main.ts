import { once } from "node:events";
import { existsSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import next from "next";
import { importPublicKey } from "../../defense/core/hop-proof";
import { BoundedEventChannel, type AppEvent } from "../../defense/core/ledger";
import { readMeasurementTag } from "../../defense/core/semantic-request";
import { OUTCOME_HEADER, type ObReason } from "../../defense/core/types";
import { createAppGuard } from "../../defense/origin/app-guard";
import type { AppControl, AppFinStats, AppInit, AppMessage } from "../../defense/origin/app-protocol";
import { READ_ONLY_PAGE_TARGETS, staticAssetTargets } from "./browser-scope";

type Control = Exclude<AppControl, { type: "fault" }>;


function empty(res: http.ServerResponse, status: number, refused = false): void {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, {
    "cache-control": "private, no-store",
    "content-length": 0,
    connection: "close",
    ...(refused ? { [OUTCOME_HEADER]: "refused" } : {}),
  });
  res.end();
}

async function start(init: AppInit, send: (message: AppMessage) => void) {
  // Read-only browser delivery: the declared GET pages and the build's own exact
  // static assets. RSC navigation, inquiry writes and authenticated routes are
  // outside this composition and are answered 404 without executing anything.
  const targets = new Set([...READ_ONLY_PAGE_TARGETS, ...staticAssetTargets(process.cwd())]);
  const { guard, stats } = createAppGuard({
    keyB: importPublicKey(init.publicKeyB), kidB: init.kidB,
    keyP: importPublicKey(init.publicKeyP), kidP: init.kidP,
    appId: init.appId, boundaryId: init.boundaryId,
    ...init.limits,
  });
  const channel = new BoundedEventChannel<AppEvent>({ send }, init.channel);
  const counters: AppFinStats["counters"] = {
    admitted: 0, refused: 0, executed: 0, stateMutations: 0,
    parserRejected: 0, protocolRefused: 0, refusedByReason: {},
  };
  const served: AppFinStats["served"] = {
    received: 0, completed: 0, aborted: 0, overloaded: 0, activeHighWater: 0, spoofedHeadersSeen: 0,
  };
  const frontend = next({ dev: false, hostname: "127.0.0.1", quiet: true });
  await frontend.prepare();
  const render = frontend.getRequestHandler();
  const server = http.createServer({
    maxHeaderSize: 16_384, headersTimeout: 10_000, requestTimeout: 15_000, keepAliveTimeout: 5_000,
    requireHostHeader: false,
    // Next registers an upgrade handler on first use. Keep upgrade requests on
    // the guarded HTTP path even after that handler is registered.
    shouldUpgradeCallback: () => false,
  }, (req, res) => {
    void handle(req, res).catch(() => {
      if (res.headersSent) res.destroy();
      else empty(res, 500);
    });
  });
  server.maxConnections = 256;
  server.on("connect", (_req, socket) => { counters.protocolRefused++; socket.destroy(); });
  server.on("checkContinue", refuseExpectation);
  server.on("checkExpectation", refuseExpectation);
  server.on("clientError", (error: NodeJS.ErrnoException, socket) => {
    if (error.code?.startsWith("HPE_") && error.code !== "HPE_INVALID_EOF_STATE") counters.parserRejected++;
    socket.destroy();
  });

  function refuse(res: http.ServerResponse, reason: ObReason, nonce: string | null): void {
    counters.refused++;
    counters.refusedByReason[reason] = (counters.refusedByReason[reason] ?? 0) + 1;
    channel.emit({ kind: "APP_REFUSED", reason, nonce });
    empty(res, reason === "ob.replay_cache_full" ? 503 : 403, true);
  }

  function refuseExpectation(req: http.IncomingMessage, res: http.ServerResponse): void {
    counters.protocolRefused++;
    refuse(res, "ob.expect_refused", readMeasurementTag(req.rawHeaders));
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const decision = await guard(req);
    if (!decision.ok) return refuse(res, decision.reason, decision.nonce);
    const { facts, identity } = decision;
    counters.admitted++;
    served.received++;
    served.activeHighWater = Math.max(served.activeHighWater, served.received - served.completed - served.aborted);
    // A successful guard has already rejected every unbound input header.
    channel.emit({ ...identity, kind: "APP_ADMITTED", spoofed: 0 });
    res.once("finish", () => {
      served.completed++;
      channel.emit({ ...identity, kind: "APP_COMPLETED", status: res.statusCode });
    });
    const abort = () => {
      if (res.writableFinished) return;
      served.aborted++;
      channel.emit({ ...identity, kind: "APP_ABORTED" });
    };
    if (res.destroyed) return abort();
    res.once("close", abort);
    if (facts.method !== "GET" || !targets.has(facts.url)) return empty(res, 404);

    // Use only verified request facts. The framework never receives proofs,
    // measurement tags or any caller-selected routing headers.
    req.method = facts.method;
    req.url = facts.url;
    req.headers = { host: facts.host, ...(facts.origin === undefined ? {} : { origin: facts.origin }) };
    req.rawHeaders = Object.entries(req.headers).flatMap(([name, value]) => typeof value === "string" ? [name, value] : []);
    counters.executed++;
    channel.emit({ ...identity, kind: "APP_EXECUTED" });
    await render(req, res);
  }

  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    port: (server.address() as AddressInfo).port,
    acknowledge: (received: number) => channel.acknowledge(received),
    async finish() {
      const drained = await channel.drain(3_000);
      send({ type: "fin_result", drained, channel: channel.stats(), stats: { counters, served, guard: stats() } });
    },
    async close() {
      const closed = new Promise<void>((resolve) => server.close(() => resolve()));
      server.closeAllConnections();
      await closed;
      await frontend.close();
    },
  };
}

async function main(): Promise<void> {
  if (!process.send || process.env.NODE_ENV !== "production") throw new Error("Expected the private Next app subprocess");
  if ([".env", ".env.local", ".env.production", ".env.production.local"].some((file) => existsSync(file))) {
    throw new Error("Run the private Next app from a credential-free build directory");
  }
  // Node 22 added shouldUpgradeCallback in 22.21.0.
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 21) || (major === 23) || (major === 24 && minor < 9)) {
    throw new Error("This private probe requires Node 22.21+, 24.9+, or newer");
  }
  process.on("disconnect", () => process.exit(1));
  const send = (message: AppMessage) => { process.send!(message); };
  const [init] = await once(process, "message") as [AppInit];
  if (init.type !== "init") throw new Error("Expected application guard configuration");
  const app = await start(init, send);
  process.on("message", (control: Control) => {
    if (control.type === "stop") void app.close().then(() => process.exit(0), () => process.exit(1));
    if (control.type === "ack") app.acknowledge(control.received);
    if (control.type === "fin") void app.finish().catch(() => process.exit(1));
  });
  send({ type: "ready", port: app.port });
}

void main().catch(() => {
  // Only a fixed message can leave this process on startup failure.
  console.error("Private Next app startup failed");
  process.exit(1);
});
