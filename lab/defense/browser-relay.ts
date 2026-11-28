/**
 * Harness-side BROWSER CLIENT ADAPTER (measurement only).
 *
 * A real browser cannot put the harness correlation tag on its requests, and a request the plane sees without one is an uncorrelated
 * ingress (an anomaly with no ledger record). This loopback adapter does for every browser request what `trackedHttp` does for a scripted
 * one: it registers the request in the collector BEFORE any byte is sent, adds the measurement tag, passes the browser's request line,
 * headers and body to the ONE fixed Defense Plane port unchanged, returns the plane's answer, and completes the record exactly once with
 * what it observed.
 *
 * It decides nothing: it filters no request header (the plane strips, admits and canonicalizes), it has no other upstream and no fallback.
 * When the plane refuses, the browser gets that refusal; when the plane is unreachable, the browser gets an empty 502 from this adapter,
 * recorded as a client-side reset/error. From the response it removes only the harness's own outcome label and the hop-by-hop framing, so
 * the browser sees what a remote client would.
 */
import { createHash } from "node:crypto";
import http from "node:http";
import type { AddressInfo, Socket } from "node:net";
import type { ClientResultKind } from "../../defense/core/ledger";
import { NONCE_HEADER, OUTCOME_HEADER } from "../../defense/core/types";
import { newNonce } from "./client";
import type { Collector, RequestMeta } from "./collector";

export type RelayExchange = {
  rid: string | null;
  phase: string;
  scenario: string;
  method: string;
  target: string;
  result: ClientResultKind;
  status: number | null;
  outcome: string | null;
  headers: Record<string, string>;
  bytes: number;
  sha256: string | null;
  latencyMs: number;
};

const HOP_BY_HOP: ReadonlySet<string> = new Set(["connection", "keep-alive", "transfer-encoding", OUTCOME_HEADER]);
const MAX_RELAY_BODY = 2 * 1_048_576;

function classify(error: unknown): ClientResultKind {
  const code = (error as { code?: string } | null)?.code;
  return code === "ECONNRESET" || code === "EPIPE" || code === "ECONNREFUSED" ? "reset" : "error";
}

export class BrowserRelay {
  private readonly server: http.Server;
  private readonly agent = new http.Agent({ keepAlive: false });
  private readonly sockets = new Set<Socket>();
  private readonly log: RelayExchange[] = [];
  private phase = "browser";
  private inFlight = 0;
  private idleWaiters: (() => void)[] = [];
  port = 0;

  constructor(private readonly collector: Collector, private readonly planePort: number, private readonly scenarioOf: (method: string, target: string) => string, private readonly timeoutMs = 10_000) {
    if (!Number.isInteger(planePort) || planePort < 1 || planePort > 65_535) throw new Error("the plane must be a fixed 127.0.0.1 port");
    this.server = http.createServer({ requireHostHeader: false }, (req, res) => { void this.handle(req, res); });
    this.server.on("connection", (socket) => { this.sockets.add(socket); socket.on("close", () => this.sockets.delete(socket)); });
  }

  async listen(): Promise<number> {
    await new Promise<void>((resolve, reject) => { this.server.once("error", reject); this.server.listen(0, "127.0.0.1", () => resolve()); });
    this.port = (this.server.address() as AddressInfo).port;
    return this.port;
  }

  setPhase(phase: string): void { this.phase = phase; }
  exchanges(): readonly RelayExchange[] { return this.log; }

  /** Resolves once no browser request is in flight through the adapter. */
  idle(): Promise<void> { return this.inFlight === 0 ? Promise.resolve() : new Promise((resolve) => this.idleWaiters.push(resolve)); }

  async close(): Promise<void> {
    const closed = new Promise<void>((resolve) => this.server.close(() => resolve()));
    for (const socket of this.sockets) socket.destroy();
    await closed;
    this.agent.destroy();
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const method = req.method ?? "";
    const target = req.url ?? "";
    const phase = this.phase;
    const scenario = this.scenarioOf(method, target);
    const nonce = newNonce();
    const meta: RequestMeta = { lane: "protected", phase, cls: "canary", scenario, journey: null, step: null, method: method === "GET" ? "GET" : method === "POST" ? "POST" : "OTHER" };
    this.inFlight++;
    const started = performance.now();
    const registered = this.collector.sent(nonce, meta);
    let done = false;
    const complete = (result: ClientResultKind, status: number | null, outcome: string | null, headers: Record<string, string>, body: Buffer | null) => {
      if (done) return;
      done = true;
      const latencyMs = performance.now() - started;
      if (registered) this.collector.clientCompleted(nonce, { result, status: status ?? undefined, outcomeHeader: outcome ?? undefined, latencyMs });
      this.log.push({
        rid: this.collector.recordFor(nonce)?.rid ?? null, phase, scenario, method, target, result, status, outcome, headers,
        bytes: body?.length ?? 0, sha256: body === null ? null : createHash("sha256").update(body).digest("hex"), latencyMs,
      });
      if (--this.inFlight === 0) for (const wake of this.idleWaiters.splice(0)) wake();
    };
    const unavailable = (result: ClientResultKind) => {
      if (done) return;
      complete(result, null, null, {}, null);
      if (!res.headersSent && !res.destroyed) { res.writeHead(502, { "content-length": 0, "cache-control": "no-store" }); res.end(); }
      else res.destroy();
    };
    if (!registered) { unavailable("error"); return; }

    const headers = [...req.rawHeaders, NONCE_HEADER, nonce];
    const upstream = http.request({ host: "127.0.0.1", port: this.planePort, method, path: target, headers, agent: this.agent }, (response) => {
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", (chunk: Buffer) => { total += chunk.length; if (total > MAX_RELAY_BODY) { upstream.destroy(); unavailable("error"); return; } chunks.push(chunk); });
      response.on("error", (error) => unavailable(classify(error)));
      response.on("end", () => {
        if (done) return;
        clearTimeout(timer);
        const body = Buffer.concat(chunks);
        const outcome = response.headers[OUTCOME_HEADER];
        const forwarded: string[] = [];
        const observed: Record<string, string> = {};
        for (let index = 0; index + 1 < response.rawHeaders.length; index += 2) {
          const name = response.rawHeaders[index].toLowerCase();
          if (HOP_BY_HOP.has(name)) continue;
          forwarded.push(response.rawHeaders[index], response.rawHeaders[index + 1]);
          observed[name] = observed[name] === undefined ? response.rawHeaders[index + 1] : `${observed[name]}, ${response.rawHeaders[index + 1]}`;
        }
        complete("response", response.statusCode ?? null, typeof outcome === "string" ? outcome : null, observed, body);
        if (res.destroyed) return;
        res.writeHead(response.statusCode ?? 502, forwarded);
        res.end(body);
      });
    });
    const timer = setTimeout(() => { upstream.destroy(); unavailable("timeout"); }, this.timeoutMs);
    upstream.on("error", (error) => { clearTimeout(timer); unavailable(classify(error)); });
    req.pipe(upstream);
  }
}
