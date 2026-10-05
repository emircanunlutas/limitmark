/**
 * The Origin Boundary: a separate process that admits a request only when it carries a valid Plane-to-Boundary (PB) proof, then issues
 * a distinct Boundary-to-App (BA) proof and forwards the request, REBUILT from the verified claims, to the one fixed loopback App.
 *
 * It judges authenticity only: it knows nothing about routes, forms or L1, and it has no input from the Defense Plane's liveness, so a
 * Plane failure cannot change what it accepts. There is no configuration, flag or mode that makes it pass anything unauthenticated, and no
 * unauthenticated route (not even a health check). A body byte is read only after the proof's signature and the replay reservation.
 *
 * This is application-layer refusal on an open socket. It is NOT network or transport isolation and says nothing about volumetric,
 * handshake or connection-state exhaustion.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { KeyObject } from "node:crypto";
import type { BoundaryEvent, EgressErrorKind } from "../core/ledger";
import { EGRESS_ERROR_KINDS } from "../core/ledger";
import { admitHopRequest, newAdmissionStats, type PbAdmissionConfig, type Refused } from "../core/hop-admission";
import { issueBa, type BaIssuerConfig } from "../core/hop-proof";
import { ClockFence, ReplayGuard } from "../core/replay-guard";
import { HOP_BA_HEADER, HOP_PB_HEADER, readMeasurementTag, semanticWireHeaders } from "../core/semantic-request";
import { OB_REASONS, type ObReason } from "../core/types";
import type { BoundaryLimits, BoundaryStats } from "./protocol";

export type BoundaryOptions = {
  /** The one upstream: the Protected App, a fixed loopback port. A request cannot choose or influence it. */
  appPort: number;
  keyP: KeyObject;
  kidP: string;
  boundaryId: string;
  keyB: KeyObject;
  kidB: string;
  appId: string;
  limits: BoundaryLimits;
  emit: (event: Omit<BoundaryEvent, "seq" | "t">) => number;
  /** Injected for tests; the process entry uses the real clocks. */
  now?: () => number;
  mono?: () => number;
};

export type Boundary = {
  listen(): Promise<number>;
  close(): Promise<void>;
  stats(): BoundaryStats;
};

const RELAY_RESPONSE_HEADERS: ReadonlySet<string> = new Set(["content-type", "cache-control", "x-content-type-options", "etag", "last-modified", "location", "content-language"]);
const PARSER_CODES: ReadonlySet<string> = new Set([
  "HPE_HEADER_OVERFLOW", "HPE_INVALID_METHOD", "HPE_INVALID_HEADER_TOKEN", "HPE_UNEXPECTED_CONTENT_LENGTH", "HPE_INVALID_CONTENT_LENGTH",
  "HPE_INVALID_TRANSFER_ENCODING", "HPE_INVALID_CONSTANT", "HPE_INVALID_URL", "HPE_INVALID_VERSION", "HPE_CR_EXPECTED", "HPE_LF_EXPECTED",
  "HPE_INVALID_CHUNK_SIZE", "HPE_INVALID_STATUS", "HPE_STRICT",
]);
const MAX_RESPONSE_BYTES = 1_048_576;

function forwardErrorKind(error: unknown): EgressErrorKind {
  const code = (error as { code?: string } | null)?.code;
  if (code === "ECONNREFUSED") return "refused";
  if (code === "ECONNRESET" || code === "EPIPE" || (error instanceof Error && /socket hang up/.test(error.message))) return "reset";
  if (code === "ETIMEDOUT") return "timeout";
  return "error";
}

export function createBoundary(options: BoundaryOptions): Boundary {
  if (!Number.isInteger(options.appPort) || options.appPort < 1 || options.appPort > 65_535) throw new Error("the app must be a fixed 127.0.0.1 port");
  const wall = options.now ?? (() => Date.now());
  const mono = options.mono ?? (() => performance.now());
  const guard = new ReplayGuard(options.limits.replayCapacity, mono);
  const fence = new ClockFence(wall, mono);
  const admissionStats = newAdmissionStats();
  const admission: PbAdmissionConfig = {
    role: "pb", keyP: options.keyP, kidP: options.kidP, boundaryId: options.boundaryId, guard, fence, now: wall,
    bodyDeadlineMs: options.limits.bodyDeadlineMs, stats: admissionStats,
  };
  const baIssuer: BaIssuerConfig = { kid: options.kidB, privateKey: options.keyB, appId: options.appId, lifetimeMs: options.limits.baLifetimeMs, now: wall };
  const upstream = Object.freeze({ host: "127.0.0.1" as const, port: options.appPort });
  const agent = new http.Agent({ keepAlive: false });
  const sockets = new Set<import("node:net").Socket>();
  const counters = {
    arrived: 0, admitted: 0, rejected: 0, appProofsIssued: 0, relayed: 0, forwardResponded: 0, forwardFailed: 0, responded: 0, aborted: 0, parserRejected: 0, protocolRefused: 0,
  };
  const rejectedByReason: Record<string, number> = Object.fromEntries(OB_REASONS.map((reason) => [reason, 0]));
  const forwardFailedByKind = Object.fromEntries(EGRESS_ERROR_KINDS.map((kind) => [kind, 0])) as Record<EgressErrorKind, number>;

  // requireHostHeader is off so a missing Host is a measured refusal (the proof binds Host) rather than an unattributed parser answer.
  const server = http.createServer({ maxHeaderSize: 16_384, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 5_000, requireHostHeader: false }, (req, res) => {
    void handle(req, res).catch(() => { if (!res.writableEnded) res.destroy(); });
  });
  server.maxConnections = 512;
  server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });

  // The HTTP parser refused the bytes before any request existed: anonymous, bounded, counted.
  server.on("clientError", (error: NodeJS.ErrnoException, socket) => {
    const code = error.code ?? "";
    if (PARSER_CODES.has(code) && socket.writable) {
      counters.parserRejected++;
      options.emit({ nonce: null, kind: "BOUNDARY_PARSER_REJECTED", code });
      socket.end(`HTTP/1.1 ${code === "HPE_HEADER_OVERFLOW" ? "431 Request Header Fields Too Large" : "400 Bad Request"}\r\nconnection: close\r\ncontent-length: 0\r\nx-ba0-outcome: refused\r\n\r\n`);
      return;
    }
    socket.destroy();
  });
  // No 100-continue invitation to an unauthenticated sender, no upgrade, no tunnel.
  server.on("checkContinue", (req, res) => { refuse(res, { ok: false, reason: "ob.expect_refused", nonce: readMeasurementTag(req.rawHeaders) }); });
  server.on("upgrade", (_req, socket) => { counters.protocolRefused++; options.emit({ nonce: null, kind: "BOUNDARY_PROTOCOL_REFUSED", code: "upgrade" }); socket.destroy(); });
  server.on("connect", (_req, socket) => { counters.protocolRefused++; options.emit({ nonce: null, kind: "BOUNDARY_PROTOCOL_REFUSED", code: "connect" }); socket.destroy(); });

  /** Exactly one terminal event per request, whatever happens to the connection. */
  function track(res: http.ServerResponse, nonce: string | null): void {
    res.once("close", () => {
      if (res.writableFinished) { counters.responded++; options.emit({ nonce, kind: "BOUNDARY_RESPONDED", status: res.statusCode }); }
      else { counters.aborted++; options.emit({ nonce, kind: "BOUNDARY_ABORTED" }); }
    });
  }

  /** One uniform answer for every authentication failure: same status, no body, connection closed. The reason exists only in telemetry. */
  function refuse(res: http.ServerResponse, refused: Refused): void {
    counters.arrived++;
    counters.rejected++;
    rejectedByReason[refused.reason] = (rejectedByReason[refused.reason] ?? 0) + 1;
    options.emit({ nonce: refused.nonce, kind: "BOUNDARY_ARRIVED" });
    options.emit({ nonce: refused.nonce, kind: "BOUNDARY_REJECTED", reason: refused.reason as ObReason });
    track(res, refused.nonce);
    if (res.writableEnded || res.destroyed) return;
    // Cache exhaustion is only reachable AFTER a proof verified, so a distinct status tells an unauthenticated sender nothing.
    res.writeHead(refused.reason === "ob.replay_cache_full" ? 503 : 403, { "content-length": 0, connection: "close", "x-ba0-outcome": "refused" });
    res.end();
    const socket = res.socket;
    if (socket) setTimeout(() => { if (!socket.destroyed) socket.destroy(); }, 1_000).unref();
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const outcome = await admitHopRequest(admission, {
      method: req.method ?? "", url: req.url ?? "", rawHeaders: req.rawHeaders, stream: req,
      crossCheck: (claims) => claims.pairs.every(([name, value]) => req.headers[name] === value) && (["content-type", "host", "origin"] as const).every((name) => req.headers[name] === undefined || claims.pairs.some(([key]) => key === name)),
    });
    if (!outcome.ok) { refuse(res, outcome); return; }

    const nonce = outcome.nonce;
    counters.arrived++;
    counters.admitted++;
    options.emit({ nonce, kind: "BOUNDARY_ARRIVED" });
    options.emit({ nonce, kind: "BOUNDARY_ADMITTED", hop: outcome.hop, pbTag: outcome.pbTag });
    // The terminal event is emitted only after everything the request did, so a client that vanishes cannot put it ahead of the forward events.
    const closed = new Promise<void>((resolve) => res.once("close", () => resolve()));

    let headers: Record<string, string> | null = null;
    let baTag = "";
    try {
      const issued = issueBa(baIssuer, outcome.pb);
      baTag = issued.tag;
      counters.appProofsIssued++;
      options.emit({ nonce, kind: "APP_PROOF_ISSUED", hop: outcome.hop, pbTag: outcome.pbTag, baTag });
      headers = { ...semanticWireHeaders(outcome.request), [HOP_BA_HEADER]: issued.header, [HOP_PB_HEADER]: outcome.pb.header };
    } catch {
      sendStatus(res, 503, "refused");
    }
    if (headers !== null) await forward(res, nonce, outcome.hop, outcome.pbTag, baTag, outcome.request.method, outcome.request.target, headers, outcome.body);
    await closed;
    if (res.writableFinished) { counters.responded++; options.emit({ nonce, kind: "BOUNDARY_RESPONDED", status: res.statusCode }); }
    else { counters.aborted++; options.emit({ nonce, kind: "BOUNDARY_ABORTED" }); }
  }

  function sendStatus(res: http.ServerResponse, status: number, label: string): void {
    if (res.writableEnded || res.destroyed) return;
    res.writeHead(status, { "content-length": 0, "x-ba0-outcome": label, "cache-control": "no-store" });
    res.end();
  }

  function forward(res: http.ServerResponse, nonce: string, hop: number, pbTag: string, baTag: string, method: string, path: string, headers: Record<string, string>, body: Buffer): Promise<void> {
    return new Promise<void>((resolve) => {
      let settled = false;
      const fail = (kind: EgressErrorKind) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        counters.forwardFailed++;
        forwardFailedByKind[kind]++;
        options.emit({ nonce, kind: "BOUNDARY_FORWARD_FAILED", forwardError: kind });
        sendStatus(res, kind === "timeout" ? 504 : 502, "forward_failed");
        resolve();
      };
      const upstreamRequest = http.request({ host: upstream.host, port: upstream.port, method, path, headers, agent }, (upstreamResponse) => {
        const chunks: Buffer[] = [];
        let total = 0;
        upstreamResponse.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) { upstreamRequest.destroy(); fail("error"); return; }
          chunks.push(chunk);
        });
        upstreamResponse.on("error", () => fail("reset"));
        upstreamResponse.on("aborted", () => fail("reset"));
        upstreamResponse.on("end", () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const status = upstreamResponse.statusCode ?? 502;
          counters.forwardResponded++;
          options.emit({ nonce, kind: "BOUNDARY_FORWARD_RESPONDED", status });
          const payload = Buffer.concat(chunks);
          const relayed: Record<string, string | number> = {};
          for (const [name, value] of Object.entries(upstreamResponse.headers)) if (RELAY_RESPONSE_HEADERS.has(name) && typeof value === "string") relayed[name] = value;
          relayed["content-length"] = payload.length;
          if (!res.destroyed) { res.writeHead(status, relayed); res.end(payload); }
          resolve();
        });
      });
      const timer = setTimeout(() => { upstreamRequest.destroy(); fail("timeout"); }, options.limits.forwardTimeoutMs);
      upstreamRequest.on("error", (error) => fail(forwardErrorKind(error)));
      counters.relayed++;
      options.emit({ nonce, kind: "BOUNDARY_FORWARDED", hop, pbTag, baTag });
      upstreamRequest.end(body.length === 0 ? undefined : body);
    });
  }

  return {
    listen: () => new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve((server.address() as AddressInfo).port); });
    }),
    close: () => new Promise<void>((resolve) => {
      server.close(() => { agent.destroy(); resolve(); });
      const timeout = setTimeout(() => { for (const socket of sockets) socket.destroy(); }, 1_000);
      timeout.unref();
      server.closeIdleConnections();
    }),
    stats: () => ({
      ...counters, rejectedByReason: { ...rejectedByReason }, forwardFailedByKind: { ...forwardFailedByKind }, replay: guard.stats(),
      contentReadsStarted: admissionStats.contentReadsStarted, contentBytesRead: admissionStats.contentBytesRead, clockStepMs: fence.stepMs(), clockStep: fence.stepDetected(),
    }),
  };
}
