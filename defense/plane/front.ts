/**
 * The Defense Plane front door: an HTTP server that bounds the request, runs L1 through the composer and, only on a pass, proxies to
 * ONE fixed loopback synthetic origin chosen at construction. A request cannot choose, influence or learn the upstream.
 *
 * Order for every request, with the lifecycle event emitted at each step (events go to an asynchronous bounded channel owned by the
 * caller; this file never performs durable or blocking I/O):
 *
 *   INGRESS_ACCEPTED -> (bounded body read) -> L1_ENTERED -> L1_PASSED|REJECTED|SHED|ERROR
 *   -> [EGRESS_ATTEMPTED -> EGRESS_RESPONDED|EGRESS_FAILED] -> INGRESS_RESPONDED|INGRESS_ABORTED
 *
 * The correlation nonce is read here, for measurement only, and is removed with every other spoofable internal/forwarding header
 * BEFORE any layer sees the request. Layers never see it and nothing is decided from it.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";
import { LayerComposer, type ComposerOptions, type ComposerStats } from "../core/composer";
import type { EgressErrorKind, PlaneEvent } from "../core/ledger";
import {
  HOP_HEADER, L1_LIMITS, NONCE_HEADER, NONCE_PATTERN, OUTCOME_HEADER, REJECT_STAGE, REJECT_STATUS, isSpoofableHeader,
  type BodyStatus, type Layer, type LayerOutcome, type LayerRequest,
} from "../core/types";
import { ShapeGate } from "../layers/a7-shape-gate";
import { HOP_PB_HEADER, buildApprovedRequest, semanticWireHeaders, type ApprovedRequest } from "../core/semantic-request";
// Type-only, by design: this file is shared with the legacy Slice-1/2 composition, whose runtime module graph must contain no L2 code
// and no override implementation.
import type { EnrollmentObservation, L2Port } from "../core/l2-port";
import type { LaneDecision } from "../core/lanes";
import type { VerdictOverridePort } from "../core/override-port";

export type EmitEvent = (event: Omit<PlaneEvent, "seq" | "t">) => number;

/** Slice 2: issues the Plane-to-Boundary proof for a request the plane approved. Absent in a Slice-1 run. */
export type HopIssuer = { issue(approved: ApprovedRequest, context: { hop: number; corr: string }): { header: string; tag: string } };
export type HopStats = { issued: number; signFailures: number; droppedUnbound: number };

export type FrontOptions = {
  /** The one upstream. Must be a loopback address; there is no way to change it per request. */
  upstream: { host: "127.0.0.1"; port: number };
  emit: EmitEvent;
  layer?: Layer;
  composer?: Partial<ComposerOptions>;
  /** Slice 2: when present the forwarded request is REBUILT from the approved semantic request and carries a PB proof. */
  hop?: HopIssuer;
  /** Slice 3: the L2 stage, run after an L1 pass and before canonicalization and PB issuance. Absent in a Slice-1/2 composition. */
  l2?: L2Port;
  /** Slice 3, HARNESS ONLY: absent in every normal composition. See core/override-port.ts. */
  verdictOverride?: VerdictOverridePort;
  bodyDeadlineMs?: number;
  egressTimeoutMs?: number;
  maxResponseBytes?: number;
};

export type FrontStats = {
  accepted: number;
  inFlight: number;
  inFlightHighWater: number;
  parserRejected: number;
  proxied: number;
  completed: number;
  aborted: number;
  strippedHeaders: number;
};

/** Request headers that may be sent to the origin. Anything else (including every spoofable header) is dropped. */
const FORWARD_REQUEST_HEADERS: ReadonlySet<string> = new Set([
  "host", "accept", "accept-language", "user-agent", "content-type", "content-length", "origin", "referer", "cookie", "cache-control",
  "pragma", "upgrade-insecure-requests", "if-none-match", "if-modified-since", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "sec-fetch-user",
]);
const FORWARD_RESPONSE_HEADERS: ReadonlySet<string> = new Set(["content-type", "cache-control", "x-content-type-options", "etag", "last-modified", "location", "content-language"]);
const PARSER_CODES: ReadonlySet<string> = new Set([
  "HPE_HEADER_OVERFLOW", "HPE_INVALID_METHOD", "HPE_INVALID_HEADER_TOKEN", "HPE_UNEXPECTED_CONTENT_LENGTH", "HPE_INVALID_CONTENT_LENGTH",
  "HPE_INVALID_TRANSFER_ENCODING", "HPE_INVALID_CONSTANT", "HPE_INVALID_URL", "HPE_INVALID_VERSION", "HPE_CR_EXPECTED", "HPE_LF_EXPECTED",
  "HPE_INVALID_CHUNK_SIZE", "HPE_INVALID_STATUS", "HPE_STRICT",
]);
const REFUSAL_BODY = Buffer.from(JSON.stringify({ kind: "refused" }));

function mintNonce(): string { return `u${randomBytes(16).toString("base64url").slice(0, 21)}`; }

type BodyResult = { status: BodyStatus; body: Uint8Array | null };

function readBody(req: http.IncomingMessage, declared: number, deadlineMs: number): Promise<BodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (result: BodyResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      req.off("data", onData); req.off("end", onEnd); req.off("close", onClose); req.off("error", onClose);
      resolve(result);
    };
    const onData = (chunk: Buffer) => {
      total += chunk.length;
      // The caller already refused anything declared above the cap, so this only trips on a framing lie; it is still bounded.
      if (total > L1_LIMITS.maxBodyBytes || total > declared) { chunks.length = 0; finish({ status: "overflow", body: null }); return; }
      chunks.push(chunk);
    };
    const onEnd = () => finish({ status: "complete", body: new Uint8Array(Buffer.concat(chunks)) });
    const onClose = () => { if (!done) finish({ status: "aborted", body: null }); };
    const timer = setTimeout(() => finish({ status: "timeout", body: null }), deadlineMs);
    req.on("data", onData); req.on("end", onEnd); req.on("close", onClose); req.on("error", onClose);
  });
}

function egressErrorKind(error: unknown): EgressErrorKind {
  const code = (error as { code?: string } | null)?.code;
  if (code === "ECONNREFUSED") return "refused";
  if (code === "ECONNRESET" || code === "EPIPE" || (error instanceof Error && /socket hang up/.test(error.message))) return "reset";
  if (code === "ETIMEDOUT") return "timeout";
  return "error";
}

export type Front = {
  listen(): Promise<number>;
  close(deadlineMs?: number): Promise<void>;
  stats(): FrontStats;
  /** Slice 2 only; all zero in a Slice-1 run. */
  hopStats(): HopStats;
  layerComposerStats(): ComposerStats;
  composerOccupancy(): number;
  gate: ShapeGate | null;
};

export function createFront(options: FrontOptions): Front {
  if (options.upstream.host !== "127.0.0.1" || !Number.isInteger(options.upstream.port) || options.upstream.port < 1 || options.upstream.port > 65_535) {
    throw new Error("the upstream must be a fixed 127.0.0.1 port");
  }
  const upstream = Object.freeze({ host: options.upstream.host, port: options.upstream.port });
  const gate = options.layer === undefined ? new ShapeGate() : null;
  const layer: Layer = options.layer ?? gate!;
  const composer = new LayerComposer(layer, { timeoutMs: 250, maxConcurrent: 64, failurePolicy: "fail_closed", ...options.composer });
  const bodyDeadlineMs = options.bodyDeadlineMs ?? 5_000;
  const egressTimeoutMs = options.egressTimeoutMs ?? 5_000;
  const maxResponseBytes = options.maxResponseBytes ?? 1_048_576;
  const agent = new http.Agent({ keepAlive: false });
  const stats: FrontStats = { accepted: 0, inFlight: 0, inFlightHighWater: 0, parserRejected: 0, proxied: 0, completed: 0, aborted: 0, strippedHeaders: 0 };
  const sockets = new Set<import("node:net").Socket>();
  const hopStats: HopStats = { issued: 0, signFailures: 0, droppedUnbound: 0 };

  // requireHostHeader is off so a missing Host is a measured L1 rejection (a7.host_header_invalid) rather than an unattributed parser answer.
  const server = http.createServer({ maxHeaderSize: 16_384, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 5_000, requireHostHeader: false }, (req, res) => {
    void handle(req, res).catch(() => { if (!res.writableEnded) res.destroy(); });
  });
  server.maxConnections = 512;
  server.on("connection", (socket) => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });

  // The HTTP parser refused the bytes before any request existed. There is no nonce to attribute; the event is anonymous and the
  // collector reconciles it against the harness's own count of cases it expected to be refused at this stage.
  server.on("clientError", (error: NodeJS.ErrnoException, socket) => {
    const code = error.code ?? "";
    if (PARSER_CODES.has(code) && socket.writable) {
      stats.parserRejected++;
      options.emit({ nonce: null, kind: "PARSER_REJECTED", code });
      const status = code === "HPE_HEADER_OVERFLOW" ? "431 Request Header Fields Too Large" : "400 Bad Request";
      socket.end(`HTTP/1.1 ${status}\r\nconnection: close\r\ncontent-length: 0\r\n${OUTCOME_HEADER}: parser_rejected\r\n\r\n`);
      return;
    }
    socket.destroy();
  });

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // --- ingress: read the correlation nonce (measurement only) and strip every spoofable header from what happens next
    const rawNonces: string[] = [];
    const layerHeaders: [string, string][] = [];
    let stripped = 0;
    for (let index = 0; index + 1 < req.rawHeaders.length; index += 2) {
      const name = req.rawHeaders[index].toLowerCase();
      const value = req.rawHeaders[index + 1];
      // The harness correlation header is consumed here and is not counted as a stripped spoof attempt.
      if (name === NONCE_HEADER) { rawNonces.push(value); continue; }
      if (isSpoofableHeader(name)) { stripped++; continue; }
      layerHeaders.push([name, value]);
    }
    const correlated = rawNonces.length === 1 && NONCE_PATTERN.test(rawNonces[0]);
    const nonce = correlated ? rawNonces[0] : mintNonce();
    stats.accepted++;
    stats.strippedHeaders += stripped;
    stats.inFlight++;
    if (stats.inFlight > stats.inFlightHighWater) stats.inFlightHighWater = stats.inFlight;
    options.emit({ nonce, kind: "INGRESS_ACCEPTED", stripped, ...(correlated ? {} : { uncorrelated: true }) });

    const closed = new Promise<void>((resolve) => res.once("close", () => resolve()));
    let unreadBody = false;
    try {
      // --- bounded body read, decided from the declared length BEFORE reading anything
      const lengths = layerHeaders.filter(([name]) => name === "content-length").map(([, value]) => value);
      const declared = lengths.length === 1 && /^(?:0|[1-9][0-9]{0,8})$/.test(lengths[0]) ? Number(lengths[0]) : null;
      let bodyStatus: BodyStatus = "none";
      let body: Uint8Array | null = null;
      if (req.method === "POST" && declared !== null) {
        if (declared > L1_LIMITS.maxBodyBytes) { bodyStatus = "declared_oversize"; unreadBody = true; }
        else if (declared === 0) { bodyStatus = "complete"; body = new Uint8Array(); }
        else {
          const result = await readBody(req, declared, bodyDeadlineMs);
          bodyStatus = result.status; body = result.body;
          if (bodyStatus !== "complete") unreadBody = true;
        }
      }

      // --- L1 through the composer: exactly one explicit outcome
      options.emit({ nonce, kind: "L1_ENTERED" });
      const layerRequest: LayerRequest = { method: req.method ?? "", target: req.url ?? "", headers: layerHeaders, bodyStatus, body };
      let outcome = await composer.run(layerRequest);
      // Harness-only seam (never present in a normal composition): a REAL refusal may be delivered as a pass. The layer evaluated; the
      // shadow verdict is recorded and the delivered one is permanently labelled simulated.
      let l1Shadow: string | null = null;
      if (options.verdictOverride && outcome.kind === "reject") {
        const simulated = options.verdictOverride.l1({ request: layerRequest, nonce: correlated ? nonce : "", remotePort: req.socket.remotePort, outcome });
        if (simulated) { l1Shadow = simulated.shadow; outcome = { kind: "pass" }; }
      }
      emitVerdict(nonce, outcome, l1Shadow);

      // --- L2 (Slice 3): exactly one correlated decision follows every L2_ENTERED
      let l2Decision: LaneDecision | null = null;
      let l2Shadow: string | null = null;
      if (outcome.kind === "pass" && options.l2) {
        options.emit({ nonce, kind: "L2_ENTERED" });
        l2Decision = await options.l2.decide(layerRequest);
        if (options.verdictOverride && (l2Decision.outcome === "shed" || l2Decision.outcome === "admitted")) {
          const simulated = options.verdictOverride.l2({ request: layerRequest, nonce: correlated ? nonce : "", remotePort: req.socket.remotePort, decision: l2Decision });
          if (simulated) {
            l2Shadow = simulated.shadow;
            l2Decision = { ...l2Decision, outcome: "admitted", shedReason: undefined, lane: l2Decision.lane ?? "unverified", basis: "simulated", shadow: simulated.shadow };
          }
        }
        emitL2Decision(nonce, l2Decision);
      }
      const refusedByL2 = l2Decision !== null && l2Decision.outcome !== "admitted" && l2Decision.outcome !== "degraded";

      let observation: EnrollmentObservation | null = null;
      if (outcome.kind !== "pass") {
        const [status, label] = refusal(outcome);
        respondRefusal(res, status, label, unreadBody);
      } else if (l2Decision !== null && refusedByL2) {
        respondRefusal(res, 503, l2Decision.outcome === "shed" ? "l2_shed" : "l2_error", unreadBody);
      } else {
        const hop = options.emit({ nonce, kind: "EGRESS_ATTEMPTED" });
        stats.proxied++;
        if (options.l2 && l2Decision) {
          observation = options.l2.observe(layerRequest, l2Decision, { simulated: l1Shadow !== null || l2Shadow !== null, emit: (event) => { options.emit({ nonce, ...event }); } });
        }
        if (options.hop === undefined) await forward(req, res, layerHeaders, body, nonce, hop, undefined, observation);
        else await forwardApproved(req, res, layerRequest, body, nonce, hop, options.hop, observation);
      }
      if (!res.writableEnded && !res.destroyed) res.end();
      if (!res.destroyed) await closed;
      // Exactly one enrollment disposition per observed render, decided before the request's terminal event.
      try { observation?.finalize(); } catch { /* an observer fault never changes a response */ }
      if (unreadBody) req.resume();
      if (res.writableFinished) { stats.completed++; options.emit({ nonce, kind: "INGRESS_RESPONDED", status: res.statusCode }); }
      else { stats.aborted++; options.emit({ nonce, kind: "INGRESS_ABORTED" }); }
    } finally {
      stats.inFlight--;
      if (unreadBody) setTimeout(() => { if (!req.socket.destroyed) req.socket.destroy(); }, 1_000).unref();
    }
  }

  function emitL2Decision(nonce: string, decision: LaneDecision): void {
    options.emit({
      nonce, kind: "L2_DECIDED", class: decision.class, lane: decision.lane, outcome: decision.outcome,
      ...(decision.shedReason !== undefined ? { shedReason: decision.shedReason } : {}),
      ...(decision.errorKind !== undefined ? { l2ErrorKind: decision.errorKind } : {}),
      ...(decision.spent !== undefined ? { spent: decision.spent } : {}),
      ...(decision.touched !== undefined ? { touched: decision.touched } : {}),
      ...(decision.creditTag !== undefined ? { creditTag: decision.creditTag } : {}),
      ...(decision.dt !== undefined ? { dt: decision.dt, lvl: decision.lvl, lseq: decision.lseq } : {}),
      ...(decision.basis !== undefined ? { basis: decision.basis, shadow: decision.shadow } : {}),
    });
  }

  function emitVerdict(nonce: string, outcome: LayerOutcome, shadow: string | null = null): void {
    if (outcome.kind === "pass") options.emit({ nonce, kind: "L1_PASSED", ...(shadow !== null ? { basis: "simulated" as const, shadow } : {}) });
    else if (outcome.kind === "reject") options.emit({ nonce, kind: "L1_REJECTED", reason: outcome.reason, stage: REJECT_STAGE[outcome.reason] });
    else if (outcome.kind === "shed") options.emit({ nonce, kind: "L1_SHED" });
    else options.emit({ nonce, kind: "L1_ERROR", errorKind: outcome.errorKind });
  }

  function refusal(outcome: Exclude<LayerOutcome, { kind: "pass" }>): [number, string] {
    if (outcome.kind === "reject") return [REJECT_STATUS[outcome.reason], "rejected"];
    return [503, outcome.kind === "shed" ? "shed" : "error"];
  }

  function respondRefusal(res: http.ServerResponse, status: number, label: string, closeConnection: boolean): void {
    if (res.destroyed) return;
    res.writeHead(status, {
      "content-type": "application/json", "content-length": REFUSAL_BODY.length, "cache-control": "no-store", [OUTCOME_HEADER]: label,
      ...(closeConnection ? { connection: "close" } : {}),
    });
    res.end(REFUSAL_BODY);
  }

  /**
   * Slice 2: the semantic request the layer approved is re-derived (a pure function of the same LayerRequest), a PB proof is issued for
   * it, and ONLY the rebuilt request is sent: never a raw client header, never the plain nonce/hop headers. A failure to issue is an
   * explicit EGRESS_FAILED (fail closed): nothing is sent unsigned.
   */
  function forwardApproved(req: http.IncomingMessage, res: http.ServerResponse, layerRequest: LayerRequest, body: Uint8Array | null, nonce: string, hop: number, issuer: HopIssuer, observation: EnrollmentObservation | null = null): Promise<void> {
    let prebuilt: { method: string; path: string; headers: Record<string, string> };
    let failStage: "canon" | "sign" = "canon";
    try {
      const built = buildApprovedRequest(layerRequest);
      if (!built.ok) throw new Error("the approved request is not reproducible");
      failStage = "sign";
      hopStats.droppedUnbound += built.dropped;
      const issued = issuer.issue(built.approved, { hop, corr: nonce });
      hopStats.issued++;
      options.emit({ nonce, kind: "PROOF_ISSUED", pbTag: issued.tag });
      prebuilt = { method: built.approved.method, path: built.approved.target, headers: { ...semanticWireHeaders(built.approved), [HOP_PB_HEADER]: issued.header } };
    } catch {
      hopStats.signFailures++;
      options.emit({ nonce, kind: "EGRESS_FAILED", egressError: "error", ...(options.l2 ? { failStage } : {}) });
      respondRefusal(res, 502, "egress_failed", false);
      return Promise.resolve();
    }
    return forward(req, res, [], body, nonce, hop, prebuilt, observation);
  }

  function forward(req: http.IncomingMessage, res: http.ServerResponse, headers: readonly (readonly [string, string])[], body: Uint8Array | null, nonce: string, hop: number, prebuilt?: { method: string; path: string; headers: Record<string, string> }, observation: EnrollmentObservation | null = null): Promise<void> {
    return new Promise<void>((resolve) => {
      const outbound: Record<string, string> = {};
      if (prebuilt) Object.assign(outbound, prebuilt.headers);
      else {
        for (const [name, value] of headers) if (FORWARD_REQUEST_HEADERS.has(name)) outbound[name] = value;
        outbound[NONCE_HEADER] = nonce;
        outbound[HOP_HEADER] = String(hop);
      }
      let settled = false;
      const fail = (kind: EgressErrorKind) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        options.emit({ nonce, kind: "EGRESS_FAILED", egressError: kind });
        respondRefusal(res, kind === "timeout" ? 504 : 502, "egress_failed", false);
        resolve();
      };
      const upstreamRequest = http.request({ host: upstream.host, port: upstream.port, method: prebuilt?.method ?? req.method, path: prebuilt?.path ?? req.url, headers: outbound, agent }, (upstreamResponse) => {
        const chunks: Buffer[] = [];
        let total = 0;
        upstreamResponse.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxResponseBytes) { upstreamRequest.destroy(); fail("error"); return; }
          chunks.push(chunk);
        });
        upstreamResponse.on("error", () => fail("reset"));
        upstreamResponse.on("aborted", () => fail("reset"));
        upstreamResponse.on("end", () => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          const status = upstreamResponse.statusCode ?? 502;
          options.emit({ nonce, kind: "EGRESS_RESPONDED", status });
          const payload = Buffer.concat(chunks);
          try { observation?.onUpstream({ status, rawHeaders: upstreamResponse.rawHeaders, payload }); } catch { /* an observer fault never changes a response */ }
          const responseHeaders: Record<string, string | number> = {};
          for (const [name, value] of Object.entries(upstreamResponse.headers)) {
            if (FORWARD_RESPONSE_HEADERS.has(name) && typeof value === "string") responseHeaders[name] = value;
          }
          responseHeaders["content-length"] = payload.length;
          responseHeaders[OUTCOME_HEADER] = "proxied";
          if (!res.destroyed) {
            // Enrollment happens only once the response was completely flushed to the client: `finish` never fires for an aborted response.
            if (observation) res.once("finish", () => { try { observation.onDelivered(); } catch { /* an observer fault never changes a response */ } });
            res.writeHead(status, responseHeaders); res.end(payload);
          }
          resolve();
        });
      });
      const timer = setTimeout(() => { upstreamRequest.destroy(); fail("timeout"); }, egressTimeoutMs);
      upstreamRequest.on("error", (error) => fail(egressErrorKind(error)));
      upstreamRequest.end(body === null || body.length === 0 ? undefined : Buffer.from(body));
    });
  }

  return {
    gate,
    listen: () => new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve((server.address() as AddressInfo).port); });
    }),
    close: (deadlineMs = 2_000) => new Promise<void>((resolve) => {
      server.close(() => { agent.destroy(); resolve(); });
      const timeout = setTimeout(() => { for (const socket of sockets) socket.destroy(); }, deadlineMs);
      timeout.unref();
      server.closeIdleConnections();
    }),
    stats: () => ({ ...stats }),
    hopStats: () => ({ ...hopStats }),
    layerComposerStats: () => composer.stats(),
    composerOccupancy: () => composer.occupancy,
  };
}
