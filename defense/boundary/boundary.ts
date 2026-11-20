/**
 * The Origin Boundary: a separate process that admits a request only when it carries a valid Plane-to-Boundary (PB) proof, then issues
 * a distinct Boundary-to-App (BA) proof and forwards the request, REBUILT from the verified claims, to the one fixed loopback App.
 *
 * It verifies authenticity before applying any configured origin capacity policy. It has no input from the Defense Plane's liveness, so a
 * Plane failure cannot change what it accepts. There is no configuration, flag or mode that makes it pass anything unauthenticated, and no
 * unauthenticated route (not even a health check). A body byte is read only after the proof's signature and the replay reservation.
 *
 * This is application-layer refusal on an open socket. It is NOT network or transport isolation and says nothing about volumetric,
 * handshake or connection-state exhaustion.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { KeyObject } from "node:crypto";
import { createOriginCapacityBoundary } from "../core/capacity-boundary";
import type { CapacityExecutionEvidence, CapacitySnapshot, CompiledCustomerOriginPolicy, HttpScheme } from "../core/capacity-port";
import type { BoundaryEvent, EgressErrorKind } from "../core/ledger";
import { EGRESS_ERROR_KINDS } from "../core/ledger";
import { admitHopRequest, newAdmissionStats, type Admitted, type PbAdmissionConfig, type Refused } from "../core/hop-admission";
import { issueBa, type BaIssuerConfig } from "../core/hop-proof";
import { ClockFence, ReplayGuard } from "../core/replay-guard";
import { HOP_BA_HEADER, HOP_PB_HEADER, readMeasurementTag, semanticWireHeaders } from "../core/semantic-request";
import { OB_REASONS, type ObReason } from "../core/types";
import { createBoundaryExecution, EXECUTION_HEADER, TERMINAL_HEADER, type BoundaryExecutionOptions } from "../origin/execution-fence";
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
  /** Local integration only. The fixed origin must implement execution fencing. */
  capacity?: {
    policy: CompiledCustomerOriginPolicy;
    principal: string;
    /** Policy audience ID bound by this configuration to the PB boundaryId. */
    audience: string;
    scheme: HttpScheme;
    backendRef: string;
    execution?: BoundaryExecutionOptions;
  };
  /** Injected for tests; the process entry uses the real clocks. */
  now?: () => number;
  mono?: () => number;
};

export type Boundary = {
  listen(): Promise<number>;
  close(): Promise<void>;
  stats(): BoundaryStats & { capacity?: { state: "ready" | "unavailable"; refused: number; usage?: CapacitySnapshot } };
};
type CapacityBoundary = Boundary & { reconcile(): Promise<boolean> };

type ExecutionResult = "completed" | "never-started" | "ambiguous";
type ForwardReservation = { finish(result: ExecutionResult): void; isFresh(): boolean };

function initializeCapacity(config: NonNullable<BoundaryOptions["capacity"]>, boundaryId: string, wall: () => number, mono: () => number) {
  const { policy, principal, audience, scheme, backendRef } = config;
  const { manifest } = policy;
  if (manifest.domain.backendRef !== backendRef ||
      !manifest.channels.some((channel) => channel.principal === principal && channel.audience === audience && channel.scheme === scheme)) {
    throw new Error("capacity policy does not match the fixed origin binding");
  }
  const runtime = createOriginCapacityBoundary<Admitted, ExecutionResult>(policy, {
    // M2 accepts exact binary ticks of 1/1024 ms. Native performance.now() has arbitrary fractions.
    monotonicMs: () => Math.floor(mono() * 1024) / 1024,
    wallUpperMs: () => wall() + 1,
  }, {
    // Only handle() supplies candidates, after PB signature, wire semantics, body digest and replay verification.
    verify(candidate, activated, _wall, body) {
      const { claims, request } = candidate;
      if (claims.role !== "pb" || claims.aud !== boundaryId || body?.byteLength !== request.bodyLen) return { ok: false, reason: "unverified" };
      for (let index = 0; index < body.byteLength; index++) {
        if (body.byteAt(index) !== candidate.body[index]) return { ok: false, reason: "unverified" };
      }
      const pairs = new Map(request.pairs);
      return { ok: true, authenticated: {
        tenantId: activated.manifest.tenantId, deploymentId: activated.manifest.deploymentId,
        domainId: activated.manifest.domain.id, digest: activated.digest,
        principal, audience, scheme, authority: pairs.get("host") ?? "",
        method: request.method, target: request.target, mediaType: pairs.get("content-type") ?? null,
        bodyBytes: request.bodyLen, origin: pairs.get("origin") ?? null, proofExpiresAtWallMs: claims.exp,
      } };
    },
  }, {
    // Evidence stays in this process and is supplied only by the local forward lifecycle.
    verify: (identity, kind): CapacityExecutionEvidence => ({ ...identity, kind }),
  });
  return { ...runtime, limits: manifest.capacity };
}

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

export function createBoundary(options: BoundaryOptions & { capacity: NonNullable<BoundaryOptions["capacity"]> }): CapacityBoundary;
export function createBoundary(options: BoundaryOptions): Boundary;
export function createBoundary(options: BoundaryOptions): Boundary | CapacityBoundary {
  if (!Number.isInteger(options.appPort) || options.appPort < 1 || options.appPort > 65_535) throw new Error("the app must be a fixed 127.0.0.1 port");
  const wall = options.now ?? (() => Date.now());
  const mono = options.mono ?? (() => performance.now());
  const capacityConfig = options.capacity;
  const capacityConfigured = capacityConfig !== undefined;
  let capacity: ReturnType<typeof initializeCapacity> | undefined;
  let execution: ReturnType<typeof createBoundaryExecution> | undefined;
  if (capacityConfig !== undefined) {
    try { capacity = initializeCapacity(capacityConfig, options.boundaryId, wall, mono); }
    catch { /* A configured origin fails closed, while proof admission remains independent. */ }
    if (capacityConfig.execution && capacity) {
      try { execution = createBoundaryExecution(capacityConfig.execution, capacityConfig.backendRef, options.appPort, options.limits.forwardTimeoutMs); }
      catch { /* An invalid origin credential leaves capacity admission closed. */ }
    }
  }
  let capacityRefused = 0;
  let capacityHealthy = capacity !== undefined;
  let generationReady = false;
  let reconciliation: Promise<boolean> | undefined;
  const capacityForwards = new Set<Promise<void>>();
  let startup: Promise<number> | undefined;
  let shutdown: Promise<void> | undefined;
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
  const emit = (event: Parameters<BoundaryOptions["emit"]>[0]) => {
    try { options.emit(event); } catch { /* A failing diagnostic sink cannot interrupt request cleanup. */ }
  };

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
      emit({ nonce: null, kind: "BOUNDARY_PARSER_REJECTED", code });
      socket.end(`HTTP/1.1 ${code === "HPE_HEADER_OVERFLOW" ? "431 Request Header Fields Too Large" : "400 Bad Request"}\r\nconnection: close\r\ncontent-length: 0\r\nx-ba0-outcome: refused\r\n\r\n`);
      return;
    }
    socket.destroy();
  });
  // No 100-continue invitation to an unauthenticated sender, no upgrade, no tunnel.
  server.on("checkContinue", (req, res) => { refuse(res, { ok: false, reason: "ob.expect_refused", nonce: readMeasurementTag(req.rawHeaders) }); });
  server.on("upgrade", (_req, socket) => { counters.protocolRefused++; emit({ nonce: null, kind: "BOUNDARY_PROTOCOL_REFUSED", code: "upgrade" }); socket.destroy(); });
  server.on("connect", (_req, socket) => { counters.protocolRefused++; emit({ nonce: null, kind: "BOUNDARY_PROTOCOL_REFUSED", code: "connect" }); socket.destroy(); });

  /** Exactly one terminal event per request, whatever happens to the connection. */
  function track(res: http.ServerResponse, nonce: string | null): void {
    res.once("close", () => {
      if (res.writableFinished) { counters.responded++; emit({ nonce, kind: "BOUNDARY_RESPONDED", status: res.statusCode }); }
      else { counters.aborted++; emit({ nonce, kind: "BOUNDARY_ABORTED" }); }
    });
  }

  /** One uniform answer for every authentication failure: same status, no body, connection closed. The reason exists only in telemetry. */
  function refuse(res: http.ServerResponse, refused: Refused): void {
    counters.arrived++;
    counters.rejected++;
    rejectedByReason[refused.reason] = (rejectedByReason[refused.reason] ?? 0) + 1;
    emit({ nonce: refused.nonce, kind: "BOUNDARY_ARRIVED" });
    emit({ nonce: refused.nonce, kind: "BOUNDARY_REJECTED", reason: refused.reason as ObReason });
    track(res, refused.nonce);
    if (res.writableEnded || res.destroyed) return;
    // Cache exhaustion and an expiry-horizon hold are only reachable AFTER a proof verified, so a distinct status tells an unauthenticated sender nothing.
    res.writeHead(refused.reason === "ob.replay_cache_full" || refused.reason === "ob.expiry_horizon" ? 503 : 403, { "content-length": 0, connection: "close", "x-ba0-outcome": "refused" });
    res.end();
    const socket = res.socket;
    if (socket) setTimeout(() => { if (!socket.destroyed) socket.destroy(); }, 1_000).unref();
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const closed = new Promise<void>((resolve) => res.once("close", resolve));
    const outcome = await admitHopRequest(admission, {
      method: req.method ?? "", url: req.url ?? "", rawHeaders: req.rawHeaders, stream: req,
      crossCheck: (claims) => claims.pairs.every(([name, value]) => req.headers[name] === value) && (["content-type", "host", "origin"] as const).every((name) => req.headers[name] === undefined || claims.pairs.some(([key]) => key === name)),
    });
    if (!outcome.ok) { refuse(res, outcome); return; }

    const nonce = outcome.nonce;
    counters.arrived++;
    counters.admitted++;
    emit({ nonce, kind: "BOUNDARY_ARRIVED" });
    emit({ nonce, kind: "BOUNDARY_ADMITTED", hop: outcome.hop, pbTag: outcome.pbTag });
    // The terminal event is emitted only after everything the request did, so a client that vanishes cannot put it ahead of the forward events.
    try {
      if (!res.destroyed && !req.socket.destroyed) await relayAdmitted(res, outcome);
    } catch {
      res.destroy();
    } finally {
      await closed;
      if (res.writableFinished) { counters.responded++; emit({ nonce, kind: "BOUNDARY_RESPONDED", status: res.statusCode }); }
      else { counters.aborted++; emit({ nonce, kind: "BOUNDARY_ABORTED" }); }
    }
  }

  async function relayAdmitted(res: http.ServerResponse, outcome: Admitted): Promise<void> {
    const runtime = capacity;
    let reservation: ForwardReservation | undefined;
    let body: Uint8Array = outcome.body;
    const refuseCapacity = () => { capacityRefused++; sendStatus(res, 503, "capacity_refused"); };
    try {
      if (capacityConfigured) {
        const startedMono = mono();
        const attempt = capacityHealthy && generationReady && !shutdown ? runtime?.request.begin() : undefined;
        if (!runtime || !attempt) { refuseCapacity(); return; }
        const granted = runtime.request.submit(attempt, { candidate: outcome, body });
        if (granted?.kind !== "granted") {
          // Stage 1 dispatches immediately or sheds. A queued attempt never survives this stack frame.
          runtime.request.cancel(attempt);
          refuseCapacity();
          return;
        }
        const identity = runtime.execution.identity(granted.lease);
        if (!identity) { disableCapacity(); refuseCapacity(); return; }
        let reported = false;
        reservation = {
          finish(result) {
            if (reported) return;
            reported = true;
            const event = runtime.execution.verify(identity.lease, identity.execution, result);
            if (!event || !runtime.execution.settle(event)) disableCapacity();
          },
          isFresh() {
            const elapsed = mono() - startedMono;
            return elapsed >= 0 && elapsed < options.limits.baLifetimeMs && runtime.execution.canDispatch(identity.lease, identity.execution);
          },
        };
        const owned = runtime.execution.takeBody(identity.lease, identity.execution);
        if ((owned?.byteLength ?? 0) !== body.byteLength) { disableCapacity(); refuseCapacity(); return; }
        body = owned ?? body;
      }
      const issued = issueBa(baIssuer, outcome.pb);
      const wireExecution = reservation && execution ? execution.request(issued.header) : undefined;
      const headers = { ...semanticWireHeaders(outcome.request), [HOP_BA_HEADER]: issued.header, [HOP_PB_HEADER]: outcome.pb.header,
        ...(wireExecution && { [EXECUTION_HEADER]: wireExecution.header }) };
      if (reservation && !reservation.isFresh()) {
        refuseCapacity();
        return;
      }
      counters.appProofsIssued++;
      emit({ nonce: outcome.nonce, kind: "APP_PROOF_ISSUED", hop: outcome.hop, pbTag: outcome.pbTag, baTag: issued.tag });
      const pending = forward(res, outcome, issued.tag, headers, body, reservation, wireExecution?.evidence);
      reservation = undefined;
      if (runtime) capacityForwards.add(pending);
      try { await pending; }
      finally { capacityForwards.delete(pending); }
    } catch {
      if (res.headersSent) res.destroy();
      else sendStatus(res, 503, "refused");
    } finally {
      reservation?.finish("never-started");
    }
  }

  function disableCapacity(): void {
    capacityHealthy = false;
    capacity?.maintenance.close();
  }

  function sendStatus(res: http.ServerResponse, status: number, label: string): void {
    if (res.writableEnded || res.destroyed) return;
    res.writeHead(status, { "content-length": 0, "x-ba0-outcome": label, "cache-control": "no-store" });
    res.end();
  }

  function forward(res: http.ServerResponse, { nonce, hop, pbTag, request }: Admitted, baTag: string, headers: Record<string, string>, body: Uint8Array,
    reservation?: ForwardReservation, verifyTerminal?: (proof: string | undefined) => ExecutionResult | undefined): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      let writeStarted = false;
      let terminal: ExecutionResult = "ambiguous";
      const fail = (kind: EgressErrorKind, capacityRefusal = false) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        upstreamRequest.destroy();
        reservation?.finish(!writeStarted ? "never-started" : terminal);
        counters.forwardFailed++;
        forwardFailedByKind[kind]++;
        emit({ nonce, kind: "BOUNDARY_FORWARD_FAILED", forwardError: kind });
        if (capacityRefusal) {
          capacityRefused++;
          sendStatus(res, 503, "capacity_refused");
        } else {
          sendStatus(res, kind === "timeout" ? 504 : 502, "forward_failed");
        }
        resolve();
      };
      const onResponse = (upstreamResponse: http.IncomingMessage) => {
        const proofs = upstreamResponse.headersDistinct[TERMINAL_HEADER];
        if (proofs?.length === 1) terminal = verifyTerminal?.(proofs[0]) ?? "ambiguous";
        const chunks: Buffer[] = [];
        let total = 0;
        upstreamResponse.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) { fail("error"); return; }
          chunks.push(chunk);
        });
        upstreamResponse.on("error", () => fail("reset"));
        upstreamResponse.on("aborted", () => fail("reset"));
        upstreamResponse.once("close", () => { if (!upstreamResponse.complete) fail("reset"); });
        upstreamResponse.on("end", () => {
          if (settled) return;
          if (!upstreamResponse.complete) { fail("reset"); return; }
          settled = true;
          clearTimeout(timer);
          const status = upstreamResponse.statusCode ?? 502;
          reservation?.finish(terminal);
          counters.forwardResponded++;
          emit({ nonce, kind: "BOUNDARY_FORWARD_RESPONDED", status });
          const payload = Buffer.concat(chunks);
          const relayed: Record<string, string | number> = {};
          for (const [name, value] of Object.entries(upstreamResponse.headers)) if (RELAY_RESPONSE_HEADERS.has(name) && typeof value === "string") relayed[name] = value;
          relayed["content-length"] = payload.length;
          if (!res.destroyed) { res.writeHead(status, relayed); res.end(payload); }
          resolve();
        });
      };
      let upstreamRequest: http.ClientRequest;
      try {
        upstreamRequest = http.request({ host: upstream.host, port: upstream.port, method: request.method, path: request.target, headers, agent }, onResponse);
      } catch (error) {
        reservation?.finish("never-started");
        reject(error);
        return;
      }
      // A downstream disconnect does not attest origin termination. Drain the bounded upstream response when possible.
      const timeout = capacity ? Math.min(options.limits.forwardTimeoutMs, capacity.limits.executionTimeoutMs) : options.limits.forwardTimeoutMs;
      const timer = setTimeout(() => fail("timeout"), timeout);
      upstreamRequest.on("error", (error) => fail(forwardErrorKind(error)));
      upstreamRequest.once("close", () => fail("reset"));
      upstreamRequest.once("upgrade", (_response, socket) => { socket.destroy(); fail("error"); });
      const write = () => {
        if (settled) return;
        try {
          if (reservation && (res.destroyed || res.socket?.destroyed)) { fail("reset"); return; }
          if (reservation && (shutdown || !capacityHealthy || !generationReady || !reservation.isFresh())) { fail("error", true); return; }
          writeStarted = true;
          upstreamRequest.end(body.length === 0 ? undefined : body);
        }
        catch { fail("error"); }
      };
      counters.relayed++;
      emit({ nonce, kind: "BOUNDARY_FORWARDED", hop, pbTag, baTag });
      if (reservation) {
        // No request bytes are handed to Node before this gate. Destroy plus `settled` fences
        // a delayed connect callback, including on timeout and shutdown before dispatch.
        upstreamRequest.once("socket", (socket) => {
          if (socket.connecting) socket.once("connect", write);
          else write();
        });
      } else {
        write();
      }
    });
  }

  const boundary: Boundary = {
    listen,
    close,
    stats: () => ({
      ...counters, rejectedByReason: { ...rejectedByReason }, forwardFailedByKind: { ...forwardFailedByKind }, replay: guard.stats(),
      contentReadsStarted: admissionStats.contentReadsStarted, contentBytesRead: admissionStats.contentBytesRead, clockStepMs: fence.stepMs(), clockStep: fence.stepDetected(),
      ...(capacityConfigured && { capacity: capacity
        ? { state: capacityHealthy && generationReady && !shutdown ? "ready" as const : "unavailable" as const, refused: capacityRefused, usage: capacity.request.snapshot() }
        : { state: "unavailable" as const, refused: capacityRefused } }),
    }),
  };
  return capacityConfigured ? Object.assign(boundary, { reconcile }) : boundary;

  function reconcile(): Promise<boolean> {
    if (!execution || !capacityHealthy || shutdown) return Promise.resolve(false);
    if (reconciliation) return reconciliation;
    reconciliation = execution.reconcile().then((ready) => {
      generationReady = ready && capacityHealthy && !shutdown;
      return generationReady;
    }, () => { generationReady = false; return false; }).finally(() => { reconciliation = undefined; });
    return reconciliation;
  }

  function listen(): Promise<number> {
    if (shutdown) return Promise.reject(new Error("boundary is closed"));
    return startup ??= new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        if (shutdown) reject(new Error("boundary is closed"));
        else resolve((server.address() as AddressInfo).port);
      });
    });
  }

  function close(): Promise<void> {
    if (shutdown) return shutdown;
    capacity?.maintenance.close();
    shutdown = (startup ?? Promise.resolve()).catch(() => undefined).then(async () => {
      await new Promise<void>((resolve) => {
        const timeout = setTimeout(() => { for (const socket of sockets) socket.destroy(); }, 1_000);
        timeout.unref();
        server.close(() => { clearTimeout(timeout); resolve(); });
        server.closeIdleConnections();
      });
      // Downstream shutdown ends delivery. Charged upstream work still gets its bounded drain.
      await Promise.allSettled(capacityForwards);
      agent.destroy();
    });
    return shutdown;
  }
}
