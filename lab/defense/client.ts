/**
 * Harness-side clients. Every request gets a unique opaque nonce, is registered in the collector BEFORE any byte is written (SENT)
 * and is completed in the collector exactly once with what the client actually observed. The traffic-class label lives only in the
 * collector's metadata; it is never put on the wire.
 */
import { randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { NONCE_HEADER, OUTCOME_HEADER } from "../../defense/core/types";
import type { ClientResultKind } from "../../defense/core/ledger";
import type { Collector, RequestMeta } from "./collector";

export const newNonce = (): string => randomBytes(16).toString("base64url");

export type Exchange = {
  nonce: string;
  result: ClientResultKind;
  status: number | null;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  latencyMs: number;
  outcomeHeader: string | undefined;
  registered: boolean;
};

export type HttpSpec = { method: string; path: string; headers?: Record<string, string>; body?: string };

const agent = new http.Agent({ keepAlive: false });
const MAX_CLIENT_BODY = 1_048_576;

function classify(error: unknown): ClientResultKind {
  const code = (error as { code?: string } | null)?.code;
  return code === "ECONNRESET" || code === "EPIPE" || code === "ECONNREFUSED" ? "reset" : "error";
}

/**
 * A tracked HTTP exchange against <host>:<port> (default 127.0.0.1). Always resolves; never throws. `host` exists for the field canary, which
 * reaches the Defense Plane at its reviewed bound address; every Slice-1/2/3 caller omits it.
 */
export async function trackedHttp(collector: Collector, port: number, meta: RequestMeta, spec: HttpSpec, timeoutMs: number, host = "127.0.0.1"): Promise<Exchange> {
  const nonce = newNonce();
  const registered = collector.sent(nonce, meta);
  const started = performance.now();
  // Idempotent: whichever event settles first completes the ledger record; later events (a late error after the response) are ignored.
  let final: Exchange | null = null;
  const finish = (partial: Omit<Exchange, "nonce" | "latencyMs" | "registered">): Exchange => {
    if (final) return final;
    const latencyMs = performance.now() - started;
    if (registered) collector.clientCompleted(nonce, { result: partial.result, status: partial.status ?? undefined, outcomeHeader: partial.outcomeHeader, latencyMs });
    final = { ...partial, nonce, latencyMs, registered };
    return final;
  };
  if (!registered) return finish({ result: "error", status: null, headers: {}, body: Buffer.alloc(0), outcomeHeader: undefined });
  return new Promise<Exchange>((resolve) => {
    let done = false;
    const settle = (value: Exchange) => { if (!done) { done = true; clearTimeout(timer); resolve(value); } };
    const headers: Record<string, string> = { ...(spec.headers ?? {}), [NONCE_HEADER]: nonce };
    if (spec.body !== undefined) headers["content-length"] = String(Buffer.byteLength(spec.body));
    const request = http.request({ host, port, method: spec.method, path: spec.path, headers, agent }, (response) => {
      const chunks: Buffer[] = [];
      let total = 0;
      response.on("data", (chunk: Buffer) => { total += chunk.length; if (total <= MAX_CLIENT_BODY) chunks.push(chunk); });
      response.on("error", (error) => settle(finish({ result: classify(error), status: null, headers: {}, body: Buffer.alloc(0), outcomeHeader: undefined })));
      response.on("end", () => {
        const outcome = response.headers[OUTCOME_HEADER];
        settle(finish({ result: "response", status: response.statusCode ?? null, headers: response.headers, body: Buffer.concat(chunks), outcomeHeader: typeof outcome === "string" ? outcome : undefined }));
      });
    });
    const timer = setTimeout(() => { request.destroy(); settle(finish({ result: "timeout", status: null, headers: {}, body: Buffer.alloc(0), outcomeHeader: undefined })); }, timeoutMs);
    request.on("error", (error) => settle(finish({ result: classify(error), status: null, headers: {}, body: Buffer.alloc(0), outcomeHeader: undefined })));
    request.end(spec.body);
  });
}

export type RawSpec = {
  /** Bytes written immediately. */
  head: Buffer;
  /** Optional bytes written after `afterMs` (used to stall a body). */
  tail?: Buffer;
  afterMs?: number;
  /** When set, the client drops the connection this long after connecting (a client that vanishes mid-request). */
  closeAfterMs?: number;
};

/** A tracked raw-TCP exchange: the exact bytes are written, nothing is normalised by an HTTP client. */
export async function trackedRaw(collector: Collector, port: number, meta: RequestMeta, build: (nonce: string) => RawSpec, timeoutMs: number, beforeWrite?: (socket: net.Socket, nonce: string) => Promise<void>): Promise<Exchange> {
  const nonce = newNonce();
  const registered = collector.sent(nonce, meta);
  const started = performance.now();
  let final: Exchange | null = null;
  const finish = (result: ClientResultKind, status: number | null, outcomeHeader: string | undefined): Exchange => {
    if (final) return final;
    const latencyMs = performance.now() - started;
    if (registered) collector.clientCompleted(nonce, { result, status: status ?? undefined, outcomeHeader, latencyMs });
    final = { nonce, result, status, headers: {}, body: Buffer.alloc(0), latencyMs, outcomeHeader, registered };
    return final;
  };
  if (!registered) return finish("error", null, undefined);
  const spec = build(nonce);
  return new Promise<Exchange>((resolve) => {
    let done = false;
    let received = Buffer.alloc(0);
    const socket = net.connect({ host: "127.0.0.1", port });
    const settle = (value: Exchange) => { if (!done) { done = true; clearTimeout(timer); socket.destroy(); resolve(value); } };
    const parse = (): Exchange | null => {
      // An interim 1xx (e.g. `100 Continue`, which the HTTP stack sends for `Expect: 100-continue`) is not the response: skip it.
      let offset = 0;
      let end = received.indexOf("\r\n\r\n", offset);
      while (end >= 0 && /^HTTP\/1\.[01] 1\d\d/.test(received.subarray(offset, offset + 12).toString("latin1"))) { offset = end + 4; end = received.indexOf("\r\n\r\n", offset); }
      if (end < 0) return null;
      const lines = received.subarray(offset, end).toString("latin1").split("\r\n");
      const status = /^HTTP\/1\.[01] (\d{3})/.exec(lines[0]);
      if (!status) return finish("error", null, undefined);
      const outcome = lines.find((line) => line.toLowerCase().startsWith(`${OUTCOME_HEADER}:`));
      return finish("response", Number(status[1]), outcome ? outcome.slice(OUTCOME_HEADER.length + 1).trim() : undefined);
    };
    const timer = setTimeout(() => settle(parse() ?? finish("timeout", null, undefined)), timeoutMs);
    const transmit = () => {
      socket.write(spec.head);
      if (spec.tail) setTimeout(() => { if (!done && !socket.destroyed) socket.write(spec.tail!); }, spec.afterMs ?? 0);
      if (spec.closeAfterMs !== undefined) setTimeout(() => socket.destroy(), spec.closeAfterMs);
    };
    socket.on("connect", () => {
      if (beforeWrite === undefined) { transmit(); return; }
      // The hook runs while the connection is open and nothing has been sent: the caller may use the socket's own local port.
      beforeWrite(socket, nonce).then(() => { if (!done && !socket.destroyed) transmit(); }, () => settle(finish("error", null, undefined)));
    });
    socket.on("data", (chunk) => { received = Buffer.concat([received, chunk]); const parsed = parse(); if (parsed) settle(parsed); });
    socket.on("error", (error) => settle(parse() ?? finish(classify(error), null, undefined)));
    socket.on("close", () => settle(parse() ?? finish("reset", null, undefined)));
  });
}
