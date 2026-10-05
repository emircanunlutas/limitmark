/**
 * Synthetic origin: a small, disposable stand-in for the public site, bound to 127.0.0.1 only.
 *
 * Two instances of this SAME code run independently in a BA0 run: a `control` instance reached directly (no Defense Plane) and a
 * `protected` instance reached only through the plane. Each has its own server, its own concurrency capacity and its own observations,
 * so protected-versus-control comparison is meaningful and the origin's view of a request is independent of the plane's.
 *
 * It reports what it observed through `onObservation` (a measurement hook owned by the harness). Nothing it does depends on that
 * hook, on the correlation nonce, or on any traffic-class label.
 *
 * It mirrors the application's demo-mode behaviour for the surveyed journey (pages, the hidden form token, the strict form grammar,
 * the Origin check, the redirect response). A contract test in tests/ pins that mirror to the real request schema and token pattern.
 */
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { AppEvent, OriginEvent } from "../core/ledger";
import type { Lane, ObReason } from "../core/types";
import { HOP_HEADER, NONCE_HEADER, NONCE_PATTERN, OB_REASONS, isSpoofableHeader } from "../core/types";
import { HOP_BA_HEADER, HOP_PB_HEADER, MEASUREMENT_HEADER } from "../core/semantic-request";

const GUARDED_PARSER_CODES: ReadonlySet<string> = new Set([
  "HPE_HEADER_OVERFLOW", "HPE_INVALID_METHOD", "HPE_INVALID_HEADER_TOKEN", "HPE_UNEXPECTED_CONTENT_LENGTH", "HPE_INVALID_CONTENT_LENGTH",
  "HPE_INVALID_TRANSFER_ENCODING", "HPE_INVALID_CONSTANT", "HPE_INVALID_URL", "HPE_INVALID_VERSION", "HPE_CR_EXPECTED", "HPE_LF_EXPECTED",
  "HPE_INVALID_CHUNK_SIZE", "HPE_INVALID_STATUS", "HPE_STRICT",
]);
export const SYNTHETIC_REDIRECT_LOCATION = "/test-talep-et/tesekkurler";
export const SYNTHETIC_MAX_BODY_BYTES = 32_768;

export type OriginFault =
  | { kind: "reset"; remaining: number }
  | { kind: "hang"; remaining: number }
  | { kind: "delay"; remaining: number; delayMs: number };

/**
 * What the application interprets about a request, as a plain value. An unguarded origin builds it from the request as it always did;
 * a guarded one (Slice 2) builds it from the VERIFIED CLAIMS of the hop proof, so the application interprets exactly the representation
 * the Defense Plane approved and never a header view of its own.
 */
export type RequestFacts = {
  method: string;
  url: string;
  contentType: string | undefined;
  origin: string | undefined;
  host: string | undefined;
  /** Pre-read, digest-verified body (guarded) or null (the handler reads the stream, as before). */
  body: Buffer | null;
};
export type AppIdentity = { nonce: string; hop: number; pbTag: string; baTag: string };
export type AppGuardDecision = { ok: true; facts: RequestFacts; identity: AppIdentity } | { ok: false; reason: ObReason; nonce: string | null };
/** Slice 2: admits a request BEFORE any application semantics, routing, parsing or state can run. */
export type AppGuard = (req: http.IncomingMessage) => Promise<AppGuardDecision>;

export type SyntheticOriginOptions = {
  instance: Lane;
  onObservation: (event: OriginEvent) => void;
  /** Finite capacity: concurrent requests beyond this get an explicit 503. */
  maxConcurrent?: number;
  /** Slice 2: every request must pass this guard first. Absent = the Slice-1 behaviour, byte for byte. */
  guard?: AppGuard;
  /** Slice 2: the application's own lifecycle (admit, execute, mutate, complete) and refusals. Used only with `guard`. */
  onApp?: (event: Omit<AppEvent, "seq" | "t">) => void;
};

/** The application's own independent counters (Slice 2). Separate from `SyntheticOriginStats`, whose shape Slice 1 pins. */
export type AppCounters = {
  admitted: number;
  refused: number;
  executed: number;
  stateMutations: number;
  parserRejected: number;
  protocolRefused: number;
  refusedByReason: Record<string, number>;
};

export type SyntheticOriginStats = {
  received: number;
  completed: number;
  aborted: number;
  overloaded: number;
  activeHighWater: number;
  spoofedHeadersSeen: number;
};

const FIELD_NAMES = new Set(["name", "email", "company", "service", "system", "objective", "environment", "authority", "protection", "provider", "notes", "submissionToken", "cf-turnstile-response"]);
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const LIMITS = { name: 100, email: 254, company: 160, system: 1000, objective: 2000, provider: 160, notes: 2000 } as const;
const UNAVAILABLE = "Talep gönderimi şu anda kullanılamıyor.";

const NAV = `<nav><a href="/#hizmetler">Hizmetler</a> <a href="/#sss">SSS</a> <a href="/gizlilik">Gizlilik</a> <a href="/test-talep-et">Test Talep Et</a></nav>`;
const page = (title: string, body: string) => `<!doctype html><html lang="tr"><head><meta charset="utf-8"><title>${title}</title></head><body>${NAV}<main>${body}</main></body></html>`;
const HOME = page("LimitMark", `<h1>Direnç testi</h1><section id="hizmetler"><h2>Hizmetler</h2></section><section id="sss"><h2 id="faq-title">Sık sorulan sorular</h2></section><a href="/test-talep-et">Test Talep Et</a>`);
const PRIVACY = page("Gizlilik", `<article><h1>Gizlilik</h1><p>Bu sayfa, talep sürecindeki temel gizlilik yaklaşımını açıklar.</p><a href="/test-talep-et">Talep Formuna Dön</a></article>`);
const THANKS = page("Talebinizi aldık", `<div class="confirmation-page"><h1>Demo akışı tamamlandı.</h1><p>Bu bir deneme akışıydı. Formdaki bilgiler kaydedilmedi.</p><a href="/">Ana Sayfaya Dön</a></div>`);
const formPage = (token: string) => page("Test Talep Et", `<h1>Test Talep Et</h1><form class="request-form" method="post" action="/api/public-inquiries"><input type="hidden" name="submissionToken" value="${token}"><button type="submit">Gönder</button></form>`);

export type ParsedForm = { ok: true; fields: Map<string, string> } | { ok: false };

export function parseStrictForm(body: Buffer): ParsedForm {
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body); } catch { return { ok: false }; }
  const fields = new Map<string, string>();
  if (text === "") return { ok: true, fields };
  const decode = (value: string): string | null => {
    if (/%(?![0-9a-fA-F]{2})/u.test(value)) return null;
    try { return decodeURIComponent(value.replace(/\+/g, " ")); } catch { return null; }
  };
  for (const pair of text.split("&")) {
    const separator = pair.indexOf("=");
    const name = decode(separator < 0 ? pair : pair.slice(0, separator));
    const value = decode(separator < 0 ? "" : pair.slice(separator + 1));
    if (name === null || value === null || !FIELD_NAMES.has(name) || fields.has(name)) return { ok: false };
    fields.set(name, value);
  }
  return { ok: true, fields };
}

/** Same accept/reject decisions as the application's request schema for the fields the journey uses (pinned by a contract test). */
export function validateSubmission(fields: ReadonlyMap<string, string>): boolean {
  const text = (key: keyof typeof LIMITS, required: boolean): boolean => {
    const value = (fields.get(key) ?? "").replace(/\r\n?/g, "\n").trim();
    return value.length <= LIMITS[key] && (!required || value.length > 0);
  };
  const oneOf = (key: string, allowed: readonly string[], required: boolean): boolean => {
    const value = fields.get(key);
    return value === undefined ? !required : allowed.includes(value);
  };
  return text("name", true) && text("email", true) && EMAIL.test((fields.get("email") ?? "").trim()) && text("company", false) &&
    oneOf("service", ["web", "network", "protection", "unsure"], true) && text("system", true) && text("objective", true) &&
    oneOf("environment", ["production", "staging", "multiple", "unknown"], true) && oneOf("authority", ["owner", "authorized", "uncertain"], true) &&
    oneOf("protection", ["unknown", "none", "using"], false) && text("provider", false) && text("notes", false);
}

export type SyntheticOrigin = {
  readonly instance: Lane;
  listen(): Promise<number>;
  close(): Promise<void>;
  armFault(fault: OriginFault): void;
  stats(): SyntheticOriginStats;
  appStats(): AppCounters;
};

export function createSyntheticOrigin(options: SyntheticOriginOptions): SyntheticOrigin {
  const maxConcurrent = options.maxConcurrent ?? 64;
  const stats: SyntheticOriginStats = { received: 0, completed: 0, aborted: 0, overloaded: 0, activeHighWater: 0, spoofedHeadersSeen: 0 };
  let active = 0;
  let fault: OriginFault | null = null;
  const hung = new Set<http.ServerResponse>();
  const counters: AppCounters = { admitted: 0, refused: 0, executed: 0, stateMutations: 0, parserRejected: 0, protocolRefused: 0, refusedByReason: Object.fromEntries(OB_REASONS.map((reason) => [reason, 0])) };
  /** The synthetic application's whole state: a count and a bounded ring of submission digests. It never changes a response. */
  const committed: string[] = [];
  const guard = options.guard;
  const onApp = options.onApp ?? (() => undefined);

  const server = http.createServer({ maxHeaderSize: 16_384, keepAliveTimeout: 5_000, requestTimeout: 10_000, headersTimeout: 10_000, ...(guard ? { requireHostHeader: false } : {}) }, (req, res) => {
    if (guard) { void handleGuarded(req, res, guard); return; }
    const nonceRaw = req.headers[NONCE_HEADER];
    const nonce = typeof nonceRaw === "string" && NONCE_PATTERN.test(nonceRaw) ? nonceRaw : null;
    const hopRaw = req.headers[HOP_HEADER];
    const hop = typeof hopRaw === "string" && /^[1-9][0-9]{0,15}$/.test(hopRaw) ? Number(hopRaw) : null;
    let spoofed = 0;
    for (const name of Object.keys(req.headers)) if (name !== NONCE_HEADER && name !== HOP_HEADER && isSpoofableHeader(name)) spoofed++;
    stats.received++;
    stats.spoofedHeadersSeen += spoofed;
    active++;
    if (active > stats.activeHighWater) stats.activeHighWater = active;
    options.onObservation({ instance: options.instance, nonce, kind: "ORIGIN_RECEIVED", hop, spoofed });

    let finished = false;
    res.on("finish", () => { finished = true; stats.completed++; options.onObservation({ instance: options.instance, nonce, kind: "ORIGIN_COMPLETED", hop, status: res.statusCode }); });
    res.on("close", () => {
      active--;
      hung.delete(res);
      if (!finished) { stats.aborted++; options.onObservation({ instance: options.instance, nonce, kind: "ORIGIN_ABORTED", hop }); }
    });

    const armed = fault && fault.remaining > 0 ? fault : null;
    if (armed) armed.remaining--;
    if (armed?.kind === "reset") { req.socket.destroy(); return; }
    if (armed?.kind === "hang") { hung.add(res); return; }
    const respond = () => { void handle(req, res, factsOf(req), null); };
    if (armed?.kind === "delay") setTimeout(respond, armed.delayMs); else respond();
  });
  server.maxConnections = 256;
  if (guard) {
    // A guarded application accepts nothing but a request its guard admits: no 100-continue invitation, no upgrade, no tunnel.
    server.on("checkContinue", (req, res) => {
      counters.protocolRefused++;
      refuse(res, "ob.expect_refused", readTag(req));
    });
    server.on("upgrade", (_req, socket) => { counters.protocolRefused++; socket.destroy(); });
    server.on("connect", (_req, socket) => { counters.protocolRefused++; socket.destroy(); });
    server.on("clientError", (error: NodeJS.ErrnoException, socket) => {
      // Only a refusal of malformed bytes is a parser refusal (the same closed list the boundary uses); a reset, or a client that vanished
      // mid-message (HPE_INVALID_EOF_STATE), is not counted as one.
      if (GUARDED_PARSER_CODES.has(error.code ?? "") && socket.writable) {
        counters.parserRejected++;
        socket.end("HTTP/1.1 400 Bad Request\r\nconnection: close\r\ncontent-length: 0\r\n\r\n");
      } else socket.destroy();
    });
  }

  const factsOf = (req: http.IncomingMessage): RequestFacts => ({
    method: req.method ?? "", url: req.url ?? "", contentType: req.headers["content-type"], origin: req.headers.origin, host: req.headers.host, body: null,
  });
  const readTag = (req: http.IncomingMessage): string | null => {
    const raw = req.headers[MEASUREMENT_HEADER];
    return typeof raw === "string" && NONCE_PATTERN.test(raw) ? raw : null;
  };

  /** A refusal is uniform whatever the reason: one status, no body, the connection closed. Reasons exist only in telemetry. */
  function refuse(res: http.ServerResponse, reason: ObReason, nonce: string | null): void {
    counters.refused++;
    counters.refusedByReason[reason] = (counters.refusedByReason[reason] ?? 0) + 1;
    onApp({ nonce, kind: "APP_REFUSED", reason });
    if (res.writableEnded || res.destroyed) return;
    res.writeHead(reason === "ob.replay_cache_full" ? 503 : 403, { "content-length": 0, connection: "close", "x-ba0-outcome": "refused" });
    res.end();
    const socket = res.socket;
    if (socket) setTimeout(() => { if (!socket.destroyed) socket.destroy(); }, 1_000).unref();
  }

  async function handleGuarded(req: http.IncomingMessage, res: http.ServerResponse, admit: AppGuard): Promise<void> {
    const decision = await admit(req);
    if (!decision.ok) { refuse(res, decision.reason, decision.nonce); return; }
    const { facts, identity } = decision;
    let spoofed = 0;
    for (const name of Object.keys(req.headers)) if (name !== HOP_PB_HEADER && name !== HOP_BA_HEADER && name !== MEASUREMENT_HEADER && name !== NONCE_HEADER && name !== HOP_HEADER && isSpoofableHeader(name)) spoofed++;
    stats.received++;
    stats.spoofedHeadersSeen += spoofed;
    counters.admitted++;
    active++;
    if (active > stats.activeHighWater) stats.activeHighWater = active;
    onApp({ nonce: identity.nonce, kind: "APP_ADMITTED", hop: identity.hop, pbTag: identity.pbTag, baTag: identity.baTag, spoofed });
    let finished = false;
    let closed = false;
    const closeOnce = () => {
      if (closed) return;
      closed = true;
      active--;
      hung.delete(res);
      if (!finished) { stats.aborted++; onApp({ nonce: identity.nonce, kind: "APP_ABORTED", hop: identity.hop, pbTag: identity.pbTag, baTag: identity.baTag }); }
    };
    res.on("finish", () => { finished = true; stats.completed++; onApp({ nonce: identity.nonce, kind: "APP_COMPLETED", hop: identity.hop, pbTag: identity.pbTag, baTag: identity.baTag, status: res.statusCode }); });
    res.on("close", closeOnce);
    if (res.destroyed) { closeOnce(); return; }

    const armed = fault && fault.remaining > 0 ? fault : null;
    if (armed) armed.remaining--;
    if (armed?.kind === "reset") { req.socket.destroy(); return; }
    if (armed?.kind === "hang") { hung.add(res); return; }
    const respond = () => { void handle(req, res, facts, identity); };
    if (armed?.kind === "delay") setTimeout(respond, armed.delayMs); else respond();
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse, facts: RequestFacts, identity: AppIdentity | null): Promise<void> {
    if (active > maxConcurrent) {
      stats.overloaded++;
      return send(res, 503, "application/json", JSON.stringify({ kind: "state", state: { errors: {}, message: UNAVAILABLE } }));
    }
    counters.executed++;
    if (identity) onApp({ nonce: identity.nonce, kind: "APP_EXECUTED", hop: identity.hop, pbTag: identity.pbTag, baTag: identity.baTag });
    const url = facts.url;
    const method = facts.method;
    if (method === "GET") {
      if (url === "/") return send(res, 200, "text/html; charset=utf-8", HOME);
      if (url === "/gizlilik") return send(res, 200, "text/html; charset=utf-8", PRIVACY);
      if (url === "/test-talep-et" || /^\/test-talep-et\?hizmet=(?:web|network|protection|unsure)$/.test(url)) return send(res, 200, "text/html; charset=utf-8", formPage(randomBytes(32).toString("base64url")));
      if (url === SYNTHETIC_REDIRECT_LOCATION) return send(res, 200, "text/html; charset=utf-8", THANKS);
      return send(res, 404, "text/plain; charset=utf-8", "Not found");
    }
    if (method === "POST" && url === "/api/public-inquiries") return handleSubmission(req, res, facts, identity);
    return send(res, 404, "text/plain; charset=utf-8", "Not found");
  }

  async function handleSubmission(req: http.IncomingMessage, res: http.ServerResponse, facts: RequestFacts, identity: AppIdentity | null): Promise<void> {
    if (facts.contentType !== "application/x-www-form-urlencoded") return send(res, 404, "text/plain; charset=utf-8", "Not found");
    const chunks: Buffer[] = [];
    let length = 0;
    if (facts.body !== null) { chunks.push(facts.body); length = facts.body.length; }
    else {
      for await (const chunk of req as AsyncIterable<Buffer>) {
        length += chunk.length;
        if (length > SYNTHETIC_MAX_BODY_BYTES) {
          res.setHeader("connection", "close");
          return send(res, 413, "application/json", JSON.stringify({ kind: "state", state: { errors: {}, message: UNAVAILABLE } }));
        }
        chunks.push(chunk);
      }
    }
    const state = (status: number, value: unknown) => send(res, status, "application/json", JSON.stringify(value));
    if (facts.origin !== `http://${facts.host}`) return state(403, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
    const parsed = parseStrictForm(Buffer.concat(chunks));
    if (!parsed.ok) return state(400, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
    if (!validateSubmission(parsed.fields)) return state(200, { kind: "state", state: { errors: { form: "invalid" } } });
    const token = parsed.fields.get("submissionToken");
    if (token === undefined || !TOKEN_PATTERN.test(token)) return state(200, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
    // The one state mutation of the synthetic application: a valid submission is committed. It is counted by the application itself,
    // before the response, and never alters what the response says.
    counters.stateMutations++;
    committed.push(createHash("sha256").update(token).digest("base64url").slice(0, 16));
    if (committed.length > 256) committed.shift();
    if (identity) onApp({ nonce: identity.nonce, kind: "APP_MUTATED", hop: identity.hop, pbTag: identity.pbTag, baTag: identity.baTag });
    return state(200, { kind: "redirect", location: SYNTHETIC_REDIRECT_LOCATION });
  }

  function send(res: http.ServerResponse, status: number, contentType: string, body: string): void {
    if (res.writableEnded || res.destroyed) return;
    const bytes = Buffer.from(body, "utf8");
    res.writeHead(status, { "content-type": contentType, "content-length": bytes.length, "cache-control": "private, no-store, max-age=0, must-revalidate", "x-content-type-options": "nosniff" });
    res.end(bytes);
  }

  return {
    instance: options.instance,
    listen: () => new Promise<number>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve((server.address() as AddressInfo).port); });
    }),
    close: () => new Promise<void>((resolve) => {
      for (const response of hung) response.destroy();
      server.close(() => resolve());
      server.closeAllConnections();
    }),
    armFault(next) { fault = next; },
    stats: () => ({ ...stats }),
    appStats: () => ({ ...counters, refusedByReason: { ...counters.refusedByReason } }),
  };
}
