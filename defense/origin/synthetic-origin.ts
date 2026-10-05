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
import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { OriginEvent } from "../core/ledger";
import type { Lane } from "../core/types";
import { HOP_HEADER, NONCE_HEADER, NONCE_PATTERN, isSpoofableHeader } from "../core/types";

export const SYNTHETIC_REDIRECT_LOCATION = "/test-talep-et/tesekkurler";
export const SYNTHETIC_MAX_BODY_BYTES = 32_768;

export type OriginFault =
  | { kind: "reset"; remaining: number }
  | { kind: "hang"; remaining: number }
  | { kind: "delay"; remaining: number; delayMs: number };

export type SyntheticOriginOptions = {
  instance: Lane;
  onObservation: (event: OriginEvent) => void;
  /** Finite capacity: concurrent requests beyond this get an explicit 503. */
  maxConcurrent?: number;
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
};

export function createSyntheticOrigin(options: SyntheticOriginOptions): SyntheticOrigin {
  const maxConcurrent = options.maxConcurrent ?? 64;
  const stats: SyntheticOriginStats = { received: 0, completed: 0, aborted: 0, overloaded: 0, activeHighWater: 0, spoofedHeadersSeen: 0 };
  let active = 0;
  let fault: OriginFault | null = null;
  const hung = new Set<http.ServerResponse>();

  const server = http.createServer({ maxHeaderSize: 16_384, keepAliveTimeout: 5_000, requestTimeout: 10_000, headersTimeout: 10_000 }, (req, res) => {
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
    const respond = () => { void handle(req, res); };
    if (armed?.kind === "delay") setTimeout(respond, armed.delayMs); else respond();
  });
  server.maxConnections = 256;

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (active > maxConcurrent) {
      stats.overloaded++;
      return send(res, 503, "application/json", JSON.stringify({ kind: "state", state: { errors: {}, message: UNAVAILABLE } }));
    }
    const url = req.url ?? "";
    const method = req.method ?? "";
    if (method === "GET") {
      if (url === "/") return send(res, 200, "text/html; charset=utf-8", HOME);
      if (url === "/gizlilik") return send(res, 200, "text/html; charset=utf-8", PRIVACY);
      if (url === "/test-talep-et" || /^\/test-talep-et\?hizmet=(?:web|network|protection|unsure)$/.test(url)) return send(res, 200, "text/html; charset=utf-8", formPage(randomBytes(32).toString("base64url")));
      if (url === SYNTHETIC_REDIRECT_LOCATION) return send(res, 200, "text/html; charset=utf-8", THANKS);
      return send(res, 404, "text/plain; charset=utf-8", "Not found");
    }
    if (method === "POST" && url === "/api/public-inquiries") return handleSubmission(req, res);
    return send(res, 404, "text/plain; charset=utf-8", "Not found");
  }

  async function handleSubmission(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (req.headers["content-type"] !== "application/x-www-form-urlencoded") return send(res, 404, "text/plain; charset=utf-8", "Not found");
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of req as AsyncIterable<Buffer>) {
      length += chunk.length;
      if (length > SYNTHETIC_MAX_BODY_BYTES) {
        res.setHeader("connection", "close");
        return send(res, 413, "application/json", JSON.stringify({ kind: "state", state: { errors: {}, message: UNAVAILABLE } }));
      }
      chunks.push(chunk);
    }
    const state = (status: number, value: unknown) => send(res, status, "application/json", JSON.stringify(value));
    if (req.headers.origin !== `http://${req.headers.host}`) return state(403, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
    const parsed = parseStrictForm(Buffer.concat(chunks));
    if (!parsed.ok) return state(400, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
    if (!validateSubmission(parsed.fields)) return state(200, { kind: "state", state: { errors: { form: "invalid" } } });
    const token = parsed.fields.get("submissionToken");
    if (token === undefined || !TOKEN_PATTERN.test(token)) return state(200, { kind: "state", state: { errors: {}, message: UNAVAILABLE } });
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
  };
}
