import { importJWK, type JWK, type JWTVerifyGetKey, type JWSHeaderParameters } from "jose";
import { decodeCanonicalBase64url } from "../../src/lib/ingress-protocol";

export const JWKS_DEFAULTS = {
  maximumResponseBytes: 64 * 1024,
  maximumKeys: 8,
  timeoutMs: 2_000,
  cacheLifetimeMs: 10 * 60_000,
  staleGraceMs: 5 * 60_000,
  refreshCooldownMs: 30_000,
} as const;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** JSON.parse keeps the last duplicate member. JWT/JWKS security policy must reject that ambiguity. */
export function parseJsonWithoutDuplicateMembers(text: string): unknown {
  let offset = 0;
  const whitespace = () => { while (/\s/u.test(text[offset] ?? "")) offset++; };
  const string = (): string => {
    const start = offset;
    if (text[offset++] !== '"') throw new Error("json-string");
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '"') return JSON.parse(text.slice(start, offset)) as string;
      if (character === "\\") {
        const escape = text[offset++];
        if (escape === "u") {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(offset, offset + 4))) throw new Error("json-escape");
          offset += 4;
        } else if (!'"\\/bfnrt'.includes(escape ?? "")) throw new Error("json-escape");
      } else if (!character || character.charCodeAt(0) < 0x20) throw new Error("json-character");
    }
    throw new Error("json-string");
  };
  const value = (): void => {
    whitespace();
    if (text[offset] === '"') { string(); return; }
    if (text[offset] === "{") {
      offset++; whitespace();
      const members = new Set<string>();
      if (text[offset] === "}") { offset++; return; }
      while (true) {
        whitespace();
        const member = string();
        if (members.has(member)) throw new Error("json-duplicate-member");
        members.add(member);
        whitespace();
        if (text[offset++] !== ":") throw new Error("json-colon");
        value(); whitespace();
        if (text[offset] === "}") { offset++; return; }
        if (text[offset++] !== ",") throw new Error("json-object");
      }
    }
    if (text[offset] === "[") {
      offset++; whitespace();
      if (text[offset] === "]") { offset++; return; }
      while (true) {
        value(); whitespace();
        if (text[offset] === "]") { offset++; return; }
        if (text[offset++] !== ",") throw new Error("json-array");
      }
    }
    const remainder = text.slice(offset);
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remainder);
    if (!match) throw new Error("json-value");
    offset += match[0].length;
  };
  value(); whitespace();
  if (offset !== text.length) throw new Error("json-trailing");
  return JSON.parse(text) as unknown;
}

function decodeJwtJson(segment: string, maximumBytes: number): JsonObject {
  const bytes = decodeCanonicalBase64url(segment);
  if (bytes.length < 2 || bytes.length > maximumBytes) throw new Error("jwt-segment-size");
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  const value = parseJsonWithoutDuplicateMembers(text);
  if (!isObject(value)) throw new Error("jwt-object");
  return value;
}

export function inspectCompactJwt(token: string, maximumTokenBytes = 16_384): { header: JsonObject; payload: JsonObject } {
  if (!token || token.length > maximumTokenBytes || token.trim() !== token || token.includes(",")) throw new Error("jwt-shape");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("jwt-shape");
  const header = decodeJwtJson(parts[0], 2_048);
  const payload = decodeJwtJson(parts[1], 12_288);
  const signature = decodeCanonicalBase64url(parts[2]);
  if (signature.length < 64 || signature.length > 1_024) throw new Error("jwt-signature-size");
  return { header, payload };
}

export type BoundedJwksOptions = {
  endpoint: URL;
  fetch?: typeof fetch;
  now?: () => number;
  maximumResponseBytes?: number;
  maximumKeys?: number;
  timeoutMs?: number;
  cacheLifetimeMs?: number;
  staleGraceMs?: number;
  refreshCooldownMs?: number;
  allowAdditionalTopLevelMembers?: boolean;
};

type Cache = { keys: ReadonlyMap<string, CryptoKey>; fetchedAtMs: number };
const privateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;
const allowedRsaJwkMembers = new Set(["kty", "kid", "use", "alg", "n", "e", "key_ops", "x5c", "x5t", "x5t#S256"]);

export class BoundedRs256JwksResolver {
  readonly resolve: JWTVerifyGetKey;
  private readonly endpoint: URL;
  private readonly request: typeof fetch;
  private readonly now: () => number;
  private readonly limits: { maximumResponseBytes: number; maximumKeys: number; timeoutMs: number; cacheLifetimeMs: number; staleGraceMs: number; refreshCooldownMs: number };
  private readonly allowAdditionalTopLevelMembers: boolean;
  private cache?: Cache;
  private refresh?: Promise<Cache>;
  private lastRefreshAttemptMs = Number.NEGATIVE_INFINITY;

  constructor(options: BoundedJwksOptions) {
    const endpoint = new URL(options.endpoint.href);
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.port || endpoint.search || endpoint.hash) throw new Error("jwks-endpoint");
    this.endpoint = endpoint;
    this.request = options.fetch ?? fetch;
    this.now = options.now ?? Date.now;
    this.limits = {
      maximumResponseBytes: options.maximumResponseBytes ?? JWKS_DEFAULTS.maximumResponseBytes,
      maximumKeys: options.maximumKeys ?? JWKS_DEFAULTS.maximumKeys,
      timeoutMs: options.timeoutMs ?? JWKS_DEFAULTS.timeoutMs,
      cacheLifetimeMs: options.cacheLifetimeMs ?? JWKS_DEFAULTS.cacheLifetimeMs,
      staleGraceMs: options.staleGraceMs ?? JWKS_DEFAULTS.staleGraceMs,
      refreshCooldownMs: options.refreshCooldownMs ?? JWKS_DEFAULTS.refreshCooldownMs,
    };
    if (Object.values(this.limits).some((value) => !Number.isSafeInteger(value) || value < 1)) throw new Error("jwks-limits");
    this.allowAdditionalTopLevelMembers = options.allowAdditionalTopLevelMembers ?? false;
    this.resolve = async (header) => this.getKey(header);
  }

  private async readResponse(response: Response): Promise<string> {
    const claimed = response.headers.get("content-length");
    if (claimed !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(claimed) || Number(claimed) > this.limits.maximumResponseBytes)) throw new Error("jwks-size");
    if (!response.body) throw new Error("jwks-body");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
      while (true) {
        const item = await reader.read();
        if (item.done) break;
        length += item.value.length;
        if (length > this.limits.maximumResponseBytes) throw new Error("jwks-size");
        chunks.push(item.value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  }

  private async fetchKeys(): Promise<Cache> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.limits.timeoutMs);
    try {
      const response = await this.request(this.endpoint, { method: "GET", redirect: "manual", signal: controller.signal, headers: { accept: "application/json" } });
      if (response.status !== 200) throw new Error("jwks-status");
      if (response.url) {
        const finalUrl = new URL(response.url);
        if (finalUrl.origin !== this.endpoint.origin || finalUrl.pathname !== this.endpoint.pathname || finalUrl.search || finalUrl.hash) throw new Error("jwks-redirect");
      }
      const parsed = parseJsonWithoutDuplicateMembers(await this.readResponse(response));
      if (!isObject(parsed) || !Array.isArray(parsed.keys)) throw new Error("jwks-shape");
      if (!this.allowAdditionalTopLevelMembers && Object.keys(parsed).some((key) => key !== "keys")) throw new Error("jwks-members");
      if (parsed.keys.length < 1 || parsed.keys.length > this.limits.maximumKeys) throw new Error("jwks-key-count");
      const keys = new Map<string, CryptoKey>();
      for (const candidate of parsed.keys) {
        if (!isObject(candidate) || candidate.kty !== "RSA" || candidate.alg !== "RS256" || candidate.use !== "sig" ||
            typeof candidate.kid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(candidate.kid) ||
            typeof candidate.n !== "string" || typeof candidate.e !== "string" ||
            privateJwkMembers.some((member) => member in candidate)) throw new Error("jwks-key");
        if (Object.keys(candidate).some((member) => !allowedRsaJwkMembers.has(member)) ||
            candidate.x5c !== undefined && (!Array.isArray(candidate.x5c) || candidate.x5c.length > 4 || candidate.x5c.some((item) => typeof item !== "string" || item.length > 8_192)) ||
            candidate.x5t !== undefined && typeof candidate.x5t !== "string" || candidate["x5t#S256"] !== undefined && typeof candidate["x5t#S256"] !== "string") throw new Error("jwks-key-members");
        if (candidate.key_ops !== undefined && (!Array.isArray(candidate.key_ops) || candidate.key_ops.length !== 1 || candidate.key_ops[0] !== "verify")) throw new Error("jwks-key-ops");
        const modulus = decodeCanonicalBase64url(candidate.n);
        const exponent = decodeCanonicalBase64url(candidate.e);
        if (modulus.length < 256 || modulus.length > 1_024 || exponent.length < 1 || exponent.length > 8 || keys.has(candidate.kid)) throw new Error("jwks-key-material");
        const imported = await importJWK(candidate as JWK, "RS256");
        if (imported instanceof Uint8Array || imported.type !== "public" || imported.algorithm.name !== "RSASSA-PKCS1-v1_5") throw new Error("jwks-import");
        keys.set(candidate.kid, imported);
      }
      return { keys, fetchedAtMs: this.now() };
    } finally { clearTimeout(timeout); }
  }

  private async refreshCache(): Promise<Cache> {
    if (this.refresh) return this.refresh;
    this.lastRefreshAttemptMs = this.now();
    this.refresh = this.fetchKeys().then((cache) => { this.cache = cache; return cache; }).finally(() => { this.refresh = undefined; });
    return this.refresh;
  }

  private async getKey(header: JWSHeaderParameters): Promise<CryptoKey> {
    if (header.alg !== "RS256" || typeof header.kid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/u.test(header.kid)) throw new Error("jwks-header");
    const nowMs = this.now();
    const cached = this.cache?.keys.get(header.kid);
    const ageMs = this.cache ? nowMs - this.cache.fetchedAtMs : Number.POSITIVE_INFINITY;
    if (ageMs < 0) throw new Error("jwks-clock");
    if (cached && ageMs <= this.limits.cacheLifetimeMs) return cached;
    const mayRefresh = nowMs - this.lastRefreshAttemptMs >= this.limits.refreshCooldownMs;
    if (mayRefresh || this.refresh) {
      try {
        const refreshed = await this.refreshCache();
        const key = refreshed.keys.get(header.kid);
        if (key) return key;
      } catch {
        if (cached && ageMs <= this.limits.cacheLifetimeMs + this.limits.staleGraceMs) return cached;
        throw new Error("jwks-unavailable");
      }
    }
    if (cached && ageMs <= this.limits.cacheLifetimeMs + this.limits.staleGraceMs) return cached;
    throw new Error("jwks-unknown-key");
  }
}
