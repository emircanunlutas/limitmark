import {
  INGRESS_MAX_AGE_MS,
  assertIngressFresh,
  decodeCanonicalBase64url,
  encodeBase64url,
} from "../../src/lib/ingress-protocol";
import { UNAVAILABLE_AUTHORITY_OBSERVATION } from "../../operator/lifecycle-observation";

export const ADMISSION_POLICY_EPOCH = "phase5c-i1-epoch-1";
export const ADMISSION_AUTHORITY_ID = "production-public-inquiries-v1";
export const PRE_PERMIT_LIFETIME_MS = 60_000;
export const NONCE_RETENTION_MS = 120_000;
export const AUTHORITY_RELEASE_RETENTION_AFTER_RETIRE_MS = 12 * 60_000;
export const LIFECYCLE_RECEIPT_CAPACITY = 4_096;

export const admissionPolicy = {
  pre: { client: { limit: 30, windowMs: 600_000 }, global: { limit: 300, windowMs: 60_000 } },
  post: { client: { limit: 5, windowMs: 600_000 }, global: { limit: 100, windowMs: 60_000 } },
} as const;

export type ClaimPreInput = {
  releaseId: string;
  clientPseudonym: string;
  requestBinding: string;
  nonce: string;
  issuedAtMs: number;
};
export type ConsumePostInput = Omit<ClaimPreInput, "issuedAtMs"> & { permit: string };
export type PreDecision = { decision: "allowed"; permit: string; expiresAtMs: number } | { decision: "limited" | "replay" | "unavailable" };
export type PostDecision = { decision: "allowed" | "limited" | "replay" | "unavailable" };

export interface SqlCursorLike<T> extends Iterable<T> { toArray?: () => T[] }
export interface DurableSqlLike { exec<T = Record<string, unknown>>(query: string, ...bindings: unknown[]): SqlCursorLike<T> }
export interface DurableStorageLike {
  sql: DurableSqlLike;
  transactionSync<T>(callback: () => T): T;
  setAlarm?(timestamp: number): Promise<void>;
}

type MetaRow = { authority_id: string; policy_epoch: string; last_now_ms: number };
type ReleaseRow = { release_id: string; key_id: string; activated_ms: number; retired_ms: number | null };
type CountRow = { count: number };
type NonceRow = {
  release_id: string; client_id: string; request_binding: string; permit: string;
  permit_expires_ms: number; retain_until_ms: number; post_consumed: number;
};

function rows<T>(cursor: SqlCursorLike<T>): T[] {
  return cursor.toArray ? cursor.toArray() : Array.from(cursor);
}

function exactlyOne<T>(storage: DurableStorageLike, query: string, ...bindings: unknown[]): T | null {
  const result = rows(storage.sql.exec<T>(query, ...bindings));
  return result.length === 1 ? result[0] : null;
}

function isOpaque(value: string, bytes: number): boolean {
  try { decodeCanonicalBase64url(value, bytes); return true; } catch { return false; }
}

function validRelease(value: string): boolean {
  return /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
}

function validKeyId(value: string): boolean { return /^[A-Za-z0-9_-]{1,64}$/u.test(value); }

export function createAuthoritySchema(storage: DurableStorageLike): void {
  storage.sql.exec("CREATE TABLE IF NOT EXISTS authority_meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, last_now_ms INTEGER NOT NULL)");
  storage.sql.exec("CREATE TABLE IF NOT EXISTS active_releases (release_id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, activated_ms INTEGER NOT NULL, retired_ms INTEGER)");
  storage.sql.exec("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, release_id TEXT NOT NULL, client_id TEXT NOT NULL, request_binding TEXT NOT NULL, permit TEXT NOT NULL UNIQUE, claimed_ms INTEGER NOT NULL, permit_expires_ms INTEGER NOT NULL, retain_until_ms INTEGER NOT NULL, post_consumed INTEGER NOT NULL CHECK(post_consumed IN (0,1)))");
  storage.sql.exec("CREATE TABLE IF NOT EXISTS observations (id TEXT PRIMARY KEY, stage TEXT NOT NULL CHECK(stage IN ('pre','post')), scope TEXT NOT NULL CHECK(scope IN ('client','global')), subject TEXT NOT NULL, observed_at_ms INTEGER NOT NULL)");
  storage.sql.exec("CREATE INDEX IF NOT EXISTS observations_window ON observations(stage,scope,subject,observed_at_ms)");
  storage.sql.exec("CREATE INDEX IF NOT EXISTS nonces_retention ON nonces(retain_until_ms)");
  storage.sql.exec("CREATE TABLE IF NOT EXISTS lifecycle_receipts (digest TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=1), operation TEXT NOT NULL CHECK(operation IN ('initialize','rotate-release')), environment TEXT NOT NULL, authority_id TEXT NOT NULL, policy_epoch TEXT NOT NULL, key_fingerprint TEXT NOT NULL, sequence INTEGER NOT NULL UNIQUE, applied_ms INTEGER NOT NULL, current_release_id TEXT NOT NULL, next_release_id TEXT NOT NULL, next_key_id TEXT NOT NULL, activates_ms INTEGER NOT NULL, retires_ms INTEGER)");
  storage.sql.exec("CREATE TABLE IF NOT EXISTS lifecycle_receipt_coverage (singleton INTEGER PRIMARY KEY CHECK(singleton=1), complete INTEGER NOT NULL CHECK(complete=1))");
}

export type LifecycleReceipt = {
  digest: string; version: 1; operation: "initialize" | "rotate-release"; environment: "production" | "staging";
  authorityId: string; policyEpoch: string; keyFingerprint: string; sequence: number; appliedMs: number;
  currentReleaseId: string; nextReleaseId: string; nextKeyId: string; activatesMs: number; retiresMs: number | null;
};
type ReceiptRow = { digest: string; schema_version: number; operation: LifecycleReceipt["operation"]; environment: LifecycleReceipt["environment"];
  authority_id: string; policy_epoch: string; key_fingerprint: string; sequence: number; applied_ms: number;
  current_release_id: string; next_release_id: string; next_key_id: string; activates_ms: number; retires_ms: number | null };
function receiptFromRow(row: ReceiptRow): LifecycleReceipt {
  if (row.schema_version !== 1) throw new Error("receipt-history");
  return { digest: row.digest, version: 1, operation: row.operation, environment: row.environment, authorityId: row.authority_id,
    policyEpoch: row.policy_epoch, keyFingerprint: row.key_fingerprint, sequence: row.sequence, appliedMs: row.applied_ms,
    currentReleaseId: row.current_release_id, nextReleaseId: row.next_release_id, nextKeyId: row.next_key_id,
    activatesMs: row.activates_ms, retiresMs: row.retires_ms };
}
function findReceipt(storage: DurableStorageLike, digest: string): LifecycleReceipt | null {
  const row = exactlyOne<ReceiptRow>(storage, "SELECT digest,schema_version,operation,environment,authority_id,policy_epoch,key_fingerprint,sequence,applied_ms,current_release_id,next_release_id,next_key_id,activates_ms,retires_ms FROM lifecycle_receipts WHERE digest=?", digest);
  return row ? receiptFromRow(row) : null;
}
function ensureNewReceiptCapacity(storage: DurableStorageLike): void {
  const count = exactlyOne<CountRow>(storage, "SELECT COUNT(*) AS count FROM lifecycle_receipts")?.count;
  if (count === undefined || count >= LIFECYCLE_RECEIPT_CAPACITY) throw new Error("receipt-capacity");
}
function insertReceipt(storage: DurableStorageLike, receipt: Omit<LifecycleReceipt, "sequence">): LifecycleReceipt {
  const sequence = (exactlyOne<{ value: number }>(storage, "SELECT COALESCE(MAX(sequence),0) + 1 AS value FROM lifecycle_receipts")?.value ?? 0);
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error("receipt-history");
  storage.sql.exec("INSERT INTO lifecycle_receipts(digest,schema_version,operation,environment,authority_id,policy_epoch,key_fingerprint,sequence,applied_ms,current_release_id,next_release_id,next_key_id,activates_ms,retires_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    receipt.digest, receipt.version, receipt.operation, receipt.environment, receipt.authorityId, receipt.policyEpoch, receipt.keyFingerprint, sequence,
    receipt.appliedMs, receipt.currentReleaseId, receipt.nextReleaseId, receipt.nextKeyId, receipt.activatesMs, receipt.retiresMs);
  return { ...receipt, sequence };
}

/** SELECT-only, including on a DO whose schema has never been initialized. */
export function inspectLifecycleAuthority(storage: DurableStorageLike, digest: string, nowMs = Date.now()) {
  if (!/^[a-f0-9]{64}$/u.test(digest) || !Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("invalid-reconciliation");
  const table = (name: string) => exactlyOne<{ name: string }>(storage,
    "SELECT name FROM sqlite_master WHERE type='table' AND name=?", name) !== null;
  if (!table("authority_meta")) return { version: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: nowMs, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [] } as const;
  const meta = exactlyOne<MetaRow>(storage, "SELECT authority_id,policy_epoch,last_now_ms FROM authority_meta WHERE singleton=1");
  if (!meta) {
    if (table("active_releases") && rows(storage.sql.exec<ReleaseRow>("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases LIMIT 1")).length)
      return UNAVAILABLE_AUTHORITY_OBSERVATION;
    return { version: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
      observedAtMs: nowMs, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [] } as const;
  }
  if (meta.authority_id !== ADMISSION_AUTHORITY_ID || meta.policy_epoch !== ADMISSION_POLICY_EPOCH || !table("active_releases"))
    return UNAVAILABLE_AUTHORITY_OBSERVATION;
  const releases = rows(storage.sql.exec<ReleaseRow>("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY activated_ms")).slice(0, 3);
  if (!table("lifecycle_receipts") || !table("lifecycle_receipt_coverage") ||
      !exactlyOne(storage, "SELECT singleton FROM lifecycle_receipt_coverage WHERE singleton=1")) return { version: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID,
    policyEpoch: ADMISSION_POLICY_EPOCH, observedAtMs: nowMs, initialized: true, coverage: "INCOMPLETE", status: "HISTORY_INCOMPLETE",
    receipt: null, releases } as const;
  const receipt = findReceipt(storage, digest);
  return { version: 1, environment: "production", authorityId: ADMISSION_AUTHORITY_ID, policyEpoch: ADMISSION_POLICY_EPOCH,
    observedAtMs: nowMs, initialized: true, coverage: "COMPLETE", status: receipt ? "EXACT_RECEIPT" : "NOT_FOUND",
    receipt, releases } as const;
}

export type AuthorityInitialization = {
  environment: "production" | "staging";
  authorityId: string;
  policyEpoch: string;
  releaseId: string;
  releaseKeyId: string;
  nowMs: number;
  confirmProduction: boolean;
};

export function initializeAuthority(storage: DurableStorageLike, specification: AuthorityInitialization,
  commandReceipt?: Omit<LifecycleReceipt, "sequence">): { status: "initialized" | "already-initialized"; receipt?: LifecycleReceipt } {
  createAuthoritySchema(storage);
  if ((specification.environment !== "production" && specification.environment !== "staging") ||
      specification.authorityId !== ADMISSION_AUTHORITY_ID || specification.policyEpoch !== ADMISSION_POLICY_EPOCH ||
      !validRelease(specification.releaseId) || !validKeyId(specification.releaseKeyId) || !Number.isSafeInteger(specification.nowMs) || specification.nowMs < 0 ||
      specification.environment === "production" && specification.confirmProduction !== true) throw new Error("initialization-policy");
  return storage.transactionSync(() => {
    if (commandReceipt) {
      const prior = findReceipt(storage, commandReceipt.digest);
      if (prior) return { status: "already-initialized", receipt: prior } as const;
    }
    const meta = exactlyOne<MetaRow>(storage, "SELECT authority_id,policy_epoch,last_now_ms FROM authority_meta WHERE singleton=1");
    if (meta) {
      if (commandReceipt) throw new Error("authority-already-initialized");
      const releases = rows(storage.sql.exec<ReleaseRow>("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases ORDER BY activated_ms"));
      if (meta.authority_id === specification.authorityId && meta.policy_epoch === specification.policyEpoch && releases.length === 1 &&
          releases[0].release_id === specification.releaseId && releases[0].key_id === specification.releaseKeyId &&
          releases[0].activated_ms === specification.nowMs && releases[0].retired_ms === null) return { status: "already-initialized" } as const;
      throw new Error("authority-already-initialized");
    }
    if (commandReceipt) ensureNewReceiptCapacity(storage);
    storage.sql.exec("INSERT INTO authority_meta(singleton,authority_id,policy_epoch,last_now_ms) VALUES(1,?,?,?)",
      specification.authorityId, specification.policyEpoch, specification.nowMs);
    storage.sql.exec("INSERT INTO active_releases(release_id,key_id,activated_ms,retired_ms) VALUES(?,?,?,NULL)",
      specification.releaseId, specification.releaseKeyId, specification.nowMs);
    if (commandReceipt) {
      storage.sql.exec("INSERT INTO lifecycle_receipt_coverage(singleton,complete) VALUES(1,1)");
      return { status: "initialized", receipt: insertReceipt(storage, commandReceipt) } as const;
    }
    return { status: "initialized" } as const;
  });
}

export function rotateAuthorityRelease(storage: DurableStorageLike, input: {
  authorityId: string; policyEpoch: string; currentReleaseId: string; nextReleaseId: string; nextKeyId: string;
  activatesAtMs: number; previousRetiresAtMs: number;
}, commandReceipt?: Omit<LifecycleReceipt, "sequence">): { status: "rotated" | "already-rotated"; receipt?: LifecycleReceipt } {
  createAuthoritySchema(storage);
  if (input.authorityId !== ADMISSION_AUTHORITY_ID || input.policyEpoch !== ADMISSION_POLICY_EPOCH || !validRelease(input.currentReleaseId) ||
      !validRelease(input.nextReleaseId) || input.currentReleaseId === input.nextReleaseId || !validKeyId(input.nextKeyId) ||
      !Number.isSafeInteger(input.activatesAtMs) || !Number.isSafeInteger(input.previousRetiresAtMs) || input.activatesAtMs < 0 ||
      input.previousRetiresAtMs <= input.activatesAtMs || input.previousRetiresAtMs - input.activatesAtMs > 5 * 60_000) throw new Error("release-rotation-policy");
  return storage.transactionSync(() => {
    if (commandReceipt) {
      const prior = findReceipt(storage, commandReceipt.digest);
      if (prior) return { status: "already-rotated", receipt: prior } as const;
    }
    const meta = exactlyOne<MetaRow>(storage, "SELECT authority_id,policy_epoch,last_now_ms FROM authority_meta WHERE singleton=1");
    if (!meta || meta.authority_id !== input.authorityId || meta.policy_epoch !== input.policyEpoch) throw new Error("authority-mismatch");
    if (commandReceipt) {
      if (!exactlyOne(storage, "SELECT singleton FROM lifecycle_receipt_coverage WHERE singleton=1")) throw new Error("receipt-history");
      ensureNewReceiptCapacity(storage);
    }
    const existingNext = exactlyOne<ReleaseRow>(storage, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases WHERE release_id=?", input.nextReleaseId);
    if (existingNext) {
      const prior = exactlyOne<ReleaseRow>(storage, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases WHERE release_id=?", input.currentReleaseId);
      if (!commandReceipt && existingNext.key_id === input.nextKeyId && existingNext.activated_ms === input.activatesAtMs && existingNext.retired_ms === null && prior?.retired_ms === input.previousRetiresAtMs) return { status: "already-rotated" };
      throw new Error("release-already-exists");
    }
    if (meta.last_now_ms > input.activatesAtMs) throw new Error("authority-mismatch");
    const current = exactlyOne<ReleaseRow>(storage, "SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases WHERE release_id=? AND retired_ms IS NULL", input.currentReleaseId);
    let rowsPresent = rows(storage.sql.exec<ReleaseRow>("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases"));
    if (rowsPresent.length === 2) {
      const retired = rowsPresent.find((release) => release.retired_ms !== null);
      if (!retired || retired.retired_ms! + AUTHORITY_RELEASE_RETENTION_AFTER_RETIRE_MS > input.activatesAtMs) throw new Error("release-retention");
      storage.sql.exec("DELETE FROM active_releases WHERE release_id=? AND retired_ms=?", retired.release_id, retired.retired_ms);
      rowsPresent = rows(storage.sql.exec<ReleaseRow>("SELECT release_id,key_id,activated_ms,retired_ms FROM active_releases"));
    }
    if (!current || rowsPresent.length !== 1) throw new Error("release-state");
    storage.sql.exec("UPDATE active_releases SET retired_ms=? WHERE release_id=?", input.previousRetiresAtMs, input.currentReleaseId);
    storage.sql.exec("INSERT INTO active_releases(release_id,key_id,activated_ms,retired_ms) VALUES(?,?,?,NULL)", input.nextReleaseId, input.nextKeyId, input.activatesAtMs);
    if (commandReceipt) return { status: "rotated", receipt: insertReceipt(storage, commandReceipt) };
    return { status: "rotated" };
  });
}

function validPre(input: ClaimPreInput): boolean {
  return validRelease(input.releaseId) && isOpaque(input.clientPseudonym, 32) && isOpaque(input.requestBinding, 32) &&
    isOpaque(input.nonce, 16) && Number.isSafeInteger(input.issuedAtMs) && input.issuedAtMs >= 0;
}

function validPost(input: ConsumePostInput): boolean {
  return validRelease(input.releaseId) && isOpaque(input.clientPseudonym, 32) && isOpaque(input.requestBinding, 32) &&
    isOpaque(input.nonce, 16) && isOpaque(input.permit, 32);
}

export class PublicInquiryAdmissionAuthority {
  private readonly storage: DurableStorageLike;
  constructor(
    state: { storage: DurableStorageLike },
    private readonly options: { now?: () => number; expectedAuthorityId?: string; expectedPolicyEpoch?: string; faultAfterObservation?: () => void } = {},
  ) {
    this.storage = state.storage;
  }

  private authorityNow(releaseId: string): number | null {
    const meta = exactlyOne<MetaRow>(this.storage, "SELECT authority_id,policy_epoch,last_now_ms FROM authority_meta WHERE singleton=1");
    if (!meta || meta.authority_id !== (this.options.expectedAuthorityId ?? ADMISSION_AUTHORITY_ID) ||
        meta.policy_epoch !== (this.options.expectedPolicyEpoch ?? ADMISSION_POLICY_EPOCH)) return null;
    const observed = (this.options.now ?? Date.now)();
    if (!Number.isSafeInteger(observed) || observed < 0 || observed < meta.last_now_ms) return null;
    if (!exactlyOne(this.storage, "SELECT release_id FROM active_releases WHERE release_id=? AND activated_ms<=? AND (retired_ms IS NULL OR retired_ms>?)", releaseId, observed, observed)) return null;
    this.storage.sql.exec("UPDATE authority_meta SET last_now_ms=? WHERE singleton=1", observed);
    return observed;
  }

  private prune(nowMs: number): void {
    this.storage.sql.exec("DELETE FROM observations WHERE (stage='pre' AND ((scope='client' AND observed_at_ms<=?) OR (scope='global' AND observed_at_ms<=?))) OR (stage='post' AND ((scope='client' AND observed_at_ms<=?) OR (scope='global' AND observed_at_ms<=?)))",
      nowMs - admissionPolicy.pre.client.windowMs, nowMs - admissionPolicy.pre.global.windowMs,
      nowMs - admissionPolicy.post.client.windowMs, nowMs - admissionPolicy.post.global.windowMs);
    this.storage.sql.exec("DELETE FROM nonces WHERE retain_until_ms<=?", nowMs);
  }

  private count(stage: "pre" | "post", scope: "client" | "global", subject: string, lowerExclusive: number, nowMs: number): number {
    return exactlyOne<CountRow>(this.storage,
      "SELECT COUNT(*) AS count FROM observations WHERE stage=? AND scope=? AND subject=? AND observed_at_ms>? AND observed_at_ms<=?",
      stage, scope, subject, lowerExclusive, nowMs)?.count ?? Number.MAX_SAFE_INTEGER;
  }

  claimPre(input: ClaimPreInput): PreDecision {
    if (!validPre(input)) return { decision: "unavailable" };
    createAuthoritySchema(this.storage);
    const permit = encodeBase64url(crypto.getRandomValues(new Uint8Array(32)));
    const attempt = encodeBase64url(crypto.getRandomValues(new Uint8Array(16)));
    try {
      return this.storage.transactionSync(() => {
        const nowMs = this.authorityNow(input.releaseId);
        if (nowMs === null) return { decision: "unavailable" } as const;
        try { assertIngressFresh(input.issuedAtMs, nowMs); } catch { return { decision: "unavailable" } as const; }
        this.prune(nowMs);
        if (exactlyOne(this.storage, "SELECT nonce FROM nonces WHERE nonce=?", input.nonce)) return { decision: "replay" } as const;
        const clientCount = this.count("pre", "client", input.clientPseudonym, nowMs - admissionPolicy.pre.client.windowMs, nowMs);
        const globalCount = this.count("pre", "global", "*", nowMs - admissionPolicy.pre.global.windowMs, nowMs);
        if (clientCount >= admissionPolicy.pre.client.limit || globalCount >= admissionPolicy.pre.global.limit) return { decision: "limited" } as const;
        this.storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'pre','client',?,?)", `${attempt}:c`, input.clientPseudonym, nowMs);
        this.options.faultAfterObservation?.();
        this.storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'pre','global','*',?)", `${attempt}:g`, nowMs);
        const expiresAtMs = nowMs + PRE_PERMIT_LIFETIME_MS;
        this.storage.sql.exec("INSERT INTO nonces(nonce,release_id,client_id,request_binding,permit,claimed_ms,permit_expires_ms,retain_until_ms,post_consumed) VALUES(?,?,?,?,?,?,?,?,0)",
          input.nonce, input.releaseId, input.clientPseudonym, input.requestBinding, permit, nowMs, expiresAtMs, nowMs + NONCE_RETENTION_MS);
        return { decision: "allowed", permit, expiresAtMs } as const;
      });
    } catch {
      return { decision: "unavailable" };
    }
  }

  consumePost(input: ConsumePostInput): PostDecision {
    if (!validPost(input)) return { decision: "unavailable" };
    createAuthoritySchema(this.storage);
    const attempt = encodeBase64url(crypto.getRandomValues(new Uint8Array(16)));
    try {
      return this.storage.transactionSync(() => {
        const nowMs = this.authorityNow(input.releaseId);
        if (nowMs === null) return { decision: "unavailable" } as const;
        this.prune(nowMs);
        const nonce = exactlyOne<NonceRow>(this.storage,
          "SELECT release_id,client_id,request_binding,permit,permit_expires_ms,retain_until_ms,post_consumed FROM nonces WHERE nonce=?", input.nonce);
        if (!nonce || nonce.release_id !== input.releaseId || nonce.client_id !== input.clientPseudonym || nonce.request_binding !== input.requestBinding || nonce.permit !== input.permit || nonce.permit_expires_ms <= nowMs) return { decision: "unavailable" } as const;
        if (nonce.post_consumed !== 0) return { decision: "replay" } as const;
        const clientCount = this.count("post", "client", input.clientPseudonym, nowMs - admissionPolicy.post.client.windowMs, nowMs);
        const globalCount = this.count("post", "global", "*", nowMs - admissionPolicy.post.global.windowMs, nowMs);
        if (clientCount >= admissionPolicy.post.client.limit || globalCount >= admissionPolicy.post.global.limit) return { decision: "limited" } as const;
        this.storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'post','client',?,?)", `${attempt}:c`, input.clientPseudonym, nowMs);
        this.options.faultAfterObservation?.();
        this.storage.sql.exec("INSERT INTO observations(id,stage,scope,subject,observed_at_ms) VALUES(?,'post','global','*',?)", `${attempt}:g`, nowMs);
        this.storage.sql.exec("UPDATE nonces SET post_consumed=1 WHERE nonce=? AND post_consumed=0", input.nonce);
        return { decision: "allowed" } as const;
      });
    } catch {
      return { decision: "unavailable" };
    }
  }

  cleanup(maximumRows = 500): { deleted: number } | { unavailable: true } {
    if (!Number.isInteger(maximumRows) || maximumRows < 1 || maximumRows > 500) return { unavailable: true };
    createAuthoritySchema(this.storage);
    try {
      return this.storage.transactionSync(() => {
        const meta = exactlyOne<MetaRow>(this.storage, "SELECT authority_id,policy_epoch,last_now_ms FROM authority_meta WHERE singleton=1");
        if (!meta || meta.authority_id !== (this.options.expectedAuthorityId ?? ADMISSION_AUTHORITY_ID) || meta.policy_epoch !== (this.options.expectedPolicyEpoch ?? ADMISSION_POLICY_EPOCH)) return { unavailable: true } as const;
        const nowMs = (this.options.now ?? Date.now)();
        if (!Number.isSafeInteger(nowMs) || nowMs < meta.last_now_ms) return { unavailable: true } as const;
        const before = exactlyOne<CountRow>(this.storage, "SELECT COUNT(*) AS count FROM observations")?.count ?? 0;
        this.storage.sql.exec("DELETE FROM observations WHERE id IN (SELECT id FROM observations WHERE (stage='pre' AND ((scope='client' AND observed_at_ms<=?) OR (scope='global' AND observed_at_ms<=?))) OR (stage='post' AND ((scope='client' AND observed_at_ms<=?) OR (scope='global' AND observed_at_ms<=?))) LIMIT ?)",
          nowMs - admissionPolicy.pre.client.windowMs, nowMs - admissionPolicy.pre.global.windowMs,
          nowMs - admissionPolicy.post.client.windowMs, nowMs - admissionPolicy.post.global.windowMs, maximumRows);
        this.storage.sql.exec("DELETE FROM nonces WHERE nonce IN (SELECT nonce FROM nonces WHERE retain_until_ms<=? LIMIT ?)", nowMs, maximumRows);
        const after = exactlyOne<CountRow>(this.storage, "SELECT COUNT(*) AS count FROM observations")?.count ?? before;
        return { deleted: Math.max(0, before - after) };
      });
    } catch {
      return { unavailable: true };
    }
  }

  async alarm(): Promise<void> {
    this.cleanup(500);
    if (this.storage.setAlarm) await this.storage.setAlarm((this.options.now ?? Date.now)() + 60_000);
  }
}

export const authorityFreshnessMaximumMs = INGRESS_MAX_AGE_MS;
