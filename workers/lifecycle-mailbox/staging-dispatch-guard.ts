import { DurableObject } from "cloudflare:workers";
import type { DurableObjectState } from "@cloudflare/workers-types";
import { commandDigest, verifyOperatorCommand } from "../admission-service/operator-command";
import { parseSealedLifecycleArtifact } from "../../operator/lifecycle-submitter";
import type { LifecycleResult } from "../../operator/lifecycle-submitter";
import type { LifecycleReceipt } from "../admission-service/authority";
import type { GuardOutcome } from "./dispatch-guard";

// ---------------------------------------------------------------------------
// Gate 2 staging capability. Structurally mirrors LifecycleDispatchGuard but is
// a distinct Durable Object class/namespace (never sharing consumed-claim
// history, latch state or settlement ledger with Production) and supports
// only initialization dispatch. STAGING ROTATION IS NOT IMPLEMENTED — Gate 9
// stays CLOSED: processRotation below never parses, signs, verifies or
// touches storage, and always fails closed.
// ---------------------------------------------------------------------------

export const STAGING_GUARD_OBJECT_NAME = "staging-lifecycle-dispatch-v1";
export const STAGING_GUARD_CAPACITY = 4_096;

export type StagingLifecycleExecutorBinding = {
  submitInitializationArtifact(sealedJson: string): Promise<LifecycleResult>;
};
export type StagingLifecycleReaderBinding = { inspectLifecycle(digest: string): Promise<{
  status: string; receipt?: LifecycleReceipt | null; environment?: string; authorityId?: string; policyEpoch?: string;
}> };
export type StagingGuardEnvironment = {
  LIFECYCLE_EXECUTOR: StagingLifecycleExecutorBinding;
  LIFECYCLE_READER: StagingLifecycleReaderBinding;
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  LIFECYCLE_ENVIRONMENT: string;
};
type Claim = { digest: string; operation: string; status: string };
type Latch = { digest: string };
type SqlRow = Record<string, unknown>;
type SqlStore = { sql: { exec<T = SqlRow>(query: string, ...params: unknown[]): Iterable<T> }; transactionSync<T>(callback: () => T): T; sync(): Promise<void> };
type LocalFaultHooks = { afterClaimSync?(): Promise<void>; beforeExecutorCall?(): Promise<void> };

/** Consumed digests are permanent. There is deliberately no reset, lease or replay method. */
export class StagingLifecycleDispatchGuard extends DurableObject<StagingGuardEnvironment> {
  readonly #ledger: SqlStore;
  readonly #localFaults: LocalFaultHooks;
  constructor(state: DurableObjectState, env: StagingGuardEnvironment, localFaults: LocalFaultHooks = {}) {
    super(state, env);
    this.#ledger = state.storage as unknown as SqlStore;
    this.#localFaults = localFaults;
    this.#ledger.sql.exec("CREATE TABLE IF NOT EXISTS claims(digest TEXT PRIMARY KEY, operation TEXT NOT NULL, status TEXT NOT NULL)");
    this.#ledger.sql.exec("CREATE TABLE IF NOT EXISTS latch(singleton INTEGER PRIMARY KEY CHECK(singleton=1), digest TEXT NOT NULL)");
    this.#ledger.sql.exec("CREATE TABLE IF NOT EXISTS settlements(digest TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version=1), status TEXT NOT NULL CHECK(status='SETTLED'), sequence INTEGER NOT NULL UNIQUE, settled_ms INTEGER NOT NULL)");
  }

  #one<T>(query: string, ...params: unknown[]): T | null {
    return Array.from(this.#ledger.sql.exec<T>(query, ...params))[0] ?? null;
  }

  async processInitialization(sealedJson: string): Promise<GuardOutcome> {
    if (this.env.LIFECYCLE_ENVIRONMENT !== "staging" || typeof sealedJson !== "string")
      return { version: 1, digest: "", status: "UNAVAILABLE", reason: "configuration" };
    let digest = "";
    try {
      const artifact = parseSealedLifecycleArtifact(new TextEncoder().encode(sealedJson), "initialize", Date.now(), "staging");
      await verifyOperatorCommand(artifact.command, artifact.signature, this.env.AUTHORITY_OPERATOR_PUBLIC_KEY);
      digest = await commandDigest(artifact.command);
      // This check occurs after the awaited signature/hash work and before claim.
      parseSealedLifecycleArtifact(new TextEncoder().encode(sealedJson), "initialize", Date.now(), "staging");
    } catch { return { version: 1, digest, status: "REFUSED", reason: "invalid-command" }; }
    try {
      const snapshot = await this.env.LIFECYCLE_READER.inspectLifecycle(digest);
      if (snapshot.status === "EXACT_RECEIPT" && snapshot.receipt?.digest === digest &&
          snapshot.environment === "staging" && snapshot.authorityId === "staging-public-inquiries-v1" &&
          snapshot.policyEpoch === "phase5c-i1-epoch-1")
        return { version: 1, digest, status: "ALREADY_APPLIED", receipt: snapshot.receipt };
      if (snapshot.status !== "NOT_FOUND") return { version: 1, digest, status: "UNAVAILABLE", reason: "authority-history" };
    } catch { return { version: 1, digest, status: "UNAVAILABLE", reason: "authority-read" }; }
    let won = false;
    let prior: Claim | null = null;
    try {
      this.#ledger.transactionSync(() => {
        prior = this.#one<Claim>("SELECT digest,operation,status FROM claims WHERE digest=?", digest);
        if (prior) return;
        if (this.#one<Latch>("SELECT digest FROM latch WHERE singleton=1")) return;
        const count = this.#one<{ count: number }>("SELECT COUNT(*) AS count FROM claims")?.count;
        if (count === undefined || count >= STAGING_GUARD_CAPACITY) return;
        this.#ledger.sql.exec("INSERT INTO claims(digest,operation,status) VALUES(?,'initialize','CLAIMED')", digest);
        this.#ledger.sql.exec("INSERT INTO latch(singleton,digest) VALUES(1,?)", digest);
        won = true;
      });
      if (!won) return { version: 1, digest, status: prior ? "UNCONFIRMED" : "UNAVAILABLE",
        reason: prior ? "consumed" : "active-or-capacity" };
      await this.#ledger.sync();
    } catch { return { version: 1, digest, status: "UNCONFIRMED", reason: "claim-durability" }; }
    try { await this.#localFaults.afterClaimSync?.(); }
    catch { return { version: 1, digest, status: "UNCONFIRMED", reason: "pre-dispatch" }; }
    try { parseSealedLifecycleArtifact(new TextEncoder().encode(sealedJson), "initialize", Date.now(), "staging"); }
    catch { return { version: 1, digest, status: "UNCONFIRMED", reason: "expired-after-claim" }; }
    let response: LifecycleResult;
    try {
      await this.#localFaults.beforeExecutorCall?.();
      response = await this.env.LIFECYCLE_EXECUTOR.submitInitializationArtifact(sealedJson);
    } catch { return { version: 1, digest, status: "UNCONFIRMED", reason: "dispatch-ambiguous" }; }
    const safeResponse = response && typeof response === "object" ? response : null;
    const receipt = safeResponse && "receipt" in safeResponse ? safeResponse.receipt : undefined;
    const positive = receipt && receipt.digest === digest && receipt.environment === "staging" &&
      receipt.authorityId === "staging-public-inquiries-v1" && receipt.policyEpoch === "phase5c-i1-epoch-1";
    const responseStatus = safeResponse && "status" in safeResponse ? safeResponse.status : undefined;
    const status: GuardOutcome["status"] = positive && responseStatus === "initialized" ? "SUCCESS" :
      positive && responseStatus === "already-initialized" ? "ALREADY_APPLIED" :
      responseStatus === "refused" ? "REFUSED" : "UNCONFIRMED";
    try {
      this.#ledger.sql.exec("UPDATE claims SET status=? WHERE digest=?", status, digest);
      await this.#ledger.sync();
    } catch { return { version: 1, digest, status: "UNCONFIRMED", reason: "result-durability" }; }
    return { version: 1, digest, status, ...(positive ? { receipt: receipt as LifecycleReceipt } : {}) };
  }

  /** STAGING ROTATION — NOT IMPLEMENTED / GATE 9 — CLOSED. No sealed artifact is
   * parsed, no signature is verified and no storage is touched: this always
   * fails closed regardless of input. */
  async processRotation(): Promise<GuardOutcome> {
    return { version: 1, digest: "", status: "REFUSED", reason: "staging-rotation-not-implemented" };
  }

  /** Positive exact receipt releases only the supervisor latch, never a claim. */
  async settle(digest: string): Promise<{ version: 1; settled: boolean }> {
    if (!/^[a-f0-9]{64}$/u.test(digest)) return { version: 1, settled: false };
    if (!this.#one<Claim>("SELECT digest,operation,status FROM claims WHERE digest=?", digest))
      return { version: 1, settled: false };
    if (this.#one("SELECT digest FROM settlements WHERE digest=?", digest)) {
      try { await this.#ledger.sync(); return { version: 1, settled: true }; }
      catch { return { version: 1, settled: false }; }
    }
    const latch = this.#one<Latch>("SELECT digest FROM latch WHERE singleton=1");
    if (!latch || latch.digest !== digest) return { version: 1, settled: false };
    let snapshot: Awaited<ReturnType<StagingLifecycleReaderBinding["inspectLifecycle"]>>;
    try { snapshot = await this.env.LIFECYCLE_READER.inspectLifecycle(digest); }
    catch { return { version: 1, settled: false }; }
    if (snapshot.status !== "EXACT_RECEIPT" || snapshot.receipt?.digest !== digest || snapshot.environment !== "staging" ||
        snapshot.authorityId !== "staging-public-inquiries-v1" || snapshot.policyEpoch !== "phase5c-i1-epoch-1")
      return { version: 1, settled: false };
    try {
      this.#ledger.transactionSync(() => {
        if (this.#one("SELECT digest FROM settlements WHERE digest=?", digest)) return;
        const current = this.#one<Latch>("SELECT digest FROM latch WHERE singleton=1");
        if (current?.digest !== digest) return;
        const sequence = this.#one<{ value: number }>("SELECT COALESCE(MAX(sequence),0)+1 AS value FROM settlements")?.value;
        if (!Number.isSafeInteger(sequence) || !sequence || sequence > STAGING_GUARD_CAPACITY) throw new Error("settlement-capacity");
        this.#ledger.sql.exec("INSERT INTO settlements(digest,version,status,sequence,settled_ms) VALUES(?,1,'SETTLED',?,?)", digest, sequence, Date.now());
        this.#ledger.sql.exec("DELETE FROM latch WHERE singleton=1 AND digest=?", digest);
      });
      await this.#ledger.sync();
      return { version: 1, settled: !!this.#one("SELECT digest FROM settlements WHERE digest=?", digest) };
    } catch {
      return { version: 1, settled: false };
    }
  }
}
