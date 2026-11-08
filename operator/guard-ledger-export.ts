import { createHash } from "node:crypto";
import { statSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import gates from "../deployment/lifecycle-environment-gates.json";
import { parseStrictJson } from "./lifecycle-submitter";

/**
 * READ-ONLY export of a lifecycle dispatch guard's ledger (claims, latch, settlements) for forensics and for the recovery decision table.
 *
 * What this is NOT: it issues no claim, consume, settle, initialization or guard-generation operation, creates no table, writes no file, opens no
 * network connection and holds no secret. The ledger rows hold only digests, operation names and statuses. The guard's rows are RELAY-LOCAL
 * BOOKKEEPING (the guard itself says nothing reads them as evidence): the export is an auditable copy of that bookkeeping, never Authority
 * evidence. Any recovery decision still requires Authority-signed reconciliations (see GUARD-GENERATION-RECOVERY-DESIGN.md).
 *
 * Identity: the caller names the environment and the guard object; both must equal the reviewed pins in deployment/lifecycle-environment-gates.json.
 * A local SQLite file carries no embedded identity, so its provenance is recorded as "operator-asserted"; a future live source must report the
 * identity itself (not implemented: it needs a SELECT-only method on the guard, which is a separate approval).
 *
 * Fail closed: unknown keys, wrong types, bad digests, duplicates, over-capacity tables, a ledger that violates the guard's own invariants
 * (below) or an incomplete source all throw GuardExportRefusal with a fixed code and no row content.
 */
export const GUARD_LEDGER_EXPORT_FORMAT = "limitmark-guard-ledger-export-v1";
export const GUARD_LEDGER_CAPACITY = 4_096;
export const GUARD_LEDGER_MAX_FILE_BYTES = 64 * 1024 * 1024;
const POLICY_EPOCH = "phase5c-i1-epoch-1";

export type GuardEnvironmentName = "production" | "staging" | "lab";
export class GuardExportRefusal extends Error {
  constructor(readonly code: string) { super(code); this.name = "GuardExportRefusal"; }
}
const refuse = (code: string): never => { throw new GuardExportRefusal(code); };

export type GuardClaimRow = { digest: string; operation: "initialize" | "rotate-release"; status: "CLAIMED" | "SUCCESS" | "ALREADY_APPLIED" | "REFUSED" | "UNCONFIRMED" };
export type GuardSettlementRow = { digest: string; sequence: number; settledMs: number };
export type GuardLedgerRows = { claims: GuardClaimRow[]; latch: { digest: string } | null; settlements: GuardSettlementRow[] };

/** A source of ledger rows. Implementations must be read-only; the only one provided reads a local SQLite file. */
export interface GuardLedgerSource {
  readonly kind: "sqlite-file";
  read(): GuardLedgerRows;
}

/** Identity the live guard itself reported (inside an operator-signed, read-only export request answered by the guard). */
export type GuardExportRequestBinding = { requestDigest: string; nonce: string; accountId: string; observedAtMs: number };

const digestPattern = /^[a-f0-9]{64}$/u;
const claimStatuses = new Set(["CLAIMED", "SUCCESS", "ALREADY_APPLIED", "REFUSED", "UNCONFIRMED"]);

type GateEntry = { guardObject: string; authorityObject: string };
const gateTable = gates as unknown as Record<string, GateEntry | unknown>;

function exactKeys(value: unknown, keys: readonly string[], code: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return refuse(code);
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record);
  if (actual.length !== keys.length || !keys.every((key) => Object.hasOwn(record, key))) return refuse(code);
  return record;
}

/** Explicit environment + guard-object identity check against the reviewed pins. */
export function guardTarget(environment: string, guardObject: string): { environment: GuardEnvironmentName; guardObject: string; authorityId: string; policyEpoch: string } {
  if (environment !== "production" && environment !== "staging" && environment !== "lab") return refuse("target-environment");
  const entry = gateTable[environment] as Partial<GateEntry> | undefined;
  if (!entry || typeof entry.guardObject !== "string" || typeof entry.authorityObject !== "string") return refuse("target-environment");
  if (guardObject !== entry.guardObject) return refuse("target-guard-object");
  return { environment, guardObject: entry.guardObject, authorityId: entry.authorityObject, policyEpoch: POLICY_EPOCH };
}

/** Validates untrusted rows against the guard's schema and invariants and returns a normalized, sorted copy. */
export function normalizeGuardLedgerRows(environment: GuardEnvironmentName, input: unknown): GuardLedgerRows {
  const raw = exactKeys(input, ["claims", "latch", "settlements"], "rows-shape");
  if (!Array.isArray(raw.claims) || !Array.isArray(raw.settlements)) return refuse("rows-shape");
  if (raw.claims.length > GUARD_LEDGER_CAPACITY || raw.settlements.length > GUARD_LEDGER_CAPACITY) return refuse("rows-capacity");
  const allowedOperations = environment === "production" ? new Set(["initialize", "rotate-release"]) : new Set(["initialize"]);
  const claims: GuardClaimRow[] = raw.claims.map((entry) => {
    const row = exactKeys(entry, ["digest", "operation", "status"], "claim-shape");
    if (typeof row.digest !== "string" || !digestPattern.test(row.digest) || typeof row.operation !== "string" || !allowedOperations.has(row.operation) ||
        typeof row.status !== "string" || !claimStatuses.has(row.status)) return refuse("claim-value");
    return { digest: row.digest, operation: row.operation as GuardClaimRow["operation"], status: row.status as GuardClaimRow["status"] };
  });
  const settlements: GuardSettlementRow[] = raw.settlements.map((entry) => {
    const row = exactKeys(entry, ["digest", "sequence", "settledMs"], "settlement-shape");
    if (typeof row.digest !== "string" || !digestPattern.test(row.digest) || !Number.isSafeInteger(row.sequence) || (row.sequence as number) < 1 ||
        (row.sequence as number) > GUARD_LEDGER_CAPACITY || !Number.isSafeInteger(row.settledMs) || (row.settledMs as number) < 0) return refuse("settlement-value");
    return { digest: row.digest, sequence: row.sequence as number, settledMs: row.settledMs as number };
  });
  let latch: { digest: string } | null = null;
  if (raw.latch !== null) {
    const row = exactKeys(raw.latch, ["digest"], "latch-shape");
    if (typeof row.digest !== "string" || !digestPattern.test(row.digest)) return refuse("latch-value");
    latch = { digest: row.digest };
  }
  claims.sort((a, b) => (a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0));
  settlements.sort((a, b) => a.sequence - b.sequence);

  // Invariants of the guard itself (dispatch-guard.ts): a claim row is inserted together with the single latch row only when no latch exists, and the
  // latch is deleted only inside the transaction that inserts that digest's settlement. Therefore every claim except the latched one is settled.
  if (new Set(claims.map((claim) => claim.digest)).size !== claims.length) return refuse("ledger-duplicate-claim");
  if (new Set(settlements.map((settlement) => settlement.digest)).size !== settlements.length) return refuse("ledger-duplicate-settlement");
  settlements.forEach((settlement, index) => { if (settlement.sequence !== index + 1) refuse("ledger-settlement-sequence"); });
  const claimed = new Set(claims.map((claim) => claim.digest));
  if (settlements.some((settlement) => !claimed.has(settlement.digest))) return refuse("ledger-settlement-without-claim");
  if (latch !== null && !claimed.has(latch.digest)) return refuse("ledger-latch-without-claim");
  if (latch !== null && settlements.some((settlement) => settlement.digest === latch!.digest)) return refuse("ledger-latch-and-settlement");
  const settled = new Set(settlements.map((settlement) => settlement.digest));
  const unsettled = claims.filter((claim) => !settled.has(claim.digest));
  if (latch === null ? unsettled.length !== 0 : unsettled.length !== 1 || unsettled[0].digest !== latch.digest) return refuse("ledger-unsettled-claims");
  return { claims, latch, settlements };
}

/** Deterministic JSON: object keys sorted recursively, arrays in their (already sorted) order, no insignificant whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
}

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");

export type GuardLedgerExport = ReturnType<typeof buildGuardLedgerExport>;

export function buildGuardLedgerExport(input: { environment: string; guardObject: string; provenance: GuardLedgerSource["kind"] | "mailbox-export"; rows: unknown; request?: GuardExportRequestBinding }) {
  const target = guardTarget(input.environment, input.guardObject);
  if (input.provenance !== "sqlite-file" && input.provenance !== "mailbox-export") return refuse("provenance");
  if ((input.provenance === "mailbox-export") !== (input.request !== undefined)) return refuse("provenance");
  if (input.request !== undefined) {
    const r = exactKeys(input.request, ["requestDigest", "nonce", "accountId", "observedAtMs"], "export-request-binding");
    if (typeof r.requestDigest !== "string" || !digestPattern.test(r.requestDigest) || typeof r.nonce !== "string" || !/^[a-f0-9]{32}$/u.test(r.nonce) ||
        typeof r.accountId !== "string" || !/^[a-f0-9]{32}$/u.test(r.accountId) || !Number.isSafeInteger(r.observedAtMs) || (r.observedAtMs as number) < 0) return refuse("export-request-binding");
  }
  const ledger = normalizeGuardLedgerRows(target.environment, input.rows);
  const settled = new Set(ledger.settlements.map((settlement) => settlement.digest));
  const unsettled = ledger.claims.filter((claim) => !settled.has(claim.digest));
  const latched = ledger.latch === null ? null : ledger.claims.find((claim) => claim.digest === ledger.latch!.digest)!;
  const body = {
    format: GUARD_LEDGER_EXPORT_FORMAT,
    target,
    provenance: input.request === undefined
      ? { kind: input.provenance, identityEvidence: "operator-asserted", readOnly: true, evidenceClass: "relay-local-bookkeeping-unsigned" }
      : { kind: input.provenance, identityEvidence: "guard-reported-after-operator-signed-request", readOnly: true, evidenceClass: "relay-local-bookkeeping-unsigned",
          request: { requestDigest: input.request.requestDigest, nonce: input.request.nonce, accountId: input.request.accountId, observedAtMs: input.request.observedAtMs } },
    ledger,
    derived: {
      claimCount: ledger.claims.length,
      settlementCount: ledger.settlements.length,
      latchHeld: ledger.latch !== null,
      latchedDigest: ledger.latch?.digest ?? null,
      latchedOperation: latched?.operation ?? null,
      latchedStatus: latched?.status ?? null,
      /** True when no further command can dispatch until the latched digest is settled (settle needs the Authority's EXACT_RECEIPT for that digest). */
      dispatchBlocked: ledger.latch !== null,
      /** A latched claim whose status is not SUCCESS/ALREADY_APPLIED has no positive relay outcome recorded: a candidate for the recovery decision table, NOT a verdict. */
      strandedCandidate: latched !== null && latched !== undefined && latched.status !== "SUCCESS" && latched.status !== "ALREADY_APPLIED",
      unsettledDigests: unsettled.map((claim) => claim.digest),
      claimsRemaining: GUARD_LEDGER_CAPACITY - ledger.claims.length,
      settlementsRemaining: GUARD_LEDGER_CAPACITY - ledger.settlements.length,
    },
  };
  const contentSha256 = sha256(`${GUARD_LEDGER_EXPORT_FORMAT}\n${canonicalJson(body)}`);
  return { ...body, contentSha256 };
}

export function serializeGuardLedgerExport(value: GuardLedgerExport): string {
  return `${canonicalJson(value)}\n`;
}

/** Re-derives an export from its own ledger and requires byte equality: detects any edited row, derived field, target or hash. */
export function verifyGuardLedgerExport(text: string, expected: { environment: string; guardObject: string }): GuardLedgerExport {
  if (typeof text !== "string" || text.length === 0 || text.length > GUARD_LEDGER_MAX_FILE_BYTES) return refuse("export-size");
  let parsed: unknown;
  try { parsed = parseStrictJson(text); } catch { return refuse("export-json"); }
  const document = exactKeys(parsed, ["format", "target", "provenance", "ledger", "derived", "contentSha256"], "export-shape");
  if (document.format !== GUARD_LEDGER_EXPORT_FORMAT) return refuse("export-format");
  const provenance = (document.provenance ?? {}) as Record<string, unknown>;
  const live = provenance.kind === "mailbox-export";
  const rebuilt = buildGuardLedgerExport({ environment: expected.environment, guardObject: expected.guardObject, provenance: live ? "mailbox-export" : "sqlite-file", rows: document.ledger,
    ...(live ? { request: provenance.request as GuardExportRequestBinding } : {}) });
  if (serializeGuardLedgerExport(rebuilt) !== (text.endsWith("\n") ? text : `${text}\n`)) return refuse("export-mismatch");
  return rebuilt;
}

// ----------------------------------------------------------------------------------------------------------------- local SQLite source

const expectedColumns: Record<string, readonly string[]> = {
  claims: ["digest", "operation", "status"],
  latch: ["singleton", "digest"],
  settlements: ["digest", "version", "status", "sequence", "settled_ms"],
};

/**
 * Reads a guard ledger from a local SQLite file (a copy of a disposable-fixture or locally persisted guard store). The file is opened read-only, the
 * connection is put in query_only mode, only fixed SELECT statements run, and nothing is created or altered. Missing tables or unexpected columns are
 * refused rather than tolerated.
 */
export function readGuardLedgerFromSqlite(path: string): GuardLedgerRows {
  let size: number;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) return refuse("source-not-file");
    size = stat.size;
  } catch (error) {
    if (error instanceof GuardExportRefusal) throw error;
    return refuse("source-unreadable");
  }
  if (size < 1 || size > GUARD_LEDGER_MAX_FILE_BYTES) return refuse("source-size");
  let database: DatabaseSync | undefined;
  try {
    database = new DatabaseSync(path, { readOnly: true });
    database.exec("PRAGMA query_only = ON");
    const tables = new Set((database.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as Array<{ name: string }>).map((row) => row.name));
    for (const [table, columns] of Object.entries(expectedColumns)) {
      if (!tables.has(table)) return refuse("source-incomplete");
      const actual = (database.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((row) => row.name);
      if (actual.length !== columns.length || !columns.every((column) => actual.includes(column))) return refuse("source-schema");
    }
    const claims = database.prepare("SELECT digest, operation, status FROM claims LIMIT ?").all(GUARD_LEDGER_CAPACITY + 1) as Array<Record<string, unknown>>;
    const latchRows = database.prepare("SELECT singleton, digest FROM latch LIMIT 2").all() as Array<Record<string, unknown>>;
    const settlementRows = database.prepare("SELECT digest, version, status, sequence, settled_ms FROM settlements LIMIT ?").all(GUARD_LEDGER_CAPACITY + 1) as Array<Record<string, unknown>>;
    if (latchRows.length > 1 || (latchRows.length === 1 && latchRows[0].singleton !== 1)) return refuse("source-latch");
    if (settlementRows.some((row) => row.version !== 1 || row.status !== "SETTLED")) return refuse("source-settlement-values");
    return {
      claims: claims.map((row) => ({ digest: row.digest, operation: row.operation, status: row.status }) as GuardClaimRow),
      latch: latchRows.length === 1 ? { digest: latchRows[0].digest as string } : null,
      settlements: settlementRows.map((row) => ({ digest: row.digest, sequence: row.sequence, settledMs: row.settled_ms }) as GuardSettlementRow),
    };
  } catch (error) {
    if (error instanceof GuardExportRefusal) throw error;
    return refuse("source-unreadable");
  } finally {
    try { database?.close(); } catch { /* read-only handle */ }
  }
}

export const sqliteGuardLedgerSource = (path: string): GuardLedgerSource => ({ kind: "sqlite-file", read: () => readGuardLedgerFromSqlite(path) });

export function exportGuardLedger(source: GuardLedgerSource, target: { environment: string; guardObject: string }): GuardLedgerExport {
  return buildGuardLedgerExport({ environment: target.environment, guardObject: target.guardObject, provenance: source.kind, rows: source.read() });
}

// ----------------------------------------------------------------------------------------------------------------- live (mailbox) export result

/**
 * Turns the guard's answer to an operator-signed, read-only export request (as published by the observer under ledger-export/<nonce>.json) into the same
 * deterministic export document. Everything the guard reported is re-validated here: the request digest/nonce must be the ones the operator signed
 * (the caller passes them), the environment, Authority, guard object and account must equal the expected pins, and the rows go through the same
 * invariant checks as a SQLite file. Anything else (REFUSED, TOO_LARGE, unknown keys, mismatching identity) is a refusal with a fixed code.
 */
export function guardLedgerExportFromMailboxResult(text: string, expected: { environment: string; guardObject: string; accountId: string; requestDigest: string; nonce: string }) {
  if (typeof text !== "string" || text.length === 0 || text.length > 8_192) return refuse("export-size");
  let parsed: unknown;
  try { parsed = parseStrictJson(text); } catch { return refuse("export-json"); }
  const target = guardTarget(expected.environment, expected.guardObject);
  if (target.environment !== "production") return refuse("target-environment");
  const document = exactKeys(parsed, ["version", "status", "requestDigest", "nonce", "accountId", "guardObject", "authorityId", "environment", "observedAtMs", "ledger"], "export-shape");
  if (document.version !== 1 || document.status !== "EXPORTED") return refuse("export-status");
  if (document.requestDigest !== expected.requestDigest || document.nonce !== expected.nonce) return refuse("export-request-mismatch");
  if (document.accountId !== expected.accountId || document.environment !== target.environment || document.guardObject !== target.guardObject || document.authorityId !== target.authorityId) return refuse("export-identity");
  if (!Number.isSafeInteger(document.observedAtMs)) return refuse("export-shape");
  const ledger = exactKeys(document.ledger, ["claims", "latch", "settlements"], "export-shape");
  return buildGuardLedgerExport({ environment: expected.environment, guardObject: expected.guardObject, provenance: "mailbox-export", rows: ledger,
    request: { requestDigest: expected.requestDigest, nonce: expected.nonce, accountId: expected.accountId, observedAtMs: document.observedAtMs as number } });
}
