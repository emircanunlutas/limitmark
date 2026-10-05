/**
 * Accounting derived from the correlated lifecycle records. Counters here are COMPUTED from the records; they are never the source of
 * truth. The identities are secondary reconciliation checks: the primary check is the per-request lifecycle validation
 * (defense/core/ledger.ts), which already flags duplicate terminals, missing transitions, impossible order, disappearance, duplicate
 * origin processing and unresolved work. A failing identity makes the run INVALID.
 */
import { ALL_REJECT_REASONS, REJECT_REASONS } from "../../defense/core/types";
import { EGRESS_ERROR_KINDS, TERMINAL_OUTCOMES, type EgressErrorKind, type TerminalOutcome } from "../../defense/core/ledger";
import { Collector, type LedgerRecord } from "./collector";

export type Identity = { id: string; description: string; left: number; right: number; ok: boolean };

export type AccountingReport = {
  sent: { protected: number; control: number; preIngress: number; total: number };
  ingress: { accepted: number; loss: number; unresolved: number; terminal: Record<TerminalOutcome, number> };
  l1: { entered: number; passed: number; rejected: number; shed: number; error: number; rejectedByReason: Record<string, number>; errorByKind: Record<string, number> };
  egress: { attempted: number; responded: number; failed: number; failedByKind: Record<EgressErrorKind, number> };
  origin: {
    protectedReceived: number; protectedCompleted: number; protectedAborted: number; controlReceived: number; controlCompleted: number; controlAborted: number;
    /** Protected-origin receipts with no plane L1 pass behind them (a bypass). Must be 0. */
    receivedWithoutL1Pass: number;
    spoofedHeadersSeen: number;
  };
  /** A layer PASS is not delivery: passes minus origin receipts, attributed to egress failures. */
  delivery: { l1PassedNotReceivedByOrigin: number; egressFailedWithOriginReceipt: number };
  parser: { expectedPreIngress: number; planeReported: number };
  client: { completed: number; byResult: Record<string, number> };
  residualHostileAtOrigin: Record<string, number>;
  identities: Identity[];
  identitiesOk: boolean;
};

const zeroMap = <K extends string>(keys: readonly K[]): Record<K, number> => Object.fromEntries(keys.map((key) => [key, 0])) as Record<K, number>;

export function deriveAccounting(records: Iterable<LedgerRecord>, parserRejectedByPlane: number): AccountingReport {
  const sent = { protected: 0, control: 0, preIngress: 0, total: 0 };
  const terminal = zeroMap(TERMINAL_OUTCOMES);
  const rejectedByReason: Record<string, number> = Object.fromEntries(REJECT_REASONS.map((reason) => [reason, 0]));
  const errorByKind: Record<string, number> = { throw: 0, timeout: 0, invalid_verdict: 0 };
  const failedByKind = zeroMap(EGRESS_ERROR_KINDS);
  const origin = { protectedReceived: 0, protectedCompleted: 0, protectedAborted: 0, controlReceived: 0, controlCompleted: 0, controlAborted: 0, receivedWithoutL1Pass: 0, spoofedHeadersSeen: 0 };
  const l1 = { entered: 0, passed: 0, rejected: 0, shed: 0, error: 0 };
  const egress = { attempted: 0, responded: 0, failed: 0 };
  const clientByResult: Record<string, number> = {};
  const residual: Record<string, number> = {};
  let accepted = 0; let loss = 0; let unresolved = 0; let clientCompleted = 0; let failedWithReceipt = 0; let rejectsWithUnknownReason = 0;

  for (const record of records) {
    sent.total++;
    if (record.meta.lane === "protected") sent.protected++; else if (record.meta.lane === "control") sent.control++; else sent.preIngress++;
    for (const event of record.harness) if (event.kind === "CLIENT_COMPLETED") { clientCompleted++; clientByResult[event.result ?? "unknown"] = (clientByResult[event.result ?? "unknown"] ?? 0) + 1; }

    const kinds = new Set(record.plane.map((event) => event.kind));
    if (record.meta.lane === "protected") {
      if (kinds.has("INGRESS_ACCEPTED")) accepted++; else loss++;
      const outcome = Collector.terminalOf(record);
      if (outcome === null) { if (kinds.has("INGRESS_ACCEPTED")) unresolved++; } else terminal[outcome]++;
      if (kinds.has("L1_ENTERED")) l1.entered++;
      if (kinds.has("L1_PASSED")) l1.passed++;
      if (kinds.has("L1_SHED")) l1.shed++;
      for (const event of record.plane) {
        if (event.kind === "L1_REJECTED") {
          l1.rejected++;
          // A Slice-2 semantic reason is a member of the closed list too; it only appears in a row once it actually occurs.
          if (event.reason && (ALL_REJECT_REASONS as readonly string[]).includes(event.reason)) rejectedByReason[event.reason] = (rejectedByReason[event.reason] ?? 0) + 1; else rejectsWithUnknownReason++;
        } else if (event.kind === "L1_ERROR") { l1.error++; errorByKind[event.errorKind ?? "unknown"] = (errorByKind[event.errorKind ?? "unknown"] ?? 0) + 1; }
        else if (event.kind === "EGRESS_FAILED") { egress.failed++; if (event.egressError) failedByKind[event.egressError]++; }
      }
      if (kinds.has("EGRESS_ATTEMPTED")) egress.attempted++;
      if (kinds.has("EGRESS_RESPONDED")) egress.responded++;
      const received = record.origin.some((event) => event.kind === "ORIGIN_RECEIVED" && event.instance === "protected");
      if (received && kinds.has("EGRESS_FAILED")) failedWithReceipt++;
      if (received && !kinds.has("EGRESS_ATTEMPTED")) origin.receivedWithoutL1Pass++;
      if (received && record.meta.cls === "hostile") residual[record.meta.scenario] = (residual[record.meta.scenario] ?? 0) + 1;
    } else if (record.meta.lane === "pre_ingress") {
      if (record.origin.length > 0) origin.receivedWithoutL1Pass++;
    }
    for (const event of record.origin) {
      origin.spoofedHeadersSeen += event.spoofed ?? 0;
      if (event.instance === "protected") {
        if (event.kind === "ORIGIN_RECEIVED") origin.protectedReceived++; else if (event.kind === "ORIGIN_COMPLETED") origin.protectedCompleted++; else origin.protectedAborted++;
      } else if (event.kind === "ORIGIN_RECEIVED") origin.controlReceived++; else if (event.kind === "ORIGIN_COMPLETED") origin.controlCompleted++; else origin.controlAborted++;
    }
  }

  const terminalTotal = TERMINAL_OUTCOMES.reduce((total, key) => total + terminal[key], 0);
  const identity = (id: string, description: string, left: number, right: number): Identity => ({ id, description, left, right, ok: left === right });
  const identities: Identity[] = [
    identity("ledger.sent_protected_equals_ingress_accepted_plus_loss", "every request sent to the plane is accepted at ingress or reported as ingress loss", sent.protected, accepted + loss),
    identity("ledger.ingress_loss_is_zero", "no request sent to the plane disappears before ingress", loss, 0),
    identity("ledger.ingress_accepted_equals_terminal_plus_unresolved", "ingress equals the sum of derived terminal outcomes plus unresolved work", accepted, terminalTotal + unresolved),
    identity("ledger.unresolved_is_zero", "no accepted request is unresolved at finalization", unresolved, 0),
    identity("ledger.l1_in_equals_pass_reject_shed_error", "L1 input equals its outcomes", l1.entered, l1.passed + l1.rejected + l1.shed + l1.error),
    identity("ledger.l1_in_equals_ingress_accepted", "every accepted request enters L1 (nothing disappears between ingress and the layer)", l1.entered, accepted),
    identity("ledger.egress_attempted_equals_l1_pass", "only L1 passes proceed to egress; an error never does (fail closed)", egress.attempted, l1.passed),
    identity("ledger.egress_attempted_equals_responded_plus_failed", "every egress attempt is attributed", egress.attempted, egress.responded + egress.failed),
    identity("ledger.reject_reasons_equal_rejects", "every reject carries exactly one closed-enum reason", Object.values(rejectedByReason).reduce((a, b) => a + b, 0) + rejectsWithUnknownReason, l1.rejected),
    identity("ledger.reject_unknown_reason_is_zero", "no reject has a reason outside the closed enum", rejectsWithUnknownReason, 0),
    identity("ledger.origin_protected_received_equals_responded_plus_failed_with_receipt", "protected-origin receipts reconcile with egress outcomes", origin.protectedReceived, egress.responded + failedWithReceipt),
    identity("ledger.origin_protected_received_equals_completed_plus_aborted", "every protected-origin receipt resolves", origin.protectedReceived, origin.protectedCompleted + origin.protectedAborted),
    identity("ledger.origin_without_l1_pass_is_zero", "the origin never processes a request the plane did not pass", origin.receivedWithoutL1Pass, 0),
    identity("ledger.origin_control_received_equals_sent_control", "every control request is observed once by the control origin", origin.controlReceived, sent.control),
    identity("ledger.origin_control_received_equals_completed_plus_aborted", "every control-origin receipt resolves", origin.controlReceived, origin.controlCompleted + origin.controlAborted),
    identity("ledger.pre_ingress_sent_equals_parser_rejected", "requests expected to die in the HTTP parser equal the plane's anonymous parser rejections", sent.preIngress, parserRejectedByPlane),
    identity("ledger.client_completed_equals_sent", "every sent request has a client-side result", clientCompleted, sent.total),
    identity("ledger.spoofed_headers_at_origin_is_zero", "no spoofable internal or forwarding header reaches the origin", origin.spoofedHeadersSeen, 0),
  ];

  return {
    sent,
    ingress: { accepted, loss, unresolved, terminal },
    l1: { ...l1, rejectedByReason, errorByKind },
    egress: { ...egress, failedByKind },
    origin,
    delivery: { l1PassedNotReceivedByOrigin: l1.passed - origin.protectedReceived, egressFailedWithOriginReceipt: failedWithReceipt },
    parser: { expectedPreIngress: sent.preIngress, planeReported: parserRejectedByPlane },
    client: { completed: clientCompleted, byResult: clientByResult },
    residualHostileAtOrigin: residual,
    identities,
    identitiesOk: identities.every((entry) => entry.ok),
  };
}
