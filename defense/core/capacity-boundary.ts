import { types } from "node:util";
import { classifyVerifiedCandidate, readCompiledPolicyInternal } from "./capacity-policy";
import { createOriginCapacityState, supportedTimestamp } from "./origin-capacity";
import type {
  AttemptStatus, CapacityAttempt, CapacityDecisionClock, CapacityExecution, CapacityExecutionIdentity,
  CapacityExecutionVerifier, CapacityGeneration, CapacityLease, CapacityRequestInput, CapacitySettlementEvent,
  CompiledCustomerOriginPolicy, OriginRequestVerifier, VerificationBody,
} from "./capacity-port";

const MAX_BRACKET_MS = 1;
const MAX_WORK = 256;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const getBuffer = Object.getOwnPropertyDescriptor(typedArrayPrototype, "buffer")!.get!;
const getByteOffset = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteOffset")!.get!;
const getByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;
const getResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "resizable")?.get;

function sourceView(input: unknown, limit: number): Uint8Array | undefined {
  if (input === undefined) return new Uint8Array(0);
  if (!types.isUint8Array(input)) return;
  const buffer = getBuffer.call(input) as ArrayBuffer;
  if (types.isSharedArrayBuffer(buffer) || getResizable?.call(buffer)) return;
  const length = getByteLength.call(input) as number;
  if (length > limit) return;
  // Intrinsics bypass a caller's shadowed properties and constructor/species.
  return new Uint8Array(buffer, getByteOffset.call(input), length);
}

function bodyView(body: Uint8Array) {
  const length = body.byteLength;
  let readable: Uint8Array | undefined = body;
  const view: VerificationBody = Object.freeze({
    byteLength: length,
    byteAt: (index: number) => Number.isSafeInteger(index) ? readable?.[index] : undefined,
  });
  return { view, revoke: () => { readable = undefined; } };
}

type Evidence = CapacityExecutionIdentity & {
  kind: "terminal" | "verified-termination" | "ambiguous";
  hardStop?: number;
};

/**
 * Isolated M2 composition. Pass the request capability to callers, and keep
 * maintenance and execution capabilities with their trusted owners.
 */
export function createOriginCapacityBoundary<T, TProof>(
  policy: CompiledCustomerOriginPolicy,
  clock: CapacityDecisionClock,
  verifier: OriginRequestVerifier<T>,
  executionVerifier: CapacityExecutionVerifier<TProof>,
) {
  const { manifest: { capacity: limits } } = readCompiledPolicyInternal(policy);
  const { controller, owner } = createOriginCapacityState(policy);
  const generation = Object.freeze(Object.create(null)) as CapacityGeneration;
  const mono = clock.monotonicMs.bind(clock);
  const wall = clock.wallUpperMs.bind(clock);
  const verifyRequest = verifier.verify.bind(verifier);
  const verifyExecution = executionVerifier.verify.bind(executionVerifier);
  const preparingBodyLimit = Math.max(limits.maxBodyBytes, limits.maxQueuedBytes);
  let preparingBodyBytes = 0;
  let sampling = false;
  let driving = false;
  let wallOffset = -Infinity;

  function takeSample() {
    if (sampling) return;
    sampling = true;
    try {
      const lower = mono();
      const wallUpper = wall();
      const upper = mono();
      if (!supportedTimestamp(lower) || !supportedTimestamp(upper) || !supportedTimestamp(wallUpper) ||
          lower > upper || upper - lower > MAX_BRACKET_MS) return;
      // Preserve every accepted upper wall observation as a monotonic proof
      // cutoff, including forward jumps that leave some proof slack.
      const nextOffset = Math.max(wallOffset, wallUpper - lower);
      const effectiveWall = upper + nextOffset;
      if (!supportedTimestamp(effectiveWall) || !owner.observeTime(lower, upper, effectiveWall)) return;
      wallOffset = nextOffset;
      return { lower, wallUpper: owner.effectiveWall() };
    } catch {
      return;
    } finally {
      sampling = false;
    }
  }

  function submit(attempt: CapacityAttempt, input: CapacityRequestInput<T>): AttemptStatus | undefined {
    if (!owner.startPreparation(attempt)) return controller.attemptStatus(attempt);
    let charged = 0;
    try {
      const anchor = takeSample();
      if (!anchor) {
        owner.reject(attempt, "clock-invalid");
        return controller.attemptStatus(attempt);
      }
      if (controller.attemptStatus(attempt)?.kind !== "preparing") return controller.attemptStatus(attempt);
      if (typeof input !== "object" || input === null) {
        owner.reject(attempt, "unverified");
        return controller.attemptStatus(attempt);
      }
      const { candidate, body: rawBody, callerDeadlineMonoMs: requestedDeadline } = input;
      if (requestedDeadline !== undefined && !supportedTimestamp(requestedDeadline)) {
        owner.reject(attempt, "deadline-invalid");
        return controller.attemptStatus(attempt);
      }
      const source = sourceView(rawBody, limits.maxBodyBytes);
      if (!source) {
        owner.reject(attempt, "unsupported");
        return controller.attemptStatus(attempt);
      }
      const bytes = source.byteLength;
      if (bytes + preparingBodyBytes > preparingBodyLimit) {
        owner.reject(attempt, "preparation-bytes-exceeded");
        return controller.attemptStatus(attempt);
      }
      charged = bytes;
      preparingBodyBytes += bytes;
      const owned = new Uint8Array(source);
      const { view, revoke } = bodyView(owned);
      const classification = classifyVerifiedCandidate(policy, {
        verify(candidate, activated, wallNowMs, body) {
          try {
            return verifyRequest(candidate, activated, wallNowMs, body);
          } finally {
            revoke();
          }
        },
      }, candidate, anchor.wallUpper, view);
      if (classification.kind !== "classified") {
        owner.reject(attempt, classification.kind);
        return controller.attemptStatus(attempt);
      }
      if (classification.bodyBytes !== bytes) {
        owner.reject(attempt, "unsupported");
        return controller.attemptStatus(attempt);
      }

      const proofExpiry = classification.proofExpiresAtWallMs;
      if (!supportedTimestamp(proofExpiry)) {
        owner.reject(attempt, "deadline-invalid");
        return controller.attemptStatus(attempt);
      }
      // Clamp before subtracting the margin so out-of-window proof expiry
      // cannot extend the original authenticated budget on wall rollback.
      const initialSlack = Math.min(limits.proofWindowMs, proofExpiry - anchor.wallUpper) - limits.dispatchMarginMs;
      const proofCutoff = anchor.lower + Math.max(0, initialSlack);
      const deadline = Math.min(anchor.lower + limits.callerBudgetMs, requestedDeadline ?? Infinity);

      // No external calls from the final successful bracket through bind
      // and admit. The controller still checks cancellation and closure.
      if (!takeSample()) {
        owner.reject(attempt, "clock-invalid");
        return controller.attemptStatus(attempt);
      }
      if (owner.bind(attempt, classification.operationId, bytes, proofCutoff, proofExpiry, deadline, bytes ? owned : undefined)) {
        return owner.admit(attempt);
      }
    } catch {
      owner.reject(attempt, "unverified");
    } finally {
      preparingBodyBytes -= charged;
      owner.finishPreparation(attempt);
    }
    return controller.attemptStatus(attempt);
  }

  function advance(budget = 32): number {
    if (!Number.isSafeInteger(budget) || budget < 1 || budget > MAX_WORK) throw new RangeError("invalid maintenance budget");
    if (sampling || driving) return 0;
    driving = true;
    try {
      let work = 0;
      while (work < budget) {
        // The sample and at most one state operation share this unit. A
        // second grant always needs a second bracket, even in one call.
        const sample = takeSample();
        if (!sample) {
          owner.observeTime(NaN, NaN, NaN);
          if (!owner.isClosed()) return work + 1;
        }
        const steps = owner.advance(1);
        if (steps === 0) break;
        work += steps;
      }
      return work;
    } finally {
      driving = false;
    }
  }

  const events = new WeakMap<CapacitySettlementEvent, Evidence>();
  let verifying = false;

  function executionIdentity(lease: CapacityLease) {
    const execution = owner.executionFor(lease);
    if (!execution || controller.leaseState(lease) === "settled") return;
    return Object.freeze({ generation, lease, execution });
  }

  function verifyEvidence(lease: CapacityLease, execution: CapacityExecution, proof: TProof) {
    const identity = executionIdentity(lease);
    const state = controller.leaseState(lease);
    if (!identity || execution !== identity.execution || verifying) return;
    verifying = true;
    try {
      const result = verifyExecution(identity, proof);
      if (!result || typeof result !== "object") return;
      const { kind, generation: scope, lease: subject, execution: process } = result;
      const hardStop = kind === "ambiguous" && "hardStopMonoMs" in result ? result.hardStopMonoMs : undefined;
      if (scope !== generation || subject !== lease || process !== execution ||
          state !== controller.leaseState(lease)) return;
      if (kind === "ambiguous") {
        if (state !== "active" || (hardStop !== undefined && !supportedTimestamp(hardStop))) return;
      } else if (kind !== "completed" && kind !== "aborted" && kind !== "timeout-confirmed" && kind !== "never-started") {
        return;
      }
      const event = Object.freeze(Object.create(null)) as CapacitySettlementEvent;
      const previous = owner.replaceEvent(lease, event);
      if (previous) events.delete(previous);
      events.set(event, { ...identity, kind: kind === "ambiguous" ? kind : state === "active" ? "terminal" : "verified-termination", hardStop });
      return event;
    } catch {
      return;
    } finally {
      verifying = false;
    }
  }

  function settle(event: CapacitySettlementEvent): boolean {
    const evidence = events.get(event);
    if (!evidence) return false;
    events.delete(event);
    if (!owner.consumeEvent(evidence.lease, event)) return false;
    return owner.settle(evidence.lease, evidence.execution, evidence.kind, evidence.hardStop);
  }

  return Object.freeze({
    request: Object.freeze({ ...controller, begin: () => owner.begin(false), submit }),
    maintenance: Object.freeze({
      advance, close: owner.close,
      retention: () => ({
        preparingBodyBytes, preparingBodyLimit, ...owner.payloadBytes(), pendingNotifications: 0,
      }),
    }),
    execution: Object.freeze({
      identity: executionIdentity, verify: verifyEvidence, settle, takeBody: owner.takeBody,
    }),
  });
}

