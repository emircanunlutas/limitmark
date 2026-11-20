import { IndexedMinHeap } from "./capacity-heap";
import { readCompiledPolicyInternal } from "./capacity-policy";
import type {
  AttemptRejection, AttemptStatus, CapacityAttempt, CapacityExecution, CapacityLease, CapacityPool,
  CapacitySnapshot, ClassSpec, CompiledCustomerOriginPolicy, LeaseState, OperationSpec,
  CapacitySettlementEvent, OriginCapacityPort, WaitExpiryReason,
} from "./capacity-port";

const DEFAULT_WORK = 32;
const MAX_WORK = 256;
const MAX_PREPARATIONS = 32;
// Binary fixed-point milliseconds. With the policy's 31-bit durations, all
// deadline sums and differences stay below 2^53 ticks and are exact.
const MAX_TIMESTAMP = 2 ** 42;
const TICKS_PER_MS = 1024;

export function supportedTimestamp(value: number): boolean {
  return Number.isFinite(value) && Math.abs(value) <= MAX_TIMESTAMP && Number.isInteger(value * TICKS_PER_MS);
}

type Usage = { reserved: number; shared: number; ambiguous: number; queued: number; bytes: number };
const emptyUsage = (): Usage => ({ reserved: 0, shared: 0, ambiguous: 0, queued: 0, bytes: 0 });

type ClassState = {
  index: number;
  spec: ClassSpec;
  usage: Usage;
  head: Request | null;
  tail: Request | null;
};
type Request = {
  attempt: CapacityAttempt;
  cls: ClassState;
  cost: number;
  bytes: number;
  proofCutoff: number;
  proofExpiry: number;
  callerCutoff: number;
  waitCutoff: number;
  prev: Request | null;
  next: Request | null;
  monoIndex: number;
  wallIndex: number;
  callerIndex: number;
  body?: Uint8Array;
};
type Lease = {
  proofExpiry: number;
  proofCutoff: number;
  callerCutoff: number;
  cls: ClassState;
  pool: CapacityPool;
  cost: number;
  execution: CapacityExecution;
  state: LeaseState;
  hardStop: number;
  boundIndex: number;
  body?: Uint8Array;
  event?: CapacitySettlementEvent;
};
type AttemptRecord = { status: AttemptStatus; preparationInFlight: boolean; holdUntilFinish?: boolean; request?: Request };
type MaintenanceAction =
  | { kind: "close-preparation"; attempt: CapacityAttempt }
  | { kind: "close-queue" | "expire" | "reserved" | "shared"; request: Request }
  | { kind: "hard-stop"; lease: Lease };

type Settlement = "terminal" | "ambiguous" | "verified-termination";

function identity<T>(): T {
  return Object.freeze(Object.create(null)) as T;
}

function heap<T>(key: (item: T) => number, index: keyof T & string) {
  return new IndexedMinHeap(key, (item) => item[index] as number, (item, value) => {
    Object.assign(item as object, { [index]: value });
  });
}

/**
 * Internal composition seam for the trusted boundary and deterministic state
 * tests. The boundary keeps the scalar owner private to its own generation.
 */
export function createOriginCapacityState(policy: CompiledCustomerOriginPolicy) {
  const { controller, owner } = new CapacityState(policy);
  return { controller, owner };
}

class CapacityState {
  readonly #limits;
  readonly #sharedLimit;
  readonly #classes: ClassState[];
  readonly #classById: Map<string, ClassState>;
  readonly #operations: Map<string, OperationSpec>;
  readonly #attempts = new WeakMap<CapacityAttempt, AttemptRecord>();
  readonly #preparing = new Map<CapacityAttempt, AttemptRecord>();
  readonly #outstandingPreparation = new Set<CapacityAttempt>();
  readonly #leases = new WeakMap<CapacityLease, Lease>();
  readonly #usage = emptyUsage();
  readonly #monoExpiry = heap<Request>((item) => Math.min(item.proofCutoff, item.waitCutoff), "monoIndex");
  readonly #wallExpiry = heap<Request>((item) => item.proofExpiry, "wallIndex");
  readonly #callerExpiry = heap<Request>((item) => item.callerCutoff, "callerIndex");
  readonly #hardStops = heap<Lease>((item) => item.hardStop, "boundIndex");
  readonly #openLeases = new Set<Lease>();
  #queuedBodyBytes = 0;
  #leaseBodyBytes = 0;
  #closed = false;
  #lower = Number.NEGATIVE_INFINITY;
  #upper = Number.NEGATIVE_INFINITY;
  #wall = Number.NEGATIVE_INFINITY;
  #clockValid = false;
  #cursor = 0;
  #rotation = 0;
  #action: MaintenanceAction | null = null;
  #wake = { hardStop: Infinity, mono: Infinity, wall: Infinity, caller: Infinity };

  readonly controller: OriginCapacityPort = Object.freeze({
    cancel: (attempt: CapacityAttempt) => this.#cancel(attempt, "cancelled"),
    attemptStatus: (attempt: CapacityAttempt) => this.#attempts.get(attempt)?.status,
    leaseState: (lease: CapacityLease) => this.#leases.get(lease)?.state,
    snapshot: () => this.#snapshot(),
    hasPendingMaintenance: () => this.#pending(),
  });

  readonly owner = Object.freeze({
    begin: (preparationInFlight = true) => this.#begin(preparationInFlight),
    startPreparation: (attempt: CapacityAttempt) => this.#startPreparation(attempt),
    reject: (attempt: CapacityAttempt, reason: AttemptRejection) => this.#rejectPreparation(attempt, reason),
    bind: (attempt: CapacityAttempt, operation: string, bytes: number, proofCutoff: number, proofExpiry: number,
      callerDeadline: number, body?: Uint8Array) =>
      this.#bind(attempt, operation, bytes, proofCutoff, proofExpiry, callerDeadline, body),
    finishPreparation: (attempt: CapacityAttempt) => this.#finishPreparation(attempt),
    admit: (attempt: CapacityAttempt) => this.#admit(attempt),
    observeTime: (lower: number, upper: number, wall: number) => this.#observeTime(lower, upper, wall),
    effectiveWall: () => this.#wall,
    canDispatch: (handle: CapacityLease, execution: CapacityExecution) => {
      const lease = this.#leases.get(handle);
      return !this.#closed && this.#clockValid && lease?.execution === execution && lease.state === "active" &&
        !this.#dispatchExpiry(lease);
    },
    isClosed: () => this.#closed,
    executionFor: (lease: CapacityLease) => this.#leases.get(lease)?.execution,
    settle: (lease: CapacityLease, execution: CapacityExecution, kind: Settlement, hardStop?: number) =>
      this.#settle(lease, execution, kind, hardStop),
    replaceEvent: (lease: CapacityLease, event: CapacitySettlementEvent) => this.#replaceEvent(lease, event),
    consumeEvent: (lease: CapacityLease, event: CapacitySettlementEvent) => this.#consumeEvent(lease, event),
    takeBody: (lease: CapacityLease, execution: CapacityExecution) => this.#takeBody(lease, execution),
    payloadBytes: () => ({ queued: this.#queuedBodyBytes, leased: this.#leaseBodyBytes }),
    close: () => this.#close(),
    advance: (budget = DEFAULT_WORK) => this.#advance(budget),
    indexSizes: () => ({
      mono: this.#monoExpiry.size, wall: this.#wallExpiry.size,
      caller: this.#callerExpiry.size, hardStop: this.#hardStops.size,
    }),
  });

  constructor(policy: CompiledCustomerOriginPolicy) {
    const { manifest, sharedUnits } = readCompiledPolicyInternal(policy);
    this.#limits = manifest.capacity;
    this.#sharedLimit = sharedUnits;
    this.#classes = manifest.classes.map((spec, index) => ({ index, spec, usage: emptyUsage(), head: null, tail: null }));
    this.#classById = new Map(this.#classes.map((cls) => [cls.spec.id, cls]));
    this.#operations = new Map(manifest.operations.map((op) => [op.id, op]));
  }

  #set(record: AttemptRecord, status: AttemptStatus): AttemptStatus {
    record.status = Object.freeze(status);
    return record.status;
  }

  #begin(preparationInFlight: boolean): CapacityAttempt | undefined {
    if (this.#closed || this.#outstandingPreparation.size >= MAX_PREPARATIONS) return;
    const attempt = identity<CapacityAttempt>();
    const record: AttemptRecord = { status: Object.freeze({ kind: "preparing" }), preparationInFlight };
    this.#attempts.set(attempt, record);
    this.#preparing.set(attempt, record);
    this.#outstandingPreparation.add(attempt);
    return attempt;
  }

  #startPreparation(attempt: CapacityAttempt): boolean {
    const record = this.#preparing.get(attempt);
    if (this.#closed || record?.status.kind !== "preparing" || record.preparationInFlight) return false;
    record.preparationInFlight = true;
    record.holdUntilFinish = true;
    return true;
  }

  #rejectPreparation(attempt: CapacityAttempt, reason: AttemptRejection): void {
    const record = this.#preparing.get(attempt);
    if (!record) return;
    if (this.#closed) this.#cancel(attempt, "controller-closed");
    else this.#reject(attempt, record, reason);
  }

  #finishPreparation(attempt: CapacityAttempt): boolean {
    const record = this.#attempts.get(attempt);
    if (this.#closed && (record?.status.kind === "preparing" || record?.status.kind === "ready")) {
      this.#cancel(attempt, "controller-closed");
    }
    if (record?.status.kind === "preparing") this.#reject(attempt, record, "unverified");
    // Ready attempts continue to occupy a slot until admitted, queued or retired.
    if (record?.status.kind === "ready") return false;
    return this.#outstandingPreparation.delete(attempt);
  }

  #bind(attempt: CapacityAttempt, opId: string, bytes: number, proofCutoff: number, proofExpiry: number,
    deadline: number, body?: Uint8Array): boolean {
    const record = this.#attempts.get(attempt);
    if (this.#closed || record?.status.kind !== "preparing") return false;
    const operation = this.#operations.get(opId);
    if (!operation || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > (operation.body?.maxBytes ?? 0)) {
      this.#reject(attempt, record, "unsupported");
      return false;
    }
    if (!supportedTimestamp(proofCutoff) || !supportedTimestamp(proofExpiry) || !supportedTimestamp(deadline)) {
      this.#reject(attempt, record, "deadline-invalid");
      return false;
    }
    const callerCutoff = deadline - this.#limits.dispatchMarginMs - this.#limits.executionTimeoutMs;
    record.request = {
      attempt, cls: this.#classById.get(operation.classId)!, cost: operation.costUnits,
      bytes: this.#limits.metadataBytesPerRequest + bytes, proofCutoff, proofExpiry, callerCutoff, body,
      waitCutoff: Number.POSITIVE_INFINITY, prev: null, next: null, monoIndex: -1, wallIndex: -1, callerIndex: -1,
    };
    this.#set(record, { kind: "ready" });
    return true;
  }

  #retire(attempt: CapacityAttempt, record: AttemptRecord, status: AttemptStatus): AttemptStatus {
    this.#preparing.delete(attempt);
    // An interrupted preparation continues to hold its permit until it unwinds.
    if (!record.holdUntilFinish && (record.status.kind !== "preparing" || !record.preparationInFlight)) {
      this.#outstandingPreparation.delete(attempt);
    }
    record.request = undefined;
    return this.#set(record, status);
  }

  #reject(attempt: CapacityAttempt, record: AttemptRecord, reason: AttemptRejection): AttemptStatus {
    return this.#retire(attempt, record, { kind: "rejected", reason });
  }

  #cancel(attempt: CapacityAttempt, reason: "cancelled" | "controller-closed"): boolean {
    const record = this.#attempts.get(attempt);
    const kind = record?.status.kind;
    if (!record || (kind !== "preparing" && kind !== "ready" && kind !== "queued")) return false;
    if (kind === "queued") this.#unlink(record.request!);
    this.#retire(attempt, record, { kind: "cancelled", reason: this.#closed ? "controller-closed" : reason });
    this.#restartScan();
    return true;
  }

  #observeTime(lower: number, upper: number, wall: number): boolean {
    if (!supportedTimestamp(lower) || !supportedTimestamp(upper) || !supportedTimestamp(wall) ||
        lower > upper || lower < this.#upper) {
      this.#clockValid = false;
      return false;
    }
    this.#clockValid = true;
    this.#lower = lower;
    this.#upper = upper;
    this.#wall = Math.max(wall, this.#wall);
    return true;
  }

  #dispatchExpiry(request: Pick<Request, "proofCutoff" | "proofExpiry" | "callerCutoff">): WaitExpiryReason | undefined {
    if (this.#upper >= request.proofCutoff || this.#wall + this.#limits.dispatchMarginMs >= request.proofExpiry) return "proof-expired";
    if (this.#upper > request.callerCutoff) return "caller-deadline-exceeded";
  }

  #expiry(request: Request): WaitExpiryReason | undefined {
    const expired = this.#dispatchExpiry(request);
    if (expired) return expired;
    if (this.#upper >= request.waitCutoff) return "wait-timeout";
  }

  #pool(request: Request): CapacityPool | undefined {
    const { cls, cost } = request;
    if (cls.usage.reserved + cost <= cls.spec.reservedUnits) return "reserved";
    if (cls.usage.shared + cost <= cls.spec.maxActiveUnits - cls.spec.reservedUnits &&
        this.#usage.shared + cost <= this.#sharedLimit) return "shared";
  }

  #grant(request: Request, expectedPool?: CapacityPool): boolean {
    const record = this.#attempts.get(request.attempt)!;
    const queued = record.status.kind === "queued";
    if (this.#closed || !this.#clockValid || (!queued && record.status.kind !== "ready") ||
        request.cls.head !== (queued ? request : null) || this.#expiry(request)) return false;
    const pool = this.#pool(request);
    if (!pool || (expectedPool && pool !== expectedPool)) return false;

    if (queued) this.#unlink(request);
    const lease = identity<CapacityLease>();
    const charge: Lease = {
      proofCutoff: request.proofCutoff, proofExpiry: request.proofExpiry, callerCutoff: request.callerCutoff,
      cls: request.cls, pool, cost: request.cost, execution: identity<CapacityExecution>(),
      state: "active", hardStop: Number.POSITIVE_INFINITY, boundIndex: -1,
      body: request.body,
    };
    this.#leaseBodyBytes += request.body?.byteLength ?? 0;
    this.#leases.set(lease, charge);
    this.#openLeases.add(charge);
    request.cls.usage[pool] += request.cost;
    this.#usage[pool] += request.cost;
    this.#retire(request.attempt, record, { kind: "granted", pool, lease });
    this.#restartScan();
    return true;
  }

  #admit(attempt: CapacityAttempt): AttemptStatus | undefined {
    const record = this.#attempts.get(attempt);
    if (record?.status.kind !== "ready") return record?.status;
    if (this.#closed) {
      this.#cancel(attempt, "controller-closed");
      return record.status;
    }
    if (!this.#clockValid) return this.#reject(attempt, record, "deadline-invalid");
    const request = record.request!;
    const expiry = this.#expiry(request);
    if (expiry) return this.#retire(attempt, record, { kind: "expired", reason: expiry });
    if (this.#grant(request)) return record.status;

    const cls = request.cls;
    if (cls.spec.maxQueued === 0) return this.#reject(attempt, record, "queue-disabled");
    if (this.#upper >= request.callerCutoff) {
      return this.#retire(attempt, record, { kind: "expired", reason: "caller-deadline-exceeded" });
    }
    if (cls.usage.queued >= cls.spec.maxQueued) return this.#reject(attempt, record, "class-queue-full");
    if (this.#usage.queued >= this.#limits.maxQueued) return this.#reject(attempt, record, "domain-queue-full");
    if (this.#usage.bytes + request.bytes > this.#limits.maxQueuedBytes) {
      return this.#reject(attempt, record, "queue-bytes-exceeded");
    }
    request.waitCutoff = this.#lower + cls.spec.maxWaitMs;
    const queueExpiry = this.#expiry(request);
    if (queueExpiry) return this.#retire(attempt, record, { kind: "expired", reason: queueExpiry });
    this.#enqueue(request);
    this.#preparing.delete(attempt);
    if (!record.holdUntilFinish) this.#outstandingPreparation.delete(attempt);
    this.#restartScan();
    return this.#set(record, { kind: "queued", bytes: request.bytes });
  }

  #enqueue(request: Request): void {
    const cls = request.cls;
    request.prev = cls.tail;
    if (cls.tail) cls.tail.next = request;
    else cls.head = request;
    cls.tail = request;
    this.#monoExpiry.push(request);
    this.#wallExpiry.push(request);
    this.#callerExpiry.push(request);
    cls.usage.queued++;
    cls.usage.bytes += request.bytes;
    this.#usage.queued++;
    this.#usage.bytes += request.bytes;
    this.#queuedBodyBytes += request.body?.byteLength ?? 0;
  }

  #unlink(request: Request): void {
    const cls = request.cls;
    if (request.prev) request.prev.next = request.next;
    else cls.head = request.next;
    if (request.next) request.next.prev = request.prev;
    else cls.tail = request.prev;
    request.prev = null;
    request.next = null;
    this.#monoExpiry.remove(request);
    this.#wallExpiry.remove(request);
    this.#callerExpiry.remove(request);
    cls.usage.queued--;
    cls.usage.bytes -= request.bytes;
    this.#usage.queued--;
    this.#usage.bytes -= request.bytes;
    this.#queuedBodyBytes -= request.body?.byteLength ?? 0;
  }

  #takeBody(handle: CapacityLease, execution: CapacityExecution): Uint8Array | undefined {
    const lease = this.#leases.get(handle);
    if (!lease || lease.execution !== execution || lease.state !== "active") return;
    return this.#dropBody(lease);
  }

  #replaceEvent(handle: CapacityLease, event: CapacitySettlementEvent): CapacitySettlementEvent | undefined {
    const lease = this.#leases.get(handle);
    if (!lease || lease.state === "settled") return;
    const previous = lease.event;
    lease.event = event;
    return previous;
  }

  #consumeEvent(handle: CapacityLease, event: CapacitySettlementEvent): boolean {
    const lease = this.#leases.get(handle);
    if (!lease || lease.event !== event) return false;
    lease.event = undefined;
    return true;
  }

  #dropBody(lease: Lease): Uint8Array | undefined {
    const body = lease.body;
    lease.body = undefined;
    this.#leaseBodyBytes -= body?.byteLength ?? 0;
    return body;
  }

  #settle(handle: CapacityLease, execution: CapacityExecution, kind: Settlement, hardStop?: number): boolean {
    const lease = this.#leases.get(handle);
    if (!lease || lease.execution !== execution || lease.state === "settled") return false;
    if (kind === "terminal") return lease.state === "active" && this.#release(lease);
    if (kind === "verified-termination") return lease.state === "ambiguous-held" && this.#release(lease);
    if (kind !== "ambiguous" || lease.state !== "active") return false;
    if (hardStop !== undefined && !supportedTimestamp(hardStop)) return false;

    lease.state = "ambiguous-held";
    lease.cls.usage.ambiguous += lease.cost;
    this.#usage.ambiguous += lease.cost;
    if (hardStop !== undefined) {
      lease.hardStop = hardStop;
      this.#hardStops.push(lease);
    }
    this.#restartScan();
    return true;
  }

  #release(lease: Lease): boolean {
    if (!this.#openLeases.delete(lease)) return false;
    if (lease.state === "ambiguous-held") {
      this.#hardStops.remove(lease);
      lease.cls.usage.ambiguous -= lease.cost;
      this.#usage.ambiguous -= lease.cost;
    }
    lease.state = "settled";
    lease.event = undefined;
    this.#dropBody(lease);
    lease.cls.usage[lease.pool] -= lease.cost;
    this.#usage[lease.pool] -= lease.cost;
    this.#restartScan();
    return true;
  }

  #close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#restartScan();
  }

  #restartScan(): void {
    this.#cursor = 0;
    this.#action = null;
    this.#wake = { hardStop: Infinity, mono: Infinity, wall: Infinity, caller: Infinity };
  }

  #scanEnd(): number {
    return this.#closed ? 3 : 4 + 2 * this.#classes.length;
  }

  // A root checked earlier in the scan can become due while the scan is in
  // progress. Finish the scan, then revisit due roots without polling them
  // outside the maintenance budget.
  #wakeDue(): boolean {
    return this.#clockValid && (this.#lower >= this.#wake.hardStop ||
      this.#upper >= this.#wake.mono || this.#wall + this.#limits.dispatchMarginMs >= this.#wake.wall ||
      this.#upper > this.#wake.caller);
  }

  #pending(): boolean {
    if (!this.#closed && !this.#clockValid) return false;
    if (this.#action) return true;
    const hasRecords = this.#usage.queued > 0 || this.#hardStops.size > 0 || (this.#closed && this.#preparing.size > 0);
    return hasRecords && (this.#cursor < this.#scanEnd() || this.#wakeDue());
  }

  #inspect(): MaintenanceAction | null {
    const phase = this.#cursor++;
    if (phase === 0) {
      const lease = this.#hardStops.peek();
      this.#wake.hardStop = lease?.hardStop ?? Infinity;
      return this.#clockValid && lease && lease.hardStop <= this.#lower ? { kind: "hard-stop", lease } : null;
    }
    if (this.#closed) {
      if (phase === 1) {
        const attempt = this.#preparing.keys().next().value;
        return attempt ? { kind: "close-preparation", attempt } : null;
      }
      const request = this.#monoExpiry.peek();
      return request ? { kind: "close-queue", request } : null;
    }
    if (phase <= 3) {
      const request = phase === 1 ? this.#monoExpiry.peek() : phase === 2 ? this.#wallExpiry.peek() : this.#callerExpiry.peek();
      if (request) {
        if (phase === 1) this.#wake.mono = Math.min(request.proofCutoff, request.waitCutoff);
        else if (phase === 2) this.#wake.wall = request.proofExpiry;
        else this.#wake.caller = request.callerCutoff;
      }
      return request && this.#expiry(request) ? { kind: "expire", request } : null;
    }
    const offset = phase - 4;
    const count = this.#classes.length;
    const reserved = offset < count;
    const index = reserved ? offset : (this.#rotation + offset - count) % count;
    const request = this.#classes[index].head;
    if (!request) return null;
    if (this.#expiry(request)) return { kind: "expire", request };
    const pool = reserved ? "reserved" : "shared";
    return this.#pool(request) === pool ? { kind: pool, request } : null;
  }

  #perform(action: MaintenanceAction): boolean {
    if (action.kind === "hard-stop") {
      if (this.#clockValid && action.lease.state === "ambiguous-held" && action.lease.hardStop <= this.#lower) {
        this.#release(action.lease);
      }
    } else if (action.kind === "close-preparation") {
      this.#cancel(action.attempt, "controller-closed");
    } else if (action.kind === "close-queue") {
      this.#cancel(action.request.attempt, "controller-closed");
    } else if (action.kind === "expire") {
      const request = action.request;
      const reason = this.#expiry(request);
      const record = this.#attempts.get(request.attempt)!;
      if (reason && record.status.kind === "queued") {
        this.#unlink(request);
        this.#retire(request.attempt, record, { kind: "expired", reason });
        this.#restartScan();
      }
    } else if (this.#grant(action.request, action.kind)) {
      if (action.kind === "shared") {
        this.#rotation = (action.request.cls.index + 1) % this.#classes.length;
      }
      return true;
    }
    return false;
  }

  #advance(budget: number): number {
    if (!Number.isSafeInteger(budget) || budget < 1 || budget > MAX_WORK) throw new RangeError("invalid maintenance budget");
    let work = 0;
    while (work < budget && this.#pending()) {
      work++;
      const action = this.#action;
      if (!action) {
        if (this.#cursor === this.#scanEnd()) this.#restartScan();
        this.#action = this.#inspect();
      } else {
        this.#action = null;
        if (this.#perform(action)) break;
      }
    }
    return work;
  }

  #snapshot(): CapacitySnapshot {
    return {
      ...this.#usage, closed: this.#closed, preparationSlots: this.#outstandingPreparation.size,
      leases: this.#openLeases.size, classes: this.#classes.map((cls) => ({ id: cls.spec.id, ...cls.usage })),
    };
  }
}

