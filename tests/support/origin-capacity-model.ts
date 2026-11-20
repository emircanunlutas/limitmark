import type { CapacityPool, CustomerOriginPolicyManifest, LeaseState } from "../../defense/core/capacity-port";

type Entry = {
  classId: string;
  cost: number;
  bytes: number;
  state: "queued" | "granted" | "cancelled" | "expired" | "rejected";
  pool?: CapacityPool;
  lease?: LeaseState;
  waitUntil: number;
  hardStop?: number;
};

/** Independent oracle: insertion order for FIFO and sums over rows for every budget decision. */
export class OriginCapacityModel {
  readonly rows = new Map<number, Entry>();
  closed = false;
  lower = 0;
  upper = 0;
  wall = 1000;
  private nextShared = 0;

  constructor(readonly manifest: CustomerOriginPolicyManifest) {}

  private usage(rows: Entry[]) {
    const queued = rows.filter((row) => row.state === "queued");
    const live = rows.filter((row) => row.lease === "active" || row.lease === "ambiguous-held");
    const sum = (items: Entry[], measure: (row: Entry) => number) => items.reduce((total, row) => total + measure(row), 0);
    return {
      reserved: sum(live.filter((row) => row.pool === "reserved"), (row) => row.cost),
      shared: sum(live.filter((row) => row.pool === "shared"), (row) => row.cost),
      ambiguous: sum(live.filter((row) => row.lease === "ambiguous-held"), (row) => row.cost),
      queued: queued.length,
      bytes: sum(queued, (row) => row.bytes),
    };
  }

  snapshot() {
    const rows = [...this.rows.values()];
    return {
      ...this.usage(rows), closed: this.closed, preparationSlots: 0,
      leases: rows.filter((row) => row.lease && row.lease !== "settled").length,
      classes: this.manifest.classes.map(({ id }) => ({ id, ...this.usage(rows.filter((row) => row.classId === id)) })),
    };
  }

  private choice(row: Entry): CapacityPool | undefined {
    const { classes, shared } = this.snapshot();
    const spec = this.manifest.classes.find((item) => item.id === row.classId)!;
    const used = classes.find((item) => item.id === row.classId)!;
    const sharedLimit = this.manifest.capacity.activeUnits - this.manifest.classes.reduce((sum, item) => sum + item.reservedUnits, 0);
    if (row.cost <= spec.reservedUnits - used.reserved) return "reserved";
    if (row.cost <= Math.min(spec.maxActiveUnits - spec.reservedUnits - used.shared, sharedLimit - shared)) return "shared";
  }

  private grant(row: Entry, pool: CapacityPool) {
    row.state = "granted";
    row.pool = pool;
    row.lease = "active";
  }

  private expired(row: Entry) {
    const { dispatchMarginMs, executionTimeoutMs } = this.manifest.capacity;
    // Fixed authenticated deadlines used by the differential fixture.
    return this.upper >= Math.min(180, row.waitUntil) || this.wall + dispatchMarginMs >= 1350 ||
      this.upper + dispatchMarginMs + executionTimeoutMs > 2850;
  }

  admit(id: number, opId: string, body: number) {
    const operation = this.manifest.operations.find((item) => item.id === opId)!;
    const spec = this.manifest.classes.find((item) => item.id === operation.classId)!;
    const row: Entry = {
      classId: operation.classId, cost: operation.costUnits,
      bytes: this.manifest.capacity.metadataBytesPerRequest + body, waitUntil: Infinity, state: "rejected",
    };
    if (this.closed) return;
    this.rows.set(id, row);
    if (this.expired(row)) {
      row.state = "expired";
      return;
    }
    const totals = this.snapshot();
    const classTotals = totals.classes.find((item) => item.id === row.classId)!;
    const pool = classTotals.queued === 0 ? this.choice(row) : undefined;
    if (pool) {
      this.grant(row, pool);
    } else if (spec.maxQueued > classTotals.queued && this.manifest.capacity.maxQueued > totals.queued &&
      this.manifest.capacity.maxQueuedBytes >= totals.bytes + row.bytes) {
      row.waitUntil = this.lower + spec.maxWaitMs;
      row.state = this.expired(row) ? "expired" : "queued";
    }
  }

  cancel(id: number): boolean {
    const row = this.rows.get(id);
    if (row?.state !== "queued") return false;
    row.state = "cancelled";
    return true;
  }

  settle(id: number, kind: "terminal" | "ambiguous" | "verified-termination", hardStop?: number): boolean {
    const row = this.rows.get(id);
    if (!row) return false;
    if (kind === "verified-termination" && row.lease === "ambiguous-held") {
      row.lease = "settled";
      return true;
    }
    if (row.lease !== "active" || kind === "verified-termination") return false;
    row.lease = kind === "terminal" ? "settled" : "ambiguous-held";
    row.hardStop = hardStop;
    return true;
  }

  observe(lower: number, upper: number, wall: number) {
    this.lower = lower;
    this.upper = upper;
    this.wall = Math.max(wall, this.wall);
  }

  private heads() {
    const waiting = [...this.rows.values()].filter((row) => row.state === "queued");
    return this.manifest.classes.map(({ id }) => waiting.find((row) => row.classId === id));
  }

  hasEligibleHead(): boolean {
    return !this.closed && this.heads().some((row) => row && !this.expired(row) && this.choice(row));
  }

  dispatchOne(): boolean {
    if (this.closed) return false;
    const heads = this.heads();
    const reserved = heads.find((row) => row && !this.expired(row) && this.choice(row) === "reserved");
    if (reserved) {
      this.grant(reserved, "reserved");
      return true;
    }

    const ordered = [...heads.slice(this.nextShared), ...heads.slice(0, this.nextShared)];
    const offset = ordered.findIndex((row) => row && !this.expired(row) && this.choice(row) === "shared");
    if (offset === -1) return false;
    this.grant(ordered[offset]!, "shared");
    this.nextShared = (this.nextShared + offset + 1) % heads.length;
    return true;
  }

  drain() {
    for (const row of this.rows.values()) {
      if (row.lease === "ambiguous-held" && row.hardStop !== undefined && this.lower >= row.hardStop) row.lease = "settled";
      if (row.state === "queued" && this.closed) row.state = "cancelled";
      if (row.state === "queued" && this.expired(row)) row.state = "expired";
    }
    while (this.dispatchOne()) {
      // Each grant changes the FIFO heads, including reservation eligibility.
    }
  }
}

