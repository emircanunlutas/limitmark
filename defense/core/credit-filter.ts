/**
 * Slice 3: the credit-provenance filter: a FIXED-MEMORY, TWO-GENERATION, KEYED Bloom filter with a deterministic monotonic epoch.
 *
 *  - Memory is allocated once at construction (two bit arrays). A render never allocates, nothing is ever evicted, and an insertion can
 *    never fail: untrusted render volume can only RAISE THE FILL RATIO. The consequence of heavy fill is a rising false-positive rate (a
 *    fabricated token is more often mistaken for an enrolled one), which is a loss of attenuation, never a loss of genuine credit: there
 *    are no false negatives inside the defined generation window.
 *  - Keys are HMAC-SHA256(per-process random key, token). The key never leaves this object; no token (and no recoverable function of one)
 *    is stored. An attacker cannot choose what is inserted (only the application's own random tokens are enrolled) and cannot aim at bits.
 *  - Time is an epoch: epoch(t) = floor((t - t0) / epochMs) on an injected MONOTONIC clock. The generation for epoch e lives in array
 *    (e & 1); when the epoch advances, the array about to become active (which held epoch e-2) is zeroed. Every operation advances to the
 *    current epoch FIRST, so a lazily-observed filter can never answer from a stale generation. A token enrolled in epoch E is therefore
 *    positive from its insertion until the epoch reaches E+2: at least `epochMs`, at most `2*epochMs`.
 *
 * Pure apart from the CSPRNG key and the injected clock.
 */
import { createHmac, randomBytes } from "node:crypto";

export type CreditFilterOptions = {
  /** Bits per generation. A power of two. */
  bits: number;
  hashes: number;
  /** Generation length; also the minimum guaranteed credit lifetime. */
  epochMs: number;
  mono: () => number;
  /** Test seam only: a fixed key makes hashing deterministic. Production uses the CSPRNG default. */
  key?: Buffer;
};

export type FilterStats = {
  epoch: number;
  bitsPerGeneration: number;
  hashes: number;
  popcount: [active: number, previous: number];
  fillRatio: [active: number, previous: number];
  /** Estimated false-positive rate of a lookup over both generations, from the fill ratios. */
  fprEstimate: number;
  inserts: number;
  lookups: number;
  hits: number;
  rotations: number;
};

/** The estimate above which the filter is reported as POISONED (a recorded condition; it does not change a decision). */
export const FPR_POISON_THRESHOLD = 0.01;

export class CreditFilter {
  private readonly bits: number;
  private readonly mask: number;
  private readonly hashes: number;
  private readonly epochMs: number;
  private readonly key: Buffer;
  private readonly arrays: [Uint8Array, Uint8Array];
  private readonly counts: [number, number] = [0, 0];
  private readonly t0: number;
  private currentEpoch = 0;
  private counters = { inserts: 0, lookups: 0, hits: 0, rotations: 0 };

  constructor(private readonly options: CreditFilterOptions) {
    const { bits, hashes, epochMs } = options;
    if (!Number.isSafeInteger(bits) || bits < 64 || bits > 2 ** 30 || (bits & (bits - 1)) !== 0) throw new Error("bits must be a power of two between 64 and 2^30");
    if (!Number.isSafeInteger(hashes) || hashes < 1 || hashes > 16) throw new Error("hashes must be an integer between 1 and 16");
    if (!Number.isSafeInteger(epochMs) || epochMs < 1) throw new Error("epochMs must be a positive integer");
    this.bits = bits;
    this.mask = bits - 1;
    this.hashes = hashes;
    this.epochMs = epochMs;
    this.key = options.key ?? randomBytes(32);
    this.arrays = [new Uint8Array(bits >>> 3), new Uint8Array(bits >>> 3)];
    this.t0 = options.mono();
  }

  /** The epoch for the current instant. Pure arithmetic on the monotonic clock. */
  epochNow(): number { return Math.max(0, Math.floor((this.options.mono() - this.t0) / this.epochMs)); }

  /** Moves to the current epoch, zeroing every generation that has aged out. Called first by every operation. */
  advance(): number {
    const target = this.epochNow();
    if (target > this.currentEpoch) {
      // Advancing by one zeroes the array that held epoch-1; by two or more zeroes both: nothing older than the previous epoch may survive.
      const steps = Math.min(target - this.currentEpoch, 2);
      for (let step = 1; step <= steps; step++) {
        const entering = target - steps + step;
        const slot = entering & 1;
        this.arrays[slot].fill(0);
        this.counts[slot] = 0;
        this.counters.rotations++;
      }
      this.currentEpoch = target;
    }
    return this.currentEpoch;
  }

  /** The keyed digest of a token: the only form in which it is ever remembered (and only as a lookup key, never stored by this class). */
  digest(token: string): Buffer { return createHmac("sha256", this.key).update(token, "latin1").digest(); }

  private index(digest: Buffer, i: number): number {
    const h1 = digest.readUInt32LE(0);
    const h2 = digest.readUInt32LE(4) | 1;
    // Enhanced double hashing: (h1 + i*h2 + i*i) mod 2^k, all in 32-bit unsigned arithmetic.
    return ((h1 + Math.imul(i, h2) + Math.imul(i, i)) >>> 0) & this.mask;
  }

  private test(slot: number, digest: Buffer): boolean {
    const array = this.arrays[slot];
    for (let i = 0; i < this.hashes; i++) {
      const bit = this.index(digest, i);
      if ((array[bit >>> 3] & (1 << (bit & 7))) === 0) return false;
    }
    return true;
  }

  /** True when the digest is in the current or the previous generation. Never a false negative for a token enrolled within the window. */
  has(digest: Buffer): boolean {
    const epoch = this.advance();
    this.counters.lookups++;
    const hit = this.test(epoch & 1, digest) || (epoch >= 1 && this.test((epoch - 1) & 1, digest));
    if (hit) this.counters.hits++;
    return hit;
  }

  /** True only when the digest is in the ACTIVE generation: its bits then live exactly as long as a token enrolled now would. */
  hasInActive(digest: Buffer): boolean {
    const epoch = this.advance();
    return this.test(epoch & 1, digest);
  }

  /** Enrolls into the ACTIVE generation. Cannot fail, allocates nothing, evicts nothing. */
  insert(digest: Buffer): void {
    const epoch = this.advance();
    const slot = epoch & 1;
    const array = this.arrays[slot];
    for (let i = 0; i < this.hashes; i++) {
      const bit = this.index(digest, i);
      const byte = bit >>> 3;
      const flag = 1 << (bit & 7);
      if ((array[byte] & flag) === 0) { array[byte] |= flag; this.counts[slot]++; }
    }
    this.counters.inserts++;
  }

  stats(): FilterStats {
    const epoch = this.advance();
    const active = this.counts[epoch & 1];
    const previous = epoch >= 1 ? this.counts[(epoch - 1) & 1] : 0;
    const fill = (count: number) => count / this.bits;
    const fpr = (count: number) => Math.pow(fill(count), this.hashes);
    return {
      epoch, bitsPerGeneration: this.bits, hashes: this.hashes, popcount: [active, previous], fillRatio: [fill(active), fill(previous)],
      fprEstimate: 1 - (1 - fpr(active)) * (1 - fpr(previous)), ...this.counters,
    };
  }

  get isPoisoned(): boolean { return this.stats().fprEstimate > FPR_POISON_THRESHOLD; }
}
