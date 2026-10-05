import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { CreditFilter, FPR_POISON_THRESHOLD } from "../defense/core/credit-filter";

const KEY = Buffer.alloc(32, 7);
const token = () => randomBytes(32).toString("base64url");
function make(overrides: Partial<{ bits: number; hashes: number; epochMs: number }> = {}) {
  let now = 1_000;
  const filter = new CreditFilter({ bits: 4096, hashes: 7, epochMs: 1000, mono: () => now, key: KEY, ...overrides });
  return { filter, tick: (ms: number) => { now += ms; } };
}

test("an enrolled token is positive for at least one epoch and at most two, and a never-enrolled token is (almost) never positive", () => {
  const { filter, tick } = make();
  const tokens = Array.from({ length: 100 }, token);
  for (const value of tokens) filter.insert(filter.digest(value));
  for (const value of tokens) assert.equal(filter.has(filter.digest(value)), true, "no false negative immediately");
  tick(999);
  for (const value of tokens) assert.equal(filter.has(filter.digest(value)), true, "still inside the guaranteed epochMs window");
  tick(1); // t0 + 2*epochMs: the epoch reaches E+2 (insertion happened in epoch 0)
  for (const value of tokens) assert.equal(filter.has(filter.digest(value)), true, "epoch E+1 still holds it (previous generation)");
  tick(1_000);
  for (const value of tokens) assert.equal(filter.has(filter.digest(value)), false, "gone once the epoch reaches E+2");
});

test("no false negatives for any token enrolled within the last epochMs, across every position in the epoch", () => {
  for (const offset of [0, 1, 250, 500, 999]) {
    const { filter, tick } = make();
    tick(offset);
    const mine = token();
    filter.insert(filter.digest(mine));
    tick(1000); // exactly one epochMs later: must still be positive
    assert.equal(filter.has(filter.digest(mine)), true, `offset ${offset}`);
  }
});

test("rotation is lazy-safe: a filter observed only after a long idle never answers from a stale generation", () => {
  const { filter, tick } = make();
  const mine = token();
  filter.insert(filter.digest(mine));
  tick(10 * 1000);
  assert.equal(filter.has(filter.digest(mine)), false);
  assert.deepEqual(filter.stats().popcount, [0, 0], "both generations were cleared by the single observation");
});

test("insertion never fails, allocates nothing new and never evicts: memory is fixed and the fill ratio is the only thing that moves", () => {
  const { filter } = make({ bits: 1024 });
  const before = process.memoryUsage().arrayBuffers;
  const first = token();
  filter.insert(filter.digest(first));
  for (let i = 0; i < 20_000; i++) filter.insert(filter.digest(token()));
  assert.equal(filter.has(filter.digest(first)), true, "an early genuine enrollment survives arbitrary later insertion volume");
  const stats = filter.stats();
  assert.equal(stats.inserts, 20_001);
  assert.ok(stats.fillRatio[0] > 0.9, "the filter saturates rather than refusing");
  assert.ok(stats.fprEstimate > FPR_POISON_THRESHOLD);
  assert.ok(process.memoryUsage().arrayBuffers - before < 8 * 1024 * 1024, "no per-insert buffer allocation outside the transient hash");
});

test("the measured false-positive rate tracks the standard estimate, and grows with fill", () => {
  const { filter } = make({ bits: 2 ** 14 });
  const fprAt = (probes: number) => { let hits = 0; for (let i = 0; i < probes; i++) if (filter.has(filter.digest(token()))) hits++; return hits / probes; };
  for (let i = 0; i < 1000; i++) filter.insert(filter.digest(token()));
  const low = fprAt(20_000);
  const lowEstimate = filter.stats().fprEstimate;
  for (let i = 0; i < 1500; i++) filter.insert(filter.digest(token()));
  const high = fprAt(20_000);
  const highEstimate = filter.stats().fprEstimate;
  assert.ok(high > low, `${high} > ${low}`);
  assert.ok(Math.abs(low - lowEstimate) < 0.02 + lowEstimate, `measured ${low} vs estimate ${lowEstimate}`);
  assert.ok(Math.abs(high - highEstimate) < 0.03 + highEstimate * 0.6, `measured ${high} vs estimate ${highEstimate}`);
});

test("hashing is keyed: the same token under a different key lands on different bits, and tokens are never retained", () => {
  const a = new CreditFilter({ bits: 4096, hashes: 7, epochMs: 1000, mono: () => 0, key: Buffer.alloc(32, 1) });
  const b = new CreditFilter({ bits: 4096, hashes: 7, epochMs: 1000, mono: () => 0, key: Buffer.alloc(32, 2) });
  const value = token();
  a.insert(a.digest(value));
  assert.equal(b.has(b.digest(value)), false);
  assert.notDeepEqual(a.digest(value), b.digest(value));
  const source = readFileSync(path.join(__dirname, "..", "defense", "core", "credit-filter.ts"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
  assert.doesNotMatch(source, /new Map|new Set|\.push\(|\.set\(/, "the filter keeps no per-token collection");
});

test("construction refuses nonsense sizes", () => {
  for (const bad of [{ bits: 1000 }, { bits: 32 }, { hashes: 0 }, { hashes: 99 }, { epochMs: 0 }]) assert.throws(() => make(bad as never));
});
