import assert from "node:assert/strict";
import { test } from "node:test";
import type { PlaneEvent } from "../defense/core/ledger";
import type { MeasurementBarrier } from "../defense/plane/l2-protocol";
import { BA0_FIELD_C2_V1 } from "../lab/defense/field-thresholds";
import { exercised, n2ExerciseSpec, N2ServerObserver, OverlapMeter } from "../lab/defense/n2-measurement";

const spec = n2ExerciseSpec(BA0_FIELD_C2_V1);
const barrier = (phase: MeasurementBarrier["phase"], seq: number, atMs: number, acceptedExternal = 0, inFlightExternal = 0): MeasurementBarrier =>
  ({ phase, seq, atMs, wallAt: new Date(Date.UTC(2026, 9, 6) + atMs).toISOString(), acceptedExternal, inFlightExternal });
const event = (seq: number, t: number, nonce: string, kind: PlaneEvent["kind"]): PlaneEvent =>
  ({ seq, t, nonce, kind, ...(kind === "INGRESS_ACCEPTED" ? { ingress: "external" as const } : {}) });

test("N=2 exposure derives from the reviewed cycle, pacing interval, telemetry period and duration", () => {
  assert.deepEqual(spec, { durationMs: 60000, binMs: 1000, bins: 60, startsPerBin: 4, overlapMsPerBin: 160 });
  assert.equal(spec.bins * spec.startsPerBin, 240);
  assert.equal(spec.bins * spec.overlapMsPerBin, 9600);
});

test("bounded source-event reconstruction proves repeated exposure on a full synthetic campaign, independent of IPC arrival", () => {
  const observer = new N2ServerObserver(spec);
  observer.arm(barrier("armed", 0, 100));
  // Real source timestamps: four independent 40-ms overlaps in each second, not just one high-water observation.
  let seq = 0;
  for (let bin = 0; bin < 60; bin++) {
    for (let pair = 0; pair < 4; pair++) {
      const at = 200 + bin * 1000 + pair * 200;
      observer.observe(event(++seq, at, `a${bin}-${pair}`, "INGRESS_ACCEPTED"));
      observer.observe(event(++seq, at + 40, `b${bin}-${pair}`, "INGRESS_ACCEPTED"));
      observer.observe(event(++seq, at + 80, `a${bin}-${pair}`, "INGRESS_RESPONDED"));
      observer.observe(event(++seq, at + 120, `b${bin}-${pair}`, "INGRESS_RESPONDED"));
    }
  }
  observer.close(barrier("closed", seq, 65200, 480));
  const result = observer.snapshot();
  assert.deepEqual(result.exposure.overlappingStarts, Array(60).fill(4));
  assert.deepEqual(result.exposure.overlapMs, Array(60).fill(160));
  assert.equal(exercised(result.exposure, spec, 480), true);
  assert.equal(result.beforeArmed + result.afterClosed + result.faults + result.inFlightAtClose, 0);
  assert.equal(result.inWindow, 480); assert.equal(result.settledInWindow, 480);
});

test("residency splits exactly across intervals and rounds down; a single jitter overlap or tiny renewals fail", () => {
  const meter = new OverlapMeter(spec);
  meter.change(970, 1, true); meter.change(990, 2, true); meter.change(1010.0009, 1); meter.change(1020, 0);
  const result = meter.snapshot();
  assert.deepEqual(result.overlapMs.slice(0, 2), [10, 10]);
  assert.deepEqual(result.overlappingStarts.slice(0, 2), [1, 0]);
  assert.equal(exercised(result, spec, 1500), false);
  const adequate = { binMs: 1000, overlapMs: Array(60).fill(160), overlappingStarts: Array(60).fill(4) };
  assert.equal(exercised(adequate, spec, 1500), true);
  for (const bad of [
    { ...adequate, overlapMs: Array(60).fill(159.999) },
    { ...adequate, overlappingStarts: Array(60).fill(3) },
    { ...adequate, overlapMs: [9600, ...Array(59).fill(0)] },
    { ...adequate, overlappingStarts: Array(60).fill(26) },
    { ...adequate, overlapMs: Array(59).fill(160) },
    { ...adequate, overlapMs: [NaN, ...Array(59).fill(160)] },
  ]) assert.equal(exercised(bad, spec, 1500), false);
});

test("source watermarks reject a 2.5-second early start even when the corresponding frame arrives after ARMED", () => {
  const observer = new N2ServerObserver(spec);
  observer.arm(barrier("armed", 10, 3000, 1));
  assert.equal(observer.earlyIngress, 1, "cumulative source counter catches queued early ingress");
  observer.observe(event(1, 500, "early", "INGRESS_ACCEPTED"));
  observer.observe(event(2, 510, "early", "INGRESS_RESPONDED"));
  assert.equal(observer.snapshot().beforeArmed, 1);
  assert.equal(observer.snapshot().inWindow, 0);
});

test("source closure binds delayed frames, crossing requests and later ingress to their actual measurement phase", () => {
  const observer = new N2ServerObserver(spec);
  observer.arm(barrier("armed", 0, 100));
  observer.close(barrier("closed", 2, 300, 1, 1));
  observer.observe(event(1, 200, "crossing", "INGRESS_ACCEPTED"));
  observer.observe(event(3, 350, "crossing", "INGRESS_RESPONDED"));
  observer.observe(event(4, 400, "late", "INGRESS_ACCEPTED"));
  observer.observe(event(5, 450, "late", "INGRESS_RESPONDED"));
  const result = observer.snapshot();
  assert.equal(result.inWindow, 1); assert.equal(result.afterClosed, 1);
  assert.equal(result.inFlightAtClose, 1); assert.equal(result.settledInWindow, 0);
});

test("more than two active requests and backward source time are sticky faults with bounded nonce retention", () => {
  const observer = new N2ServerObserver(spec);
  observer.arm(barrier("armed", 0, 100));
  for (let i = 0; i < 100; i++) observer.observe(event(i + 1, 200 + i, `n${i}`, "INGRESS_ACCEPTED"));
  observer.observe(event(101, 150, "backward", "INGRESS_ACCEPTED"));
  assert.equal(observer.snapshot().faults, 101, "98 overflow faults, one backward-time fault and two unresolved requests");
});
