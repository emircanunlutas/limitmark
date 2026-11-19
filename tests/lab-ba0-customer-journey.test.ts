import assert from "node:assert/strict";
import { test } from "node:test";
import { protectedLineageComplete } from "../defense/core/lineage";
import { runJourney } from "../lab/defense/canary";
import { Collector } from "../lab/defense/collector";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";
import { HopTrustRoot } from "../lab/defense/hop-keys";
import { AppProcess, BoundaryProcess } from "../lab/defense/origin-processes";
import { PLANE_L2_ENTRY, PlaneProcess } from "../lab/defense/plane-process";

test("one loopback customer journey passes L1 and L2 and executes at the guarded origin", async (t) => {
  const collector = new Collector(null);
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const keys = new HopTrustRoot();
  const { hop, channel, composer, l2 } = BA0_FIELD_V1;
  const appLimits = { replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs };
  const app = await AppProcess.start(collector, keys.appInit(appLimits, channel));
  t.after(() => app.stop());
  const boundary = await BoundaryProcess.start(collector, keys.boundaryInit(app.port, {
    ...appLimits, forwardTimeoutMs: hop.forwardTimeoutMs, baLifetimeMs: hop.baLifetimeMs,
  }, channel));
  t.after(() => boundary.stop());
  // Omitting the field ingress selects the plane's ephemeral 127.0.0.1 listener.
  const plane = await PlaneProcess.start(collector, {
    ...BA0_FIELD_V1.plane, upstreamPort: boundary.port, channel, l2,
    composer: { ...composer, failurePolicy: "fail_closed" }, hop: keys.planeInit(hop.pbLifetimeMs),
  }, undefined, PLANE_L2_ENTRY);
  t.after(() => plane.stop());

  const journey = await runJourney(collector, {
    lane: "protected", port: plane.port, phase: "baseline", journey: 1, timeoutMs: BA0_FIELD_V1.canary.timeoutMs,
  });
  const steps = ["homepage", "privacy", "form", "valid_post", "thank_you"];
  assert.deepEqual(journey.steps.map(step => step.name), steps);
  for (const step of journey.steps) {
    assert.equal(step.status, 200, step.name);
    assert.ok(step.ok, `${step.name}: ${step.failure}`);
  }
  assert.ok(journey.completed);

  const drainMs = BA0_FIELD_V1.stop.drainMs;
  const [, boundaryFin, appFin] = await Promise.all([plane.finish(drainMs), boundary.finish(drainMs), app.finish(drainMs)]);
  collector.freeze();
  // Validates per-request ordering, proof lineage, terminal responses and delivery of all three IPC streams.
  assert.deepEqual(collector.finalize(), { anomalies: [], anomalyTotal: 0 });
  const records = [...collector.allRecords()];
  assert.deepEqual(records.map(record => record.meta.scenario), steps.map(step => `journey_${step}`));
  for (const record of records) {
    const step = record.meta.scenario;
    const isSubmission = step === "journey_valid_post";
    assert.ok(record.plane.some(event => event.kind === "L1_PASSED"), step);
    const decision = record.plane.find(event => event.kind === "L2_DECIDED");
    assert.equal(decision?.outcome, "admitted", step);
    assert.equal(decision.lane, isSubmission ? "credited" : "open", step);
    assert.ok(protectedLineageComplete({ ...record, expected: "protected" }), step);
    assert.ok(record.app.some(event => event.kind === "APP_EXECUTED"), step);
    assert.ok(record.app.some(event => event.kind === "APP_COMPLETED"), step);
    assert.equal(record.app.some(event => event.kind === "APP_MUTATED"), isSubmission, step);
  }

  const enrollment = records[2].plane.find(event => event.kind === "L2_ENROLLED");
  const submission = records[3].plane.find(event => event.kind === "L2_DECIDED");
  assert.ok(enrollment?.creditTag, "the delivered form enrolled its token");
  assert.equal(submission?.creditTag, enrollment.creditTag, "the submission used that form's credit");
  assert.equal(boundaryFin?.stats.admitted, steps.length);
  assert.equal(appFin?.stats.counters.executed, steps.length);
  assert.equal(appFin.stats.counters.stateMutations, 1);
});
