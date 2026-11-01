import assert from "node:assert/strict";
import test from "node:test";
import { AggregationType, AggregationTemporality, DataPointType, InMemoryMetricExporter, MeterProvider, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";
import { createPublicInquiryOtelRecorder, getPublicInquiryOtelRecorder, PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS } from "../src/lib/public-inquiry-otel.server";

async function recorderWithMemoryExporter(exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE)) {
  const reader = new PeriodicExportingMetricReader({ exporter, exportIntervalMillis: 60_000 });
  const provider = new MeterProvider({
    readers: [reader],
    views: [{
      instrumentName: "limitmark.public_inquiry.duration",
      aggregation: { type: AggregationType.EXPLICIT_BUCKET_HISTOGRAM, options: { boundaries: [...PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS] } },
      aggregationCardinalityLimit: 4,
    }],
  });
  const recorder = createPublicInquiryOtelRecorder(provider.getMeter("test"));
  return { exporter, provider, recorder };
}

test("OpenTelemetry export is disabled by default", () => {
  assert.equal(getPublicInquiryOtelRecorder({ NODE_ENV: "test" }).enabled, false);
});

test("OpenTelemetry recorder emits bounded low-cardinality request metrics", async () => {
  const { exporter, provider, recorder } = await recorderWithMemoryExporter();
  const finish = recorder.begin();
  recorder.recordOutcome(200);
  recorder.recordOutcome(403);
  finish();
  await provider.forceFlush();

  const metrics = exporter.getMetrics().flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
  assert.deepEqual(metrics.map((metric) => metric.descriptor.name).sort(), [
    "limitmark.public_inquiry.active",
    "limitmark.public_inquiry.duration",
    "limitmark.public_inquiry.outcomes",
    "limitmark.public_inquiry.requests",
  ]);
  const outcomes = metrics.find((metric) => metric.descriptor.name.endsWith(".outcomes"));
  assert.ok(outcomes?.dataPoints);
  assert.deepEqual(outcomes.dataPoints.map((point) => point.attributes), [
    { "limitmark.outcome": "accepted" },
    { "limitmark.outcome": "rejected" },
  ]);
  const duration = metrics.find((metric) => metric.descriptor.name.endsWith(".duration"));
  assert.equal(duration?.dataPointType, DataPointType.HISTOGRAM);
  if (duration?.dataPointType === DataPointType.HISTOGRAM) {
    assert.deepEqual(duration.dataPoints[0]?.value.buckets.boundaries, PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS);
    assert.equal(duration.dataPoints[0]?.value.buckets.counts.length, PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS.length + 1);
  }
  assert.equal(metrics.some((metric) => metric.dataPoints.some((point) => JSON.stringify(point.attributes).match(/ip|token|request.?id|path|url/iu))), false);
  await provider.shutdown();
});

test("OpenTelemetry export failures are contained", async () => {
  class ThrowingExporter extends InMemoryMetricExporter {
    override export(...args: Parameters<InMemoryMetricExporter["export"]>): void {
      void args;
      throw new Error("synthetic-export-failure");
    }
  }
  const { provider, recorder } = await recorderWithMemoryExporter(new ThrowingExporter(AggregationTemporality.CUMULATIVE));
  const finish = recorder.begin();
  assert.doesNotThrow(() => recorder.recordOutcome(503));
  assert.doesNotThrow(finish);
  await assert.doesNotReject(provider.forceFlush());
  await assert.doesNotReject(provider.shutdown());
});

test("repeated recording retains fixed instrument state and idempotent completion", async () => {
  const { exporter, provider, recorder } = await recorderWithMemoryExporter();
  for (let index = 0; index < 2_000; index += 1) {
    const finish = recorder.begin();
    recorder.recordOutcome(index % 2 === 0 ? 200 : 429);
    finish();
    finish();
  }
  await provider.forceFlush();
  const metrics = exporter.getMetrics().flatMap((resource) => resource.scopeMetrics.flatMap((scope) => scope.metrics));
  assert.equal(metrics.length, 4);
  assert.ok(metrics.every((metric) => metric.dataPoints.length <= 2));
  await provider.shutdown();
});
