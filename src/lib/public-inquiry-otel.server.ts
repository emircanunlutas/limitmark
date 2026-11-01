import "server-only";

import type { Meter } from "@opentelemetry/api";
import { OTLPMetricExporter } from "@opentelemetry/exporter-metrics-otlp-proto";
import { AggregationType, MeterProvider, PeriodicExportingMetricReader } from "@opentelemetry/sdk-metrics";

const EXPORT_INTERVAL_MS = 10_000;
const EXPORT_TIMEOUT_MS = 2_000;
const MAX_EXPORT_BATCH_SIZE = 32;
export const MAX_PUBLIC_INQUIRY_OTEL_TIME_SERIES = 4;
export const PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS = [0.1, 0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000] as const;
const DEFAULT_ENDPOINT = "http://127.0.0.1:4318/v1/metrics";
const OUTCOME_ATTRIBUTES = { "limitmark.outcome": "accepted" as const };
const REJECTED_ATTRIBUTES = { "limitmark.outcome": "rejected" as const };

export type PublicInquiryOtelRecorder = {
  enabled: boolean;
  begin(): () => void;
  recordOutcome(status: number): void;
  shutdown(): Promise<void>;
};

const noopRecorder: PublicInquiryOtelRecorder = {
  enabled: false,
  begin: () => () => {},
  recordOutcome: () => {},
  shutdown: async () => {},
};

function safeCall(action: () => void): void {
  try {
    action();
  } catch {
    // Export and recording failures are observation-only.
  }
}

export function createPublicInquiryOtelRecorder(meter: Meter, shutdown: () => Promise<void> = async () => {}): PublicInquiryOtelRecorder {
  const requests = meter.createCounter("limitmark.public_inquiry.requests", { unit: "request" });
  const outcomes = meter.createCounter("limitmark.public_inquiry.outcomes", { unit: "request" });
  const duration = meter.createHistogram("limitmark.public_inquiry.duration", { unit: "ms" });
  const active = meter.createUpDownCounter("limitmark.public_inquiry.active", { unit: "request" });

  return {
    enabled: true,
    begin: () => {
      safeCall(() => requests.add(1));
      safeCall(() => active.add(1));
      const startedAt = performance.now();
      let completed = false;
      return () => {
        if (completed) return;
        completed = true;
        try {
          safeCall(() => active.add(-1));
          safeCall(() => duration.record(Math.max(0, performance.now() - startedAt)));
        } catch {
          // Defensive completion remains independent of telemetry.
        }
      };
    },
    recordOutcome: (status) => safeCall(() => outcomes.add(1, status >= 200 && status < 300 ? OUTCOME_ATTRIBUTES : REJECTED_ATTRIBUTES)),
    shutdown: async () => {
      try {
        await shutdown();
      } catch {
        // Shutdown failures must not affect request handling.
      }
    },
  };
}

type GlobalOtelState = {
  key: string;
  recorder: PublicInquiryOtelRecorder;
};

const globalKey = Symbol.for("limitmark.public-inquiry-otel");
const globalState = globalThis as typeof globalThis & { [globalKey]?: GlobalOtelState };

function isEnabled(environment: NodeJS.ProcessEnv): boolean {
  return environment.PUBLIC_INQUIRY_OTEL_METRICS === "true";
}

export function getPublicInquiryOtelRecorder(environment: NodeJS.ProcessEnv = process.env): PublicInquiryOtelRecorder {
  if (!isEnabled(environment)) return noopRecorder;
  const endpoint = environment.PUBLIC_INQUIRY_OTEL_METRICS_ENDPOINT ?? DEFAULT_ENDPOINT;
  const key = `${endpoint}|${environment.PUBLIC_INQUIRY_OTEL_METRICS_SERVICE ?? "limitmark-public-inquiry"}`;
  if (globalState[globalKey]) return globalState[globalKey].recorder;

  try {
    const exporter = new OTLPMetricExporter({ url: endpoint });
    const reader = new PeriodicExportingMetricReader({
      exporter,
      exportIntervalMillis: EXPORT_INTERVAL_MS,
      exportTimeoutMillis: EXPORT_TIMEOUT_MS,
      maxExportBatchSize: MAX_EXPORT_BATCH_SIZE,
      cardinalityLimits: {
        counter: MAX_PUBLIC_INQUIRY_OTEL_TIME_SERIES,
        histogram: MAX_PUBLIC_INQUIRY_OTEL_TIME_SERIES,
        upDownCounter: MAX_PUBLIC_INQUIRY_OTEL_TIME_SERIES,
      },
    });
    const provider = new MeterProvider({
      readers: [reader],
      views: [{
        instrumentName: "limitmark.public_inquiry.duration",
        aggregation: {
          type: AggregationType.EXPLICIT_BUCKET_HISTOGRAM,
          options: { boundaries: [...PUBLIC_INQUIRY_DURATION_BOUNDARIES_MS] },
        },
        aggregationCardinalityLimit: MAX_PUBLIC_INQUIRY_OTEL_TIME_SERIES,
      }],
    });
    const recorder = createPublicInquiryOtelRecorder(provider.getMeter("limitmark.public-inquiry", "1"), () => provider.shutdown());
    globalState[globalKey] = { key, recorder };
    return recorder;
  } catch {
    return noopRecorder;
  }
}
