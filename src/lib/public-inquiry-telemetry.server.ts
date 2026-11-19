import "server-only";

import { getPublicInquiryOtelRecorder } from "./public-inquiry-otel.server";

const MAX_LATENCY_SAMPLES = 1_024;

type PublicInquiryTelemetryState = {
  incoming: number;
  accepted: number;
  rejected: number;
  active: number;
  latencySamples: number[];
  nextSample: number;
};

const state: PublicInquiryTelemetryState = {
  incoming: 0,
  accepted: 0,
  rejected: 0,
  active: 0,
  latencySamples: [],
  nextSample: 0,
};

function percentile(samples: readonly number[], proportion: number): number | null {
  if (samples.length === 0) return null;
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * proportion) - 1)]!;
}

export type PublicInquiryTelemetrySnapshot = {
  incoming: number;
  accepted: number;
  rejected: number;
  active: number;
  latencySampleCount: number;
  latencySampleCapacity: number;
  latencyMs: { p50: number | null; p95: number | null; p99: number | null };
};

export function beginPublicInquiryRequest(): () => void {
  state.incoming += 1;
  state.active += 1;
  let finishOtel = () => {};
  try {
    finishOtel = getPublicInquiryOtelRecorder().begin();
  } catch {
    // Export and recording failures are observation-only.
  }
  const startedAt = performance.now();
  let completed = false;

  return () => {
    if (completed) return;
    completed = true;
    try {
      finishOtel();
    } catch {
      // Export and recording failures are observation-only.
    }
    state.active -= 1;
    const latency = Math.max(0, performance.now() - startedAt);
    if (state.latencySamples.length < MAX_LATENCY_SAMPLES) {
      state.latencySamples.push(latency);
    } else {
      state.latencySamples[state.nextSample] = latency;
    }
    state.nextSample = (state.nextSample + 1) % MAX_LATENCY_SAMPLES;
  };
}

export function recordPublicInquiryOutcome(status: number): void {
  if (status >= 200 && status < 300) state.accepted += 1;
  else state.rejected += 1;
  try {
    getPublicInquiryOtelRecorder().recordOutcome(status);
  } catch {
    // Export and recording failures are observation-only.
  }
}

export function getPublicInquiryTelemetrySnapshot(): PublicInquiryTelemetrySnapshot {
  return {
    incoming: state.incoming,
    accepted: state.accepted,
    rejected: state.rejected,
    active: state.active,
    latencySampleCount: state.latencySamples.length,
    latencySampleCapacity: MAX_LATENCY_SAMPLES,
    latencyMs: {
      p50: percentile(state.latencySamples, 0.5),
      p95: percentile(state.latencySamples, 0.95),
      p99: percentile(state.latencySamples, 0.99),
    },
  };
}
