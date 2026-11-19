// Pure helpers for the legitimate-user baseline. No network, no secrets.
export function percentile(sortedAscending, p) {
  if (sortedAscending.length === 0) return null;
  const rank = Math.ceil((p / 100) * sortedAscending.length);
  return sortedAscending[Math.min(sortedAscending.length - 1, Math.max(0, rank - 1))];
}

// Anything a legitimate user should never see from the public edge.
export function classifyUnexpected({ status, headers, bodySnippet }) {
  const reasons = [];
  if (headers?.get?.("cf-mitigated")) reasons.push("cloudflare-mitigated");
  if (status === 403 || status === 429) reasons.push(`blocked-${status}`);
  if (status >= 500) reasons.push(`server-${status}`);
  if (/just a moment|attention required|verify you are human/iu.test(bodySnippet ?? "")) reasons.push("challenge-page");
  return reasons;
}

export function summarize(samples) {
  const byScenario = {};
  for (const sample of samples) {
    const entry = (byScenario[sample.scenario] ??= { total: 0, ok: 0, latencies: [], statuses: {}, unexpected: {} });
    entry.total += 1;
    if (sample.ok) entry.ok += 1;
    entry.latencies.push(sample.latencyMs);
    const status = String(sample.status ?? "network-error");
    entry.statuses[status] = (entry.statuses[status] ?? 0) + 1;
    for (const reason of sample.unexpected ?? []) entry.unexpected[reason] = (entry.unexpected[reason] ?? 0) + 1;
  }
  const result = {};
  for (const [scenario, entry] of Object.entries(byScenario)) {
    const sorted = [...entry.latencies].sort((a, b) => a - b);
    result[scenario] = { total: entry.total, ok: entry.ok, successRate: entry.total ? entry.ok / entry.total : 0,
      latencyMs: { p50: percentile(sorted, 50), p95: percentile(sorted, 95), p99: percentile(sorted, 99), max: sorted.at(-1) ?? null },
      statuses: entry.statuses, unexpected: entry.unexpected };
  }
  return result;
}
