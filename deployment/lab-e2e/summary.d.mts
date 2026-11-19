export function percentile(sortedAscending: number[], p: number): number | null;
export function classifyUnexpected(input: { status: number; headers?: Headers; bodySnippet?: string }): string[];
export type Sample = { scenario: string; ok: boolean; status?: number; latencyMs: number; unexpected?: string[] };
export function summarize(samples: Sample[]): Record<string, {
  total: number; ok: number; successRate: number;
  latencyMs: { p50: number | null; p95: number | null; p99: number | null; max: number | null };
  statuses: Record<string, number>; unexpected: Record<string, number>;
}>;
