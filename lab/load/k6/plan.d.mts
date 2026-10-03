export const HARD: Readonly<{
  rate: number; vus: number; seconds: number; timeoutMs: number; totalRequests: number; responseBytes: number; phases: number; requests: number;
}>;
export const PATHS: readonly string[];
export const DEMO_POST_PATH: string;

export type K6PlanShape = {
  schema: 2;
  baseUrl: string;
  maxTotalRequests: number;
  requests: { method: "GET" | "POST"; path: string }[];
  phases: { name: string; seconds: number; rate: number; vus: number; timeoutMs: number; measured: boolean }[];
  thresholds: { passErrorRate: number; stopErrorRate: number; passP95Ms: number; passP99Ms: number; stopP99Ms: number };
};

export type K6Model = {
  scenarios: Record<string, Record<string, unknown>>;
  thresholds: Record<string, unknown[]>;
  caps: Record<string, number>;
  expectedThresholds: { metric: string; expression: string }[];
  windowSeconds: number;
  wallSeconds: number;
  totalRequests: number;
};

export function reject(message: string): never;
export function validatePlan(plan: unknown): K6PlanShape;
export function buildModel(plan: unknown): K6Model;
