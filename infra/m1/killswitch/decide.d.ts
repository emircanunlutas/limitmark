export type KillInstance = { name: string; project: string; createdMs: number; labels: Record<string, string> };
export type KillConfig = { campaignId: string; runMaxSeconds: number; stopFraction: number };
export type KillDecision = { action: "none" | "delete"; reason: string; targets: KillInstance[] };
export type CostInput = { vms: { count: number; usdPerHour: number }[]; hours: number; egressGb: number; usdPerGb: number; storageUsd: number; tryPerUsd: number; runBudgetTry: number };
export type CostBound = { bounded: boolean; usd: number | null; tryAmount: number | null; reason: string };
export function parseMessage(message: unknown): { kind: "reaper" } | { kind: "budget"; fraction: number } | { kind: "invalid" };
export function decide(message: unknown, nowMs: number, instances: KillInstance[], config: KillConfig): KillDecision;
export function maxRunCost(input: CostInput): CostBound;
export const LABEL_PURPOSE: string;
