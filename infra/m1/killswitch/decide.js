"use strict";
// Pure decision logic of the M1 kill switch (no I/O, unit-tested from tests/m1-killswitch.test.ts). It only ever selects instances that carry the
// campaign label and purpose label; an unlabeled instance is never selected. It returns what to delete; index.js performs the deletion.

const LABEL_PURPOSE = "m1-qualification";

/** @param {{kind?: string, costAmount?: number, budgetAmount?: number}|null} message */
function parseMessage(message) {
  if (message === null || typeof message !== "object") return { kind: "invalid" };
  if (message.kind === "reaper") return { kind: "reaper" };
  if (typeof message.costAmount === "number" && Number.isFinite(message.costAmount) && typeof message.budgetAmount === "number" && message.budgetAmount > 0) {
    return { kind: "budget", fraction: message.costAmount / message.budgetAmount };
  }
  return { kind: "invalid" };
}

/**
 * @param {{kind?: string, costAmount?: number, budgetAmount?: number}|null} message
 * @param {number} nowMs
 * @param {{name: string, project: string, createdMs: number, labels: Record<string, string>}[]} instances
 * @param {{campaignId: string, runMaxSeconds: number, stopFraction: number}} config
 */
function decide(message, nowMs, instances, config) {
  const parsed = parseMessage(message);
  if (parsed.kind === "invalid") return { action: "none", reason: "invalid-message", targets: [] };
  const mine = instances.filter((i) => i.labels && i.labels.purpose === LABEL_PURPOSE && i.labels.campaign === config.campaignId);
  if (parsed.kind === "budget") {
    return parsed.fraction >= config.stopFraction
      ? { action: "delete", reason: `budget-fraction-${parsed.fraction.toFixed(3)}`, targets: mine }
      : { action: "none", reason: "below-stop-fraction", targets: [] };
  }
  // reaper: anything older than the maximum lifetime plus a 5 minute grace (the provider-enforced limit should already have removed it)
  const limitMs = (config.runMaxSeconds + 300) * 1000;
  const expired = mine.filter((i) => nowMs - i.createdMs > limitMs);
  return expired.length > 0 ? { action: "delete", reason: "ttl-exceeded", targets: expired } : { action: "none", reason: "nothing-expired", targets: [] };
}

/**
 * Upper bound of one run's spend from structure alone (not from billing data). `bounded` is false when any input is missing or non-finite, which the readiness
 * review treats as NO-GO.
 * @param {{vms: {count: number, usdPerHour: number}[], hours: number, egressGb: number, usdPerGb: number, storageUsd: number, tryPerUsd: number, runBudgetTry: number}} input
 */
function maxRunCost(input) {
  const numbers = [input.hours, input.egressGb, input.usdPerGb, input.storageUsd, input.tryPerUsd, input.runBudgetTry, ...input.vms.flatMap((v) => [v.count, v.usdPerHour])];
  if (!Array.isArray(input.vms) || input.vms.length === 0 || !numbers.every((n) => typeof n === "number" && Number.isFinite(n) && n >= 0) || input.tryPerUsd <= 0) return { bounded: false, usd: null, tryAmount: null, reason: "input-missing" };
  const usd = input.vms.reduce((sum, v) => sum + v.count * v.usdPerHour * input.hours, 0) + input.egressGb * input.usdPerGb + input.storageUsd;
  const tryAmount = usd * input.tryPerUsd;
  return { bounded: tryAmount <= input.runBudgetTry, usd, tryAmount, reason: tryAmount <= input.runBudgetTry ? "within-run-budget" : "exceeds-run-budget" };
}

module.exports = { decide, parseMessage, maxRunCost, LABEL_PURPOSE };
