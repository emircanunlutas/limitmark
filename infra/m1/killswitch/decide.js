"use strict";
// Pure decision logic of the M1 kill switch (no I/O, unit-tested from tests/m1-killswitch.test.ts). It only ever selects instances that carry the
// campaign label and purpose label; an unlabeled instance is never selected. It returns what to delete; index.js performs the deletion.

const LABEL_PURPOSE = "m1-qualification";

/** @param {{kind?: string, costAmount?: number, budgetAmount?: number}|null} message */
function parseMessage(message) {
  if (message === null || typeof message !== "object") return { kind: "invalid" };
  if (message.kind === "reaper") return { kind: "reaper" };
  if (typeof message.costAmount === "number" && Number.isFinite(message.costAmount) && message.costAmount >= 0 && typeof message.budgetAmount === "number" && Number.isFinite(message.budgetAmount) && message.budgetAmount > 0) {
    // a budget whose display name ends in "-run" is the run-scoped budget (see killswitch.tf); anything else is the campaign budget
    const runScoped = typeof message.budgetDisplayName === "string" && message.budgetDisplayName.endsWith("-run");
    return { kind: "budget", fraction: message.costAmount / message.budgetAmount, runScoped };
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
  // Selection requires BOTH labels to be present and exact; a missing, empty or malformed label means "not ours" and is never deleted.
  const labeled = (i) => i && typeof i.name === "string" && i.labels && typeof i.labels === "object" && i.labels.purpose === LABEL_PURPOSE && i.labels.campaign === config.campaignId;
  const mine = instances.filter(labeled);
  if (parsed.kind === "budget") {
    const scoped = parsed.runScoped ? mine.filter((i) => typeof config.runId === "string" && config.runId.length > 0 && i.labels.run === config.runId) : mine;
    return parsed.fraction >= config.stopFraction
      ? { action: "delete", reason: `${parsed.runScoped ? "run" : "campaign"}-budget-fraction-${parsed.fraction.toFixed(3)}`, targets: scoped }
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

/**
 * Performs the deletions one by one and NEVER stops at the first failure: a target that is already gone (404 / gone) is a success (the function can run repeatedly), a failure or a
 * timeout of one target does not skip the others. The result lists every outcome so the caller can retry only what is left.
 * @param {{name: string, project: string}[]} targets
 * @param {(target: {name: string, project: string}) => Promise<"deleted"|"gone">} deleteFn
 * @param {{timeoutMs: number}} options
 */
async function executeDeletes(targets, deleteFn, options) {
  const outcome = { deleted: [], alreadyGone: [], failed: [] };
  for (const target of targets) {
    let timer;
    try {
      const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), options.timeoutMs); });
      const result = await Promise.race([deleteFn(target), timeout]);
      (result === "gone" ? outcome.alreadyGone : outcome.deleted).push(target.name);
    } catch (error) {
      outcome.failed.push({ name: target.name, reason: error instanceof Error ? error.message : "error" });
    } finally { clearTimeout(timer); }
  }
  return outcome;
}

/**
 * After a stop request, usage may continue (a deletion is asynchronous, a delayed API answer, a restarting instance). Polls the labeled survivors until none remain or the
 * attempts are used up; the survivors that remain are returned and the caller must fail (so the event is retried), never report success.
 * @param {() => Promise<{name: string, project: string, createdMs: number, labels: Record<string,string>}[]>} listFn
 * @param {{campaignId: string, runId?: string, runMaxSeconds: number}} config
 * @param {{attempts: number, intervalMs: number, runScoped: boolean, nowMs: () => number, sleep: (ms: number) => Promise<void>}} options
 */
async function settle(listFn, config, options) {
  let remaining = [];
  for (let attempt = 1; attempt <= options.attempts; attempt++) {
    const instances = await listFn();
    remaining = decide({ costAmount: 1, budgetAmount: 1, budgetDisplayName: options.runScoped ? "x-run" : "x" }, options.nowMs(), instances, { ...config, stopFraction: 0 }).targets;
    if (remaining.length === 0) return { remaining: [], attempts: attempt };
    await options.sleep(options.intervalMs);
  }
  return { remaining: remaining.map((t) => t.name), attempts: options.attempts };
}

/**
 * Cost enforcement ledger. Each material component states what actually limits it. `strictlyBounded` is true ONLY if every component is limited by a provider limit or an
 * automated stop AND that enforcement has been verified in a real (sandbox) project. Estimates, alerts and unverified automation never count as a bound.
 * enforcement: "none" | "alert" | "provider_limit" | "automated_stop"
 * @param {{name: string, estimatedUsd: number|null, enforcement: string, verified: boolean, residualAfterStop: string}[]} components
 */
function assessCostBound(components) {
  const strong = (c) => (c.enforcement === "provider_limit" || c.enforcement === "automated_stop") && c.verified === true && typeof c.estimatedUsd === "number" && Number.isFinite(c.estimatedUsd);
  const unverified = components.filter((c) => !strong(c)).map((c) => ({ name: c.name, enforcement: c.enforcement, verified: c.verified, reason: c.estimatedUsd === null ? "no-estimate" : c.enforcement === "none" || c.enforcement === "alert" ? "not-enforced" : "enforcement-not-verified" }));
  return {
    strictlyBounded: components.length > 0 && unverified.length === 0,
    estimatedUsd: components.reduce((sum, c) => sum + (typeof c.estimatedUsd === "number" && Number.isFinite(c.estimatedUsd) ? c.estimatedUsd : 0), 0),
    unverified,
    residual: components.filter((c) => c.residualAfterStop && c.residualAfterStop !== "none").map((c) => ({ name: c.name, residual: c.residualAfterStop })),
  };
}

/**
 * Like maxRunCost but over an exchange-rate interval: the figure is bounded only if even the WORST rate stays within the run budget AND the rate is stated as verified.
 */
function maxRunCostWithRate(input, fx) {
  if (fx === null || typeof fx !== "object" || typeof fx.high !== "number" || !Number.isFinite(fx.high) || fx.high <= 0) return { bounded: false, usd: null, tryAmount: null, reason: "exchange-rate-missing" };
  const worst = maxRunCost({ ...input, tryPerUsd: fx.high });
  if (fx.verified !== true) return { bounded: false, usd: worst.usd, tryAmount: worst.tryAmount, reason: "exchange-rate-not-verified" };
  return worst;
}

module.exports = { decide, parseMessage, maxRunCost, maxRunCostWithRate, executeDeletes, settle, assessCostBound, LABEL_PURPOSE };
