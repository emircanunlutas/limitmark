import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { identityFromPackage } from "../lab/m1/identity";
import { evaluateObservationFiles } from "../lab/m1/observation-bundle";
import { buildWorld, disposeWorld, testRoot, type World } from "./support/m1-world";

// Observer readiness: what the real (loopback) collector and canary now record so that a verifier can prove COMPLETENESS, and what a verifier does when that evidence is incomplete or
// altered. Separate processes are not independence: independence needs separate custody (principals, credentials, storage) which a local run cannot demonstrate.

const root = testRoot("observer-readiness");
let world: World; let identity: { runId: string; campaignId: string };
test.before(async () => { world = await buildWorld(root, { slot: 1 }); const id = identityFromPackage(resolveEvidenceDirectory(world.serverId, root)).identity!; identity = { runId: id.runId, campaignId: id.campaignId }; });
test.after(() => { disposeWorld(world); fs.rmSync(root, { recursive: true, force: true }); });

const copy = (name: string, edit: (directory: string) => void): string => {
  const target = path.join(path.dirname(world.observerDirectory), `${path.basename(world.observerDirectory)}-${name}`);
  fs.cpSync(world.observerDirectory, target, { recursive: true }); edit(target); return target;
};
const json = (directory: string, file: string): Record<string, unknown> => JSON.parse(fs.readFileSync(path.join(directory, file), "utf8")) as Record<string, unknown>;
const rewrite = (directory: string, file: string, change: (value: Record<string, unknown>) => void): void => { const value = json(directory, file); change(value); fs.writeFileSync(path.join(directory, file), `${JSON.stringify(value)}\n`); };
const check = (directory: string, limit: number | null = 1_000) => evaluateObservationFiles(identity, directory, limit);
const created: string[] = [];
test.after(() => { for (const directory of created) fs.rmSync(directory, { recursive: true, force: true }); });
const variant = (name: string, edit: (directory: string) => void): string => { const directory = copy(name, edit); created.push(directory); return directory; };

test("the real collector records a run- and campaign-bound closing declaration with gapless counts and heartbeats, and the canary plan gives the expected step count", () => {
  const declaration = json(world.observerDirectory, "collector-declaration.json") as { runId: string; campaignId: string; receiptCount: number; lastSeq: number; heartbeatsMs: number[]; coverageStartMs: number; coverageEndMs: number };
  assert.deepEqual([declaration.runId, declaration.campaignId], [identity.runId, identity.campaignId]);
  const receipts = fs.readFileSync(path.join(world.observerDirectory, "origin-receipts.ndjson"), "utf8").split("\n").filter(Boolean);
  assert.deepEqual([declaration.receiptCount, declaration.lastSeq], [receipts.length, receipts.length]);
  assert.ok(declaration.heartbeatsMs.length >= 1 && declaration.coverageEndMs >= declaration.coverageStartMs);
  const bundle = check(world.observerDirectory);
  assert.deepEqual([bundle.result.outcome, bundle.completeness?.outcome, bundle.limitSource], ["PASS", "PASS", "verifier"], bundle.result.reasons.join(","));
  const meta = json(world.observerDirectory, "observation-meta.json") as { runWindow: { startMs: number; endMs: number } };
  assert.ok(meta.runWindow.startMs >= declaration.coverageStartMs && meta.runWindow.endMs <= declaration.coverageEndMs, "the collector covered the whole run window");
});

test("the heartbeat limit belongs to the verifier: without one the observer's own recorded limit is used and flagged; with neither the observation is unavailable; a strict verifier limit rejects", () => {
  const meta = check(world.observerDirectory, null);
  assert.equal(meta.limitSource, "observer-meta"); assert.ok(meta.result.limitations.includes("heartbeat_gap_limit_set_by_the_observer_not_the_verifier"));
  const none = variant("no-meta-limit", (d) => rewrite(d, "observation-meta.json", (m) => { delete m.completeness; }));
  const bundle = check(none, null);
  assert.deepEqual([bundle.limitMissing, bundle.limitSource, bundle.result.outcome], [true, "none", "ERROR"]);
  const strict = check(world.observerDirectory, 1);
  assert.equal(strict.result.outcome, "REJECT"); assert.ok(strict.result.reasons.includes("m1.complete.heartbeat_gap_exceeded"));
});

test("altered or missing collector evidence is never tolerated: declaration substitution, count mismatch, removed heartbeats, uncovered window, missing declaration, dropped or reordered receipts", () => {
  const cases: [string, (d: string) => void, string][] = [
    ["foreign-run", (d) => rewrite(d, "collector-declaration.json", (v) => { v.runId = "another-run"; }), "m1.complete.declaration_not_bound_to_run"],
    ["foreign-campaign", (d) => rewrite(d, "collector-declaration.json", (v) => { v.campaignId = "another-campaign"; }), "m1.complete.declaration_not_bound_to_run"],
    ["count-mismatch", (d) => rewrite(d, "collector-declaration.json", (v) => { v.receiptCount = (v.receiptCount as number) + 1; }), "m1.complete.declared_receipt_count_mismatch"],
    ["no-heartbeats", (d) => rewrite(d, "collector-declaration.json", (v) => { v.heartbeatsMs = []; }), "m1.complete.no_heartbeats"],
    ["window-start", (d) => rewrite(d, "collector-declaration.json", (v) => { v.coverageStartMs = (v.coverageEndMs as number) - 1; }), "m1.complete.collector_window_not_covering_run"],
    ["dropped-receipt", (d) => { const f = path.join(d, "origin-receipts.ndjson"); const l = fs.readFileSync(f, "utf8").split("\n").filter(Boolean); l.splice(2, 1); fs.writeFileSync(f, `${l.join("\n")}\n`); }, "m1.complete.receipt_sequence_gap"],
    ["reordered", (d) => { const f = path.join(d, "origin-receipts.ndjson"); const l = fs.readFileSync(f, "utf8").split("\n").filter(Boolean); [l[0], l[1]] = [l[1]!, l[0]!]; fs.writeFileSync(f, `${l.join("\n")}\n`); }, "m1.complete.receipt_sequence_gap"],
  ];
  for (const [name, edit, reason] of cases) { const bundle = check(variant(name, edit)); assert.notEqual(bundle.result.outcome, "PASS", name); assert.ok(bundle.result.reasons.includes(reason), `${name}: ${bundle.result.reasons.join(",")}`); }
  const missing = check(variant("no-declaration", (d) => fs.rmSync(path.join(d, "collector-declaration.json"))));
  assert.notEqual(missing.result.outcome, "PASS"); assert.equal(missing.completeness?.outcome, "ERROR");
});

test("request-level correlation and origin attribution are still enforced: a successful canary step without an origin receipt, and a receipt for a foreign run, fail", () => {
  const noReceiptForSuccess = check(variant("receipt-removed", (d) => {
    const f = path.join(d, "origin-receipts.ndjson"); const l = fs.readFileSync(f, "utf8").split("\n").filter(Boolean); const kept = l.slice(0, -1).map((line, i) => JSON.stringify({ ...(JSON.parse(line) as object), seq: i + 1 }));
    fs.writeFileSync(f, `${kept.join("\n")}\n`);
    rewrite(d, "collector-declaration.json", (v) => { v.receiptCount = kept.length; v.lastSeq = kept.length; });
  }));
  assert.equal(noReceiptForSuccess.result.outcome, "REJECT");
  assert.ok(noReceiptForSuccess.result.reasons.some((r) => r.includes("without_origin_receipt") || r.includes("without.origin.receipt")), noReceiptForSuccess.result.reasons.join(","));
  const foreign = check(variant("foreign-receipt", (d) => {
    const f = path.join(d, "origin-receipts.ndjson"); const l = fs.readFileSync(f, "utf8").split("\n").filter(Boolean);
    l[0] = JSON.stringify({ ...(JSON.parse(l[0]!) as object), runId: "another-run" }); fs.writeFileSync(f, `${l.join("\n")}\n`);
  }));
  assert.equal(foreign.result.outcome, "REJECT"); assert.ok(foreign.result.reasons.some((r) => r.includes("foreign")), foreign.result.reasons.join(","));
});
