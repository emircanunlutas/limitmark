import assert from "node:assert/strict";
import { readFileSync, readdirSync, rmSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { verifyEvidenceDirectory, type EvidenceManifest } from "../lab/evidence/manifest";
import { NOT_CLAIMED, runBa0Collapse, type Ba0CollapseOutcome } from "../lab/defense/ba0-collapse-run";
import { BA0_COLLAPSE_LOCAL_V1, type Ba0CollapseThresholds } from "../lab/defense/collapse-thresholds";

/** Same semantics, smaller and faster: shorter generations and refills, fewer repetitions. Every invariant is still checked. */
const SMALL: Ba0CollapseThresholds = {
  ...BA0_COLLAPSE_LOCAL_V1,
  journeys: { baselinePerLane: 6, pressurePerCycle: 3, afterPressure: 2, recovery: 2, gapMs: 250 },
  l2: { ...BA0_COLLAPSE_LOCAL_V1.l2, filterBits: 2 ** 11, epochMs: 600, unverified: { capacity: 3, refillPerSecond: 2 }, credited: { capacity: 16, refillPerSecond: 8 }, ledgerCapacity: 64 },
  fixtures: { ...BA0_COLLAPSE_LOCAL_V1.fixtures, f1: { count: 60, concurrency: 8 }, f3: { journeys: 6, postsPerCredit: 3 }, f4: { renders: 2_000, concurrency: 8, fabricatedProbe: 60 }, forcedBurst: 8, c2Fabricated: 4 },
  cycles: { count: 2, recoverySettleMs: 2_400, attenuationTolerance: 0.05 },
};

const json = <T>(outcome: Ba0CollapseOutcome, name: string): T => JSON.parse(readFileSync(path.join(outcome.evidenceDirectory, name), "utf8")) as T;

test("a clean local run is LAYER-DIVERSITY-VALID across C0r, C0, C1, C2 and C2': bounded residual mutation, intact canary, natural kept apart from simulated, repeated recovery, and the claim boundary stated", { timeout: 420_000 }, async () => {
  const outcome = await runBa0Collapse({ thresholds: SMALL });
  try {
    assert.deepEqual(outcome.reasons, [], JSON.stringify(outcome.gates.filter((gate) => !gate.ok)));
    assert.equal(outcome.verdict, "LAYER-DIVERSITY-VALID");
    assert.equal(outcome.anomalyTotal, 0);
    assert.deepEqual(outcome.arms.map((arm) => arm.name), ["C0r", "C0", "C1", "C2", "C2p"]);

    const manifest = json<EvidenceManifest>(outcome, "manifest.json");
    assert.equal(manifest.result, "LAYER-DIVERSITY-VALID");
    assert.notEqual(manifest.result as string, "PASS", "no defense qualification is ever concluded");
    const metrics = manifest.metrics as Record<string, unknown>;
    assert.equal(metrics.defenseQualification, "not_claimed");
    assert.equal(metrics.networkNonBypass, "not_measured");
    assert.equal(metrics.failureDomain, "shared_plane_process");
    assert.deepEqual(metrics.notClaimed, [...NOT_CLAIMED]);
    assert.deepEqual(verifyEvidenceDirectory(outcome.evidenceDirectory), [], "every artifact hash verifies");
    for (const name of ["collapse.json", "gates.json", "lanes.json", "penetration.json", "canary.json", "accounting.json", "testcontrols.json", "resources.json"]) {
      assert.ok(readdirSync(outcome.evidenceDirectory).includes(name), name);
    }

    // ---- reference vs normal: the residual the second layer removed
    const collapse = json<{ arms: { arm: string; residualMutations: Record<string, number> | null; overrideInjected: boolean | string; finalState: Record<string, unknown> | null }[] }>(outcome, "collapse.json");
    const arm = (name: string) => collapse.arms.find((entry) => entry.arm === name)!;
    assert.equal(arm("C0r").residualMutations!.f1, SMALL.fixtures.f1.count, "without L2 every fabricated valid mutation reaches the application");
    assert.ok(arm("C0").residualMutations!.f1 <= SMALL.cycles.count * (SMALL.l2.unverified.capacity + 3), "with L2 it is bounded by the unverified bucket");
    assert.ok(arm("C0").residualMutations!.f1 < arm("C0r").residualMutations!.f1);
    assert.equal(arm("C0r").overrideInjected, false);
    assert.equal(arm("C0").overrideInjected, false, "the normal arm has no collapse capability");
    assert.equal(arm("C1").overrideInjected, true);
    assert.equal(arm("C2").overrideInjected, true);
    assert.equal(arm("C0").finalState!.ledgerSize, 0);
    assert.equal(arm("C0").finalState!.digest, arm("C0").finalState!.initialDigest, "the quiescent state digest returned to the initial digest");

    // ---- natural vs simulated are never merged
    const penetration = json<{ arms: { arm: string; rows: { family: string; basis: string; l1: string; terminal: string; count: number }[] }[] }>(outcome, "penetration.json");
    const rows = (name: string) => penetration.arms.find((entry) => entry.arm === name)!.rows;
    assert.ok(rows("C0r").every((row) => row.basis === "natural"), "the reference arm has no simulated verdict");
    assert.ok(rows("C0").every((row) => row.basis === "natural"), "the normal arm has no simulated verdict");
    for (const name of ["C1", "C2"]) {
      const forced = rows(name).filter((row) => row.family.startsWith("fx_") || row.family.startsWith("c2_"));
      assert.ok(forced.length > 0 && forced.every((row) => row.basis === "simulated" && (row.l1 === "simulated_pass" || row.l1 === "natural_pass")), name);
    }
    assert.ok(rows("C2").some((row) => row.family === "c2_fabricated" && row.terminal === "app_mutated"), "the characterization states how deep a request goes when both predecessors are wrong");
    assert.ok(rows("C1").some((row) => row.family === "f1_fabricated" && row.basis === "natural"), "natural fabricated traffic in the collapse arm is still natural");

    // ---- the test controls are represented in evidence
    const controls = json<{ arms: { arm: string; overrideInjected: boolean | string; arms: { granted: boolean }[]; normalRuntimeNegativeControl: string | number }[] }>(outcome, "testcontrols.json");
    const control = (name: string) => controls.arms.find((entry) => entry.arm === name)!;
    for (const name of ["C0r", "C0"]) { assert.equal(control(name).arms.length, 0); assert.equal(control(name).normalRuntimeNegativeControl, 404); }
    for (const name of ["C1", "C2"]) { assert.ok(control(name).arms.length > 0 && control(name).arms.every((entry) => entry.granted)); }
    assert.equal(control("C2p").arms.length, 0, "C2' injects real faults and arms nothing");

    // ---- the evidence holds no submission token and no arm id
    for (const file of readdirSync(outcome.evidenceDirectory)) {
      const text = readFileSync(path.join(outcome.evidenceDirectory, file), "utf8");
      // a random base64url value: exactly 43 characters of mixed case and digits (identity and gate names are lowercase words, hashes are hex)
      assert.doesNotMatch(text, /(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/, `${file} must not contain a token-shaped value`);
    }
  } finally {
    rmSync(outcome.evidenceDirectory, { recursive: true, force: true });
  }
});
