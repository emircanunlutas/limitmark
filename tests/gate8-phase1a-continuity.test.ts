// Gate 8 Phase 1A: the committed Gate 7 continuity contract, exercised only with
// synthetic snapshots. Nothing here contacts a provider, spawns Wrangler or reads
// a key, credential, manifest or artifact.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import * as continuity from "../operator/staging-gate7-continuity";
import { STAGING_INITIALIZATION_LOCK } from "../operator/staging-initialization-lock";
import { STAGING_RENDER_PINS } from "../operator/staging-config-renderer";

const root = process.cwd();
const { STAGING_GATE7_CONTINUITY: expected, STAGING_GATE7_KEY_FINGERPRINT, ContinuityRefusal,
  validateGate7ContinuitySnapshot, STAGING_CONTINUITY_OBSERVATION_FRESHNESS_MS } = continuity;
const now = 1_790_300_000_000;
type Snapshot = Record<string, unknown> & { receipt: Record<string, unknown>; releases: Array<Record<string, unknown>> };

/** Exactly the shape inspectLifecycleAuthority returns for the initialized
 * authority and the canonical digest (EXACT_RECEIPT branch). */
function snapshot(): Snapshot {
  return {
    version: 1, environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    observedAtMs: now, initialized: true, coverage: "COMPLETE", status: "EXACT_RECEIPT",
    receipt: { digest: "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf", version: 1, operation: "initialize",
      environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
      keyFingerprint: "74f6e266c7cbdced42fffa944ee9eb397f48d1cdfd3b0b0e80817cc313073bd3", sequence: 1, appliedMs: 1790252041703,
      currentReleaseId: "staging-gate7-initial", nextReleaseId: "staging-gate7-initial", nextKeyId: "staging-gate7-key-1",
      activatesMs: 1790251978099, retiresMs: null },
    releases: [{ release_id: "staging-gate7-initial", key_id: "staging-gate7-key-1", activated_ms: 1790251978099, retired_ms: null }],
  };
}

function refuses(value: unknown, code: string, at = now): void {
  assert.throws(() => validateGate7ContinuitySnapshot(value, at),
    (error: unknown) => error instanceof ContinuityRefusal && error.code === code, `expected ${code}`);
}

function mutated(change: (value: Snapshot) => void): Snapshot {
  const value = snapshot();
  change(value);
  return value;
}

test("C1: the exact Gate 7 initialized snapshot passes with only bounded, redacted evidence", () => {
  const evidence = validateGate7ContinuitySnapshot(snapshot(), now);
  assert.deepEqual(evidence, { status: "PASS", proof: "live-initialized-continuity", accountFingerprint: "0df3a690b3154513",
    digest: "f14876a5367f3d5d97d562119203b346159117814b23232ff84958ee36d18bcf", releaseId: "staging-gate7-initial",
    releaseKeyId: "staging-gate7-key-1", receiptSequence: 1, keyFingerprintPrefix: "74f6e266c7cbdced", observedAtMs: now });
  const printed = JSON.stringify(evidence);
  for (const internal of [STAGING_GATE7_KEY_FINGERPRINT, '"releases":', '"receipt":', "appliedMs", "activated_ms", "coverage", "EXACT_RECEIPT"])
    assert.equal(printed.includes(internal), false, `evidence line must not carry ${internal}`);
});

test("C2: identity, state, receipt and release mismatches each refuse with a closed code", () => {
  refuses(mutated((v) => { v.initialized = false; }), "snapshot-state");
  refuses(mutated((v) => { v.coverage = "INCOMPLETE"; }), "snapshot-state");
  refuses(mutated((v) => { v.status = "NOT_FOUND"; }), "snapshot-state");
  refuses(mutated((v) => { v.environment = "production"; }), "snapshot-identity");
  refuses(mutated((v) => { v.authorityId = "production-public-inquiries-v1"; }), "snapshot-identity");
  refuses(mutated((v) => { v.policyEpoch = "phase5c-i1-epoch-2"; }), "snapshot-identity");
  refuses(mutated((v) => { v.version = 2; }), "snapshot-identity");
  const receiptCases: Array<[string, unknown]> = [
    ["digest", "0".repeat(64)], ["environment", "production"], ["authorityId", "production-public-inquiries-v1"],
    ["policyEpoch", "other"], ["operation", "rotate-release"], ["version", 2],
    ["currentReleaseId", "staging-gate7-other"], ["nextReleaseId", "staging-gate7-other"], ["nextKeyId", "staging-gate7-key-2"],
    ["sequence", 2], ["activatesMs", 1790251978100], ["appliedMs", 1790252041704], ["retiresMs", 1790252041703],
    ["keyFingerprint", `${"74f6e266c7cbdced"}${"0".repeat(48)}`], ["keyFingerprint", "74f6e266c7cbdced"],
    ["keyFingerprint", STAGING_GATE7_KEY_FINGERPRINT.toUpperCase()], ["sequence", "1"],
  ];
  for (const [field, value] of receiptCases) refuses(mutated((v) => { v.receipt[field] = value; }), "snapshot-receipt");
  const releaseCases: Array<[string, unknown]> = [["release_id", "staging-gate7-other"], ["key_id", "staging-gate7-key-2"],
    ["activated_ms", 1790251978100], ["retired_ms", 1790252041703]];
  for (const [field, value] of releaseCases) refuses(mutated((v) => { v.releases[0][field] = value; }), "snapshot-releases");
  refuses(mutated((v) => { v.releases = []; }), "snapshot-releases");
  refuses(mutated((v) => { v.releases.push({ ...v.releases[0], release_id: "staging-gate7-second" }); }), "snapshot-releases");
  refuses(mutated((v) => { v.releases = {} as never; }), "snapshot-releases");
});

test("C3: NOT_FOUND, HISTORY_INCOMPLETE, UNAVAILABLE and never-initialized observations refuse", () => {
  refuses(mutated((v) => { v.status = "NOT_FOUND"; v.receipt = null as never; }), "snapshot-state");
  refuses(mutated((v) => { v.status = "HISTORY_INCOMPLETE"; v.coverage = "INCOMPLETE"; v.receipt = null as never; }), "snapshot-state");
  refuses({ version: 1, status: "UNAVAILABLE" }, "snapshot-shape");
  refuses({ version: 1, environment: "staging", authorityId: "staging-public-inquiries-v1", policyEpoch: "phase5c-i1-epoch-1",
    observedAtMs: now, initialized: false, coverage: "COMPLETE", status: "NOT_FOUND", receipt: null, releases: [] }, "snapshot-state");
  // Correct state but receipt withheld: refused rather than inferred.
  refuses(mutated((v) => { v.receipt = null as never; }), "snapshot-receipt");
});

test("C4: observedAtMs freshness is the symmetric reviewed +/-300000ms window", () => {
  assert.equal(STAGING_CONTINUITY_OBSERVATION_FRESHNESS_MS, 300_000);
  assert.equal(validateGate7ContinuitySnapshot(snapshot(), now + 300_000).status, "PASS");
  assert.equal(validateGate7ContinuitySnapshot(snapshot(), now - 300_000).status, "PASS");
  refuses(snapshot(), "observation-freshness", now + 300_001);
  refuses(snapshot(), "observation-freshness", now - 300_001);
  for (const observedAtMs of [-1, 1.5, "1790300000000", null, Number.MAX_SAFE_INTEGER + 1])
    refuses(mutated((v) => { v.observedAtMs = observedAtMs; }), "observation-freshness");
  refuses(snapshot(), "observation-freshness", Number.NaN);
});

test("C5: missing, extra and non-plain members refuse at every level", () => {
  for (const key of Object.keys(snapshot())) refuses(mutated((v) => { delete v[key]; }), "snapshot-shape");
  refuses(mutated((v) => { v.extra = true; }), "snapshot-shape");
  for (const key of Object.keys(snapshot().receipt)) refuses(mutated((v) => { delete v.receipt[key]; }), "snapshot-receipt");
  refuses(mutated((v) => { v.receipt.extra = true; }), "snapshot-receipt");
  for (const key of Object.keys(snapshot().releases[0])) refuses(mutated((v) => { delete v.releases[0][key]; }), "snapshot-releases");
  refuses(mutated((v) => { v.releases[0].extra = true; }), "snapshot-releases");
  for (const value of [null, undefined, [], "snapshot", 1, new (class Snapshot {})()]) refuses(value, "snapshot-shape");
  refuses(Object.assign(Object.create({ inherited: true }), snapshot()), "snapshot-shape");
});

test("C6: the expected state is deeply frozen and carries only public identifiers", async () => {
  assert.equal(Object.isFrozen(expected), true);
  assert.equal(Object.isFrozen(expected.receipt), true);
  assert.equal(Object.isFrozen(expected.releases), true);
  assert.equal(Object.isFrozen(expected.releases[0]), true);
  assert.deepEqual(Object.keys(continuity).sort(), ["ContinuityRefusal", "STAGING_CONTINUITY_OBSERVATION_FRESHNESS_MS",
    "STAGING_CONTINUITY_TRANSPORT_REFUSAL", "STAGING_GATE7_CONTINUITY", "STAGING_GATE7_KEY_FINGERPRINT",
    "validateGate7ContinuitySnapshot"], "no unlock, setter, predicate or transport surface");
  const source = await readFile(join(root, "operator", "staging-gate7-continuity.ts"), "utf8");
  const code = source.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");
  assert.equal(/\bexport\s+(let|var)\b/u.test(code), false);
  assert.equal(/process\.(env|argv)|child_process|node:(net|http|https|tls|dns|fs)|\bfetch\s*\(|WebSocket|\bspawn/u.test(code), false);
  assert.deepEqual(code.match(/^import .*$/gmu), ['import { LIVE_READONLY_OBSERVATION_FRESHNESS_MS } from "../deployment/lifecycle-private-contract";'],
    "imports only the reviewed freshness bound");
  assert.equal(/staging-initialization-lock|STAGING_INITIALIZATION_LOCK/u.test(code), false, "independent of the evidence-only lock record");
  assert.equal(/PRIVATE|PKCS8|secretAccessKey|accessKeyId|RPC_KEY|signature/iu.test(code.replace(/^import .*$/gmu, "")), false,
    "no secret/key material fields");
  assert.equal(/(^|[^a-f0-9])[a-f0-9]{32}([^a-f0-9]|$)/u.test(code.replace(/[a-f0-9]{64}/gu, "")), false, "no raw 32-hex account ID");
});

test("C7: expected values agree with the Gate 7 evidence record, the lock record and the renderer pins", async () => {
  assert.equal(expected.receipt.keyFingerprint, STAGING_GATE7_KEY_FINGERPRINT);
  assert.equal(expected.receipt.digest, STAGING_INITIALIZATION_LOCK.digest);
  assert.equal(expected.receipt.currentReleaseId, STAGING_INITIALIZATION_LOCK.releaseId);
  assert.equal(expected.receipt.nextKeyId, STAGING_INITIALIZATION_LOCK.releaseKeyId);
  assert.equal(expected.receipt.sequence, STAGING_INITIALIZATION_LOCK.receiptSequence);
  assert.equal(expected.authorityId, STAGING_INITIALIZATION_LOCK.authorityId);
  assert.equal(expected.policyEpoch, STAGING_INITIALIZATION_LOCK.policyEpoch);
  assert.equal(expected.accountFingerprint, STAGING_INITIALIZATION_LOCK.accountFingerprint);
  assert.equal(expected.accountFingerprint, STAGING_RENDER_PINS.accountFingerprint);
  assert.equal(STAGING_GATE7_KEY_FINGERPRINT.slice(0, 16), STAGING_INITIALIZATION_LOCK.keyFingerprint);
  assert.equal(STAGING_GATE7_KEY_FINGERPRINT.slice(0, 16), STAGING_RENDER_PINS.keyFingerprint);
  const runbook = await readFile(join(root, "PHASE5C_I3_PROVISIONING_RUNBOOK.md"), "utf8");
  const start = runbook.indexOf("**Gate 7 live evidence — 2026-09-24 (environment: staging; PASS).**");
  const end = runbook.indexOf("**Gate 8 Phase 0 note");
  assert.ok(start > 0 && end > start);
  const gate7 = runbook.slice(start, end);
  for (const value of [STAGING_GATE7_KEY_FINGERPRINT, expected.receipt.digest, expected.receipt.currentReleaseId,
    expected.receipt.nextKeyId, String(expected.receipt.activatesMs), String(expected.receipt.appliedMs), expected.accountFingerprint])
    assert.ok(gate7.includes(value), `Gate 7 evidence records ${value}`);
  assert.match(gate7, /retiresMs null/u);
  assert.match(gate7, /sequence 1\b/u);
});
