import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { NOT_CLAIMED_FIELD, evidenceView, writeFieldEvidence, compactTrace } from "../lab/defense/field-evidence";
import { buildSelftestBundle, runFieldSelftest } from "../lab/defense/field-selftest";
import { BA0_FIELD_V1 } from "../lab/defense/field-thresholds";
import { EvidenceRun, REPOSITORY_ROOT, collectEnvironment, collectGitState, verifyEvidenceDirectory } from "../lab/evidence/manifest";
import { assertEvidenceSafe } from "../lab/evidence/redact";

const testRoot = (): string => { const root = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${process.pid}-${Math.random().toString(16).slice(2, 8)}`); fs.mkdirSync(root, { recursive: true }); return root; };
const ALL = ["core.json", "server-level.json", "external.json", "canary.json", "exposure.json", "preflight.json", "telemetry.json", "connections.json", "traces.json", "processes.json", "accounting.json", "recovery.json", "parameters.json"];

test("the evidence selftest pushes a synthetic level through the REAL writer and the REAL scanner: every artifact is accepted", async () => {
  const root = testRoot();
  try {
    const result = await runFieldSelftest(root);
    assert.deepEqual(result.failed, []);
    assert.equal(result.ok, true);
    assert.deepEqual(result.written, ALL);
    for (const name of ALL) assert.ok(fs.existsSync(path.join(result.directory, name)), name);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("the CORE artifact is written first, from enums and numbers, and carries the scope, the mandatory negative claims and no verdict", () => {
  const root = testRoot();
  try {
    const evidence = new EvidenceRun("field-selftest", "core", new Date(), root);
    const result = writeFieldEvidence(evidence, buildSelftestBundle());
    assert.equal(result.written[0], "core.json");
    const core = JSON.parse(fs.readFileSync(path.join(evidence.directory, "core.json"), "utf8")) as { scope: string; finalVerdict: string; claims: Record<string, unknown>; machine: unknown; sequence: unknown };
    assert.equal(core.finalVerdict, "not_decided_here", "the server side never concludes the final verdict");
    assert.equal(core.claims.defenseQualification, "not_claimed");
    assert.equal(core.claims.networkNonBypass, "not_measured");
    assert.equal(core.claims.originNetworkIsolation, "not_measured");
    assert.deepEqual(core.claims.notClaimed, [...NOT_CLAIMED_FIELD]);
    assert.match(core.scope, /one reviewed level of ordinary HTTP request pressure/);
    assert.match(core.scope, /plain HTTP/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("the mandatory negative claims are all present, and nothing in any artifact over-claims", () => {
  const required = [/DDoS resistance or capacity/, /bot detection/, /read-flood resistance/, /per-user fairness/, /network, transport, TLS or origin-network isolation/, /cloud firewall or NAT/, /synthetic stand-in/,
    /multi-source, distributed or mixed L4\/L7/, /any level above the tested one/, /L1\/L2 process independence/, /production readiness/, /calibrated limits/];
  for (const pattern of required) assert.ok(NOT_CLAIMED_FIELD.some((entry) => pattern.test(entry)), String(pattern));
  const root = testRoot();
  try {
    const evidence = new EvidenceRun("field-selftest", "claims", new Date(), root);
    writeFieldEvidence(evidence, buildSelftestBundle());
    for (const name of ALL) {
      const text = fs.readFileSync(path.join(evidence.directory, name), "utf8");
      assert.doesNotMatch(text, /EXTERNAL-L7-QUALIFICATION-VALID|DDoS-PROTECTED|\bqualified\b|protected against|origin isolation proven|network isolation proven/i, name);
    }
    const exposure = JSON.parse(fs.readFileSync(path.join(evidence.directory, "exposure.json"), "utf8")) as { statement: string };
    assert.match(exposure.statement, /host listener state only/);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("an artifact the scanner refuses is RECORDED and never loses the core or the others (the scanner refuses at the end of a run, the worst time)", () => {
  const root = testRoot();
  try {
    const bundle = buildSelftestBundle();
    bundle.canary.stepFailures = { "password:hunter2": 1 };
    const evidence = new EvidenceRun("field-selftest", "partial", new Date(), root);
    const result = writeFieldEvidence(evidence, bundle);
    assert.deepEqual(result.failed.map((entry) => entry.artifact), ["canary.json"]);
    assert.ok(result.written.includes("core.json"));
    assert.ok(result.written.includes("server-level.json"));
    assert.equal(result.written.length, ALL.length - 1);
    assert.equal(fs.existsSync(path.join(evidence.directory, "canary.json")), false, "nothing partial was written for the refused artifact");
    evidence.finalize({ git: collectGitState(), environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: { artifactsRefused: result.failed.length } });
    assert.deepEqual(verifyEvidenceDirectory(evidence.directory), [], "the finalized evidence verifies against its checksums");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("the parameters artifact renames the key names the scanner reserves, leaves every value alone, and stays labelled provisional", () => {
  const view = evidenceView(BA0_FIELD_V1) as Record<string, Record<string, unknown>>;
  assert.equal(view.hop.readDeadlineMs, BA0_FIELD_V1.hop.bodyDeadlineMs);
  assert.equal(view.plane.readDeadlineMs, BA0_FIELD_V1.plane.bodyDeadlineMs);
  assert.doesNotThrow(() => assertEvidenceSafe(view, "$parameters"));
  const root = testRoot();
  try {
    const evidence = new EvidenceRun("field-selftest", "params", new Date(), root);
    writeFieldEvidence(evidence, buildSelftestBundle());
    const parameters = JSON.parse(fs.readFileSync(path.join(evidence.directory, "parameters.json"), "utf8")) as { calibration: string; status: string; fingerprint: { id: string } };
    assert.equal(parameters.calibration, "provisional-uncalibrated");
    assert.match(parameters.status, /not production defaults/);
    assert.equal(parameters.fingerprint.id, "ba0-field-v1");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("traces are compact and identifier-free: kinds and a few facts, the evidence id, never a nonce", () => {
  const bundle = buildSelftestBundle();
  assert.ok(bundle.traces.length > 0);
  const compact = bundle.traces.map(compactTrace);
  assert.doesNotThrow(() => assertEvidenceSafe(compact, "$traces"));
  assert.match(JSON.stringify(compact), /INGRESS_ACCEPTED/);
  assert.doesNotMatch(JSON.stringify(compact), /nonce|"u[A-Z]{5}/);
});
