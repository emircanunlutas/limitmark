import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { test } from "node:test";
import { evaluateObservation, FORM_ROUTE_TARGETS } from "../defense/core/enrollment";
import { MUTATION_TARGET, requiredLedgerCapacity } from "../defense/core/lanes";
import type { LayerRequest } from "../defense/core/types";
import { ShapeGate } from "../defense/layers/a7-shape-gate";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { SemanticGate } from "../defense/plane/semantic-gate";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { NOT_CLAIMED, SCALE_STATEMENT, SCOPE_STATEMENT } from "../lab/defense/ba0-collapse-run";
import { FORCED_FIXTURES, FORCED_FIXTURE_SET_DIGEST, RENDER_SCENARIOS, forcedRequestBytes, forcedIdentity, validFormBody } from "../lab/defense/collapse-corpus";
import { BA0_COLLAPSE_LOCAL_V1, ba0CollapseFingerprint, decideCollapseVerdict } from "../lab/defense/collapse-thresholds";

const root = path.join(__dirname, "..");
const read = (file: string) => readFileSync(path.join(root, file), "utf8").replace(/\r\n/g, "\n");

test("the enrollment matcher is pinned to the application's form component: the token input, its attribute order, the form class and the field name", () => {
  const form = read("src/components/request-form.tsx");
  assert.match(form, /<input type="hidden" name=\{submissionTokenField\} value=\{state\.submissionToken \?\? submissionToken\} \/>/, "type, name, value in that order: the order React serialises into the HTML the matcher requires");
  assert.match(form, /<form ref=\{hydrateForm\} className="request-form"/, "the form element the matcher requires");
  assert.match(read("src/lib/submission-token.ts"), /export const submissionTokenField = "submissionToken";/);
  assert.match(read("src/lib/submission-token.ts"), /\^\[A-Za-z0-9_-\]\{43\}\$/, "the 43-character token shape the matcher requires");
});

test("the synthetic origin's form page satisfies the same enrollment contract the real application's page does (the real one is checked by the G1 integration script)", async () => {
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const port = await origin.listen();
  try {
    const page = await new Promise<{ status: number; rawHeaders: string[]; body: Buffer }>((resolve, reject) => {
      http.get({ host: "127.0.0.1", port, path: "/test-talep-et", agent: false }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks) }));
      }).on("error", reject);
    });
    const verdict = evaluateObservation({ status: page.status, rawHeaders: page.rawHeaders, payload: page.body }, 1_048_576);
    assert.equal(verdict.ok, true, JSON.stringify(verdict));
    const canary = /name="submissionToken" value="([A-Za-z0-9_-]{43})"/.exec(page.body.toString("utf8"));
    assert.equal(verdict.ok && verdict.token, canary?.[1], "the canary's token pattern and the matcher agree");
  } finally { await origin.close(); }
});

test("L2's route knowledge is a SUBSET of L1's: every open target and the mutation target pass the real L1, and L2 adds no route L1 would refuse", () => {
  const l1 = new ShapeGate();
  const headers = [["host", "127.0.0.1:1"]] as const;
  for (const target of ["/", "/gizlilik", "/test-talep-et/tesekkurler", ...FORM_ROUTE_TARGETS]) {
    assert.deepEqual(l1.evaluate({ method: "GET", target, headers, bodyStatus: "none", body: null }), { kind: "pass" }, target);
  }
  const body = Buffer.from(validFormBody("T".repeat(43)));
  assert.deepEqual(l1.evaluate({ method: "POST", target: MUTATION_TARGET, headers: [...headers, ["content-type", "application/x-www-form-urlencoded"], ["content-length", String(body.length)]], bodyStatus: "complete", body }), { kind: "pass" });
});

test("every forced fixture is what it claims: the REAL L1 (shape gate plus semantic gate) computes exactly the reject reason the fixture states", () => {
  const l1 = new SemanticGate(new ShapeGate());
  for (const fixture of FORCED_FIXTURES) {
    const bytes = forcedRequestBytes(fixture, 4321, "N".repeat(22)).toString("latin1");
    const [head, body] = bytes.split("\r\n\r\n");
    const lines = head.split("\r\n");
    const [method, target] = lines[0].split(" ");
    const headers = lines.slice(1).map((line) => { const at = line.indexOf(":"); return [line.slice(0, at).toLowerCase(), line.slice(at + 1).trim()] as const; }).filter(([name]) => name !== "x-ba0-nonce");
    const request: LayerRequest = { method, target, headers, bodyStatus: fixture.body === null ? "none" : "complete", body: fixture.body === null ? null : Buffer.from(body, "latin1") };
    assert.deepEqual(l1.evaluate(request), { kind: "reject", reason: fixture.l1Reason }, fixture.id);
    const identity = forcedIdentity(fixture);
    assert.equal(identity.method, method);
    assert.equal(identity.target, target);
  }
});

test("the forced fixture set is fixed and digest-pinned; building a fixture twice yields identical bytes; fixture ids are unique", () => {
  assert.equal(FORCED_FIXTURES.length, 12);
  assert.equal(new Set(FORCED_FIXTURES.map((fixture) => fixture.id)).size, FORCED_FIXTURES.length);
  assert.equal(FORCED_FIXTURE_SET_DIGEST, "945b8b10b543d8c7c19ba34ecf4557d2c1fc37dbe5d109396269c9e23d26aad9", "a change to any reviewed fixture must be a reviewed change");
  for (const fixture of FORCED_FIXTURES) assert.deepEqual(forcedRequestBytes(fixture, 4321, "N".repeat(22)), forcedRequestBytes(fixture, 4321, "N".repeat(22)));
  assert.ok(RENDER_SCENARIOS.has("journey_form") && RENDER_SCENARIOS.has("f4_render"));
});

test("the threshold set is named, versioned, fingerprinted, evidence-safe, provisional, and its L2 sizing satisfies the credited-admission bound", () => {
  const fingerprint = ba0CollapseFingerprint();
  assert.equal(fingerprint.id, "ba0-collapse-local-v1");
  assert.equal(fingerprint.sha256, "86ab47a67db8e37736147ce9ff11f034cbdc36df90aaa426aa2dd3e1bb16da6a", "any change to a threshold changes the recorded fingerprint");
  assert.equal(BA0_COLLAPSE_LOCAL_V1.calibration, "provisional-uncalibrated");
  assertEvidenceSafe(BA0_COLLAPSE_LOCAL_V1.fixtures);
  assertEvidenceSafe(BA0_COLLAPSE_LOCAL_V1.l2);
  const { l2 } = BA0_COLLAPSE_LOCAL_V1;
  assert.ok(l2.ledgerCapacity >= requiredLedgerCapacity(l2.credited.capacity, l2.credited.refillPerSecond, l2.epochMs));
  assert.ok(BA0_COLLAPSE_LOCAL_V1.cycles.recoverySettleMs >= 2 * l2.epochMs + 500, "the recovery wait outlasts two generations");
  assert.ok(BA0_COLLAPSE_LOCAL_V1.cycles.recoverySettleMs >= (l2.unverified.capacity / l2.unverified.refillPerSecond) * 1000, "and the slowest bucket's refill");
  assert.ok(BA0_COLLAPSE_LOCAL_V1.cycles.count >= 3);
});

test("the verdict is exactly one of two values and any anomaly or failed gate makes the run INVALID with every reason", () => {
  assert.deepEqual(decideCollapseVerdict({ gates: [{ id: "a", ok: true, detail: "" }], anomalyTotal: 0 }), { verdict: "LAYER-DIVERSITY-VALID", reasons: [] });
  const invalid = decideCollapseVerdict({ gates: [{ id: "a", ok: false, detail: "" }, { id: "b", ok: false, detail: "" }], anomalyTotal: 2 });
  assert.equal(invalid.verdict, "INVALID");
  assert.deepEqual(invalid.reasons, ["ledger_anomalies_present", "gate_failed:a", "gate_failed:b"]);
  assert.equal(decideCollapseVerdict({ gates: [], anomalyTotal: 0 }).verdict, "INVALID", "no gate evaluated is not a pass");
});

test("the evidence states what Slice 3 does NOT claim, and no string over-claims", () => {
  const joined = NOT_CLAIMED.join("\n").toLowerCase();
  for (const phrase of ["ddos resistance", "bot detection", "read-flood resistance", "per-user fairness", "process independence", "network or transport protection", "production readiness"]) {
    assert.ok(joined.includes(phrase), phrase);
  }
  for (const text of [SCOPE_STATEMENT, SCALE_STATEMENT, ...NOT_CLAIMED]) assertEvidenceSafe({ text });
  assert.match(SCOPE_STATEMENT, /no volumetric, network or transport behaviour is measured/);
  const source = read("lab/defense/ba0-collapse-run.ts");
  assert.doesNotMatch(source.replace(/\/\*[\s\S]*?\*\//g, ""), /result: "PASS"|verdict: "PASS"|"DDoS-resistant"|"production-ready"/);
});
