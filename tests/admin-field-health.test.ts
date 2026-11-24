import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { REASON_CODES } from "../lab/defense/field-verdict";
import { REVIEW_AGE_MS } from "../src/lib/field-health";
import { readFieldReasons } from "../src/lib/field-reasons";
import { readFieldHealth } from "../src/lib/read-field-health";
import { c, changed, now, originals, type EditableFixture } from "./support/field-health-fixture";

async function review(files = originals, time = now) {
  const result = await readFieldHealth(files, time);
  assert.equal(result.state, "Reviewed");
  return result.review;
}

test("published evidence combines four exercised components, preserving expected L2 shedding", async () => {
  const view = await review();
  assert.ok(c.status503.expectedShed > 0);
  assert.deepEqual(view.components.map(row => [row.name, row.state, row.observations]), [
    ["L1 request screening", "Healthy", c.l1.entered], ["L2 admission", "Healthy", c.l2.decided],
    ["Origin boundary", "Healthy", c.boundary.admitted], ["Protected app", "Healthy", c.app.admitted],
  ]);
});

test("recency uses end time and a fixed review clock, independent of historical faults", async () => {
  assert.equal((await review(originals, now + REVIEW_AGE_MS)).stale, false);
  const files = await changed(({ manifest, canary }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid"; canary.l1FalseRejects++;
  });
  const view = await review(files, now + REVIEW_AGE_MS + 1);
  assert.equal(view.stale, true);
  assert.deepEqual(view.components.map(c => c.state), ["Degraded", "Unknown", "Unknown", "Unknown"]);
  assert.match(view.components[0].detail, /canary/);
  assert.equal((await readFieldHealth(files, now - 1)).state, "Unknown");
});

test("integrity and access failures use bounded messages and never disclose raw input", async () => {
  const [sums, manifest, external, canary] = originals;
  const privateText = "private-diagnostic-DO-NOT-RENDER";
  for (const selection of [[sums, manifest, new File([privateText], external.name), canary],
    [sums, manifest, external, { ...canary, name: canary.name, size: canary.size, arrayBuffer: async () => { throw Error(privateText); } }]]) {
    const result = await readFieldHealth(selection, now);
    assert.equal(result.state, "Reviewed");
    assert.ok(result.review.components.every(row => row.state === (selection[2] === external ? "Unavailable" : "Unknown")));
    assert.ok(!JSON.stringify(result).includes(privateText));
  }
  assert.equal((await readFieldHealth([manifest, external, canary], now)).state, "Unavailable");
  assert.equal((await readFieldHealth([...originals, manifest], now)).state, "Unknown");
  assert.equal((await readFieldHealth([sums, new File([privateText], manifest.name)], now)).state, "Unknown");
  const ignored = { name: "unrelated.json", size: 2, arrayBuffer: async () => { assert.fail("unrelated file opened"); } };
  assert.equal((await readFieldHealth([...originals, ignored], now)).state, "Reviewed");
  assert.ok((await review([sums, manifest, canary])).components.every(row => row.state === "Unavailable"));
});

test("contradictions, missing exercise and absent final comparisons cannot yield healthy assessments", async () => {
  for (const mutate of [
    ({ manifest }: EditableFixture) => { manifest.metrics.externalAccepted++; },
    ({ canary }: EditableFixture) => { canary.l2NonAdmits++; },
    ({ canary }: EditableFixture) => { canary.jcr = []; },
    ({ external }: EditableFixture) => { external.accounting.identities[0].left++; },
    ({ external }: EditableFixture) => { external.accounting.identities.push(external.accounting.identities[0]); },
    ({ external }: EditableFixture) => {
      const tick = external.accounting.identities.find(row => row.id === "e10.final_ticks_present")!;
      tick.left = tick.right = 0;
    },
  ]) assert.ok((await review(await changed(mutate))).components.every(row => row.state === "Unknown"));
  const missing = await review(await changed(({ external }) => {
    external.accounting.identities = external.accounting.identities.filter(row => row.id !== "e5.boundary_admitted_equals_ledger");
  }));
  assert.deepEqual(missing.components.map(c => c.state), ["Healthy", "Healthy", "Unknown", "Healthy"]);
  assert.match(missing.components[2].detail, /Missing comparison/);
});

test("transport loss stops positive interpretation even with complete component counters", async () => {
  const view = await review(await changed(({ manifest, external }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid";
    manifest.resultReasons = ["field.tick_gap.private-host-detail"];
    const gap = external.accounting.identities.find(row => row.id === "e10.no_tick_gaps")!;
    gap.left = 2; gap.ok = false; external.accounting.identitiesOk = false;
  }));
  assert.ok(view.components.every(row => row.state === "Unknown" && row.detail.includes("gaps")));
  assert.match(view.diagnostics.join(" "), /missing heartbeats/);
  assert.ok(!JSON.stringify(view).includes("private-host-detail"));
});

test("preflight refusal, an unexercised component, and a component failure remain distinct", async () => {
  const refused = await review(await changed(({ manifest }) => {
    manifest.result = "REFUSED"; manifest.metrics.serverSide = "aborted";
    manifest.metrics.networkActivity = false;
    manifest.artifacts = manifest.artifacts.filter(row => row.name === "core.json");
  }));
  assert.ok(refused.components.every(c => c.state === "Unavailable"));
  const idle = await review(await changed(({ external }) => {
    // Aggregate process comparisons can contain canaries even when the external population is empty.
    external.counters.app.admitted = external.counters.app.executed = external.counters.app.completed = 0;
    const admissions = external.accounting.identities.find(row => row.id === "e5.external_app_admitted_equals_forwarded")!;
    admissions.left = admissions.right = 0;
    external.counters.boundary.forwardResponded = 0;
  }));
  assert.equal(idle.components[3].state, "Unknown");
  assert.match(idle.components[3].detail, /No external exercise/);
  const fault = await review(await changed(({ manifest, external }) => {
    manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid"; external.counters.boundary.forwardFailed = 1;
  }));
  assert.equal(fault.components[2].state, "Degraded");
});

function invalid({ manifest }: EditableFixture) {
  manifest.result = "INVALID";
  manifest.metrics.serverSide = "invalid";
}

test("correlates canary observations across admission stages without linking a decision to a particular journey", async () => {
  const view = await review(await changed(data => {
    invalid(data);
    data.manifest.resultReasons = ["field.l1_false_reject.detail", "field.l2_legitimate_non_admit"];
    data.canary.l1FalseRejects = 2;
    data.canary.l2NonAdmits = 1;
  }));
  const finding = view.findings.find(f => f.title === "Protected request admission")!;
  assert.match(finding.facts.join(" "), /2 protected requests rejected at L1/);
  assert.match(finding.facts.join(" "), /1 protected requests without L2 admission/);
  assert.match(finding.facts.join(" "), /window journeys completed/);
  assert.match(finding.conclusion, /both stages during this run/);
  assert.match(finding.uncertainty, /cannot identify which window journey/);
  assert.match(finding.guidance, /archived ledger/);
  assert.deepEqual((await review()).findings, []);
});

test("separates observed downstream interruptions from client terminal outcomes", async () => {
  const clientAbort = (data: EditableFixture) => {
    invalid(data);
    data.external.counters.clientAborted = 1;
    data.external.counters.terminal.proxied--;
    data.external.counters.terminal.client_aborted = 1;
  };
  const clientOnly = await review(await changed(clientAbort));
  assert.ok(clientOnly.components.every(stage => stage.state !== "Degraded"));
  assert.deepEqual(clientOnly.findings.map(f => f.title), ["Client-side aborts", "Limits of the run outcome"]);

  const downstream = await review(await changed(data => {
    clientAbort(data);
    data.external.counters.boundary.aborted++;
    data.external.counters.app.completed--;
    data.external.counters.app.aborted++;
  }));
  const finding = downstream.findings.find(f => f.title === "Boundary and app interruptions")!;
  assert.equal(finding.facts.length, 2);
  assert.match(finding.facts[0], /boundary aborts 1/);
  assert.match(finding.facts[1], /completions \d+, aborts 1/);
  assert.match(finding.uncertainty, /do not link individual requests/);
  assert.doesNotMatch(finding.conclusion, /caused|client|root cause/i);
  assert.match(downstream.findings.find(f => f.title === "Client-side aborts")!.uncertainty, /unresolved/);
});

test("retains distinct omissions and withholds correlation where the required observations are missing", async () => {
  const [sums, manifest] = originals;
  const absent = await review([sums, manifest]);
  assert.match(absent.findings[0].facts.join(" "), /external\.json.*canary\.json/);
  const files = await changed(data => {
    invalid(data);
    data.manifest.resultReasons = ["field.telemetry_incomplete"];
    data.canary.l1FalseRejects = data.canary.l2NonAdmits = 1;
    data.external.accounting.identities = data.external.accounting.identities.filter(row =>
      row.id !== "e10.final_ticks_present" && row.id !== "e10.streams_drained");
  });
  const gaps = await review(files);
  const coverage = gaps.findings.find(f => f.title === "Telemetry coverage across stages")!;
  assert.equal(coverage.facts.length, 3);
  assert.ok(gaps.components.every(stage => stage.state === "Unknown"));
  assert.ok(!gaps.findings.some(f => f.title === "Protected request admission"));
});

test("distinguishes an unequal handoff from a comparison that contradicts its source counters", async () => {
  const handoff = (data: EditableFixture) => {
    invalid(data);
    data.manifest.resultReasons = ["field.identity_failed"];
    const row = data.external.accounting.identities.find(row => row.id === "e2.l2_in_equals_l1_pass")!;
    row.right++;
    row.ok = data.external.accounting.identitiesOk = false;
    return row;
  };
  const mismatch = await review(await changed(data => {
    const row = handoff(data);
    data.external.counters.l1.passed = row.right;
  }));
  assert.match(mismatch.findings.find(f => f.title === "L2 admission accounting")!.facts.join(" "), /e2.l2_in_equals_l1_pass/);
  const contradiction = await review(await changed(handoff));
  assert.deepEqual(contradiction.findings.map(f => f.title), ["Conflicting run records"]);
  assert.match(contradiction.findings[0].facts[0], /L2 entries \/ L1 passes/);
  assert.ok(contradiction.components.every(stage => stage.state === "Unknown"));
});

test("incomplete journeys alone cannot identify a failing stage", async () => {
  const view = await review(await changed(data => {
    invalid(data);
    data.manifest.resultReasons = ["field.jcr_below_minimum"];
    const window = data.canary.jcr.find(row => row.phase === "window" && row.lane === "protected")!;
    window.attempted = 2; window.completed = 1; window.rate = 0.5;
  }));
  const finding = view.findings.find(f => f.title === "Protected window coverage")!;
  assert.match(finding.facts[0], /1 of 2/);
  assert.match(finding.uncertainty, /measurement/);
  assert.ok(view.components.every(c => c.state === "Unknown"));
});

test("a canary reason with a zero count is conflicting evidence, not an attributed fault", async () => {
  const view = await review(await changed(data => {
    invalid(data);
    data.manifest.resultReasons = ["field.l2_legitimate_non_admit.private"];
  }));
  assert.deepEqual(view.findings.map(f => f.title), ["Conflicting run records"]);
  assert.ok(view.components.every(stage => stage.state === "Unknown"));
});

test("displays known writer codes and a bounded count for unknown entries, even alongside a known code", async () => {
  for (const code of REASON_CODES) {
    assert.ok(readFieldReasons([`field.${code}.private`]).known.has(code));
  }
  const result = await review(await changed(data => {
    invalid(data);
    data.manifest.resultReasons = ["field.tick_gap.private", "field.private_code.secret", "private.reason", "field.__proto__.secret"];
  }));
  assert.match(result.diagnostics.join(" "), /tick_gap/);
  assert.match(result.diagnostics.join(" "), /Unrecognized reason entries · 3/);
  assert.doesNotMatch(JSON.stringify(result), /private|secret|__proto__/);
});

test("review page requires the established admin boundary, with no server upload or public navigation", () => {
  const read = (relative: string) => readFileSync(new URL(relative, import.meta.url), "utf8");
  const page = read("../src/app/admin/field-health/page.tsx");
  assert.match(page, /await requireAdmin\(\);\s*return /);
  assert.match(page, /force-dynamic/);
  assert.match(read("../src/app/admin/page.tsx"), /href="\/admin\/field-health" prefetch=\{false\}/);
  assert.doesNotMatch(read("../src/components/header.tsx"), /field-health/);
});
