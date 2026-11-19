import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { test } from "node:test";
import { KIND_LEDGER_SCHEMA } from "../lab/defense/event-kind-ledger";
import { BA0_FIELD_C2_SALVO_V1, BA0_FIELD_C2_V1, BA0_FIELD_V1, ba0FieldFingerprint, evaluateBudgetGates } from "../lab/defense/field-thresholds";
import { GENERATOR_REPORT_SCHEMA, workloadFingerprint } from "../lab/defense/generator-report";
import { RECEIPT_CHECK_CONTRACT } from "../lab/defense/m1-receipt-check";
import { M1_STATUS_CONTRACT_ID } from "../lab/defense/m1-status-contract";
import { SERVER_LEVEL_SCHEMA, finalFrom } from "../lab/defense/reconcile";
import { SALVO_DIAGNOSTIC_CHECK_SCHEMA } from "../lab/defense/salvo-diagnostic-check";
import { SALVO_DIAGNOSTICS_SCHEMA } from "../lab/defense/salvo-diagnostics";
import { SALVO_SPEC, jointExercised, sourceExercised } from "../lab/defense/salvo-spec";
import { ACCEPTANCE_CONTRACT } from "../lab/m1/acceptance";
import { CAMPAIGN_CONTRACT } from "../lab/m1/campaign";
import { CANARY_CONTRACT } from "../lab/m1/canary-contract";
import { THRESHOLDS_SCHEMA } from "../lab/m1/canary-thresholds";
import { COMMITMENT_SCHEMA } from "../lab/m1/commitment";
import { OBSERVATION_CONTRACT } from "../lab/m1/observation-check";
import { COMPLETENESS_CONTRACT } from "../lab/m1/observation-completeness";
import { PILOT_SCHEMA } from "../lab/m1/pilot";
import { RESULT_PROVENANCE_CONTRACT } from "../lab/m1/result-provenance";
import { SEAL_SCHEMA } from "../lab/m1/seal";
import { WORKLOADS } from "../lab/policy/workloads";
import { MIGRATION_REGISTRY_VERSION, REVIEWED_MIGRATIONS, isEffective } from "./support/reviewed-migrations";
import { REVIEWED_PATCHES } from "./support/reviewed-patches";
import { campaign, observe, stream } from "./support/salvo-diagnostic-fixtures";
import { refreshFixture, salvoFixture } from "./support/salvo-fixture";

/**
 * M1 step 1 (owner decision A-1): an INDEPENDENT, BA0-scoped historical pin test.
 *
 * Why it exists. The two historical-immutability guards (tests/lab-ba0-canary-continuity.test.ts "historical qualification is immutable ..." and
 * tests/lab-ba0-salvo-diagnostics.test.ts "files that decide admission ... are byte-identical to the baseline commit") are RED at the commit this
 * file was added on, because 11 entries of tests/support/reviewed-migrations.ts are PENDING (all under src/ and workers/, none under BA0 paths).
 * Their byte-identity diff throws first, so the assertions that follow it (the parameter and workload fingerprint pins in the first guard; the VALID
 * verdict and the ordered identity list in the second) are not being evaluated. Until a human resolves those entries one by one, this file is the
 * regression guard that actually executes for the BA0 verdict path.
 *
 * What it is NOT. It does not replace, weaken, skip or fix either guard, and it does not make them pass. It changes no registry status and exempts
 * nothing. It deliberately does not look at src/ or workers/: those paths stay under the two guards and under the per-entry human review.
 *
 * What it pins is only what is true at that commit: (1) the exact git blob of every BA0 verdict-path file, as a closed set, and the fact that the
 * only drift from the historical merge commit is the reviewed patches (P0-01, P0-02) and the APPROVED D1 instrumentation migration; (2) the
 * parameter and workload fingerprints; (3) the contract and schema ids in force; (4) the ORIGINAL g5.salvo_exercised behaviour on synthetic
 * R1/R2-shaped fixtures. Every expected value is a literal in this file, so editing a registry or a threshold object cannot silently move a pin.
 * A legitimate, reviewed change to a pinned file must update the literal here on purpose, in the same reviewed act.
 */
const root = path.join(__dirname, "..");
const MERGE_BASE = "64ccc9dabdde81fbc844807f8c104d707151de5e"; // the historical merge commit the first guard compares against
const git = (args: string[]): string => execFileSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 1 << 26 });

/** BA0 scope: the BA0 part of both guards' path lists (their union), without src/ and workers/. */
const BA0_SCOPE = ["defense", "lab/policy", "lab/evidence",
  ...["canary", "field-canary", "field-verdict", "field-state", "field-thresholds", "reconcile", "salvo-spec", "salvo-reconcile", "salvo-diagnostics", "salvo-diagnostic-check",
    "salvo-measurement", "n2-measurement", "external-reducer", "external-accounting", "collector", "generator-report", "ba0-field-reconcile", "exposure-proof"].map((name) => `lab/defense/${name}.ts`)];
const inScope = (file: string): boolean => BA0_SCOPE.some((scope) => file === scope || file.startsWith(`${scope}/`));

/** path -> git blob id of the committed content at the pinning commit (63 files; `git ls-tree -r` over BA0_SCOPE). */
const PINNED_BLOBS: ReadonlyMap<string, string> = new Map([
  ["defense/README.md", "d5bdc73a13c2267949cc25841ad09f11a28780c3"],
  ["defense/boundary/boundary.ts", "5d01ef4f807675d97b2ab19a6fd9350ff05a0def"],
  ["defense/boundary/field-protocol.ts", "a3b42b868267c35f9f70cd476bba84351b3c7abe"],
  ["defense/boundary/main-field.ts", "3c691d0404db9a8fb45200592ad72368fc2056e7"],
  ["defense/boundary/main.ts", "8c454b552dfbb0b51bbe403821cf922152579bfb"],
  ["defense/boundary/protocol.ts", "3ef010f2cd728949951ff7936f82702fe3f0ecf6"],
  ["defense/core/composer.ts", "1bd47e4f1ea2bdf3c4a00f1144d990d5f289b422"],
  ["defense/core/credit-filter.ts", "2aea88c466a50fc25b266fcebb8d373e791d643f"],
  ["defense/core/enrollment.ts", "f4e3c0ee4934166a8e692c7406a6157e94a54744"],
  ["defense/core/hop-admission.ts", "915e3d8e6e6c797fcfcf90292d03ed2467285b86"],
  ["defense/core/hop-proof.ts", "98536b295c885148406b0addd890ea08059011f9"],
  ["defense/core/ingress-class.ts", "8a1b25cfb7a2143916a11cdf64079030d1d35fa4"],
  ["defense/core/l2-lifecycle.ts", "989cfe0f5a9fad185c13c5e89577ee87f6de0bf4"],
  ["defense/core/l2-port.ts", "a4a5961e1628abbe179234e26fd2d4fd613ee0ef"],
  ["defense/core/lanes.ts", "734ba47e01fa227ccea776e82db162b4c5a34cca"],
  ["defense/core/ledger.ts", "cb2eb71b3d123659194fe3a5166219c3de6f2b9c"],
  ["defense/core/lineage.ts", "d7ef2a1fa72cbac4fd50b092b0365acde7bef907"],
  ["defense/core/outcome-counters.ts", "07255f152ae578e22a4a5d9f49721aa9afbdcc82"],
  ["defense/core/override-port.ts", "7cb7b132ee6a0a85b43a0d3e37ab9a5860a07bea"],
  ["defense/core/penetration.ts", "9c52318e70a779e83c740ee158386eed4e7c8b45"],
  ["defense/core/replay-guard.ts", "28591dfc2bb426cb8f3086a92836a852e94d6d99"],
  ["defense/core/semantic-request.ts", "2f78dcccebe3a4b085ace5e0c01727a1edb65e59"],
  ["defense/core/telemetry.ts", "7e2be1e9b2585acaee0b3cc53716aba37ffad860"],
  ["defense/core/types.ts", "c9ad01e9fcfb97cc5987778de794cc1f2c04e44c"],
  ["defense/layers/a7-journey-lanes.ts", "e998c061f9bc5ab0686dce488d1fde8d39168aa9"],
  ["defense/layers/a7-shape-gate.ts", "a1989621a86afdd353bca4f097300a2aa32bceec"],
  ["defense/origin/app-field-protocol.ts", "abe7f8bbe4f3c9aecbc58da5affe44a76a2c8e24"],
  ["defense/origin/app-guard.ts", "f59c4d442c8cc70f35c7fcf6b461a595c9f21207"],
  ["defense/origin/app-main-field.ts", "0a67ef738e0b9e5d832b33694a8513880143014e"],
  ["defense/origin/app-main.ts", "f294a97486ea80c6d2e9df1ea03be4aaaf7c7cbc"],
  ["defense/origin/app-protocol.ts", "06bd9507cb615ea71c64c0cad95679992108e83b"],
  ["defense/origin/synthetic-origin.ts", "fbe78170ac6234a62bd3c058156b288074d434af"],
  ["defense/plane/front.ts", "a6afaccee5fe6b1027d9b944518303d25caed9e1"],
  ["defense/plane/l2-protocol.ts", "a1976f96f05b2647546ac93e590b247ebe818d3a"],
  ["defense/plane/l2-stage.ts", "29beda4c7cc84f56196ad67cb4644416fa58b5a7"],
  ["defense/plane/main-l2.ts", "9b389ec528a3e47b1c599dfdaba5b124ec14a287"],
  ["defense/plane/main.ts", "adf891820fa3afd319b1454e07a05c41e9db6e62"],
  ["defense/plane/protocol.ts", "0cb5b2ddd4023a1f7b04a98f9a019a48edeb35fe"],
  ["defense/plane/runtime.ts", "2306b1718d4e4d07db6bea2b6e94a619bf63ac9f"],
  ["defense/plane/semantic-gate.ts", "649d553dd691d7c706a8d8f2fda1acf4b440a8ae"],
  ["lab/defense/ba0-field-reconcile.ts", "05a8a51ec698d037704d307e317641df49e9a9aa"],
  ["lab/defense/canary.ts", "8993cb1c595cb56e899869f97c252f425206d2ac"],
  ["lab/defense/collector.ts", "7deff0914f31ac46d5295005b40424308e0fb606"],
  ["lab/defense/exposure-proof.ts", "ebd4956194b6a31df82719ee69eda701223c08cf"],
  ["lab/defense/external-accounting.ts", "552cc5de47c11076f60185f5be9ceeef54a20e46"],
  ["lab/defense/external-reducer.ts", "3b76a416f6100abdc3edf54114c25ad34768f8ff"],
  ["lab/defense/field-canary.ts", "a044b1ea75da8cb0beae1f71071d0a8894044115"],
  ["lab/defense/field-state.ts", "6a76314d3d3cb34e764b6568c1261f71f43c8519"],
  ["lab/defense/field-thresholds.ts", "35043c7d10012a9122f9c90b0e8754efce47399a"],
  ["lab/defense/field-verdict.ts", "3e85f97a4c4c34c79a400f152947bc2a2df3fd71"],
  ["lab/defense/generator-report.ts", "80a59fc4627e2ecc9802e8a08a3530f794fe437e"],
  ["lab/defense/n2-measurement.ts", "866a67d33c84cc3d090b61c6c57db3fcdc29a34f"],
  ["lab/defense/reconcile.ts", "3c319ea93a7f1efc628c2d8f76caf940c9612e98"],
  ["lab/defense/salvo-diagnostic-check.ts", "4d1515c82e3bc9ae12b17ec059f3fc9b395a5b52"],
  ["lab/defense/salvo-diagnostics.ts", "005cdc41e893fa9068911c6ffabaa21ecc7a4c87"],
  ["lab/defense/salvo-measurement.ts", "a272ea324c7743a2494f44a97dc1b133ad142fc5"],
  ["lab/defense/salvo-reconcile.ts", "54292d12e68b06d5bbf9e0b4459936dbd8cec745"],
  ["lab/defense/salvo-spec.ts", "0dc1496a9957e4a79b5628c7f43313903742c23f"],
  ["lab/evidence/manifest.ts", "d2793b13977e35e77b5b9db70a2f41b5adce0ab5"],
  ["lab/evidence/redact.ts", "078c9cfbe84afbd18d6297e76d5223faaac43a34"],
  ["lab/policy/target-policy.ts", "676f1838d2ebf90bc104e12f36f637b9cccb4367"],
  ["lab/policy/thresholds.ts", "acd9187d8607562a8fbab31a7f6661e74b94475e"],
  ["lab/policy/workloads.ts", "7f1c7a2f1118f155a79046246721b3100954aa15"],
]);

/**
 * The ONLY BA0 files that differ from the merge commit, each with its blob there (null: the file did not exist) and the review that covers it.
 * Six are the reviewed patches (tests/support/reviewed-patches.ts); two are the APPROVED D1 instrumentation migration (reviewed-migrations.ts).
 */
const REVIEWED_DRIFT: ReadonlyMap<string, { historicalBlob: string | null; review: "P0-01" | "P0-02" | "INSTRUMENTATION/D1" }> = new Map([
  ["defense/boundary/boundary.ts", { historicalBlob: "28890df9650bc80aa2cf89a2db03b1656d1a0868", review: "P0-02" }],
  ["defense/core/hop-admission.ts", { historicalBlob: "a965443ce4f8567903b33331b75ec4c625d6fcf6", review: "P0-02" }],
  ["defense/core/outcome-counters.ts", { historicalBlob: null, review: "INSTRUMENTATION/D1" }],
  ["defense/core/replay-guard.ts", { historicalBlob: "63da012e54b30b3f5a413b1d1159d390c60feff4", review: "P0-02" }],
  ["defense/core/types.ts", { historicalBlob: "cde8b06dd6a8d27b94b792173b2fb1fcbf7a6150", review: "P0-02" }],
  ["defense/origin/synthetic-origin.ts", { historicalBlob: "e0f405ae5ed2274ae2438faa58eb3b0afad9ee5b", review: "P0-02" }],
  ["defense/plane/front.ts", { historicalBlob: "28287c782f2d51e9f1ca49ee22e2cc6119016ba5", review: "P0-01" }],
  ["defense/plane/runtime.ts", { historicalBlob: "5a909606d168e65d39f006d41cc5c2a798ad7e22", review: "INSTRUMENTATION/D1" }],
]);

// ------------------------------------------------------------------------------------------------------------------ 1: verdict-path files
test("BA0 verdict-path files are a closed set and each working file is exactly its pinned blob", () => {
  assert.equal(PINNED_BLOBS.size, 63);
  assert.ok([...PINNED_BLOBS.keys()].every(inScope), "every pinned path is inside the BA0 scope");
  // Closed set: tracked files plus untracked, non-ignored ones. A file added to, removed from or renamed inside the scope fails here.
  const present = git(["ls-files", "--cached", "--others", "--exclude-standard", "--", ...BA0_SCOPE]).split("\n").filter(Boolean).sort();
  assert.deepEqual(present, [...PINNED_BLOBS.keys()].sort());
  // Content: one git hash-object over the working files (the same clean filter a commit would apply), compared file by file.
  const files = [...PINNED_BLOBS.keys()];
  const working = git(["hash-object", "--", ...files]).split("\n").filter(Boolean);
  assert.equal(working.length, files.length);
  const moved = files.filter((file, index) => working[index] !== PINNED_BLOBS.get(file));
  assert.deepEqual(moved, [], "these BA0 verdict-path files are not their pinned blob");
});

test("the only BA0 drift from the historical merge commit is the six reviewed patches and the APPROVED D1 instrumentation migration", () => {
  const historical = new Map(git(["ls-tree", "-r", MERGE_BASE, "--", ...BA0_SCOPE]).split("\n").filter(Boolean).map((line) => {
    const [meta, file] = line.split("\t"); return [file, meta.split(" ")[2]] as const;
  }));
  assert.deepEqual([...historical.keys()].filter((file) => !PINNED_BLOBS.has(file)), [], "no historical BA0 file was deleted or renamed");
  const drift = [...PINNED_BLOBS.keys()].filter((file) => historical.get(file) !== PINNED_BLOBS.get(file)).sort();
  assert.deepEqual(drift, [...REVIEWED_DRIFT.keys()].sort());
  for (const [file, { historicalBlob }] of REVIEWED_DRIFT) assert.equal(historical.get(file) ?? null, historicalBlob, `${file}: the historical blob is the recorded one (or the file was absent)`);
  // Cross-check against the registries as they are today. The literals above decide; the registries must merely agree with them.
  for (const [file, { historicalBlob, review }] of REVIEWED_DRIFT) {
    if (review === "INSTRUMENTATION/D1") {
      const entry = REVIEWED_MIGRATIONS.find((candidate) => candidate.path === file);
      assert.ok(entry !== undefined && isEffective(entry), `${file}: an effective APPROVED migration entry`);
      assert.deepEqual([entry.reviewId, entry.historicalBlob, entry.reviewedBlob], [review, historicalBlob, PINNED_BLOBS.get(file)]);
    } else {
      const patch = REVIEWED_PATCHES.find((candidate) => candidate.path === file);
      assert.ok(patch !== undefined, `${file}: a reviewed patch`);
      assert.deepEqual([patch.reviewedIn, patch.historicalBlob], [review, historicalBlob]);
    }
  }
  assert.deepEqual(REVIEWED_PATCHES.map((patch) => patch.path).filter((file) => !REVIEWED_DRIFT.has(file)), [], "no reviewed patch outside the pinned drift");
  assert.deepEqual(REVIEWED_MIGRATIONS.filter((entry) => inScope(entry.path)).map((entry) => `${entry.path}:${entry.status}`),
    ["defense/core/outcome-counters.ts:APPROVED", "defense/plane/runtime.ts:APPROVED"], "the registry holds exactly two BA0 entries, both APPROVED; no PENDING entry is a BA0 file");
  assert.equal(MIGRATION_REGISTRY_VERSION, 1);
});

// ------------------------------------------------------------------------------------------------------------------ 2: fingerprints
test("the three field parameter fingerprints, the three workload fingerprints and the budget gate counts are unchanged", () => {
  assert.deepEqual([BA0_FIELD_V1, BA0_FIELD_C2_V1, BA0_FIELD_C2_SALVO_V1].map((set) => [set.id, set.level.id, ba0FieldFingerprint(set).sha256]), [
    ["ba0-field-v1", "ba0-l7-c1", "5f7fbb865fcc8f44219a01af4cb02a48113a20fb75436a7f42f5ddd772b3e625"],
    ["ba0-field-c2-v1", "ba0-l7-c2", "cf56f4e3272c9a4cd8257deacf153eaaf154501ceb3749e31179d756134917ab"],
    ["ba0-field-c2-salvo-v1", "ba0-l7-c2-salvo", "eda312909c18c7a7cd9c4525f2071b474f10b1b27c3b181e9e1a12ea27208f46"],
  ]);
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c1"]), "a91b1014db56a16b808703b3616a73ab2b8f19492e61de81727737a33a2f5cec");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2"]), "0fa05c0ca19bfa898d7784e75d4ae1d403fe7d5ea1324be2ddc9f7d724182239");
  assert.equal(workloadFingerprint(WORKLOADS["ba0-l7-pressure-c2-salvo"]), "43ee3f7c0aaacea44384cc7e614eb58fe126bb042698417cf6c65f8f138d4264");
  for (const [set, count] of [[BA0_FIELD_V1, 23], [BA0_FIELD_C2_V1, 31], [BA0_FIELD_C2_SALVO_V1, 37]] as const) {
    const gates = evaluateBudgetGates(set, 3_600_000);
    assert.equal(gates.length, count, set.id); assert.ok(gates.every((gate) => gate.ok), set.id);
  }
});

// ------------------------------------------------------------------------------------------------------------------ 3: contract and schema ids
test("the contract and schema ids in force are unchanged: a new rule gets a new id, an existing id is never re-pointed", () => {
  assert.deepEqual({
    M1_STATUS_CONTRACT_ID, OBSERVATION_CONTRACT, COMPLETENESS_CONTRACT, CANARY_CONTRACT, RECEIPT_CHECK_CONTRACT, ACCEPTANCE_CONTRACT, CAMPAIGN_CONTRACT, RESULT_PROVENANCE_CONTRACT,
    COMMITMENT_SCHEMA, SEAL_SCHEMA, THRESHOLDS_SCHEMA, PILOT_SCHEMA, KIND_LEDGER_SCHEMA, SERVER_LEVEL_SCHEMA, GENERATOR_REPORT_SCHEMA, SALVO_DIAGNOSTICS_SCHEMA, SALVO_DIAGNOSTIC_CHECK_SCHEMA,
  }, {
    M1_STATUS_CONTRACT_ID: "m1-status-contract-v1", OBSERVATION_CONTRACT: "m1-observation-check-v1", COMPLETENESS_CONTRACT: "m1-observation-completeness-v1",
    CANARY_CONTRACT: "m1-canary-contract-v1", RECEIPT_CHECK_CONTRACT: "m1-receipt-check-v1", ACCEPTANCE_CONTRACT: "m1-acceptance-prototype-v1",
    CAMPAIGN_CONTRACT: "m1-local-campaign-prototype-v1", RESULT_PROVENANCE_CONTRACT: "m1-result-provenance-v1", COMMITMENT_SCHEMA: "m1-prerun-commitment-v1",
    SEAL_SCHEMA: "m1-observer-seal-v1", THRESHOLDS_SCHEMA: "m1-canary-thresholds-v1", PILOT_SCHEMA: "m1-pilot-results-v1", KIND_LEDGER_SCHEMA: "ba0-kind-ledger-v1",
    SERVER_LEVEL_SCHEMA: "ba0-server-level-v1", GENERATOR_REPORT_SCHEMA: "ba0-generator-report-v1", SALVO_DIAGNOSTICS_SCHEMA: "ba0-salvo-diagnostics-v1",
    SALVO_DIAGNOSTIC_CHECK_SCHEMA: "ba0-salvo-diagnostic-check-v2",
  });
});

// ------------------------------------------------------------------------------------------------------------------ 4: original g5 behaviour
// Synthetic fixtures only. The raw R1/R2 evidence is not in this repository and nothing here re-scores a historical run.
const reconcile = (c: ReturnType<typeof salvoFixture>) => finalFrom(c.server, c.report, BA0_FIELD_C2_SALVO_V1.generator);
const failed = (c: ReturnType<typeof salvoFixture>) => reconcile(c).result.identities.filter((identity) => !identity.ok).map((identity) => identity.id);

/** R2 shape: 1,500 requests, both sides agree on every count; 22 odd pairs whose first-arrived request is a sub-millisecond shed, one partial even pair. */
function r2Shaped(): ReturnType<typeof salvoFixture> {
  const zero = new Set(Array.from({ length: 22 }, (_, k) => 63 + 32 * k));
  const specs = campaign({ shedOdd: true, zeroOverlap: (pair) => zero.has(pair) });
  const partial = specs[2 * 164]; partial.end = partial.at + 4.5; specs[2 * 164 + 1].at = partial.at + 1.2; specs[2 * 164 + 1].end = specs[2 * 164 + 1].at + 4.5;
  const c = salvoFixture(); c.server.salvo!.pairs = observe(stream(specs)).snapshotSalvo().pairs; refreshFixture(c);
  return c;
}

/** R1 shape: a complete 1,500-request generator report against a server window that also holds an aborted attempt (1,876 accepted; 1,486 x 200; 390 x 503). */
function r1Shaped(): ReturnType<typeof salvoFixture> {
  const c = salvoFixture(); const input = c.server.reconcileInput; const phase = c.server.salvo!.phase;
  input.externalAccepted = 1876; input.statusHistogram = { "200": 1486, "503": 390 }; input.status503 = { total: 390, expectedShed: 390, unexplained: 0 };
  phase.inWindow = 1876; phase.settledInWindow = 1876; phase.closed!.acceptedExternal = 1876;
  return c;
}

test("the original salvo gate order is unchanged: a clean salvo campaign is VALID and g5.salvo_exercised is the fifth identity", () => {
  const result = reconcile(salvoFixture());
  assert.equal(result.decision.verdict, "EXTERNAL-L7-QUALIFICATION-VALID");
  assert.deepEqual(result.result.identities.map((identity) => `${identity.id}:${identity.ok}`), [
    "g6.salvo_reviewed_binding:true", "g1.salvo_fates:true", "g2.salvo_no_unexplained_status:true", "g6.salvo_completion:true", "g5.salvo_exercised:true",
    "g6.salvo_measurement_phase:true", "g6.binding_matches:true", "g1.attempted_equals_ingress_plus_preingress:true", "g1.preingress_is_zero:true",
    "g2.status_histogram_equal:true", "g2.generator_503_equals_expected_shed:true", "g3.gets_equal_open_class:true", "g3.posts_equal_mutation_class:true",
    "g3.unknown_class_is_zero:true", "g3.l1_rejects_is_zero:true", "g4.new_connections_equal_accepted:true", "g4.server_dropped_is_zero:true",
    "g5.generator_in_flight_within_n:true", "g5.server_external_in_flight_within_n:true", "g5.no_retries_no_pipelining:true", "g5.generator_not_saturated:true"]);
  assert.deepEqual([SALVO_SPEC.pairs, SALVO_SPEC.materialRatio, SALVO_SPEC.jointMaterialPairs, SALVO_SPEC.missingPerPlannedBin, SALVO_SPEC.materialStartsPerActualBin], [750, 0.75, 743, 1, 11]);
});

test("R2-shaped evidence is still INVALID, and only at the original g5.salvo_exercised: fast first-arrival sheds are not material server overlap", () => {
  const result = reconcile(r2Shaped());
  assert.deepEqual(result.decision, { verdict: "INVALID", failureClass: "measurement", reasons: [{ code: "identity_failed", detail: "g5.salvo_exercised" }] });
  assert.deepEqual(result.result.identities.filter((identity) => !identity.ok).map((identity) => identity.id), ["g5.salvo_exercised"]);
  const salvo = result.result.salvo!;
  assert.deepEqual([salvo.generator.materialIndices.length, salvo.server.materialIndices.length, salvo.joint.materialIndices.length], [750, 727, 727]);
  // The original rule, restated from its own parts: the generator side passes alone; the server side and the joint set do not reach 743 pairs.
  assert.deepEqual([sourceExercised(salvo.generator), sourceExercised(salvo.server), jointExercised(salvo.joint)], [true, false, false]);
  assert.equal(salvo.joint.missingIndices.length, 23);
  assert.deepEqual(salvo.joint.missingIndices.filter((index) => index % 2 === 0), [164], "22 odd fast-shed pairs and the one partial even pair");
});

test("R1-shaped evidence (a server window that also holds an aborted attempt) cannot be VALID: the count identities fail before any exercise question", () => {
  const c = r1Shaped(); const result = reconcile(c);
  assert.equal(result.decision.verdict, "INVALID"); assert.equal(result.decision.failureClass, "measurement");
  // The pair records of this synthetic fixture are clean, so g5.salvo_exercised itself holds here; that says nothing about the real R1 pair records.
  assert.deepEqual(failed(c), ["g1.salvo_fates", "g6.salvo_measurement_phase", "g1.attempted_equals_ingress_plus_preingress", "g2.status_histogram_equal", "g2.generator_503_equals_expected_shed"]);
  // Contamination and the fast-shed effect do not mask each other: with both, every one of the six identities fails.
  const both = r1Shaped(); both.server.salvo!.pairs = r2Shaped().server.salvo!.pairs; refreshFixture(both);
  assert.equal(reconcile(both).decision.verdict, "INVALID");
  assert.deepEqual(failed(both), ["g1.salvo_fates", "g5.salvo_exercised", "g6.salvo_measurement_phase", "g1.attempted_equals_ingress_plus_preingress", "g2.status_histogram_equal", "g2.generator_503_equals_expected_shed"]);
});
