import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

/**
 * Slice 3 static rules: what did NOT change, what the production module graphs contain, and where the harness-only collapse
 * implementation may and may not exist. These are source-level facts, pinned so a later edit cannot quietly widen them.
 */
const root = path.join(__dirname, "..");
const rel = (file: string) => path.relative(root, file).replace(/\\/g, "/");
const read = (file: string) => readFileSync(path.join(root, file), "utf8").replace(/\r\n/g, "\n");
const code = (file: string) => read(file).replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
function tsFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? tsFiles(full) : entry.name.endsWith(".ts") ? [full] : [];
  });
}

/** SHA-256 of the BASELINE (7714fb3) text of every Slice-1/2 file Slice 3 must not touch, line endings normalised. */
const BASELINE_SHA256: Readonly<Record<string, string>> = {
  "defense/plane/main.ts": "3273b13ff4539a93926e1aea6d7e0215594076b94c5bdbc966b732cf190ff624",
  "defense/plane/protocol.ts": "c552f41dce55e2ec56f22d1a76af371ab3d2c1a001bc5e9e956fff7e670d38b1",
  "defense/plane/semantic-gate.ts": "9a791020c16bb15a83efbfb9fe3447fa88f50682726c516fc17a9b763eaef0d0",
  "defense/core/composer.ts": "522113192a0cb5d2444a0342977eb329885d2b93e678bab28b2ce0a34d7900c1",
  "defense/core/hop-proof.ts": "57bc3cb90dca8abfc20bea9aead2fc570e66a8e22f64733ba626584256a0aeea",
  "defense/core/hop-admission.ts": "a0b9376a9cc1779676d994d67b2c790a95d45aaca5c1097800c4b8fc4db8b8ae",
  "defense/core/replay-guard.ts": "d4b014a4140628bef1650a456395a78dc071175fdb514216454b0b692023a639",
  "defense/core/semantic-request.ts": "58e6b14771078f49403831b71808eccfa2b601262c3cc34a88c0d051533b8b36",
  "defense/core/lineage.ts": "497163e7bc2ef7cdc7f9fa1fa0629f419e0ad7fd42e0f56cbecadc80b6bbea35",
  "defense/layers/a7-shape-gate.ts": "b2cf12b71b6ef97811a18b8af76c44296be771230eab857e224141e58fa1f55f",
  "defense/boundary/boundary.ts": "7e1a5cdde911a07ec9434f0e68010b8c5a72c7f1bfa01a5c8a071b76ad72cea9",
  "defense/boundary/main.ts": "008cc9a81c61c64362a376097599cb05bd3d9dde58807f6e1c6dac99775bc151",
  "defense/boundary/protocol.ts": "9da59a5e8864d6b4e1444908f9508a75ac62f86b6284b28ccc2d6643953ab817",
  "defense/origin/app-guard.ts": "caa6e9f6853b930f083ce379a7535c6100035e093afbbb0aad62ce8d471a95b2",
  "defense/origin/app-main.ts": "ce5eda008f69e2034ff4348b9b21af6a016ec361260f511b1520f6f463b48472",
  "defense/origin/app-protocol.ts": "489e3f1b8976f6e498d5f620f551c9adab0a4b4e4591ab389ee06a1a93ca3a48",
  "defense/origin/synthetic-origin.ts": "0157a0b3cf6c18dccf506fe9878a71d96dce0c025ba94f04a4907f53301d8ea2",
  "lab/defense/ba0-run.ts": "b9e32ca9d3682bdc72fce893080b323d3fa048d323ae2bbd67dbd3d4b5c83762",
  "lab/defense/ba0-origin-run.ts": "b2ed7c9a2e0cdb1938673cdc8cd4f3f4b69a286f5581e5cae00b12b805a33205",
  "lab/defense/accounting.ts": "b158ba72c94b9d0f29022ce96b613f17aca87d0754329962f80901e87c4f3d01",
  "lab/defense/origin-accounting.ts": "70e2b8eb08d346ef49422e2540efd4631b53ca6b4d083eb6d540c4d2af08b6f7",
  "lab/defense/canary.ts": "f824959f854a8a917bd9dee790dfd6a11345908a3ee2bed58f37722dea00b757",
  "lab/defense/thresholds.ts": "6142556b7a05fbeb8bdf629c8d5c8866e6947b14aa73ac44bfcfe22736ebc5ae",
  "lab/defense/origin-thresholds.ts": "cb61dfdb3a770efc0096181ba521f9715369a77d07f927cd1c2eb7e316a78621",
  "lab/defense/hostile-corpus.ts": "8d92e01911b77661d2e7bb0e596caffe5f84b1041ffc2b28fea10b63cdd54791",
  "lab/defense/direct-corpus.ts": "379fac4d783f9f4dfd6ba1c1384ead27b4a1cb0ed9e66848edb8845086376d54",
  "lab/defense/semantic-corpus.ts": "5de980ff9c8e087d4878047c9431803b947411c1ee91fcc839c9bfeef2b2c9d8",
  "lab/defense/hop-keys.ts": "12377c240cfa2fd201e606972608338da6eeb29df5e6108ddd76874b3d0e90d4",
  "lab/defense/origin-processes.ts": "55a251f1c5a41813bf3373be0b740a5c52688931fedbf9c0a23fbda951760236",
};

test("the accepted Slice-1/2 files are byte-identical to the baseline: PB/BA, Boundary, App, replay, the legacy plane entry and its protocol, the Slice-1/2 runners and corpora", () => {
  for (const [file, expected] of Object.entries(BASELINE_SHA256)) {
    assert.equal(createHash("sha256").update(read(file)).digest("hex"), expected, `${file} changed`);
  }
});

// ---------------------------------------------------------------------------
// Runtime module graphs
// ---------------------------------------------------------------------------

/** Files reachable through NON-type imports/exports (a type-only import is erased and is not part of a runtime graph). */
function runtimeGraph(entry: string): Set<string> {
  const seen = new Set<string>();
  const visit = (file: string) => {
    if (seen.has(file)) return;
    seen.add(file);
    const text = code(file);
    for (const match of text.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?!type\b)[^;]*?\bfrom\s+["']([^"']+)["']/g)) {
      const specifier = match[1];
      if (!specifier.startsWith(".")) continue;
      const resolved = rel(path.resolve(path.join(root, path.dirname(file)), specifier)) + ".ts";
      if (existsSync(path.join(root, resolved))) visit(resolved);
    }
  };
  visit(entry);
  return seen;
}

const SLICE3_ONLY = [
  "defense/core/lanes.ts", "defense/core/credit-filter.ts", "defense/core/enrollment.ts", "defense/core/l2-lifecycle.ts", "defense/core/penetration.ts",
  "defense/layers/a7-journey-lanes.ts", "defense/plane/l2-stage.ts", "defense/plane/runtime.ts", "defense/plane/main-l2.ts",
];

test("the legacy Slice-1/2 plane entry has NO L2 code in its runtime module graph: L2 is absent, not disabled", () => {
  const graph = runtimeGraph("defense/plane/main.ts");
  for (const file of SLICE3_ONLY) assert.equal(graph.has(file), false, `${file} must not be reachable from the legacy entry`);
  for (const file of graph) assert.equal(file.startsWith("lab/"), false, file);
});

test("the Slice-3 production entry has L2 and NOTHING from lab/: no force-pass implementation, no fault wrapper, no collapse handler, no injected dependency", () => {
  const graph = runtimeGraph("defense/plane/main-l2.ts");
  for (const file of ["defense/plane/runtime.ts", "defense/plane/l2-stage.ts", "defense/core/lanes.ts", "defense/core/credit-filter.ts", "defense/core/enrollment.ts", "defense/layers/a7-journey-lanes.ts"]) {
    assert.equal(graph.has(file), true, `${file} is part of the normal Slice-3 composition`);
  }
  for (const file of graph) {
    assert.equal(file.startsWith("lab/"), false, `${file} must not be in a production graph`);
    assert.doesNotMatch(code(file), /collapse|force[-_ ]?pass|fixtureDigest|armId|CollapseOverride|implements\s+VerdictOverridePort|FaultableLayer/i, `${file} mentions the harness-only control`);
  }
  assert.equal(code("defense/plane/main-l2.ts").replace(/\s+/g, " ").trim(), 'import { startPlane } from "./runtime"; startPlane();', "the normal entry passes NO injected dependency");
});

test("the override port and the L2 port are interface-only: no runtime export exists in them or in the L2 protocol types", () => {
  for (const file of ["defense/core/override-port.ts", "defense/core/l2-port.ts", "defense/plane/l2-protocol.ts"]) {
    assert.doesNotMatch(code(file), /export\s+(?:const|let|var|function|class|enum|default)\b/, file);
    assert.doesNotMatch(code(file), /export\s*\{/, file);
  }
});

test("the plane runtime handles exactly init | ack | fin | stop: no fault, collapse or probe message exists in any production file", () => {
  const types = [...code("defense/plane/runtime.ts").matchAll(/raw\.type === "([a-z_:]+)"/g)].map((match) => match[1]);
  assert.deepEqual(types, ["init", "ack", "fin", "stop"]);
  for (const file of ["defense/plane/runtime.ts", "defense/plane/main-l2.ts", "defense/plane/l2-protocol.ts", "defense/plane/l2-stage.ts"]) {
    assert.doesNotMatch(code(file), /["']fault["']|collapse|probe|armId/i, file);
  }
  assert.match(code("defense/plane/runtime.ts"), /process\.on\("disconnect", \(\) => process\.exit\(1\)\)/, "the harness is gone: stop, never fall back");
  assert.doesNotMatch(code("defense/plane/runtime.ts"), /process\.env|process\.argv|readFile|createServer|node:http|node:net/, "no environment, file, or listener decides anything here");
});

test("the issuers still have exactly the accepted call sites; Slice 3 adds only the shared runtime (the normal entry's issuer), never a second signing path", () => {
  const files = [...tsFiles(path.join(root, "defense")), ...tsFiles(path.join(root, "lab", "defense"))];
  const callers = (needle: RegExp) => files.filter((file) => needle.test(code(rel(file)))).map(rel).sort();
  assert.deepEqual(callers(/\bissuePb\(/), ["defense/core/hop-proof.ts", "defense/plane/main.ts", "defense/plane/runtime.ts"]);
  assert.deepEqual(callers(/\bissueBa\(/), ["defense/boundary/boundary.ts", "defense/core/hop-proof.ts"]);
  assert.deepEqual(callers(/\bsealVerifiedPb\(/), ["defense/core/hop-admission.ts", "defense/core/hop-proof.ts"]);
  assert.deepEqual(callers(/approvedRegistry\.add\(/), ["defense/core/semantic-request.ts"]);
  assert.deepEqual(callers(/\bbuildApprovedRequest\(/), ["defense/core/semantic-request.ts", "defense/plane/front.ts", "defense/plane/semantic-gate.ts"]);
});

// ---------------------------------------------------------------------------
// Where the harness-only collapse implementation may exist
// ---------------------------------------------------------------------------

test("the verdict-override implementation, the collapse messages and the arm controller exist ONLY under lab/defense/collapse and the runner", () => {
  const everything = ["defense", "src", "workers", "operator", "scripts", "deployment", "lab"].flatMap((directory) => (existsSync(path.join(root, directory)) ? tsFiles(path.join(root, directory)) : []));
  const implementers = everything.filter((file) => /implements\s+VerdictOverridePort/.test(code(rel(file)))).map(rel);
  assert.deepEqual(implementers, ["lab/defense/collapse/override.ts"], "one implementation of the override port exists, under lab/");
  const mentions = everything.filter((file) => /collapse:arm|CollapseOverride|fixtureDigestOf/.test(code(rel(file)))).map(rel).sort();
  assert.deepEqual(mentions, ["lab/defense/ba0-collapse-run.ts", "lab/defense/collapse/controller.ts", "lab/defense/collapse/override.ts", "lab/defense/collapse/plane-collapse-main.ts", "lab/defense/collapse/protocol.ts"]);
  for (const file of everything.filter((candidate) => !rel(candidate).startsWith("lab/"))) {
    assert.doesNotMatch(code(rel(file)), /lab\/defense\/collapse|from\s+["'][^"']*\/collapse\//, `${rel(file)} must not reach the harness-only entry`);
  }
});

test("the collapse entry is the Slice-3 runtime with injected seams only: it implements no signing, holds no key and cannot reach a later stage", () => {
  const entry = code("lab/defense/collapse/plane-collapse-main.ts");
  assert.match(entry, /startPlane\(\{[\s\S]*verdictOverride: override[\s\S]*wrapL1[\s\S]*wrapL2/);
  const override = code("lab/defense/collapse/override.ts");
  assert.doesNotMatch(override, /hop-proof|hop-admission|replay-guard|semantic-request|issuePb|issueBa|createPrivateKey|importPrivateKey|sign\(/, "the override can change only a layer's verdict");
  assert.match(override, /MAX_OUTSTANDING_ARMS = 16/);
  assert.match(override, /arm\.nonce !== context\.nonce \|\| arm\.remotePort !== context\.remotePort \|\| arm\.fixtureDigest !== digest/, "a match needs the nonce, the connection and the exact fixture bytes");
  assert.match(override, /context\.nonce\.length === 0 \|\| context\.remotePort === undefined\) return null/, "an uncorrelated request can never match an arm");
  const front = code("defense/plane/front.ts");
  assert.match(front, /correlated \? nonce : ""/, "an uncorrelated request reaches the port with an empty nonce");
  assert.doesNotMatch(front, /collapse|armId|fixtureDigest/i);
});

test("the package scripts are exactly the accepted ones plus the one new Slice-3 script", () => {
  const manifest = JSON.parse(read("package.json")) as { scripts: Record<string, string> };
  assert.equal(manifest.scripts["lab:ba0"], "tsx --conditions=react-server lab/defense/ba0-run.ts");
  assert.equal(manifest.scripts["lab:ba0:origin"], "tsx --conditions=react-server lab/defense/ba0-origin-run.ts");
  assert.equal(manifest.scripts["lab:ba0:collapse"], "tsx --conditions=react-server lab/defense/ba0-collapse-run.ts");
});

test("the Slice-3 defense files obey the same static rules as the rest of defense/: no fs, no child processes, no clock or randomness of their own in the mechanism", () => {
  for (const file of SLICE3_ONLY.concat(["defense/core/l2-port.ts", "defense/core/override-port.ts", "defense/plane/l2-protocol.ts"])) {
    assert.doesNotMatch(code(file), /from\s+["']node:fs(?:\/promises)?["']|node:child_process|node:cluster|node:worker_threads|node:dgram|node:dns|fail[_-]?open|failopen/i, file);
  }
  assert.doesNotMatch(code("defense/plane/l2-stage.ts"), /refund|rollback|release|reservation|watchdog/i);
});
