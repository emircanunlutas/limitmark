import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

const root = path.join(__dirname, "..");

function tsFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? tsFiles(full) : entry.name.endsWith(".ts") ? [full] : [];
  });
}
const code = (file: string): string => readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
const defenseFiles = tsFiles(path.join(root, "defense"));
const labDefenseFiles = tsFiles(path.join(root, "lab", "defense"));
const rel = (file: string) => path.relative(root, file).replace(/\\/g, "/");

test("the defense tree exists as specified", () => {
  for (const expected of [
    "core/types.ts", "core/composer.ts", "core/ledger.ts", "layers/a7-shape-gate.ts", "plane/front.ts", "origin/synthetic-origin.ts",
    // Slice 2
    "core/hop-proof.ts", "core/hop-admission.ts", "core/replay-guard.ts", "core/semantic-request.ts", "core/lineage.ts", "plane/semantic-gate.ts",
    "boundary/boundary.ts", "boundary/main.ts", "boundary/protocol.ts", "origin/app-guard.ts", "origin/app-main.ts", "origin/app-protocol.ts",
  ]) {
    assert.ok(defenseFiles.some((file) => rel(file) === `defense/${expected}`), expected);
  }
  for (const expected of [
    "canary.ts", "hostile-corpus.ts", "accounting.ts", "thresholds.ts", "ba0-run.ts", "collector.ts",
    // Slice 2
    "hop-keys.ts", "origin-processes.ts", "direct-corpus.ts", "semantic-corpus.ts", "origin-accounting.ts", "origin-thresholds.ts", "ba0-origin-run.ts",
  ]) {
    assert.ok(labDefenseFiles.some((file) => rel(file) === `lab/defense/${expected}`), expected);
  }
});

test("layers and the composer never read the correlation nonce, a hop id, an outcome header or any traffic-class label", () => {
  const judged = defenseFiles.filter((file) => rel(file).startsWith("defense/layers/") || rel(file) === "defense/core/composer.ts");
  assert.ok(judged.length >= 2);
  for (const file of judged) {
    assert.doesNotMatch(code(file), /x-ba0|NONCE_HEADER|HOP_HEADER|OUTCOME_HEADER|nonce|hostile|legitimate|\bcorr\b|trafficClass|traffic_class/i, rel(file));
  }
});

test("layers depend only on the shared closed vocabulary, never on the plane, the ledger or the origin", () => {
  for (const file of defenseFiles.filter((candidate) => rel(candidate).startsWith("defense/layers/"))) {
    const specifiers = [...code(file).matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1]);
    for (const specifier of specifiers) assert.match(specifier, /^\.\.\/core\/types$/, `${rel(file)}: ${specifier}`);
  }
});

test("there is no fail-open path: no fail_open / error_failopen identifier or degraded-as-pass mapping exists in code", () => {
  for (const file of [...defenseFiles, ...labDefenseFiles]) {
    assert.doesNotMatch(code(file), /fail[_-]?open|failopen|failOpen/i, rel(file));
  }
  const types = code(path.join(root, "defense", "core", "types.ts"));
  assert.match(types, /export type FailurePolicy = "fail_closed";/);
  assert.doesNotMatch(types, /LayerOutcome[^;]*degraded/);
});

test("the defense path performs no durable or synchronous file I/O (authoritative measurement lives outside it)", () => {
  for (const file of defenseFiles) {
    assert.doesNotMatch(code(file), /from\s+["']node:fs(?:\/promises)?["']|require\(["']node:fs|\bfsync|\bwriteFileSync|\bappendFileSync|\bwriteSync\b/, rel(file));
  }
});

test("the plane never spawns or reaches other processes and has no network control surface beyond its one listener", () => {
  for (const file of defenseFiles) assert.doesNotMatch(code(file), /node:child_process|node:cluster|node:worker_threads|node:dgram|node:dns/, rel(file));
  const main = code(path.join(root, "defense", "plane", "main.ts"));
  assert.match(main, /process\.send/);
  assert.doesNotMatch(main, /createServer|node:http|node:net/, "main.ts only wires IPC to the front; the front owns the single loopback listener");
});

test("every listener binds 127.0.0.1 only", () => {
  for (const file of defenseFiles) for (const match of code(file).matchAll(/\.listen\(([^)]+)\)/g)) assert.match(match[1], /127\.0\.0\.1/, `${rel(file)}: listen(${match[1]})`);
});

test("the front forwards only to a loopback upstream chosen at construction (no request-derived host)", () => {
  const front = code(path.join(root, "defense", "plane", "front.ts"));
  assert.match(front, /host: upstream\.host, port: upstream\.port/);
  assert.doesNotMatch(front, /req\.headers\.host|headers\["host"\]|new URL\(req/);
});

// ---------------------------------------------------------------------------
// BA0 Slice 2: key custody, issuing authority and the closed control surface
// ---------------------------------------------------------------------------

const slice2Defense = defenseFiles.filter((file) => /^defense\/(boundary\/|origin\/app-|core\/hop-|core\/replay-guard|core\/semantic-request|core\/lineage|plane\/semantic-gate)/.test(rel(file)));
const inLabAndDefense = [...defenseFiles, ...labDefenseFiles];

test("Slice 2: the new defense files exist and are covered by every static rule above (no fs, no child processes, loopback listeners only)", () => {
  assert.ok(slice2Defense.length >= 12, `saw ${slice2Defense.length}`);
});

test("Slice 2: defense/ has no minting capability: no `mint*` identifier, no test-only issuing path, and the oracle lives only under lab/", () => {
  // (Slice 1's `mintNonce` makes an opaque CORRELATION id for a request that arrived without one; it is not a proof and signs nothing.)
  for (const file of defenseFiles) assert.doesNotMatch(code(file), /\bmint(?:Pb|Ba|Chain|Proof|Credential|Hop)\w*|\w*ForTest\b|\b(?:const|let|var|function|class)\s+\w*[oO]racle\w*/, rel(file));
  const oracle = labDefenseFiles.filter((file) => /\bmint(?:Pb|Ba)\(\s*spec\s*:/.test(code(file))).map(rel);
  assert.deepEqual(oracle, ["lab/defense/hop-keys.ts"], "proof minting for arbitrary facts exists in exactly one lab file");
});

test("Slice 2: the issuers have exactly one production call site each, and the VerifiedPb seal is called from nowhere but the admission", () => {
  const callers = (needle: RegExp) => inLabAndDefense.filter((file) => needle.test(code(file))).map(rel).sort();
  assert.deepEqual(callers(/\bissuePb\(/), ["defense/core/hop-proof.ts", "defense/plane/main.ts"]);
  assert.deepEqual(callers(/\bissueBa\(/), ["defense/boundary/boundary.ts", "defense/core/hop-proof.ts"]);
  assert.deepEqual(callers(/\bsealVerifiedPb\(/), ["defense/core/hop-admission.ts", "defense/core/hop-proof.ts"]);
  assert.deepEqual(callers(/approvedRegistry\.add\(/), ["defense/core/semantic-request.ts"], "an ApprovedRequest is minted in exactly one place");
  assert.deepEqual(callers(/\bbuildApprovedRequest\(/), ["defense/core/semantic-request.ts", "defense/plane/front.ts", "defense/plane/semantic-gate.ts"]);
});

test("Slice 2: private keys are never delivered by env, argv or file, and the App process and App guard hold no private key at all", () => {
  for (const file of slice2Defense.concat(defenseFiles.filter((candidate) => rel(candidate) === "defense/plane/main.ts"))) {
    assert.doesNotMatch(code(file), /process\.env|process\.argv|readFile|createReadStream/, rel(file));
  }
  for (const file of defenseFiles.filter((candidate) => /^defense\/origin\/app-(guard|main|protocol)\.ts$/.test(rel(candidate)))) {
    assert.doesNotMatch(code(file), /createPrivateKey|importPrivateKey|privateKey|PKCS8|pkcs8|issuePb|issueBa|edSign|\bsign\(/, `${rel(file)} must not touch a private key`);
  }
  const boundary = defenseFiles.filter((candidate) => rel(candidate).startsWith("defense/boundary/")).map(code).join("\n");
  assert.doesNotMatch(boundary, /privateKeyP|privateP|keyP\.private|boundaryId.*privateKey/, "the boundary is never given K_P's private half");
});

test("Slice 2: the boundary and the app depend on nothing from the Defense Plane, and have no input from its liveness", () => {
  for (const file of defenseFiles.filter((candidate) => /^defense\/(boundary|origin)\//.test(rel(candidate)))) {
    const text = code(file);
    for (const specifier of [...text.matchAll(/from\s+["']([^"']+)["']/g)].map((match) => match[1])) assert.doesNotMatch(specifier, /\/plane\/|^\.\/front|semantic-gate/, `${rel(file)}: ${specifier}`);
    assert.doesNotMatch(text, /\bplane\b/i, `${rel(file)} must not reference the plane (no liveness input, no heartbeat, no mode switch)`);
  }
});

test("Slice 2: there is no pass-through, unauthenticated mode, mode switch or health route in the boundary, the hop modules or the app guard", () => {
  for (const file of slice2Defense) {
    assert.doesNotMatch(code(file), /pass[-_ ]?through|unauthenticated[-_ ]?mode|allowAll|skipAuth|disableAuth|\bhealth\b|degraded/i, rel(file));
  }
  const boundary = code(path.join(root, "defense", "boundary", "boundary.ts"));
  assert.doesNotMatch(boundary, /req\.url === ["']\/|url === ["']\//, "the boundary routes nothing: it has no path-specific behaviour");
});

test("Slice 2: the control surfaces are closed: the boundary takes only init/ack/fin/stop, the app only init/ack/fault/fin/stop, and nothing in them signs", () => {
  // A control union is `Init | { type: "x" } | ...`: the init message is a named type, the rest are inline members.
  const unionOf = (file: string, name: string, init: string): string[] => {
    const text = code(path.join(root, file));
    const block = new RegExp(`export type ${name} =([\\s\\S]*?);\\r?\\n\\r?\\n`).exec(text)?.[1] ?? "";
    assert.ok(block.includes(init), `${name} includes ${init}`);
    return [...block.matchAll(/type: "([a-z_]+)"/g)].map((match) => match[1]).sort();
  };
  assert.deepEqual(unionOf("defense/boundary/protocol.ts", "BoundaryControl", "BoundaryInit"), ["ack", "fin", "stop"], "plus init");
  assert.deepEqual(unionOf("defense/origin/app-protocol.ts", "AppControl", "AppInit"), ["ack", "fault", "fin", "stop"], "plus init");
  for (const file of ["defense/boundary/protocol.ts", "defense/origin/app-protocol.ts", "defense/plane/protocol.ts"]) {
    assert.doesNotMatch(code(path.join(root, file)), /mint|issueProof|signRequest|signFacts/i, file);
  }
  const boundaryMain = code(path.join(root, "defense", "boundary", "main.ts"));
  assert.doesNotMatch(boundaryMain, /createServer|node:http|node:net/, "main.ts only wires IPC; boundary.ts owns the single loopback listener");
  assert.match(boundaryMain, /process\.send/);
  assert.match(boundaryMain, /process\.on\("disconnect", \(\) => process\.exit\(1\)\)/, "the harness is gone: stop listening, never fall back");
  const appMain = code(path.join(root, "defense", "origin", "app-main.ts"));
  assert.doesNotMatch(appMain, /createServer|node:http|node:net/);
  assert.match(appMain, /process\.on\("disconnect", \(\) => process\.exit\(1\)\)/);
  const planeFault = /\{ type: "fault"; kind: "throw" \| "hang" \| "sign"; remaining: number \}/.test(code(path.join(root, "defense", "plane", "protocol.ts")));
  assert.ok(planeFault, "the plane's only new control is a test-only signer FAILURE (never a signing request)");
});

test("Slice 2: the boundary forwards to one fixed loopback app port chosen at construction, never a request-derived host", () => {
  const boundary = code(path.join(root, "defense", "boundary", "boundary.ts"));
  assert.match(boundary, /host: upstream\.host, port: upstream\.port/);
  assert.match(boundary, /host: "127\.0\.0\.1" as const/);
  assert.doesNotMatch(boundary, /req\.headers\.host|headers\["host"\]|new URL\(req/);
});

test("Slice 2: the lab:ba0:origin script runs exactly its runner, and lab:ba0 still runs exactly the Slice-1 runner", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.match(manifest.scripts["lab:ba0:origin"], /^tsx --conditions=react-server lab\/defense\/ba0-origin-run\.ts$/);
  assert.match(manifest.scripts["lab:ba0"], /^tsx --conditions=react-server lab\/defense\/ba0-run\.ts$/);
});

test("Slice 2: the Slice-1 runner and evidence shape are untouched by Slice 2 (it never mentions the boundary, the app process or any hop proof)", () => {
  const slice1 = readFileSync(path.join(root, "lab", "defense", "ba0-run.ts"), "utf8");
  assert.doesNotMatch(slice1, /boundary|hop-keys|origin-processes|enableOriginStreams|APP-NON-BYPASS/i);
  const plane = readFileSync(path.join(root, "lab", "defense", "plane-process.ts"), "utf8");
  assert.doesNotMatch(plane, /boundary|hop/i);
});
