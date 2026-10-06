import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";

/**
 * Field-qualification static rules: what the plane may and may not bind and expose, what the new entries are, and what the Linux-only and
 * telemetry modules may never do. Source-level facts, pinned so a later edit cannot quietly widen them.
 */
const root = path.join(__dirname, "..");
const rel = (file: string) => path.relative(root, file).replace(/\\/g, "/");
const code = (file: string) => readFileSync(path.join(root, file), "utf8").replace(/\r\n/g, "\n").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
function tsFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? tsFiles(full) : entry.name.endsWith(".ts") ? [full] : [];
  });
}
const defenseFiles = tsFiles(path.join(root, "defense")).map(rel);
const labDefenseFiles = tsFiles(path.join(root, "lab", "defense")).map(rel);

test("the Boundary, the App and the harness's control origin listen on 127.0.0.1 ONLY: no ingress option, no wildcard, in any file that can bind them", () => {
  for (const file of ["defense/boundary/boundary.ts", "defense/origin/synthetic-origin.ts"]) {
    const listens = [...code(file).matchAll(/\.listen\(([^)]+)\)/g)].map((match) => match[1]);
    assert.equal(listens.length, 1, file);
    assert.match(listens[0], /^0, "127\.0\.0\.1", /, file);
    assert.doesNotMatch(code(file), /ingress|IngressBind|validateIngressBind|peerClass/, `${file} has no public-ingress capability`);
  }
  for (const file of ["defense/boundary/main-field.ts", "defense/origin/app-main-field.ts", "defense/boundary/main.ts", "defense/origin/app-main.ts"]) {
    assert.doesNotMatch(code(file), /createServer|node:http|node:net/, `${file} only wires IPC; the listener lives in boundary.ts / synthetic-origin.ts`);
  }
});

test("no wildcard address literal exists in defense/ except the refusal list that forbids it", () => {
  for (const file of defenseFiles) {
    const text = code(file);
    if (file === "defense/core/ingress-class.ts") continue;
    assert.doesNotMatch(text, /["'`]0\.0\.0\.0["'`]|["'`]::["'`]|["'`]255\.255\.255\.255["'`]/, `${file} must not name a wildcard bind`);
  }
  assert.match(code("defense/core/ingress-class.ts"), /const WILDCARDS: readonly string\[\] = \["0\.0\.0\.0", "255\.255\.255\.255"\];/, "the one place a wildcard is named is the list that refuses it");
});

test("the plane's front is the ONLY place a public ingress or peer classification exists, and no production entry sets the test seam", () => {
  const mentions = (needle: RegExp) => defenseFiles.filter((file) => needle.test(code(file))).sort();
  assert.deepEqual(mentions(/peerClass\b/), ["defense/plane/front.ts"], "the peer-class test seam is declared and used in one file");
  for (const entry of ["defense/plane/main-l2.ts", "defense/plane/main.ts", "defense/plane/runtime.ts", "lab/defense/collapse/plane-collapse-main.ts"]) {
    assert.doesNotMatch(code(entry), /peerClass/, `${entry} never passes the test seam`);
  }
  assert.deepEqual(mentions(/validateIngressBind/), ["defense/core/ingress-class.ts", "defense/plane/front.ts"]);
  assert.match(code("defense/plane/runtime.ts"), /ingress: raw\.ingress/, "the bind comes from the harness's init message and from nothing else");
  assert.doesNotMatch(code("defense/plane/runtime.ts"), /process\.env|process\.argv/);
});

test("a remote peer is never given an internal decision: the outcome header is written only for a local peer, in every response path of the front", () => {
  const front = code("defense/plane/front.ts");
  assert.match(front, /\.\.\.\(remote \? \{\} : \{ \[OUTCOME_HEADER\]: label \}\)/);
  assert.match(front, /if \(!remote\) responseHeaders\[OUTCOME_HEADER\] = "proxied";/);
  assert.match(front, /classify\(socket as Socket\) === "local"/);
  assert.equal([...front.matchAll(/OUTCOME_HEADER/g)].length, 4, "every use of the decision header is accounted for: the import, the parser refusal, the refusal body, the proxied response");
  assert.match(front, /if \(name === NONCE_HEADER && !remote\)/, "a remote peer's nonce header is stripped like any spoofable header");
});

test("the plane runtime adds exactly the field options: an ingress bind from init, a tick timer that only observes, and the close_ingress control", () => {
  const runtime = code("defense/plane/runtime.ts");
  assert.match(runtime, /raw\.type === "close_ingress"/);
  assert.match(runtime, /front\.closeIngress\(\)/);
  assert.doesNotMatch(runtime, /ch\.emit\(.*tick|channel\.emit\(.*tick/i, "ticks are their own IPC message, not events on the bounded channel");
  assert.match(runtime, /send\(ticks!\.next\(\)\)/);
  const l2 = code("defense/plane/l2-protocol.ts");
  assert.doesNotMatch(l2, /export\s+(?:const|let|var|function|class|enum|default)\b/, "the protocol file stays types only");
  assert.doesNotMatch(l2, /\bfault\b|collapse|probe/i);
});

test("the field entries are the Slice-2 entries plus one observation-only tick: the same closed control surface, and no fault control for the App", () => {
  const boundary = code("defense/boundary/main-field.ts");
  const app = code("defense/origin/app-main-field.ts");
  assert.match(boundary, /process\.on\("disconnect", \(\) => process\.exit\(1\)\)/);
  assert.match(app, /process\.on\("disconnect", \(\) => process\.exit(1)\)|process\.on\("disconnect", \(\) => process\.exit\(1\)\)/);
  assert.deepEqual([...boundary.matchAll(/raw\.type === "([a-z_]+)"/g)].map((match) => match[1]), ["init", "ack", "fin", "stop"]);
  assert.deepEqual([...app.matchAll(/raw\.type === "([a-z_]+)"/g)].map((match) => match[1]), ["init", "ack", "fin", "stop"]);
  assert.doesNotMatch(app, /fault|armFault/, "the field App has no lab fault control");
  for (const text of [boundary, app]) assert.doesNotMatch(text, /sign\(|issuePb|issueBa|privateKeyP|createPrivateKey/);
  assert.doesNotMatch(app, /importPrivateKey|privateKey/, "the App still holds no private key");
});

test("the new defense files obey the rules of the rest of defense/: no file I/O, no child process, no environment or argv, and only their own tree and node: built-ins", () => {
  const added = defenseFiles.filter((file) => /ingress-class|core\/telemetry|main-field|field-protocol/.test(file));
  assert.equal(added.length, 6);
  for (const file of added) {
    const text = code(file);
    assert.doesNotMatch(text, /from\s+["']node:fs|node:child_process|node:cluster|node:worker_threads|node:dgram|node:dns|process\.env|process\.argv|readFile|writeFile/, file);
    for (const match of text.matchAll(/from\s+["']([^"']+)["']/g)) assert.match(match[1], /^(\.\.?\/|node:)/, `${file}: ${match[1]}`);
  }
});

test("the Linux-only /proc modules are READ-ONLY: no write, no signal, no process spawn, no socket", () => {
  for (const file of ["lab/defense/proc-net.ts", "lab/defense/exposure-proof.ts", "lab/defense/proc-sampler.ts"]) {
    assert.doesNotMatch(code(file), /writeFile|appendFile|unlink|rmSync|mkdir|\.kill\(|child_process|\bspawn|execFile|node:net|node:http|node:dgram|createServer|\.connect\(|\.listen\(/, file);
  }
  const procNet = code("lab/defense/proc-net.ts");
  assert.ok(procNet.includes("readlinkSync") && procNet.includes("from \"node:fs\""), "it reads through node:fs only");
  assert.deepEqual([...procNet.matchAll(/from "([^"]+)"/g)].map((match) => match[1]), ["node:fs", "node:path"]);
});

test("the field runner reaches the processes only through the reviewed handles, and never touches the verdict-override, collapse or fault machinery", () => {
  const runner = code("lab/defense/ba0-field-run.ts");
  assert.doesNotMatch(runner, /collapse|verdictOverride|VerdictOverride|injectFault|armFault|FaultableLayer|child_process|process\.kill|SIGKILL/, "the runner kills nothing itself and has no fault control");
  assert.match(runner, /PLANE_L2_ENTRY/, "the plane is the NORMAL Slice-3 entry (no injected dependency)");
  assert.doesNotMatch(runner, /LEGACY_ENTRY|plane-collapse-main/);
  assert.doesNotMatch(runner, /process\.env/, "no environment variable decides anything about the level");
  for (const file of labDefenseFiles.filter((candidate) => /field|external-|exposure|proc-|generator-report|reconcile/.test(candidate))) {
    assert.doesNotMatch(code(file), /process\.env\.[A-Z_]*(TARGET|HOST|URL|PORT|ADDR)/, `${file}: no target comes from the environment`);
  }
});

test("the package scripts add exactly the two field scripts, each running exactly its runner", () => {
  const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")) as { scripts: Record<string, string> };
  assert.equal(manifest.scripts["lab:ba0:field"], "tsx --conditions=react-server lab/defense/ba0-field-run.ts");
  assert.equal(manifest.scripts["lab:ba0:field:reconcile"], "tsx --conditions=react-server lab/defense/ba0-field-reconcile.ts");
  assert.equal(Object.keys(manifest.scripts).filter((name) => /^lab:ba0/.test(name)).length, 5);
});

test("the Slice-1/2/3 runners and their evidence shape are not touched by the field patch (they never mention a field module)", () => {
  for (const file of ["lab/defense/ba0-run.ts", "lab/defense/ba0-origin-run.ts", "lab/defense/ba0-collapse-run.ts"]) {
    assert.doesNotMatch(readFileSync(path.join(root, file), "utf8"), /field-|external-reducer|exposure-proof|ingress-class|closed-loop/, file);
  }
});
