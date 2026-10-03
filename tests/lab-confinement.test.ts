import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { after, test } from "node:test";
import {
  DockerEndpointRefusal, assertNoAmbientDockerSelection, assertPublishedOnLoopbackOnly, dockerCliEnvironment, isLocalDockerEndpoint, resolveLocalDockerEndpoint,
  type ContainerFacts,
} from "../lab/host/docker";
import { LocalApp, killTrackedTreesSync, killTreeSync, trackChildTree, trackedChildTrees, untrackChildTree } from "../lab/host/local-app";
import { DRAIN_GRACE_MS, SETUP_ALLOWANCE_MS, executeHttpWorkload } from "../lab/load/engine";
import { PROXY_VARIABLES, assertK6ContainerConfinement, k6CreateArguments } from "../lab/load/k6";
import { checkDestinationProof, parseArguments } from "../lab/run";
import {
  PolicyRefusal, assertLabContainer, authorizeRun, buildRegistry, type AuthorizedRun, type EffectiveLimits, type PolicyRefusalCode,
} from "../lab/policy/target-policy";
import { THRESHOLD_SETS, type HttpThresholds } from "../lab/policy/thresholds";

const refusal = (code: PolicyRefusalCode) => (error: unknown) => error instanceof PolicyRefusal && error.code === code;

// ------------------------------------------------------------------------------------------------ Docker daemon selection
test("F2: only the local sockets/named pipes the lab expects count as a local Docker daemon", () => {
  for (const host of ["unix:///var/run/docker.sock", "unix:///run/docker.sock", "unix:///run/user/1000/docker.sock", "npipe:////./pipe/docker_engine", "npipe:////./pipe/dockerDesktopLinuxEngine"]) {
    assert.equal(isLocalDockerEndpoint(host), true, host);
  }
  for (const host of [
    "tcp://127.0.0.1:2375", "tcp://localhost:2376", "tcp://203.0.113.9:2376", "ssh://root@203.0.113.9", "http://127.0.0.1:2375", "unix:///tmp/forwarded-remote.sock", "unix:///var/run/docker.sock/../x",
    "unix://var/run/docker.sock", "npipe:////./pipe/other_engine", "npipe:////remote/pipe/docker_engine", "fd://", "", "unix:///var/run/docker.sock.evil",
  ]) assert.equal(isLocalDockerEndpoint(host), false, host);
});

test("F2: an ambient DOCKER_HOST / DOCKER_CONTEXT / TLS selector makes the wrapper refuse instead of following it", () => {
  for (const name of ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]) {
    assert.throws(() => assertNoAmbientDockerSelection({ [name]: "tcp://203.0.113.9:2376" }), DockerEndpointRefusal, name);
  }
  assert.doesNotThrow(() => assertNoAmbientDockerSelection({ DOCKER_HOST: "", PATH: "x" }));
  const scrubbed = dockerCliEnvironment({ LAB_PG_ADMIN_PASSWORD: "x" }, { PATH: "/bin", DOCKER_HOST: "tcp://203.0.113.9:2376", HTTP_PROXY: "http://proxy.invalid:3128", https_proxy: "http://proxy.invalid", NO_PROXY: "x", HOME: "/h" });
  assert.deepEqual(scrubbed, { PATH: "/bin", HOME: "/h", LAB_PG_ADMIN_PASSWORD: "x" });
});

test("F2: the daemon endpoint is read from the active context and must be a local socket; otherwise the wrapper refuses", async () => {
  const inspect = (answer: string) => async () => ({ stdout: `${answer}\n`, stderr: "" });
  assert.deepEqual(await resolveLocalDockerEndpoint({}, inspect("desktop-linux|npipe:////./pipe/dockerDesktopLinuxEngine")), { context: "desktop-linux", host: "npipe:////./pipe/dockerDesktopLinuxEngine" });
  await assert.rejects(resolveLocalDockerEndpoint({}, inspect("prod|ssh://deploy@203.0.113.9")), DockerEndpointRefusal);
  await assert.rejects(resolveLocalDockerEndpoint({}, inspect("remote|tcp://203.0.113.9:2376")), DockerEndpointRefusal);
  await assert.rejects(resolveLocalDockerEndpoint({}, inspect("weird name|unix:///var/run/docker.sock")), DockerEndpointRefusal);
  await assert.rejects(resolveLocalDockerEndpoint({}, inspect("|")), DockerEndpointRefusal);
  await assert.rejects(resolveLocalDockerEndpoint({ DOCKER_HOST: "tcp://203.0.113.9:2376" }, inspect("default|unix:///var/run/docker.sock")), DockerEndpointRefusal);
});

// ------------------------------------------------------------------------------------------------ labels, not names
test("F2: container ownership is the daemon's labels, not a name prefix", () => {
  assertLabContainer("limitmark-lab-pg16", { "limitmark.lab": "disposable", "limitmark.lab.role": "postgres" }, "postgres");
  assertLabContainer("limitmark-lab-app", { "limitmark.lab": "disposable" });
  // A name that merely starts with the prefix is refused without the label...
  assert.throws(() => assertLabContainer("limitmark-lab-evil", {}), refusal("target-unknown"));
  assert.throws(() => assertLabContainer("limitmark-lab-evil", { "limitmark.lab": "production" }), refusal("target-unknown"));
  // ...and the right label on a different ROLE is refused when a role is required (a postgres container is not an app donor).
  assert.throws(() => assertLabContainer("limitmark-lab-pg16", { "limitmark.lab": "disposable", "limitmark.lab.role": "postgres" }, "app"), refusal("target-unknown"));
  assert.throws(() => assertLabContainer("limitmark-lab-app", { "limitmark.lab": "disposable" }, "app"), refusal("target-unknown"));
  // The label alone does not rescue a foreign name.
  assert.throws(() => assertLabContainer("someone-elses-db", { "limitmark.lab": "disposable", "limitmark.lab.role": "postgres" }, "postgres"), refusal("target-unknown"));
});

const facts = (overrides: Partial<ContainerFacts> = {}): ContainerFacts => ({
  id: "a".repeat(64), name: "limitmark-lab-k6-0123456789ab", image: "grafana/k6:latest", running: true,
  labels: { "limitmark.lab": "disposable", "limitmark.lab.role": "k6" }, ports: {}, env: ["PATH=/usr/bin", ...PROXY_VARIABLES.map((name) => `${name}=${name.toUpperCase() === "NO_PROXY" ? "*" : ""}`)], networkMode: `container:${"b".repeat(64)}`, ...overrides,
});

test("F2 regression: Docker's automatic proxy injection into the k6 container is detected and refused", () => {
  const expected = { image: "grafana/k6:latest", netnsContainerId: "b".repeat(64) };
  assert.doesNotThrow(() => assertK6ContainerConfinement(facts(), expected));
  // What the docker CLI does with a `proxies` section in its config: it adds these when the caller did not set them.
  for (const injected of ["HTTP_PROXY=http://127.0.0.1:3128", "http_proxy=http://proxy.invalid:8080", "HTTPS_PROXY=http://proxy.invalid", "https_proxy=http://p", "ALL_PROXY=socks5://p", "FTP_PROXY=http://p", "NO_PROXY=localhost"]) {
    const name = injected.split("=")[0];
    const env = facts().env.filter((entry) => !entry.startsWith(`${name}=`)).concat(injected);
    assert.throws(() => assertK6ContainerConfinement(facts({ env }), expected), refusal("target-unknown"), injected);
  }
  // Wrong network, host network, wrong labels / role / image are refused too.
  assert.throws(() => assertK6ContainerConfinement(facts({ networkMode: "host" }), expected), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ networkMode: `container:${"c".repeat(64)}` }), expected), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ networkMode: "bridge" }), expected), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ labels: { "limitmark.lab": "disposable" } }), expected), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ image: "evil/k6:latest" }), expected), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ networkMode: "host" }), { image: "grafana/k6:latest" }), refusal("target-unknown"));
  assert.throws(() => assertK6ContainerConfinement(facts({ networkMode: "container:x" }), { image: "grafana/k6:latest" }), refusal("target-unknown"));
  assert.doesNotThrow(() => assertK6ContainerConfinement(facts({ networkMode: "bridge" }), { image: "grafana/k6:latest" }));
});

test("F2: the k6 container is created (not run), joins the verified donor by id, and sets every proxy variable explicitly", () => {
  const args = k6CreateArguments({ name: "limitmark-lab-k6-0123456789ab", image: "grafana/k6:latest", netnsContainerId: "b".repeat(64), planDirectory: "/p", scriptDirectory: "/s", planSha256: "d".repeat(64) });
  assert.equal(args[0], "create");
  assert.equal(args[args.indexOf("--network") + 1], `container:${"b".repeat(64)}`);
  for (const name of PROXY_VARIABLES) assert.ok(args.includes(`${name}=${name.toUpperCase() === "NO_PROXY" ? "*" : ""}`), name);
  assert.deepEqual(args.filter((_, index) => args[index - 1] === "--label"), ["limitmark.lab=disposable", "limitmark.lab.role=k6"]);
  assert.ok(args.includes("--cap-drop") && args.includes("--read-only") && args.includes("--pids-limit"));
  assert.ok(!args.includes("--rm"), "the container is removed explicitly, with verification, not by --rm");
  const bridge = k6CreateArguments({ name: "limitmark-lab-k6-0123456789ab", image: "grafana/k6:latest", planDirectory: "/p", scriptDirectory: "/s", planSha256: "d".repeat(64) });
  assert.ok(!bridge.includes("--network"));
});

// ------------------------------------------------------------------------------------------------ forwarding confinement
test("F2 regression: a local port is never an authorized destination by itself (a forwarder on 3000/3100 is not detectable by connecting)", () => {
  const base = { engine: undefined, manageApp: false, appContainer: undefined, k6Netns: undefined };
  const unproven = checkDestinationProof("lab-local", "http", base);
  assert.ok(unproven instanceof PolicyRefusal && unproven.code === "target-listener-unproven");
  assert.equal(checkDestinationProof("lab-local", "http", { ...base, manageApp: true }), null);
  assert.equal(checkDestinationProof("lab-local", "http", { ...base, appContainer: "limitmark-lab-app" }), null);
  // k6 needs its own proof: --manage-app / --app-container do not apply to it.
  assert.ok(checkDestinationProof("lab-local", "http", { ...base, engine: "k6", manageApp: true }) instanceof PolicyRefusal);
  assert.ok(checkDestinationProof("lab-local", "http", { ...base, engine: "k6", appContainer: "limitmark-lab-app" }) instanceof PolicyRefusal);
  assert.equal(checkDestinationProof("lab-local", "http", { ...base, engine: "k6", k6Netns: "limitmark-lab-app" }), null);
  // Managed workloads start their own process; remote targets are governed by the operator definition (never claimed as proven).
  assert.equal(checkDestinationProof("lab-local", "managed-app", base), null);
  assert.equal(checkDestinationProof("lab-remote", "http", base), null);
  assert.equal(parseArguments(["--target", "local-app", "--workload", "burst", "--app-container", "limitmark-lab-app"]).appContainer, "limitmark-lab-app");
});

const published = (hostIp: string, hostPort: string): ContainerFacts => facts({
  name: "limitmark-lab-app", labels: { "limitmark.lab": "disposable", "limitmark.lab.role": "app" }, ports: { "3000/tcp": [{ HostIp: hostIp, HostPort: hostPort }] },
});

test("F2: the application container must publish exactly 127.0.0.1:<port> and be running", () => {
  assert.doesNotThrow(() => assertPublishedOnLoopbackOnly(published("127.0.0.1", "3100"), 3100, 3000));
  for (const bad of [published("0.0.0.0", "3100"), published("127.0.0.1", "3101"), published("::", "3100"), published("192.0.2.1", "3100")]) {
    assert.throws(() => assertPublishedOnLoopbackOnly(bad, 3100, 3000), refusal("target-listener-unproven"));
  }
  assert.throws(() => assertPublishedOnLoopbackOnly({ ...published("127.0.0.1", "3100"), running: false }, 3100, 3000), refusal("target-listener-unproven"));
  assert.throws(() => assertPublishedOnLoopbackOnly({ ...published("127.0.0.1", "3100"), ports: {} }, 3100, 3000), refusal("target-listener-unproven"));
  assert.throws(() => assertPublishedOnLoopbackOnly({ ...published("127.0.0.1", "3100"), ports: { "3000/tcp": [{ HostIp: "127.0.0.1", HostPort: "3100" }, { HostIp: "0.0.0.0", HostPort: "3100" }] } }, 3100, 3000), refusal("target-listener-unproven"));
});

test("F2 regression: a lab-started app only counts when OUR process is alive, never because something else is listening", async () => {
  // A forwarder/stray listener occupies the lab port; a LocalApp that was never started (or whose child exited) must not accept it.
  const forwarder = net.createServer((socket) => socket.end());
  const listening = await new Promise<boolean>((resolve) => { forwarder.once("error", () => resolve(false)); forwarder.listen(3100, "127.0.0.1", () => resolve(true)); });
  try {
    const app = new LocalApp(3100);
    await assert.rejects(app.waitUntilListening(1_000), /exited before it was listening/);
  } finally { if (listening) await new Promise((resolve) => forwarder.close(resolve)); }
});

// ------------------------------------------------------------------------------------------------ authorization for the whole run
const servers: http.Server[] = [];
after(async () => { for (const server of servers) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } });

async function listen(handler: http.RequestListener) {
  let requests = 0;
  const server = http.createServer((request, response) => { requests++; handler(request, response); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push(server);
  return { port: (server.address() as AddressInfo).port, count: () => requests };
}

function runFor(port: number, phases: EffectiveLimits["phases"], extra: Partial<EffectiveLimits> = {}, clock?: () => number): AuthorizedRun {
  const now = new Date();
  const registry = buildRegistry([{ id: "lab-test", class: "lab-local", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/", "/gizlilik", "/test-talep-et"], allowedMethods: ["GET"] }], now);
  const run = authorizeRun({ targetId: "lab-test", workloadId: "latency-measurement", registry, now, clock });
  return { ...run, limits: { ...run.limits, phases, ...extra } };
}
const phase = (over: Partial<EffectiveLimits["phases"][number]> = {}) => ({ name: "p", durationSeconds: 2, ratePerSecond: 10, concurrency: 2, timeoutMs: 1000, ...over });
const lenient: HttpThresholds = { ...THRESHOLD_SETS["local-loopback-v1"].http["latency-measurement"], stop: { errorRate: 2, afterSamples: 1_000_000, consecutiveFailures: 1_000_000, p99Ms: 1e9 } };

test("F2 regression: authorization is re-checked for the whole run; a lapsed target stops dispatch immediately", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  let expired = false;
  const base = runFor(server.port, [phase({ durationSeconds: 5, ratePerSecond: 20, concurrency: 2 })], { maxTotalRequests: 1000 });
  // The authorization lapses 400 ms into the run.
  setTimeout(() => { expired = true; }, 400);
  const run: AuthorizedRun = {
    ...base,
    assertStillAuthorized: () => { if (expired) throw new PolicyRefusal("target-expired", "the target authorization expired while the run was in progress"); },
  };
  const started = Date.now();
  const result = await executeHttpWorkload({ run, thresholds: lenient });
  assert.equal(result.stopReason, "target authorization expired during the run");
  assert.ok(Date.now() - started < 2_000, "the run must end near the expiry, not at the end of the phase");
  const reached = server.count();
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(server.count(), reached, "no request may leave after the expiry");
  assert.ok(reached > 0 && reached < 40);
});

test("F2: the policy's own authorization lapses with its clock, for requests and for the run", () => {
  let clock = Date.parse("2030-01-01T00:00:00Z");
  const now = new Date(clock);
  const registry = buildRegistry([{ id: "lab-remote-1", class: "lab-remote", scheme: "http", host: "198.51.100.20", port: 3000, allowedPaths: ["/"], allowedMethods: ["GET"], expiresAt: "2030-01-01T01:00:00Z", disposable: true }], now);
  const run = authorizeRun({ targetId: "lab-remote-1", workloadId: "connectivity-baseline", registry, now, treeIsClean: true, clock: () => clock });
  assert.equal(run.authorizedUntilMs, Date.parse("2030-01-01T01:00:00Z"));
  assert.doesNotThrow(() => run.assertStillAuthorized());
  assert.doesNotThrow(() => run.authorizeRequest("GET", "/"));
  clock = Date.parse("2030-01-01T01:00:00Z");
  assert.throws(() => run.assertStillAuthorized(), refusal("target-expired"));
  assert.throws(() => run.authorizeRequest("GET", "/"), refusal("target-expired"));
  // Loopback fixtures never expire.
  const local = authorizeRun({ targetId: "local-app", workloadId: "connectivity-baseline", registry: buildRegistry([], now), now, clock: () => clock });
  assert.equal(local.authorizedUntilMs, null);
});

// ------------------------------------------------------------------------------------------------ strict deadline
test("F3: the deadline is strict: nothing is sent after it and in-flight requests are cancelled, not awaited for their full timeout", async () => {
  const hang = await listen(() => undefined);
  const started = Date.now();
  // 10 s request timeouts, a 1 s run: the old engine waited for every request's own timeout (up to 10 s).
  const result = await executeHttpWorkload({ run: runFor(hang.port, [phase({ durationSeconds: 60, ratePerSecond: 5, concurrency: 2, timeoutMs: 10_000 })], { maxDurationSeconds: 1 }), thresholds: lenient });
  const elapsed = Date.now() - started;
  assert.equal(result.stopReason, "global deadline reached");
  assert.ok(elapsed < 1_000 + SETUP_ALLOWANCE_MS + DRAIN_GRACE_MS + 1_500, `elapsed ${elapsed}ms`);
  assert.ok(elapsed < 8_000, "far below the 10 s request timeouts");
  assert.ok((result.phases[0].outcomes.aborted ?? 0) > 0, "in-flight requests are cancelled at the drain limit");
});

test("F3 (parity finding): a workload whose phase fills its whole duration budget completes (PASS path), it is not stopped by the deadline", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  // One phase of exactly the duration ceiling, plus a per-phase set-up that takes time (the container ownership re-check).
  const result = await executeHttpWorkload({
    run: runFor(server.port, [phase({ durationSeconds: 1, ratePerSecond: 4, concurrency: 1 })], { maxDurationSeconds: 1, maxTotalRequests: 4 }), thresholds: lenient,
    onPhaseStart: async () => { await new Promise((resolve) => setTimeout(resolve, 300)); },
  });
  assert.equal(result.stopReason, null);
  assert.ok(result.phases[0].attempted <= 4);
});

test("F3 regression: a 1 s phase at 2 req/s emits at most 2 requests (never rate x duration + 1)", async () => {
  let sent = 0;
  const send = async () => { sent++; return { outcome: "ok" as const, status: 200, latencyMs: 1, bytes: 1 }; };
  const result = await executeHttpWorkload({ run: runFor(1, [phase({ durationSeconds: 1, ratePerSecond: 2, concurrency: 1 })], { maxTotalRequests: 100 }), thresholds: lenient, send });
  assert.ok(sent <= 2, `sent ${sent}`);
  assert.equal(result.phases[0].attempted, sent);
});

test("F3: cancelling the run's signal cancels in-flight requests at once", async () => {
  const hang = await listen(() => undefined);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 300);
  const started = Date.now();
  const result = await executeHttpWorkload({ run: runFor(hang.port, [phase({ durationSeconds: 30, ratePerSecond: 5, concurrency: 2, timeoutMs: 10_000 })]), thresholds: lenient, signal: controller.signal });
  assert.ok(Date.now() - started < 2_000, "must not wait for the 10 s timeouts");
  assert.equal(result.aborted, true);
});

// ------------------------------------------------------------------------------------------------ F5: interruption cleanup of detached trees
test("F5: tracked process trees are killed on interruption cleanup (the group on POSIX, taskkill /T on Windows)", () => {
  const calls: string[] = [];
  trackChildTree(424242); trackChildTree(424243);
  assert.deepEqual(trackedChildTrees().sort(), [424242, 424243]);
  untrackChildTree(424243);
  killTrackedTreesSync((pid, signal) => { calls.push(`${pid}:${signal}`); }, "linux");
  assert.deepEqual(calls, ["-424242:SIGKILL"], "kill(-pid) addresses the whole detached group");
  assert.deepEqual(trackedChildTrees(), []);
  const posix: string[] = [];
  killTreeSync(77, (pid, signal) => { posix.push(`${pid}:${signal}`); }, "darwin");
  assert.deepEqual(posix, ["-77:SIGKILL"]);
  assert.doesNotThrow(() => killTreeSync(78, () => { throw new Error("ESRCH"); }, "linux"));
});

// ------------------------------------------------------------------------------------------------ round 2: ONE Docker confinement
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { bindToEndpoint, confinedDockerInvocationSync, resetDockerEndpointCache, resolveLocalDockerEndpointSync } from "../lab/host/docker";
import { collectEnvironment } from "../lab/evidence/manifest";


test("F2 round 2 regression: an ACTIVE remote context (no DOCKER_HOST / DOCKER_CONTEXT) is refused by the synchronous path too", () => {
  const inspect = (answer: string) => () => `${answer}\n`;
  assert.deepEqual(resolveLocalDockerEndpointSync({}, inspect("desktop-linux|npipe:////./pipe/dockerDesktopLinuxEngine")), { context: "desktop-linux", host: "npipe:////./pipe/dockerDesktopLinuxEngine" });
  for (const remote of ["prod|tcp://203.0.113.9:2376", "ci|ssh://deploy@203.0.113.9", "x|unix:///tmp/other.sock"]) assert.throws(() => resolveLocalDockerEndpointSync({}, inspect(remote)), DockerEndpointRefusal, remote);
  assert.throws(() => resolveLocalDockerEndpointSync({ DOCKER_HOST: "unix:///var/run/docker.sock" }, inspect("a|unix:///var/run/docker.sock")), DockerEndpointRefusal);
});

test("F2 round 2 regression: a verified invocation is bound to the ENDPOINT (--host and DOCKER_HOST), never to a context NAME that can be retargeted afterwards", () => {
  const endpoint = { context: "desktop-linux", host: "npipe:////./pipe/dockerDesktopLinuxEngine" };
  const invocation = bindToEndpoint(endpoint, ["ps", "-a"], { LAB_X: "1" }, { PATH: "/bin", DOCKER_CONTEXT: "evil", HTTP_PROXY: "http://p", DOCKER_HOST: "tcp://203.0.113.9:2375" });
  assert.deepEqual(invocation.args, ["--host", endpoint.host, "ps", "-a"]);
  assert.ok(!invocation.args.includes("--context"));
  assert.equal(invocation.env.DOCKER_HOST, endpoint.host, "plugins (compose/buildx) are pinned to the same verified endpoint");
  assert.equal(invocation.env.DOCKER_CONTEXT, undefined);
  assert.equal(invocation.env.HTTP_PROXY, undefined);
  assert.equal(invocation.env.LAB_X, "1");
});

test("F2 round 2 regression: retargeting the CLI's active context AFTER verification does not move a verified invocation; a fresh verification refuses it", () => {
  const local = { context: "desktop-linux", host: "npipe:////./pipe/dockerDesktopLinuxEngine" };
  let activeContext: { context: string; host: string } = local;
  const readActiveContext = () => resolveLocalDockerEndpointSync({}, () => `${activeContext.context}|${activeContext.host}\n`);
  resetDockerEndpointCache();
  try {
    const before = confinedDockerInvocationSync(["ps"], {}, readActiveContext);
    assert.equal(before.args[1], local.host);
    // The CLI's current context is switched to a remote daemon while the lab is running.
    activeContext = { context: "evil", host: "tcp://203.0.113.9:2375" };
    const during = confinedDockerInvocationSync(["ps"], {}, readActiveContext);
    assert.equal(during.args[1], local.host, "an invocation bound to the verified endpoint is unaffected by the switch");
    assert.equal(during.env.DOCKER_HOST, local.host);
    // Once the verification is reset (it also expires after 30 s), the remote active context is what gets examined, and it is refused.
    resetDockerEndpointCache();
    assert.throws(() => confinedDockerInvocationSync(["ps"], {}, readActiveContext), DockerEndpointRefusal);
    // ...and a refused verification is not cached as a success.
    assert.throws(() => confinedDockerInvocationSync(["ps"], {}, readActiveContext), DockerEndpointRefusal);
  } finally { resetDockerEndpointCache(); }
});

test("F2 round 2 regression: no lab file spawns docker except through the confinement (collectEnvironment and parity bypassed it)", () => {
  const root = path.join(__dirname, "..", "lab");
  const sources: string[] = [];
  const walk = (directory: string) => { for (const entry of readdirSync(directory)) { const full = path.join(directory, entry); if (statSync(full).isDirectory()) walk(full); else if (/\.(ts|mjs|js)$/.test(entry)) sources.push(full); } };
  walk(root);
  const direct = /(?:execFile|execFileSync|spawn|spawnSync|exec|execSync)\s*\(\s*["'`]docker["'`]|\brun\s*\(\s*["']docker["']/;
  for (const file of sources) {
    if (file.endsWith(path.join("host", "docker.ts"))) continue;
    assert.doesNotMatch(readFileSync(file, "utf8"), direct, `${path.relative(root, file)} starts docker outside the confinement`);
  }
  const parity = readFileSync(path.join(root, "linux", "parity.ts"), "utf8");
  assert.match(parity, /confinedDockerInvocation\(args, options\.env\)/);
  assert.match(parity, /if \(command === "docker"\)/);
  assert.match(readFileSync(path.join(root, "evidence", "manifest.ts"), "utf8"), /dockerVersion: dockerServerVersionSync\(\)/);
  // Every spawn in parity.ts uses the already-confined command line.
  assert.doesNotMatch(parity, /spawn\(command, args/);
});

test("F2 round 2: the evidence version probe never asks a daemon the lab did not verify (ambient selector => null, no process started)", () => {
  const previous = process.env.DOCKER_HOST;
  process.env.DOCKER_HOST = "tcp://203.0.113.9:2375";
  try { assert.equal(collectEnvironment().dockerVersion, null); }
  finally { if (previous === undefined) delete process.env.DOCKER_HOST; else process.env.DOCKER_HOST = previous; }
});

// ------------------------------------------------------------------------------------------------ round 2: ownership DURING a phase
import { assertSameLabAppContainer } from "../lab/host/docker";

test("F2 round 2: the lease re-checks the SAME container id, so a different container behind the same name is not the destination", () => {
  const facts = published("127.0.0.1", "3100");
  assert.doesNotThrow(() => assertSameLabAppContainer(facts, 3100, 3000, facts.id));
  assert.doesNotThrow(() => assertSameLabAppContainer(facts, 3100, 3000));
  assert.throws(() => assertSameLabAppContainer({ ...facts, id: "f".repeat(64) }, 3100, 3000, facts.id), refusal("target-listener-unproven"));
});

/** A destination whose ownership is a switch, plus a way to put a stranger on the same port (the audit's stop-container / replace-listener reproduction). */
async function replaceableDestination(options: { loseAfterMs: number }) {
  const port = await new Promise<number>((resolve) => { const probe = net.createServer(); probe.listen(0, "127.0.0.1", () => { const chosen = (probe.address() as AddressInfo).port; probe.close(() => resolve(chosen)); }); });
  let owned = true;
  const counts = { original: 0, stranger: 0, atLoss: 0 };
  let originalServer: http.Server | null = http.createServer((_request, response) => { counts.original++; response.end("ok"); });
  await new Promise<void>((resolve) => originalServer!.listen(port, "127.0.0.1", resolve));
  let strangerServer: http.Server | null = null;
  const lose = async () => {
    owned = false;
    counts.atLoss = counts.original + counts.stranger;
    // The container "stops": its listener goes away, and a forwarder (anything) takes the published port.
    const closing = originalServer; originalServer = null;
    await new Promise<void>((resolve) => { closing!.closeAllConnections(); closing!.close(() => resolve()); });
    strangerServer = http.createServer((_request, response) => { counts.stranger++; response.end("forwarded elsewhere"); });
    await new Promise<void>((resolve) => strangerServer!.listen(port, "127.0.0.1", resolve));
  };
  setTimeout(() => { void lose(); }, options.loseAfterMs);
  const verify = async () => {
    // What the real check does with the daemon's record: running + exactly this published binding + same id.
    const facts = { ...published("127.0.0.1", String(port)), running: owned };
    assertSameLabAppContainer(facts, port, 3000, facts.id);
  };
  const close = async () => { for (const server of [originalServer, strangerServer]) if (server) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); } };
  return { port, verify, counts, close };
}

test("F2 round 2 regression: authorized traffic does NOT keep flowing to a replacement listener after the destination container stops mid-phase", async () => {
  const destination = await replaceableDestination({ loseAfterMs: 600 });
  try {
    const run = runFor(destination.port, [phase({ durationSeconds: 10, ratePerSecond: 20, concurrency: 2 })], { maxTotalRequests: 1000, maxDurationSeconds: 10 });
    const started = Date.now();
    const result = await executeHttpWorkload({ run, thresholds: lenient, destination: { verify: destination.verify, intervalMs: 100, maxStaleMs: 300 } });
    assert.match(result.stopReason ?? "", /destination ownership lost/);
    assert.ok(Date.now() - started < 3_000, "the run ended near the loss, not at the end of the 10 s phase");
    assert.ok(destination.counts.original > 3, "traffic really flowed while the destination was owned");
    // Bounded, not zero: a few requests may already be in flight or dispatched before the next check notices (about interval + staleness at 20/s).
    assert.ok(destination.counts.stranger <= 20 * 0.8, `the replacement listener received ${destination.counts.stranger} requests`);
    const strangerAfterStop = destination.counts.stranger;
    await new Promise((resolve) => setTimeout(resolve, 600));
    assert.equal(destination.counts.stranger, strangerAfterStop, "nothing more is sent after the run stopped");
    // For contrast, the previous behaviour (ownership checked only before the phase) would have kept sending for the rest of the 10 s phase (~170 requests).
  } finally { await destination.close(); }
});

test("F2 round 2: a failing first check refuses before any request; a HUNG check stops dispatch and then the run", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  const refused = executeHttpWorkload({ run: runFor(server.port, [phase({ durationSeconds: 2, ratePerSecond: 10, concurrency: 1 })]), thresholds: lenient, destination: { verify: async () => { throw new PolicyRefusal("target-listener-unproven", "not running"); } } });
  await assert.rejects(refused, refusal("target-listener-unproven"));
  assert.equal(server.count(), 0, "no request before the first successful proof");

  let calls = 0;
  const hanging = await executeHttpWorkload({
    run: runFor(server.port, [phase({ durationSeconds: 10, ratePerSecond: 20, concurrency: 2 })], { maxTotalRequests: 1000, maxDurationSeconds: 10 }), thresholds: lenient,
    destination: { verify: () => (++calls === 1 ? Promise.resolve() : new Promise<void>(() => undefined)), intervalMs: 50, maxStaleMs: 200 },
  });
  assert.match(hanging.stopReason ?? "", /destination ownership/);
  const reached = server.count();
  await new Promise((resolve) => setTimeout(resolve, 400));
  assert.equal(server.count(), reached);
  assert.ok(reached <= 20 * 1.0, `sent ${reached} before the stale lease stopped dispatch`);
});

test("F2 round 2: a healthy lease does not disturb a normal run (no spurious stop, requests flow at the planned rate)", async () => {
  const server = await listen((_request, response) => response.end("ok"));
  let checks = 0;
  const result = await executeHttpWorkload({
    run: runFor(server.port, [phase({ durationSeconds: 2, ratePerSecond: 10, concurrency: 2 })], { maxTotalRequests: 100, maxDurationSeconds: 2 }), thresholds: lenient,
    destination: { verify: async () => { checks++; }, intervalMs: 100, maxStaleMs: 400 },
  });
  assert.equal(result.stopReason, null);
  assert.ok(result.phases[0].attempted >= 15 && result.phases[0].attempted <= 20, `attempted ${result.phases[0].attempted}`);
  assert.ok(checks >= 10, `${checks} checks over a 2 s run`);
});

test("F2 round 2: the runner wires the lease for --app-container with the container's captured id (not a phase-boundary check)", () => {
  const source = readFileSync(path.join(__dirname, "..", "lab", "run.ts"), "utf8");
  assert.match(source, /destination: containerGate === undefined \? undefined : \{ verify: async \(\) => \{ await verifyAppContainer\(containerGate, run\.target\.port, appContainerId\)/);
  assert.doesNotMatch(source, /onPhaseStart: args\.appContainer/);
  assert.match(source, /appContainerId = await verifyAppContainer/);
});

test("F2 round 2 (variant): variables that select a REMOTE BUILDER or re-point compose are not inherited, and the parity build names the local default builder", () => {
  const scrubbed = dockerCliEnvironment({}, { PATH: "/bin", BUILDX_BUILDER: "remote-farm", BUILDKIT_HOST: "tcp://203.0.113.9:1234", COMPOSE_FILE: "/tmp/evil.yaml", COMPOSE_PROJECT_NAME: "evil", HOME: "/h" });
  assert.deepEqual(scrubbed, { PATH: "/bin", HOME: "/h" });
  const parity = readFileSync(path.join(__dirname, "..", "lab", "linux", "parity.ts"), "utf8");
  assert.match(parity, /"build", "--builder", "default"/);
});
