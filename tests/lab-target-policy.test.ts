import assert from "node:assert/strict";
import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { test } from "node:test";
import {
  BUILTIN_TARGETS, LAB_PATH_CATALOGUE, PolicyRefusal, applyCliLimits, assertLabContainer, authorizeManagedPostgresRun, authorizeRun, buildRegistry, checkPath,
  isAuthorizedRequest, parseStrictPositiveInteger, validateTargetDefinition, type LabTarget, type PolicyRefusalCode,
} from "../lab/policy/target-policy";
import { WORKLOADS } from "../lab/policy/workloads";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadOperatorTargets, parseArguments } from "../lab/run";

const NOW = new Date("2030-01-01T00:00:00.000Z");
const registry = buildRegistry([], NOW);

function refusal(code: PolicyRefusalCode) {
  return (error: unknown) => error instanceof PolicyRefusal && error.code === code;
}

const remote = (overrides: Record<string, unknown> = {}) => ({
  id: "sut-test", class: "lab-remote", scheme: "http", host: "203.0.113.7", port: 3000,
  allowedPaths: ["/", "/gizlilik"], allowedMethods: ["GET"], expiresAt: "2030-01-02T00:00:00Z", disposable: true, ...overrides,
});

// ---------------------------------------------------------------------------------------------
// Live LimitMark hosts
// ---------------------------------------------------------------------------------------------
const liveHosts = [
  "limitmark.com", "www.limitmark.com", "admin.limitmark.com", "admission-rpc.limitmark.com", "LIMITMARK.COM", "limitmark.com.",
  "deep.sub.limitmark.com", "admission-rpc.example.test", "foo.admission-rpc.internal",
];

test("live LimitMark hosts can never be a target, whatever class or method is requested", () => {
  for (const host of liveHosts) {
    for (const klass of ["lab-local", "lab-remote"]) {
      assert.throws(() => validateTargetDefinition(remote({ class: klass, host, ...(klass === "lab-local" ? { expiresAt: undefined, disposable: undefined } : {}) }), NOW), refusal("target-live-limitmark"), `${host}/${klass}`);
    }
  }
});

test("a forged registry entry for a live host is still refused by authorizeRun for every workload and method", () => {
  const forged = new Map(registry);
  for (const host of liveHosts) {
    forged.set("forged-live", Object.freeze({
      id: "forged-live", class: "lab-local", scheme: "https", host, port: 443, allowedPaths: LAB_PATH_CATALOGUE, allowedMethods: ["GET", "POST"], origin: `https://${host}:443`,
    }) as unknown as LabTarget);
    for (const workload of Object.values(WORKLOADS)) {
      assert.throws(() => authorizeRun({ targetId: "forged-live", workloadId: workload.id, registry: forged, now: NOW, treeIsClean: true }), refusal("target-live-limitmark"));
    }
  }
});

test("POST is impossible for live hosts and for every non-demo path on lab hosts", () => {
  const run = authorizeRun({ targetId: "local-app", workloadId: "demo-submission-post", registry, now: NOW });
  assert.equal(run.authorizeRequest("POST", "/api/public-inquiries").method, "POST");
  for (const path of ["/", "/gizlilik", "/test-talep-et", "/api/cron/process-notifications"]) {
    assert.throws(() => run.authorizeRequest("POST", path));
  }
  const get = authorizeRun({ targetId: "local-app", workloadId: "burst", registry, now: NOW });
  assert.throws(() => get.authorizeRequest("POST", "/api/public-inquiries"), refusal("method-forbidden"));
  for (const method of ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT", "get", ""]) {
    assert.throws(() => get.authorizeRequest(method as "GET", "/"), refusal("method-forbidden"), method);
  }
});

// ---------------------------------------------------------------------------------------------
// Provider infrastructure
// ---------------------------------------------------------------------------------------------
test("Cloudflare, Vercel, Google and Resend infrastructure can never be a target", () => {
  const hostnames = [
    "www.cloudflare.com", "x.workers.dev", "bucket.r2.cloudflarestorage.com", "app.pages.dev", "limitmark-abc.vercel.app", "cname.vercel-dns.com",
    "storage.googleapis.com", "compute.googleapis.com", "www.google.com", "svc.run.app", "x.appspot.com", "1.2.3.4.bc.googleusercontent.com", "api.resend.com",
  ];
  for (const host of hostnames) assert.throws(() => validateTargetDefinition(remote({ host }), NOW), refusal("target-provider-infrastructure"), host);
  for (const host of ["104.16.1.1", "172.67.5.5", "1.1.1.1", "76.76.21.21", "8.8.8.8", "173.245.48.1", "198.41.200.1"]) {
    assert.throws(() => validateTargetDefinition(remote({ host }), NOW), refusal("target-provider-infrastructure"), host);
  }
});

test("remote targets must be explicit public/private IPv4 literals, never loopback, link-local or a DNS name", () => {
  for (const host of ["example.test", "localhost", "[::1]", "::1", "169.254.169.254", "127.0.0.2", "0.0.0.0", "224.0.0.1", "255.255.255.255", "100.64.0.1", "203.0.113.7.evil.test", "203.0.113", "0203.0.113.7", "203.0.113.256"]) {
    assert.throws(() => validateTargetDefinition(remote({ host }), NOW), refusal("target-address-forbidden"), host);
  }
  assert.equal(validateTargetDefinition(remote(), NOW).origin, "http://203.0.113.7:3000");
});

test("local targets are loopback literals only", () => {
  for (const host of ["localhost", "0.0.0.0", "192.168.1.5", "203.0.113.7", "example.test"]) {
    assert.throws(() => validateTargetDefinition({ ...remote({ host }), class: "lab-local", expiresAt: undefined, disposable: undefined }, NOW), refusal("target-address-forbidden"), host);
  }
});

test("a remote definition needs disposable:true, a future expiry within 72 h, scheme, port, reviewed paths and no unknown fields", () => {
  assert.throws(() => validateTargetDefinition(remote({ disposable: false }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ disposable: undefined }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ expiresAt: undefined }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ expiresAt: "2029-12-31T00:00:00Z" }), NOW), refusal("target-expired"));
  assert.throws(() => validateTargetDefinition(remote({ expiresAt: "2030-01-05T00:00:00Z" }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ expiresAt: "tomorrow" }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ scheme: undefined }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ scheme: "ftp" }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ port: undefined }), NOW), refusal("target-definition-invalid"));
  for (const port of [0, 70000, 3000.5, "3000", -1]) assert.throws(() => validateTargetDefinition(remote({ port }), NOW), refusal("target-definition-invalid"), String(port));
  assert.throws(() => validateTargetDefinition(remote({ allowedPaths: ["/anything-else"] }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ allowedPaths: ["/api/cron/process-notifications"] }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ allowedMethods: ["GET", "DELETE"] }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ allowedMethods: ["POST"] }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ extra: "x" }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(remote({ id: "Bad Id" }), NOW), refusal("target-definition-invalid"));
  assert.throws(() => validateTargetDefinition(null, NOW), refusal("target-definition-invalid"));
  assert.throws(() => buildRegistry([remote(), remote()], NOW), refusal("target-definition-invalid"));
  assert.throws(() => buildRegistry([{ ...remote(), id: "local-app" }], NOW), refusal("target-definition-invalid"));
});

test("a target that expires between registry load and run is refused, and remote runs need a clean tree", () => {
  const withRemote = buildRegistry([remote()], NOW);
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "burst", registry: withRemote, now: NOW }), refusal("clean-tree-required"));
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "burst", registry: withRemote, now: NOW, treeIsClean: false }), refusal("clean-tree-required"));
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "burst", registry: withRemote, now: new Date("2030-01-03T00:00:00Z"), treeIsClean: true }), refusal("target-expired"));
  assert.ok(authorizeRun({ targetId: "sut-test", workloadId: "burst", registry: withRemote, now: NOW, treeIsClean: true }));
});

test("failure workloads are refused against a remote target", () => {
  const withRemote = buildRegistry([remote()], NOW);
  assert.throws(() => authorizeRun({ targetId: "sut-test", workloadId: "app-restart", registry: withRemote, now: NOW, treeIsClean: true }), refusal("workload-local-only"));
  assert.throws(() => authorizeRun({ targetId: "local-app", workloadId: "postgres-outage", registry, now: NOW }));
  assert.throws(() => authorizeManagedPostgresRun("burst"), refusal("workload-unknown"));
  assert.ok(authorizeManagedPostgresRun("postgres-outage"));
});

// ---------------------------------------------------------------------------------------------
// admission-rpc / cron / traversal
// ---------------------------------------------------------------------------------------------
test("cron, admission-rpc and admin endpoints are never targetable, in any spelling", () => {
  for (const path of ["/api/cron/process-notifications", "/api/cron", "/api/CRON/x", "/v1/pre", "/v1/post", "/v1", "/admin", "/ADMIN/inquiries", "/admin/inquiries/1"]) {
    assert.throws(() => checkPath(path), refusal("path-denied-endpoint"), path);
  }
  const run = authorizeRun({ targetId: "local-app", workloadId: "latency-measurement", registry, now: NOW });
  for (const path of ["/api/cron/process-notifications", "/v1/pre", "/v1/post", "/admin"]) assert.throws(() => run.authorizeRequest("GET", path), refusal("path-denied-endpoint"));
});

test("paths with traversal, encoding, query, fragment, backslash or doubled slashes are refused", () => {
  for (const path of ["", "x", "/%2e%2e/admin", "/a/../api/cron", "/./", "//", "/a//b", "/?x=1", "/#f", "/\\admin", "/%61dmin", "/gizlilik?x", "/İ", "/ ", "/" + "a".repeat(200), "/\u0000"]) {
    assert.throws(() => checkPath(path), (error) => error instanceof PolicyRefusal, JSON.stringify(path));
  }
  const run = authorizeRun({ targetId: "local-app", workloadId: "latency-measurement", registry, now: NOW });
  assert.throws(() => run.authorizeRequest("GET", "/not-in-the-allowlist"), refusal("path-forbidden"));
  assert.throws(() => run.authorizeRequest("GET", "/api/public-inquiries"), refusal("path-forbidden"));
});

test("unknown targets and workloads are refused", () => {
  for (const targetId of ["", "nope", "LOCAL-APP", "local-app ", "127.0.0.1", "http://127.0.0.1:3000", "limitmark.com", "__proto__", "constructor"]) {
    assert.throws(() => authorizeRun({ targetId, workloadId: "burst", registry, now: NOW }), refusal("target-unknown"), targetId);
  }
  for (const workloadId of ["", "nope", "__proto__", "toString", "burst; rm -rf"]) {
    assert.throws(() => authorizeRun({ targetId: "local-app", workloadId, registry, now: NOW }), refusal("workload-unknown"), workloadId);
  }
});

// ---------------------------------------------------------------------------------------------
// Refusal happens before any network activity
// ---------------------------------------------------------------------------------------------
test("every refusal path performs zero network activity", () => {
  const calls: string[] = [];
  const originals = { http: http.request, https: https.request, connect: net.Socket.prototype.connect, lookup: dns.lookup, resolve: dns.resolve };
  http.request = ((...args: unknown[]) => { calls.push("http.request"); void args; throw new Error("network"); }) as typeof http.request;
  https.request = ((...args: unknown[]) => { calls.push("https.request"); void args; throw new Error("network"); }) as typeof https.request;
  net.Socket.prototype.connect = function () { calls.push("socket.connect"); throw new Error("network"); } as typeof net.Socket.prototype.connect;
  dns.lookup = ((...args: unknown[]) => { calls.push("dns.lookup"); void args; throw new Error("network"); }) as unknown as typeof dns.lookup;
  dns.resolve = ((...args: unknown[]) => { calls.push("dns.resolve"); void args; throw new Error("network"); }) as unknown as typeof dns.resolve;
  try {
    const attempts: (() => unknown)[] = [
      () => authorizeRun({ targetId: "nope", workloadId: "burst", registry, now: NOW }),
      () => authorizeRun({ targetId: "local-app", workloadId: "nope", registry, now: NOW }),
      () => authorizeRun({ targetId: "local-app", workloadId: "burst", registry, now: NOW, limits: { maxRate: 101 } }),
      () => validateTargetDefinition(remote({ host: "limitmark.com" }), NOW),
      () => validateTargetDefinition(remote({ host: "104.16.0.1" }), NOW),
      () => validateTargetDefinition(remote({ host: "evil.example.test" }), NOW),
      () => checkPath("/api/cron/process-notifications"),
      () => parseArguments(["--url", "http://example.test"]),
      () => parseArguments(["--target=local-app"]),
      () => authorizeRun({ targetId: "sut-test", workloadId: "app-restart", registry: buildRegistry([remote()], NOW), now: NOW, treeIsClean: true }),
    ];
    for (const attempt of attempts) assert.throws(attempt, (error) => error instanceof PolicyRefusal);
    // Even a successful authorization is pure: it opens no socket.
    authorizeRun({ targetId: "local-app", workloadId: "burst", registry, now: NOW }).authorizeRequest("GET", "/");
  } finally {
    http.request = originals.http; https.request = originals.https; net.Socket.prototype.connect = originals.connect; dns.lookup = originals.lookup; dns.resolve = originals.resolve;
  }
  assert.deepEqual(calls, []);
});

test("an authorized request cannot be forged or mutated", () => {
  const run = authorizeRun({ targetId: "local-app", workloadId: "burst", registry, now: NOW });
  const real = run.authorizeRequest("GET", "/");
  assert.equal(isAuthorizedRequest(real), true);
  assert.equal(isAuthorizedRequest({ ...real }), false);
  assert.equal(isAuthorizedRequest({ method: "GET", url: "http://example.test/", targetId: "local-app", path: "/", scheme: "http", host: "example.test", port: 80 }), false);
  assert.throws(() => { (real as { url: string }).url = "http://example.test/"; });
  assert.equal(real.url, "http://127.0.0.1:3000/");
});

// ---------------------------------------------------------------------------------------------
// Caps cannot be bypassed through ordinary CLI input
// ---------------------------------------------------------------------------------------------
test("CLI limit parsing rejects every non-plain-decimal form", () => {
  for (const raw of ["1e3", "1E3", "0x10", "0b1", "-1", "+5", "0", "00", "05", "", " 5", "5 ", "5.0", "5.5", ".5", "NaN", "Infinity", "-Infinity", "1_000", "９", "9999999999", "1,000", "5;", "5\n", "true"]) {
    assert.throws(() => parseStrictPositiveInteger(raw, "--max-rate"), refusal("limit-invalid"), JSON.stringify(raw));
  }
  for (const raw of [undefined, null, 5, {}, []]) assert.throws(() => parseStrictPositiveInteger(raw, "--max-rate"), refusal("limit-invalid"));
  assert.equal(parseStrictPositiveInteger("25", "--max-rate"), 25);
});

test("limits can only be lowered; a value above the reviewed ceiling is refused, not clamped", () => {
  for (const workload of Object.values(WORKLOADS)) {
    const c = workload.ceilings;
    assert.throws(() => applyCliLimits(workload, { maxRate: c.requestsPerSecond + 1 }), refusal("limit-above-reviewed-ceiling"), workload.id);
    assert.throws(() => applyCliLimits(workload, { maxConcurrency: c.concurrency + 1 }), refusal("limit-above-reviewed-ceiling"), workload.id);
    assert.throws(() => applyCliLimits(workload, { maxDurationSeconds: c.durationSeconds + 1 }), refusal("limit-above-reviewed-ceiling"), workload.id);
    assert.throws(() => applyCliLimits(workload, { maxRate: 100_000_000 }), refusal("limit-above-reviewed-ceiling"));
    assert.throws(() => applyCliLimits(workload, { maxRate: Number.POSITIVE_INFINITY }), refusal("limit-invalid"));
    assert.throws(() => applyCliLimits(workload, { maxRate: Number.NaN }), refusal("limit-invalid"));
    assert.throws(() => applyCliLimits(workload, { maxRate: 0 }), refusal("limit-invalid"));
    assert.throws(() => applyCliLimits(workload, { maxConcurrency: -3 }), refusal("limit-invalid"));
    const lowered = applyCliLimits(workload, { maxRate: 1, maxConcurrency: 1 });
    assert.ok(lowered.phases.every((phase) => phase.ratePerSecond === 1 && phase.concurrency === 1));
    const planned = lowered.phases.reduce((sum, phase) => sum + phase.durationSeconds * phase.ratePerSecond, 0);
    assert.ok(lowered.maxTotalRequests <= planned && lowered.maxTotalRequests <= c.totalRequests);
  }
});

test("environment variables cannot change the limits", () => {
  const before = JSON.stringify(applyCliLimits(WORKLOADS.burst, {}));
  const keys = ["LAB_MAX_RATE", "LAB_MAX_CONCURRENCY", "LAB_MAX_DURATION", "MAX_RATE", "RATE", "CONCURRENCY", "DURATION", "K6_VUS", "K6_DURATION", "LAB_TARGET", "TARGET_URL", "BASE_URL"];
  for (const key of keys) process.env[key] = "999999";
  try {
    assert.equal(JSON.stringify(applyCliLimits(WORKLOADS.burst, {})), before);
    assert.equal(authorizeRun({ targetId: "local-app", workloadId: "burst", registry, now: NOW }).target.origin, "http://127.0.0.1:3000");
  } finally { for (const key of keys) delete process.env[key]; }
});

test("the CLI accepts no URL, host, port, path, method, header or inline value", () => {
  const bad: string[][] = [
    ["--url", "http://127.0.0.1:3000"], ["--host", "127.0.0.1"], ["--port", "3000"], ["--path", "/"], ["--method", "POST"], ["--header", "x:y"],
    ["--base-url", "http://x"], ["--targets-file", "other.json"], ["--target=local-app"], ["--workload=burst"], ["local-app"], ["-t", "local-app"],
    ["--target", "local-app", "--target", "local-app-alt"], ["--target"], ["--target", "--workload", "burst"], ["--max-rate", "1e9"],
    ["--k6-options", "{}"], ["--vus", "1000"], ["--rps", "1000"],
  ];
  for (const argv of bad) assert.throws(() => parseArguments(argv), (error) => error instanceof PolicyRefusal, argv.join(" "));
  const ok = parseArguments(["--target", "local-app", "--workload", "burst", "--max-rate", "5", "--manage-app", "--dry-run"]);
  assert.deepEqual([ok.target, ok.workload, ok.limits.maxRate, ok.manageApp, ok.dryRun], ["local-app", "burst", 5, true, true]);
});

test("built-in targets are loopback fixtures with no real address", () => {
  for (const target of BUILTIN_TARGETS) {
    assert.equal(target.class, "lab-local");
    assert.equal(target.host, "127.0.0.1");
    assert.equal(target.scheme, "http");
  }
});

test("a shorter duration clips single-phase workloads; multi-phase workloads refuse it", () => {
  const clipped = applyCliLimits(WORKLOADS["sustained-soak"], { maxDurationSeconds: 120 });
  assert.deepEqual(clipped.phases.map((phase) => phase.durationSeconds), [120]);
  assert.equal(clipped.maxDurationSeconds, 120);
  assert.equal(clipped.maxTotalRequests, 120 * 20);
  for (const id of ["controlled-concurrency", "burst", "timeout-behaviour", "app-restart", "postgres-outage"] as const) {
    assert.throws(() => applyCliLimits(WORKLOADS[id], { maxDurationSeconds: 10 }), refusal("limit-invalid"), id);
    assert.ok(applyCliLimits(WORKLOADS[id], { maxDurationSeconds: WORKLOADS[id].ceilings.durationSeconds }), id);
  }
});

test("the PostgreSQL workload cannot be authorized as an HTTP run", () => {
  assert.throws(() => authorizeRun({ targetId: "local-app", workloadId: "postgres-outage", registry, now: NOW }), refusal("workload-local-only"));
});

test("only lab-created containers (name prefix and disposable label) may be controlled", () => {
  assertLabContainer("limitmark-lab-pg16", { "limitmark.lab": "disposable" });
  for (const [name, labels] of [
    ["postgres", { "limitmark.lab": "disposable" }], ["prod-db", { "limitmark.lab": "disposable" }], ["limitmark-lab-", { "limitmark.lab": "disposable" }],
    ["limitmark-lab-pg16", {}], ["limitmark-lab-pg16", { "limitmark.lab": "production" }], ["xlimitmark-lab-pg16", { "limitmark.lab": "disposable" }],
    ["limitmark-lab-pg16;rm", { "limitmark.lab": "disposable" }],
  ] as [string, Record<string, string>][]) {
    assert.throws(() => assertLabContainer(name, labels), refusal("target-unknown"), name);
  }
});

test("the operator targets file may define lab-remote targets only (no file-defined loopback forwarders)", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "lab-targets-"));
  try {
    const write = (value: unknown) => { const file = path.join(dir, "targets.json"); writeFileSync(file, JSON.stringify(value)); return file; };
    assert.deepEqual(loadOperatorTargets(path.join(dir, "missing.json")), []);
    assert.equal(loadOperatorTargets(write([remote()])).length, 1);
    assert.throws(() => loadOperatorTargets(write([{ ...remote(), class: "lab-local", host: "127.0.0.1", expiresAt: undefined, disposable: undefined }])), refusal("target-definition-invalid"));
    assert.throws(() => loadOperatorTargets(write([remote(), { id: "tunnel", class: "lab-local", scheme: "http", host: "127.0.0.1", port: 8443, allowedPaths: ["/"], allowedMethods: ["GET", "POST"] }])), refusal("target-definition-invalid"));
    assert.throws(() => loadOperatorTargets(write({ not: "an array" })), refusal("target-definition-invalid"));
    assert.throws(() => loadOperatorTargets(write([null])), refusal("target-definition-invalid"));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
