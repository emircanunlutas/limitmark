import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import { test } from "node:test";
import { peerClassOf } from "../defense/core/ingress-class";
import type { PlaneEvent } from "../defense/core/ledger";
import { createSyntheticOrigin } from "../defense/origin/synthetic-origin";
import { createFront } from "../defense/plane/front";
import { proveExposure } from "../lab/defense/exposure-proof";
import { realFieldEnvironment } from "../lab/defense/field-preflight";
import { fsProcReader, listeningOnly, parseTcpTable, socketInodesOf } from "../lab/defense/proc-net";
import { ProcSampler } from "../lab/defense/proc-sampler";

/**
 * THE LINUX-ONLY VERIFICATION SUITE for the field modules: it reads a REAL /proc and uses REAL kernel socket addresses. It is skipped everywhere else,
 * and a skip is reported as a skip: it is NEVER a pass. It was NOT run on the Windows machine this patch was developed on. The disposable Linux
 * self-qualification (authorized separately) runs it:
 *
 *   npx tsx --conditions=react-server --test tests/lab-linux-field.integration.test.ts
 *
 * It opens loopback and host-local sockets only and sends no external traffic. What it still cannot cover (needs the disposable VM, root and the
 * lab bootstrap): the real `ufw status numbered` text, the systemd unit state and the DISPOSABLE marker; those checks are exercised against the
 * documented formats in `lab-ba0-field-preflight.test.ts` only.
 */
const linux = process.platform === "linux";
const skip = linux ? false : "Linux-only suite: it reads a real /proc and is NOT run on this platform (a skip, never a pass)";

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const listen = (server: net.Server, port: number, host: string): Promise<number> => new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => resolve((server.address() as net.AddressInfo).port)); });
const close = (server: net.Server): Promise<void> => new Promise((resolve) => server.close(() => resolve()));
const hostAddresses = (): string[] => Object.values(os.networkInterfaces()).flatMap((list) => (list ?? []).filter((entry) => entry.family === "IPv4" && !entry.internal).map((entry) => entry.address));

test("the real /proc parsers find a real listening socket and attribute its inode to this process", { skip }, async () => {
  const server = net.createServer();
  const port = await listen(server, 0, "127.0.0.1");
  try {
    const reader = fsProcReader();
    const entries = listeningOnly(parseTcpTable(reader.readText("/proc/net/tcp") ?? "", 4));
    const mine = entries.find((entry) => entry.port === port);
    assert.ok(mine, "the loopback listener is in /proc/net/tcp");
    assert.equal(mine.ip, "127.0.0.1");
    assert.ok(socketInodesOf(reader, process.pid)?.has(mine.inode), "its inode is one of this process's open sockets");
    assert.ok(reader.readLink(`/proc/${process.pid}/ns/net`)?.startsWith("net:["), "the network namespace is readable");
  } finally { await close(server); }
});

test("real IPv6: a ::1 listener is loopback and a :: listener is a wildcard (skipped when the host has no IPv6)", { skip }, async () => {
  const loopback = net.createServer();
  const wildcard = net.createServer();
  let loopbackPort = 0;
  let wildcardPort = 0;
  try { loopbackPort = await listen(loopback, 0, "::1"); wildcardPort = await listen(wildcard, 0, "::"); } catch { await close(loopback).catch(() => undefined); await close(wildcard).catch(() => undefined); return; }
  try {
    const reader = fsProcReader();
    const v6 = listeningOnly(parseTcpTable(reader.readText("/proc/net/tcp6") ?? "", 6));
    assert.equal(v6.find((entry) => entry.port === loopbackPort)?.ip, "::1");
    assert.equal(v6.find((entry) => entry.port === wildcardPort)?.ip, "::");
  } finally { await close(loopback); await close(wildcard); }
});

test("the exposure proof on a real /proc: a loopback listener passes; a wildcard listener in the topology is a violation; a topology socket held by an outside process is a foreign holder", { skip }, async () => {
  const reader = fsProcReader();
  const plane = { ip: "10.255.255.1", port: 8080 };
  const base = { reader, mode: "running" as const, pids: { runner: process.pid }, plane, expectPlaneListening: false, ambientAllowedPorts: [] as number[], forbiddenAmbientPorts: [3000], fullScan: false };
  // the host's own ambient listeners are the baseline, whatever they are
  const snapshot = proveExposure({ ...base, mode: "pre_bind", baselineAmbientPorts: undefined, ambientAllowedPorts: [] });
  const baselineAmbientPorts = snapshot.ambientNonLoopbackPorts;
  const input = { ...base, baselineAmbientPorts };

  const loopback = net.createServer();
  const loopbackPort = await listen(loopback, 0, "127.0.0.1");
  try {
    const clean = proveExposure(input);
    assert.deepEqual(clean.violations, [], "a private listener is fine");
    assert.ok(clean.topologyListeners.loopback >= 1);

    const wildcard = net.createServer();
    await listen(wildcard, 0, "0.0.0.0");
    try { assert.ok(proveExposure(input).violations.includes("topology_wildcard_v4")); } finally { await close(wildcard); }

    // a second process inherits the listening socket: the same inode is then held outside the topology
    const child = spawn(process.execPath, ["-e", "process.on('message', (_m, handle) => { if (handle) process.send({ held: true }); }); setInterval(() => undefined, 1000);"], { stdio: ["ignore", "ignore", "ignore", "ipc"] });
    try {
      const held = new Promise<void>((resolve) => child.on("message", () => resolve()));
      child.send({ go: true }, loopback);
      await Promise.race([held, sleep(5_000)]);
      const result = proveExposure({ ...input, fullScan: true });
      assert.ok(result.violations.includes("foreign_holder"), result.violations.join(","));
      assert.ok(result.foreignHolders >= 1);
    } finally { child.kill("SIGTERM"); await new Promise((resolve) => child.once("exit", resolve)); }
    assert.ok(loopbackPort > 0);
  } finally { await close(loopback); }
});

test("the real sampler reads this process and the host: positive memory and fds, a bounded CPU percentage, a readable fd limit", { skip }, async () => {
  const sampler = new ProcSampler(fsProcReader());
  sampler.sample({ self: process.pid });
  const until = Date.now() + 200;
  while (Date.now() < until) { /* burn some CPU */ }
  const second = sampler.sample({ self: process.pid });
  assert.equal(second.perRole.self.alive, true);
  assert.ok(second.perRole.self.rssMb > 0);
  assert.ok(second.perRole.self.fds >= 3);
  assert.ok(second.perRole.self.threads >= 1);
  assert.ok(second.perRole.self.cpuMsDelta >= 0);
  assert.ok(second.host !== null, "/proc/stat and /proc/meminfo are readable");
  assert.ok(second.host!.cpuBusyPct >= 0 && second.host!.cpuBusyPct <= 100);
  assert.ok(second.host!.memAvailablePct > 0 && second.host!.memAvailablePct <= 100);
  assert.ok(typeof second.perRole.self.fdLimit === "number" || second.perRole.self.fdLimit === null);
});

test("real kernel peer classes: the host connecting to its own address is LOCAL, and a connection from a different local address is REMOTE (needs two host addresses)", { skip }, async () => {
  const addresses = hostAddresses();
  if (addresses.length === 0) return;
  const events: PlaneEvent[] = [];
  const origin = createSyntheticOrigin({ instance: "protected", onObservation: () => undefined });
  const originPort = await origin.listen();
  let seq = 0;
  const front = createFront({ upstream: { host: "127.0.0.1", port: originPort }, emit: (event) => { events.push({ ...event, seq: ++seq, t: 0 }); return seq; }, ingress: { ip: addresses[0], port: 0 + (await freePort()) } });
  const port = await front.listen();
  const get = (localAddress?: string): Promise<{ status: number; outcome: string | undefined }> => new Promise((resolve, reject) => {
    const request = http.request({ host: addresses[0], port, path: "/gizlilik", method: "GET", agent: false, ...(localAddress ? { localAddress } : {}) }, (response) => {
      response.resume();
      response.on("end", () => resolve({ status: response.statusCode ?? 0, outcome: response.headers["x-ba0-outcome"] as string | undefined }));
    });
    request.on("error", reject);
    request.end();
  });
  try {
    const same = await get();
    assert.equal(same.status, 200);
    assert.equal(same.outcome, "proxied", "the host itself is a local peer: it keeps the harness behaviour");
    assert.equal(events.find((event) => event.kind === "INGRESS_ACCEPTED")?.ingress, undefined);
    assert.equal(peerClassOf("127.0.0.1", addresses[0]), "local");
    if (addresses.length >= 2) {
      const other = await get(addresses[1]);
      assert.equal(other.status, 200);
      assert.equal(other.outcome, undefined, "a remote peer is never told an internal decision");
      assert.ok(events.some((event) => event.kind === "INGRESS_ACCEPTED" && event.ingress === "external"));
      assert.equal(front.externalStats().accepted, 1);
    }
  } finally { await front.close(300); await origin.close(); }
});

async function freePort(): Promise<number> {
  const probe = net.createServer();
  const port = await listen(probe, 0, "127.0.0.1");
  await close(probe);
  return port;
}

test("the real field environment answers without throwing: interface addresses, the marker, and the old unit's state (null where systemctl does not exist)", { skip }, async () => {
  const env = realFieldEnvironment();
  assert.equal(env.platform, "linux");
  assert.ok(Array.isArray(env.localIpv4Addresses()));
  const marker = env.readMarker();
  assert.ok(marker === null || typeof marker === "string");
  const unit = await env.unitState("limitmark-lab-app.service");
  assert.ok(unit === null || typeof unit === "string");
  const ufw = await env.ufwStatus();
  assert.ok(ufw === null || typeof ufw === "string");
});
