import assert from "node:assert/strict";
import { test } from "node:test";
import { proveExposure, EXPOSURE_STATEMENT, type ExposureInput } from "../lab/defense/exposure-proof";
import { addressClass, listeningOnly, parseTcpTable, socketInode } from "../lab/defense/proc-net";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { APP, BOUNDARY, FakeProc, PLANE, RUNNER, SSHD, encodeIpv4, encodeIpv6, healthyTopology } from "./support/fake-proc";

const PLANE_BIND = { ip: "10.0.0.5", port: 8080 };
const input = (reader: FakeProc, overrides: Partial<ExposureInput> = {}): ExposureInput => ({
  reader, mode: "running", pids: { runner: RUNNER, plane: PLANE, boundary: BOUNDARY, app: APP }, plane: PLANE_BIND, expectPlaneListening: true,
  ambientAllowedPorts: [22], forbiddenAmbientPorts: [3000], baselineAmbientPorts: [22], fullScan: false, ...overrides,
});

// ------------------------------------------------------------------------------------------------ parsing
test("the /proc/net parsers read the kernel's own formats: little-endian words, IPv4, IPv6, mapped and wildcard addresses", () => {
  const proc = healthyTopology();
  proc.addSocket({ family: 6, ip: "::1", port: 9000, inode: 20 }, [RUNNER]);
  proc.addSocket({ family: 6, ip: "::ffff:127.0.0.1", port: 9001, inode: 21 }, [RUNNER]);
  proc.addSocket({ family: 6, ip: "2001:db8::1", port: 9002, inode: 22 }, [RUNNER]);
  proc.addSocket({ family: 6, ip: "::ffff:0.0.0.0", port: 9003, inode: 23 }, [RUNNER]);
  proc.addSocket({ family: 4, ip: "127.0.0.1", port: 9004, inode: 24, state: "01" }, [RUNNER]);
  const v4 = parseTcpTable(proc.readText("/proc/net/tcp")!, 4);
  const v6 = parseTcpTable(proc.readText("/proc/net/tcp6")!, 6);
  assert.equal(encodeIpv4("127.0.0.1"), "0100007F");
  assert.equal(encodeIpv6("::1"), "00000000000000000000000001000000");
  assert.deepEqual(v4.find((entry) => entry.port === 8080), { family: 4, ip: "10.0.0.5", port: 8080, state: "0A", uid: 1000, inode: 2 });
  assert.equal(v6.find((entry) => entry.port === 9000)?.ip, "::1");
  assert.equal(v6.find((entry) => entry.port === 9001)?.ip, "::ffff:127.0.0.1");
  assert.equal(v6.find((entry) => entry.port === 9002)?.ip, "2001:db8:0:0:0:0:0:1");
  assert.equal(v6.find((entry) => entry.port === 22)?.ip, "::");
  assert.equal(addressClass(v6.find((entry) => entry.port === 9001)!), "loopback");
  assert.equal(addressClass(v6.find((entry) => entry.port === 9003)!), "wildcard", "the IPv4-mapped wildcard is a wildcard");
  assert.equal(addressClass(v6.find((entry) => entry.port === 9002)!), "other");
  assert.equal(listeningOnly(v4).some((entry) => entry.port === 9004), false, "an established socket is not a listener");
  assert.equal(socketInode("socket:[12345]"), 12345);
  assert.equal(socketInode("pipe:[12345]"), null);
  assert.equal(socketInode(null), null);
  assert.deepEqual(parseTcpTable("header\ngarbage line\n", 4), [], "malformed lines are skipped, never guessed at");
});

// ------------------------------------------------------------------------------------------------ the invariant
test("a healthy topology passes: the exact plane socket is the only non-loopback topology listener, sshd is the only ambient one", () => {
  const result = proveExposure(input(healthyTopology()));
  assert.deepEqual(result.violations, []);
  assert.equal(result.ok, true);
  assert.equal(result.planeSocket, "exact");
  assert.deepEqual(result.topologyListeners, { loopback: 3, nonLoopbackExact: 1, wildcard: 0, nonLoopbackOther: 0 });
  assert.deepEqual(result.ambientNonLoopbackPorts, [22]);
});

test("the Boundary or the App on a wildcard address is a violation, in either family, including the IPv4-mapped wildcard", () => {
  for (const [family, ip, expected] of [[4, "0.0.0.0", "topology_wildcard_v4"], [6, "::", "topology_wildcard_v6"], [6, "::ffff:0.0.0.0", "topology_wildcard_v6"]] as const) {
    const proc = healthyTopology();
    proc.addSocket({ family, ip, port: 41_500, inode: 30 }, [APP]);
    const result = proveExposure(input(proc));
    assert.ok(result.violations.includes(expected), `${ip}: ${result.violations.join(",")}`);
    assert.equal(result.ok, false);
  }
});

test("the plane itself on a wildcard is a violation (and its reviewed socket is then absent)", () => {
  const proc = new FakeProc();
  for (const pid of [RUNNER, PLANE, BOUNDARY, APP, SSHD]) proc.addProcess(pid);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 8080, inode: 2 }, [PLANE]);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  const result = proveExposure(input(proc));
  assert.ok(result.violations.includes("topology_wildcard_v4"));
  assert.ok(result.violations.includes("plane_not_listening"));
});

test("a non-loopback IPv6 socket anywhere in the topology is a violation", () => {
  const proc = healthyTopology();
  proc.addSocket({ family: 6, ip: "2001:db8::5", port: 8080, inode: 31 }, [PLANE]);
  assert.ok(proveExposure(input(proc)).violations.includes("topology_nonloopback_v6"));
});

test("the Boundary or the App on a non-loopback IPv4 address is a violation", () => {
  const proc = healthyTopology();
  proc.addSocket({ family: 4, ip: "10.0.0.5", port: 41_600, inode: 32 }, [BOUNDARY]);
  assert.ok(proveExposure(input(proc)).violations.includes("topology_nonloopback_service"));
});

test("the plane on the reviewed address but another port, on another address, or with a second non-loopback socket is a violation", () => {
  for (const [ip, port] of [["10.0.0.5", 8081], ["10.0.0.6", 8080]] as const) {
    const proc = new FakeProc();
    for (const pid of [RUNNER, PLANE, BOUNDARY, APP, SSHD]) proc.addProcess(pid);
    proc.addSocket({ family: 4, ip, port, inode: 2 }, [PLANE]);
    proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
    const result = proveExposure(input(proc));
    assert.ok(result.violations.includes("plane_misbound"), `${ip}:${port} ${result.violations.join(",")}`);
    assert.equal(result.planeSocket, "misbound");
  }
  const second = healthyTopology();
  second.addSocket({ family: 4, ip: "10.0.0.5", port: 8082, inode: 33 }, [PLANE]);
  assert.ok(proveExposure(input(second)).violations.includes("plane_misbound"));
});

test("an absent plane socket while it must be listening is a violation; after a close it must be absent; while a close is in progress neither is required", () => {
  const down = healthyTopology();
  down.sockets.splice(down.sockets.findIndex((socket) => socket.inode === 2), 1);
  down.holders.set(PLANE, []);
  assert.ok(proveExposure(input(down)).violations.includes("plane_not_listening"));
  assert.deepEqual(proveExposure(input(down, { mode: "final", expectPlaneListening: false })).violations, [], "after the ingress close the plane has no listener");
  assert.deepEqual(proveExposure(input(down, { planeMayBeClosing: true })).violations, [], "a close in progress");
  assert.ok(proveExposure(input(healthyTopology(), { mode: "final", expectPlaneListening: false })).violations.includes("plane_still_listening"), "the ingress must be gone after the close");
  assert.deepEqual(proveExposure(input(healthyTopology(), { planeMayBeClosing: true })).violations, [], "present while closing is fine too");
});

test("the same listening inode held by two topology processes is an inherited listener (a violation)", () => {
  const proc = healthyTopology();
  proc.holders.set(BOUNDARY, [...(proc.holders.get(BOUNDARY) ?? []), 2]);
  assert.ok(proveExposure(input(proc)).violations.includes("shared_listener_inode"));
});

test("a process OUTSIDE the topology holding a topology listening inode is a stale or inherited holder (preflight and final scan every readable process)", () => {
  const proc = healthyTopology();
  proc.addProcess(777);
  proc.holders.set(777, [2]);
  assert.deepEqual(proveExposure(input(proc, { fullScan: false })).violations, [], "the per-tick check does not scan every process");
  const result = proveExposure(input(proc, { fullScan: true }));
  assert.ok(result.violations.includes("foreign_holder"));
  assert.equal(result.foreignHolders, 1);
});

test("processes whose fds cannot be read are COUNTED, never treated as clean", () => {
  const proc = healthyTopology();
  proc.addProcess(888);
  proc.unreadablePids.add(888);
  const result = proveExposure(input(proc, { fullScan: true }));
  assert.equal(result.scan.pidsUnreadable, 1);
  assert.ok(result.scan.pidsScanned >= 1);
  assert.equal(result.ok, true, "an unreadable foreign process is a stated limit of the proof, not a violation");
});

test("an unreadable /proc fails closed: unreadable tcp, an unreadable topology fd table, a missing or different network namespace", () => {
  const noTcp = healthyTopology();
  noTcp.tcpUnreadable = true;
  assert.ok(proveExposure(input(noTcp)).violations.includes("proc_unreadable"));
  const noFd = healthyTopology();
  noFd.unreadablePids.add(APP);
  assert.ok(proveExposure(input(noFd)).violations.includes("proc_unreadable"));
  const unknownNs = healthyTopology();
  unknownNs.netns.set(BOUNDARY, null);
  assert.ok(proveExposure(input(unknownNs)).violations.includes("netns_unproven"));
  const otherNs = healthyTopology();
  otherNs.netns.set(BOUNDARY, "net:[4026532999]");
  assert.ok(proveExposure(input(otherNs)).violations.includes("netns_mismatch"));
  const noV6 = healthyTopology();
  noV6.tcp6Absent = true;
  assert.equal(proveExposure(input(noV6)).ok, true, "a kernel without IPv6 has no tcp6 table: that is no IPv6 sockets, not an unreadable /proc");
});

test("a listener the topology does not own on the plane's own port (any address) is a stale listener", () => {
  for (const [ip, family] of [["127.0.0.1", 4], ["0.0.0.0", 4], ["::", 6]] as const) {
    const proc = healthyTopology();
    proc.addProcess(555);
    proc.addSocket({ family, ip, port: 8080, inode: 40 }, [555]);
    assert.ok(proveExposure(input(proc)).violations.includes("stale_listener_on_plane_port"), ip);
  }
});

test("the old Field Lab service: a non-loopback listener on port 3000 from ANY owner is a violation, a loopback one is not", () => {
  const exposed = healthyTopology();
  exposed.addProcess(600);
  exposed.addSocket({ family: 4, ip: "0.0.0.0", port: 3000, inode: 50 }, [600]);
  assert.ok(proveExposure(input(exposed)).violations.includes("ambient_forbidden_port"));
  assert.ok(proveExposure(input(exposed, { mode: "pre_bind", pids: { runner: RUNNER }, baselineAmbientPorts: undefined })).violations.includes("ambient_forbidden_port"));
  const private3000 = healthyTopology();
  private3000.addProcess(601);
  private3000.addSocket({ family: 4, ip: "127.0.0.1", port: 3000, inode: 51 }, [601]);
  assert.equal(proveExposure(input(private3000)).ok, true, "reachable from this host only: not generator-accessible");
});

test("ambient listeners: at preflight any non-loopback one off the allowlist is a violation; during the run any one that is NEW since the preflight snapshot is", () => {
  const before = new FakeProc();
  before.addProcess(RUNNER).addProcess(SSHD).addProcess(700);
  before.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  before.addSocket({ family: 4, ip: "0.0.0.0", port: 80, inode: 60 }, [700]);
  const pre = proveExposure(input(before, { mode: "pre_bind", pids: { runner: RUNNER }, baselineAmbientPorts: undefined, expectPlaneListening: false }));
  assert.ok(pre.violations.includes("ambient_unexpected_listener"));
  assert.deepEqual(pre.ambientNonLoopbackPorts, [22, 80]);
  const proc = healthyTopology();
  proc.addProcess(700);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 80, inode: 60 }, [700]);
  const during = proveExposure(input(proc, { baselineAmbientPorts: [22] }));
  assert.ok(during.violations.includes("ambient_new_listener"));
  assert.equal(proveExposure(input(proc, { baselineAmbientPorts: [22, 80] })).ok, true, "a listener that was in the snapshot is not new");
});

test("pre_bind with only the runner: the proof also holds before the plane exists", () => {
  const proc = new FakeProc();
  proc.addProcess(RUNNER).addProcess(SSHD);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  const result = proveExposure(input(proc, { mode: "pre_bind", pids: { runner: RUNNER }, baselineAmbientPorts: undefined, expectPlaneListening: false }));
  assert.deepEqual(result.violations, []);
  assert.equal(result.planeSocket, "absent");
});

test("the result is evidence-safe (counts, ports and enum codes, never an address) and states what it does NOT prove", () => {
  const proc = healthyTopology();
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 41_500, inode: 30 }, [APP]);
  const result = proveExposure(input(proc));
  assert.doesNotThrow(() => assertEvidenceSafe(result, "$exposure"));
  const text = JSON.stringify(result);
  assert.doesNotMatch(text, /\d+\.\d+\.\d+\.\d+/);
  assert.equal(result.statement, EXPOSURE_STATEMENT);
  assert.match(EXPOSURE_STATEMENT, /host listener state only/);
  assert.match(EXPOSURE_STATEMENT, /no claim about cloud firewall, NAT, forwarders or network isolation/);
});
