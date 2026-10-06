import assert from "node:assert/strict";
import { test } from "node:test";
import { IngressRefusal, isLoopbackAddress, parseIpv4, peerClassOf, validateIngressBind } from "../defense/core/ingress-class";

test("a peer is LOCAL only when the kernel says it is this host; everything else, and anything unknown, is REMOTE", () => {
  assert.equal(peerClassOf("127.0.0.1", "127.0.0.1"), "local");
  assert.equal(peerClassOf("127.0.0.7", "10.0.0.5"), "local", "any loopback address");
  assert.equal(peerClassOf("::1", "::1"), "local");
  assert.equal(peerClassOf("::ffff:127.0.0.1", "10.0.0.5"), "local", "an IPv4-mapped loopback peer");
  assert.equal(peerClassOf("10.0.0.5", "10.0.0.5"), "local", "the host connecting to its own address: remote equals local");
  assert.equal(peerClassOf("::ffff:10.0.0.5", "10.0.0.5"), "local");
  assert.equal(peerClassOf("203.0.113.7", "10.0.0.5"), "remote");
  assert.equal(peerClassOf("10.0.0.6", "10.0.0.5"), "remote", "another host on the same network");
  assert.equal(peerClassOf(undefined, "10.0.0.5"), "remote", "no remote address: not trusted");
  assert.equal(peerClassOf("", "10.0.0.5"), "remote");
  assert.equal(peerClassOf("203.0.113.7", undefined), "remote");
  assert.equal(peerClassOf("2001:db8::1", "2001:db8::1"), "local", "equal addresses are the same host in any family");
  assert.equal(peerClassOf("2001:db8::2", "2001:db8::1"), "remote");
});

test("loopback recognition is exact (127.0.0.0/8 and ::1), not a prefix guess", () => {
  for (const address of ["127.0.0.1", "127.255.255.254", "::1"]) assert.equal(isLoopbackAddress(address), true, address);
  for (const address of ["128.0.0.1", "126.255.255.255", "1270.0.0.1", "127.0.0", "::2", "::ffff:127.0.0.1x", "localhost"]) assert.equal(isLoopbackAddress(address), false, address);
});

test("parseIpv4 accepts only a canonical dotted quad", () => {
  assert.deepEqual(parseIpv4("203.0.113.10"), [203, 0, 113, 10]);
  for (const text of ["", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.256", "0x7f.0.0.1", "2130706433", "1.2.3.-4", " 1.2.3.4", "1.2.3.4 ", "1..2.3", "::1"]) assert.equal(parseIpv4(text), null, JSON.stringify(text));
});

test("the reviewed ingress is a fixed canonical IPv4 and a fixed port: no wildcard, hostname, IPv6, reserved address, port 0 or extra field", () => {
  const ok = validateIngressBind({ ip: "203.0.113.10", port: 8080 });
  assert.deepEqual({ ...ok }, { ip: "203.0.113.10", port: 8080 });
  assert.ok(Object.isFrozen(ok));
  assert.equal(validateIngressBind({ ip: "127.0.0.1", port: 8123 }).ip, "127.0.0.1", "loopback is accepted by the plane (the harness's field policy is what forbids it for a level)");
  const refused: [string, unknown][] = [
    ["wildcard v4", { ip: "0.0.0.0", port: 8080 }], ["broadcast", { ip: "255.255.255.255", port: 8080 }], ["wildcard v6", { ip: "::", port: 8080 }],
    ["IPv6 literal", { ip: "::1", port: 8080 }], ["IPv4-mapped IPv6", { ip: "::ffff:10.0.0.5", port: 8080 }], ["hostname", { ip: "example.test", port: 8080 }],
    ["localhost", { ip: "localhost", port: 8080 }], ["short form", { ip: "10.1", port: 8080 }], ["leading zero", { ip: "010.0.0.5", port: 8080 }], ["multicast", { ip: "224.0.0.1", port: 8080 }],
    ["reserved", { ip: "240.0.0.1", port: 8080 }], ["this network", { ip: "0.1.2.3", port: 8080 }], ["link-local", { ip: "169.254.169.254", port: 8080 }],
    ["port 0", { ip: "10.0.0.5", port: 0 }], ["port too big", { ip: "10.0.0.5", port: 65536 }], ["fractional port", { ip: "10.0.0.5", port: 80.5 }], ["string port", { ip: "10.0.0.5", port: "8080" }],
    ["extra field", { ip: "10.0.0.5", port: 8080, backlog: 1 }], ["missing port", { ip: "10.0.0.5" }], ["null", null], ["array", ["10.0.0.5", 8080]], ["string", "10.0.0.5:8080"], ["undefined", undefined],
  ];
  for (const [label, candidate] of refused) assert.throws(() => validateIngressBind(candidate), IngressRefusal, label);
});
