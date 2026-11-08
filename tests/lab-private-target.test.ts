import assert from "node:assert/strict";
import { test } from "node:test";
import { PolicyRefusal, validateTargetDefinition } from "../lab/policy/target-policy";

// Private (RFC1918) addresses as disposable remote targets, for the isolated-VPC plan. Characterizes the CURRENT behavior of lab/policy/target-policy.ts;
// it changes no policy. Fixed clock so expiry is deterministic.
const NOW = new Date("2030-01-01T00:00:00Z");
const remote = (host: string, overrides: Record<string, unknown> = {}) => ({
  id: "sut-private", class: "lab-remote", scheme: "http", host, port: 8080,
  allowedPaths: ["/", "/gizlilik"], allowedMethods: ["GET"], expiresAt: "2030-01-02T00:00:00Z", disposable: true, ...overrides,
});
const accepted = (host: string, overrides: Record<string, unknown> = {}) => { try { validateTargetDefinition(remote(host, overrides), NOW); return true; } catch (error) { if (error instanceof PolicyRefusal) return false; throw error; } };

test("RFC1918 private literals are accepted as disposable remote targets (the isolated-VPC plan needs no policy change)", () => {
  for (const host of ["10.0.0.5", "10.255.255.254", "172.16.0.9", "172.31.255.1", "192.168.1.20"]) assert.equal(accepted(host), true, host);
});

test("the address classes that must stay refused are still refused, private ranges notwithstanding", () => {
  for (const host of ["127.0.0.1", "127.1.2.3", "0.0.0.0", "169.254.169.254", "169.254.0.1", "100.64.0.1", "100.127.255.254", "224.0.0.1", "239.255.255.255", "255.255.255.255"]) assert.equal(accepted(host), false, host);
});

test("a private literal still needs the same guards as any remote target: disposable flag, bounded expiry, explicit scheme and port, literal (no hostname)", () => {
  assert.equal(accepted("10.0.0.5", { disposable: false }), false);
  assert.equal(accepted("10.0.0.5", { disposable: undefined }), false);
  assert.equal(accepted("10.0.0.5", { expiresAt: "2030-01-05T00:00:00Z" }), false, "expiry beyond 72 hours");
  assert.equal(accepted("10.0.0.5", { expiresAt: "2029-12-31T00:00:00Z" }), false, "already expired");
  assert.equal(accepted("10.0.0.5", { port: undefined }), false);
  assert.equal(accepted("10.0.0.5", { scheme: undefined }), false);
  assert.equal(accepted("sut.internal"), false, "hostnames are not accepted");
  assert.equal(accepted("10.0.0"), false);
  assert.equal(accepted("10.0.0.256"), false);
  assert.equal(accepted("010.000.000.005"), false, "non-canonical octets");
});

import { validateIngressBind } from "../defense/core/ingress-class";
test("the plane's reviewed ingress bind accepts a private literal and still refuses wildcard, link-local, multicast and non-literals", () => {
  assert.deepEqual({ ...validateIngressBind({ ip: "10.0.0.5", port: 8080 }) }, { ip: "10.0.0.5", port: 8080 });
  for (const ip of ["0.0.0.0", "::", "169.254.1.1", "224.0.0.1", "localhost", "10.0.0", "10.0.0.05"]) assert.throws(() => validateIngressBind({ ip, port: 8080 }), undefined, ip);
});
