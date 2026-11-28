import assert from "node:assert/strict";
import { test } from "node:test";
import { assertModeMatchesEnvironment, referenceLinkMode } from "../lab/defense/browser-link-mode";

test("a uniform reference trace is read as its mode", () => {
  assert.equal(referenceLinkMode(["client", "client", "client"]), "client");
  assert.equal(referenceLinkMode(["document", "document", "document"]), "document");
});

test("a mixed reference trace is rejected, whichever click falls back", () => {
  for (const trace of [["client", "document", "client"], ["document", "client", "client"], ["client", "client", "document"], ["document", "document", "client"], ["document", "client", "document"]]) {
    assert.throws(() => referenceLinkMode(trace), /neither all client nor all document/u, trace.join());
  }
});

test("an incomplete, excessive or unrecognised reference trace is rejected", () => {
  for (const trace of [[], ["client"], ["client", "client"], ["document", "document"], ["client", "client", "client", "client"]]) {
    assert.throws(() => referenceLinkMode(trace), /exactly 3 reference link clicks/u, trace.join());
  }
  assert.throws(() => referenceLinkMode(["client", "client", "direct"]), /neither all client nor all document/u);
  assert.throws(() => referenceLinkMode(["direct", "direct", "direct"]), /neither all client nor all document/u);
});

test("the inferred mode must agree with the environment, in both directions", () => {
  assertModeMatchesEnvironment("client", undefined);
  assertModeMatchesEnvironment("client", "0");
  assertModeMatchesEnvironment("document", "1");
  assert.throws(() => assertModeMatchesEnvironment("client", "1"), /does not match the build under test/u);
  assert.throws(() => assertModeMatchesEnvironment("document", undefined), /does not match the build under test/u);
  assert.throws(() => assertModeMatchesEnvironment("document", "true"), /does not match the build under test/u);
});

test("a mixed trace is rejected before the environment is consulted", () => {
  const mixed = ["client", "document", "client"];
  for (const environment of [undefined, "1"]) assert.throws(() => assertModeMatchesEnvironment(referenceLinkMode(mixed), environment), /neither all client nor all document/u);
});