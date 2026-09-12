import assert from "node:assert/strict";
import test from "node:test";
import { executeVerifiedPublicInquiry } from "../src/lib/public-inquiry-flow.server";
import type { AdmissionClient } from "../src/lib/admission-client.server";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import type { TurnstileDecision } from "../src/lib/turnstile";

const token = "s".repeat(43);
const ingress = { releaseId: "dpl_reviewed", issuedAtMs: 1_000, keyId: "current",
  clientPseudonym: encodeBase64url(new Uint8Array(32).fill(1)), requestBinding: encodeBase64url(new Uint8Array(32).fill(2)), nonce: encodeBase64url(new Uint8Array(16).fill(3)) };
function form() {
  const value = new FormData();
  for (const [key, item] of Object.entries({ name: "Synthetic", email: "qa@example.test", service: "web", system: "Disposable",
    objective: "Review flow", environment: "staging", authority: "authorized", submissionToken: token, "cf-turnstile-response": "challenge" })) value.set(key, item);
  return value;
}

function dependencies(options: { pre?: "allowed" | "limited" | "unavailable" | "replay"; post?: "allowed" | "limited" | "unavailable" | "replay"; turnstile?: TurnstileDecision } = {}) {
  const calls: string[] = [];
  const admission: AdmissionClient = {
    async claimPre() { calls.push("pre"); return options.pre && options.pre !== "allowed" ? { decision: options.pre } : { decision: "allowed", permit: encodeBase64url(new Uint8Array(32).fill(4)), expiresAtMs: 60_000 }; },
    async consumePost() { calls.push("post"); return { decision: options.post ?? "allowed" }; },
  };
  return { calls, admission, turnstile: { async verify() { calls.push("turnstile"); return options.turnstile ?? "verified"; } },
    repository: { async create() { calls.push("db"); return { status: "created" as const }; } } };
}

test("verified flow orders PRE, Turnstile, POST and repository", async () => {
  const deps = dependencies();
  assert.deepEqual(await executeVerifiedPublicInquiry({ form: form(), ingress, ...deps }), { kind: "redirect", location: "/test-talep-et/tesekkurler" });
  assert.deepEqual(deps.calls, ["pre", "turnstile", "post", "db"]);
});

test("PRE denial/unavailability/replay prevents Turnstile and persistence", async () => {
  for (const pre of ["limited", "unavailable", "replay"] as const) {
    const deps = dependencies({ pre });
    assert.equal((await executeVerifiedPublicInquiry({ form: form(), ingress, ...deps })).kind, "state");
    assert.deepEqual(deps.calls, ["pre"]);
  }
});

test("Turnstile rejection or outage consumes PRE only and POST failure prevents DB", async () => {
  for (const turnstile of ["rejected", "unavailable"] as const) {
    const deps = dependencies({ turnstile });
    await executeVerifiedPublicInquiry({ form: form(), ingress, ...deps });
    assert.deepEqual(deps.calls, ["pre", "turnstile"]);
  }
  for (const post of ["limited", "unavailable", "replay"] as const) {
    const deps = dependencies({ post });
    await executeVerifiedPublicInquiry({ form: form(), ingress, ...deps });
    assert.deepEqual(deps.calls, ["pre", "turnstile", "post"]);
  }
});

test("schema and token failures do no admission work and preserve corrected values", async () => {
  const invalid = form(); invalid.set("email", "invalid");
  const deps = dependencies();
  const result = await executeVerifiedPublicInquiry({ form: invalid, ingress, ...deps });
  assert.equal(result.kind, "state");
  if (result.kind === "state") assert.equal(result.state.values?.email, "invalid");
  assert.deepEqual(deps.calls, []);
});
