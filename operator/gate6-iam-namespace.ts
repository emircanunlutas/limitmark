import { randomBytes } from "node:crypto";

// Gate 6A: the dedicated, collision-resistant object namespace used only by
// local/operator-side R2 IAM credential verification (never by the reviewed
// lifecycle chain). Every real lifecycle key this repository ever writes or
// reads is a fixed literal with no random/prefixed component: "initialize.json",
// "rotate-release.json", "settle.json", "reconcile.json", "lifecycle/<digest>.json",
// "settlement/<nonce>.json", "reconciliation/<nonce>.json" (digest/nonce are
// hex, never under a "gate6-iam-test/" prefix). The staging mailbox
// (workers/lifecycle-mailbox/staging-processor.ts) only ever issues
// `REQUEST_BUCKET.get("initialize.json")` and `REQUEST_BUCKET.get("settle.json")`
// -- two fixed literal reads, never a LIST and never any other key -- so it is
// structurally unable to observe, let alone interpret, anything under this
// prefix; tests/gate6-namespace.test.ts proves this directly against that code.

export const GATE6_IAM_TEST_PREFIX = "gate6-iam-test/";
const noncePattern = /^[a-f0-9]{32}$/u;
export const GATE6_IAM_TEST_KEY_PATTERN = new RegExp(`^${GATE6_IAM_TEST_PREFIX}[a-f0-9]{32}\\.json$`, "u");

/** One bounded 128-bit random nonce, hex-encoded -- the same shape already
 * used for reconcile/settle nonces elsewhere in this repository. */
export function gate6IamTestNonce(): string {
  return randomBytes(16).toString("hex");
}

/** The exact synthetic Gate 6 IAM-test object key for one nonce. Never
 * produces, and never accepts, a bare lifecycle-shaped key. */
export function gate6IamTestKey(nonce: string): string {
  if (!noncePattern.test(nonce)) throw new Error("invalid-gate6-iam-test-nonce");
  return `${GATE6_IAM_TEST_PREFIX}${nonce}.json`;
}

/** Upper bound on a Gate 6 IAM-test fixture object. Deliberately small: this
 * namespace exists only to prove effective PUT/GET permission, never to move
 * meaningful data. */
export const GATE6_IAM_TEST_MAX_OBJECT_BYTES = 256;

/** The one harmless, fixed-shape synthetic content ever written under this
 * namespace. No lifecycle semantics: a Worker that somehow parsed this as a
 * command artifact, control object, or lifecycle/settlement/reconciliation
 * result would still find none of the fields any of those parsers require. */
export function gate6IamTestFixtureBody(nonce: string, createdAtMs: number): Uint8Array {
  if (!noncePattern.test(nonce) || !Number.isSafeInteger(createdAtMs) || createdAtMs < 0) throw new Error("invalid-gate6-iam-test-fixture");
  const bytes = new TextEncoder().encode(JSON.stringify({ version: 1, purpose: "gate6-iam-test", nonce, createdAtMs }));
  if (bytes.byteLength > GATE6_IAM_TEST_MAX_OBJECT_BYTES) throw new Error("gate6-iam-test-fixture-too-large");
  return bytes;
}
