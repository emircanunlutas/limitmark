import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { encodeBase64url } from "../src/lib/ingress-protocol";
import { validateLifecycleMailboxConfig } from "../deployment/lifecycle-private-contract";

// CLOUDFLARE_ACCOUNT_ID is a REQUIRED production guard-export identity pin: present, exact, equal to the config account, no default and no bypass.
const ACCOUNT = "a".repeat(32);
const template = async () => JSON.parse(await readFile(new URL("../deployment/lifecycle-mailbox.template.jsonc", import.meta.url), "utf8"));
async function rendered(vars: Record<string, unknown> = {}, accountId: unknown = ACCOUNT) {
  const config = await template();
  config.account_id = accountId; config.main = "../workers/lifecycle-mailbox/index.ts";
  config.vars = { AUTHORITY_OPERATOR_PUBLIC_KEY: encodeBase64url(new Uint8Array(32).fill(7)), CLOUDFLARE_ACCOUNT_ID: accountId, LIFECYCLE_ENVIRONMENT: "production", ...vars };
  return config;
}

test("the template ships the pin as an unresolved placeholder equal to the account placeholder (no default account id)", async () => {
  const config = await template();
  assert.equal(config.vars.CLOUDFLARE_ACCOUNT_ID, "__REQUIRED_CLOUDFLARE_ACCOUNT_ID__");
  assert.equal(config.vars.CLOUDFLARE_ACCOUNT_ID, config.account_id);
  assert.doesNotThrow(() => validateLifecycleMailboxConfig(config));
});

test("rendered config validation: the pin must be present, a 32-hex id, and exactly the config account", async () => {
  const good = await rendered();
  const refused = (config: unknown, pattern?: RegExp) => (pattern ? assert.throws(() => validateLifecycleMailboxConfig(config, false), pattern) : assert.throws(() => validateLifecycleMailboxConfig(config, false)));
  assert.doesNotThrow(() => validateLifecycleMailboxConfig(good, false));
  const missing = await rendered(); delete missing.vars.CLOUDFLARE_ACCOUNT_ID;
  refused(missing, /unsafe-lifecycle-guard/u);
  refused(await rendered({ CLOUDFLARE_ACCOUNT_ID: "b".repeat(32) }), /unsafe-lifecycle-guard/u);
  refused(await rendered({ CLOUDFLARE_ACCOUNT_ID: "" }));
  refused(await rendered({ CLOUDFLARE_ACCOUNT_ID: undefined }));
  refused(await rendered({}, "0".repeat(32)), /unsafe-lifecycle-account/u);
  refused(await rendered({}, "A".repeat(32)), /unsafe-lifecycle-account/u);
  refused(await rendered({}, "short"));
  refused(await rendered({ EXTRA: "x" }));
});

test("the guard has no default account and no bypass: absence refuses before any signature work, and the request account is compared for equality only", async () => {
  const source = (await readFile(new URL("../workers/lifecycle-mailbox/dispatch-guard.ts", import.meta.url), "utf8")).replace(/\/\*[\s\S]*?\*\//gu, "");
  const method = source.slice(source.indexOf("async exportLedger("), source.indexOf("async settle("));
  assert.match(method, /typeof account !== "string" \|\| !\/\^\[a-f0-9\]\{32\}\$\/u\.test\(account\)/u);
  assert.match(method, /request\[5\] !== account/u);
  assert.doesNotMatch(method, /\?\? ["'`]|\|\| ["'`][a-f0-9]{8}|CLOUDFLARE_ACCOUNT_ID \|\||process\.env/u);
  assert.ok(method.indexOf("typeof account") < method.indexOf("verifyGuardExportRequest"), "configuration is checked before verification");
  // the behavioral cases (absent/malformed/upper-case account, other account in the request) are in tests/guard-export-method.test.ts and the workerd integration
});
