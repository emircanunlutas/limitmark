// After a production build: tsx --conditions=react-server tests/admin-inquiry-receipts.browser.ts
// This test starts and removes its own disposable PostgreSQL 16 lab.
import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import path from "node:path";
import { chromium, expect } from "@playwright/test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { controlLabContainer } from "../lab/host/docker";
import { labDbDown, labDbStatus, labDbUp, runtimeUrl, testEnvironment, type PgLabState } from "../lab/postgres/lab-db";
import { disposableTestDatabase } from "./support/test-database-guard";

async function runJourney(state: PgLabState) {
  const guard = disposableTestDatabase(testEnvironment(state));
  const db = guard.connect();
  assert.ok(db);
  let id: string;
  try {
    const [row] = await guard.destructive(db, tx => tx`INSERT INTO inquiries
      (name,email,service,system,objective,environment,authority,submission_token,payload_fingerprint)
      VALUES ('Receipt fixture','fixture@example.test','web','Fixture','Save verification','staging','owner',
      ${randomBytes(32).toString("base64url")},${"a".repeat(64)}) RETURNING id`);
    id = row.id;
  } finally { await db.end(); }

  const issuer = "https://receipt-fixture.cloudflareaccess.com";
  const audience = "receipt_fixture";
  const email = "reviewer@example.test";
  const otherEmail = "colleague@example.test";
  const keys = await generateKeyPair("RS256");
  const assertion = (actor: string) => new SignJWT({ email: actor, type: "app" })
    .setProtectedHeader({ alg: "RS256", kid: "fixture" }).setIssuer(issuer).setAudience(audience)
    .setSubject(actor).setIssuedAt().setExpirationTime("5m").sign(keys.privateKey);
  const server = fork(path.join(__dirname, "support/admin-receipt-server.mjs"), [], {
    execArgv: [], env: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1",
      VERCEL: "1", VERCEL_ENV: "production", DATABASE_URL: runtimeUrl(state),
      CLOUDFLARE_ACCESS_TEAM_DOMAIN: issuer, CLOUDFLARE_ACCESS_AUD: audience, ADMIN_ALLOWED_EMAILS: `${email},${otherEmail}`,
      FIXTURE_PUBLIC_JWK: JSON.stringify({ ...await exportJWK(keys.publicKey), kid: "fixture", alg: "RS256", use: "sig" }),
    },
  });
  try {
    const [port] = await Promise.race([
      once(server, "message", { signal: AbortSignal.timeout(30_000) }),
      once(server, "exit").then(() => { throw new Error("Fixture server exited before startup"); }),
    ]);
    const origin = `http://127.0.0.1:${port}`;
    const url = `${origin}/admin/inquiries/${id}`;
    const browser = await chromium.launch({ executablePath: process.env.RECEIPT_TEST_BROWSER });
    try {
      const context = await browser.newContext({ serviceWorkers: "block" });
      await context.route("**/*", route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
      const page = await context.newPage();
      assert.equal((await page.goto(url))?.status(), 404);
      await context.setExtraHTTPHeaders({ "cf-access-jwt-assertion": await assertion(email) });
      await page.goto(url + "?mutation=success");
      const warning = page.locator("main > .page-shell .admin-notice-warning").first();
      await expect(warning).toContainText("could not be confirmed");
      const success = page.locator(".admin-notice-success");
      await expect(success).toHaveCount(0);

      const stale = await context.newPage();
      await stale.goto(url);
      await page.getByLabel("Add internal note").fill("Synthetic review note");
      await page.getByRole("button", { name: "Add note" }).click();
      await expect(success).toContainText("Internal note added. Saved on");
      const receiptUrl = page.url();
      assert.match(receiptUrl, /\?receipt=[0-9a-f-]{36}$/);
      await stale.getByLabel("Add internal note").fill("Stale edit");
      await stale.getByRole("button", { name: "Add note" }).click();
      await expect(stale.getByText(/Nothing changed because this inquiry was updated elsewhere/)).toBeVisible();
      await expect(stale.locator(".admin-notice-success")).toHaveCount(0);

      await page.getByLabel("Permitted next status").selectOption("in_review");
      await page.getByRole("button", { name: "Change status" }).click();
      await expect(success).toContainText("Status changed: Received → In review. Saved on");
      await page.getByRole("checkbox").check();
      await page.getByRole("button", { name: "Archive inquiry" }).click();
      await expect(success).toContainText("Archived from In review. Saved on");
      await page.getByRole("button", { name: "Restore inquiry" }).click();
      await expect(success).toContainText("Restored to In review. Saved on");

      await page.goto(receiptUrl);
      await expect(success).toContainText("Internal note added. Saved on");
      await expect(page.locator(".admin-note-list li")).toHaveCount(1);

      await page.getByLabel("Add internal note").fill("Attempt during interruption");
      await controlLabContainer("stop", state.container);
      await page.getByRole("button", { name: "Add note" }).click();
      await expect(page.getByRole("heading", { name: "Inquiry data unavailable" })).toBeVisible({ timeout: 30_000 });
      await expect(page.getByText(/check whether your change was saved/)).toBeVisible();
      assert.notEqual(page.url(), receiptUrl);
      assert.match(page.url(), /\?receipt=[0-9a-f-]{36}$/);
      await expect(success).toHaveCount(0);
      await controlLabContainer("start", state.container);
      await expect.poll(async () => (await labDbStatus("16")).healthy, { timeout: 30_000 }).toBe(true);
      await page.reload();
      await expect(warning).toContainText("No matching save could be confirmed");
      await expect(page.locator(".admin-note-list li")).toHaveCount(1);
      await page.goto(receiptUrl);
      await expect(success).toContainText("Internal note added. Saved on");
      await page.goto(receiptUrl + "&receipt=invalid");
      await expect(warning).toContainText("could not be confirmed");
      await expect(success).toHaveCount(0);
      await context.setExtraHTTPHeaders({ "cf-access-jwt-assertion": await assertion(otherEmail) });
      await page.goto(receiptUrl);
      await expect(warning).toContainText("No matching save could be confirmed");
      await expect(success).toHaveCount(0);
    } finally { await browser.close(); }
  } finally { server.kill(); }
}

async function verify() {
  const state = await labDbUp("16");
  try { await runJourney(state); }
  finally { await labDbDown("16"); }
}

verify().then(() => console.log("Admin inquiry receipt browser journey passed")).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
