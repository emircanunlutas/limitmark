// Run after a production build with loopback demo and closed Next servers, plus a guarded TEST_DATABASE_URL.
import assert from "node:assert/strict";
import { chromium, expect, type Page, type Request as BrowserRequest } from "@playwright/test";
import { drizzle } from "drizzle-orm/postgres-js";
import * as schema from "../src/lib/db/schema";
import { PostgresInquiryRepository } from "../src/lib/inquiry-repository";
import {
  createIngressEnvelope, encodeBase64url, INGRESS_BODY_ENCODING, INGRESS_ENVIRONMENT, INGRESS_HEADER,
  INGRESS_IDENTITY_VERSION, INGRESS_MUTATION_CONTENT_TYPE, INGRESS_MUTATION_PATH, INGRESS_VERSION,
  sha256Base64url, type IngressPayload,
} from "../src/lib/ingress-protocol";
import { importRequestBindingKey } from "../src/lib/ingress-verifier.server";
import { handlePublicInquiry, type PublicInquiryHandlerDependencies } from "../src/lib/public-inquiry-handler.server";
import { disposableTestDatabase } from "./support/test-database-guard";

function loopbackOrigin(name: string) {
  const origin = process.env[name];
  assert.match(origin ?? "", /^http:\/\/127\.0\.0\.1:\d+$/);
  return origin!;
}

async function fillForm(page: Page, origin: string) {
  await page.goto(origin + "/test-talep-et");
  await page.locator("#name").fill("Sentetik Başvuru");
  await page.locator("#email").fill("qa@example.test");
  await page.locator("#system").fill("Hazırlık ortamı");
  await page.locator("#objective").fill("Başvuru kaydını doğrulamak");
  await page.locator("#environment").selectOption("staging");
  await page.locator('input[name="authority"][value="owner"]').check();
  return page.locator('input[name="submissionToken"]').inputValue();
}

async function verify() {
  const demoOrigin = loopbackOrigin("INQUIRY_TEST_DEMO_ORIGIN");
  const closedOrigin = loopbackOrigin("INQUIRY_TEST_CLOSED_ORIGIN");
  assert.notEqual(demoOrigin, closedOrigin);
  const guard = disposableTestDatabase();
  const client = guard.connect();
  assert.ok(client, "Configure the disposable test database");
  try {
    await guard.migrate(client, "drizzle");
    const repository = new PostgresInquiryRepository(drizzle(client, { schema }));
    const closedClient = guard.connect()!;
    await closedClient.end();
    const disconnectedRepository = new PostgresInquiryRepository(drizzle(closedClient, { schema }));
    const origin = "https://limitmark.com";
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
    const now = 100_000;
    const originSecret = "O".repeat(43);
    const permit = encodeBase64url(new Uint8Array(32).fill(5));
    let attempt: "rejected" | "disconnected" | "lost-ack" | "drop-response" | "available" = "rejected";
    const deps: PublicInquiryHandlerDependencies = {
      environment: { NODE_ENV: "production", REQUEST_SUBMISSION_MODE: "postgres", VERCEL: "1", VERCEL_ENV: "production",
        PUBLIC_ORIGIN_PROTECTION: "required", PUBLIC_ORIGIN_SECRET: originSecret },
      ingressPolicy: { audience: "prj_limitmark", deploymentId: "dpl_reviewed", publicKeys: new Map([["current", pair.publicKey]]),
        requestBindingKey: await importRequestBindingKey(encodeBase64url(new Uint8Array(32).fill(9))), now: () => now },
      admission: {
        async claimPre() { return attempt === "rejected" ? { decision: "limited" } : { decision: "allowed", permit, expiresAtMs: now + 60_000 }; },
        async consumePost() { return { decision: "allowed" }; },
      },
      turnstile: { async verify() { return "verified"; } },
      repository: {
        async create(input) {
          if (attempt === "disconnected") return disconnectedRepository.create(input);
          const stored = await repository.create(input);
          if (attempt === "lost-ack") throw new Error("Simulated loss of commit acknowledgement");
          return stored;
        },
      },
    };
    async function counts(token: string) {
      const [row] = await client!`SELECT
        (SELECT count(*) FROM inquiries WHERE submission_token = ${token})::int AS inquiries,
        (SELECT count(*) FROM inquiry_events e JOIN inquiries i ON i.id = e.inquiry_id WHERE submission_token = ${token})::int AS events,
        (SELECT count(*) FROM notification_outbox o JOIN inquiries i ON i.id = o.inquiry_id WHERE submission_token = ${token})::int AS jobs`;
      return { ...row };
    }

    const browser = await chromium.launch({ executablePath: process.env.INQUIRY_TEST_BROWSER });
    try {
      const context = await browser.newContext({ serviceWorkers: "block" });
      await context.route("**/*", route => [demoOrigin, closedOrigin].includes(new URL(route.request().url()).origin)
        ? route.continue() : route.abort());
      const page = await context.newPage();
      await page.goto(closedOrigin + "/test-talep-et/tesekkurler");
      await expect(page.getByRole("heading", { name: "Talebinizi aldık." })).toHaveCount(0);
      await expect(page.getByText("Talebinizin alındığını bu sayfadan doğrulayamıyoruz.", { exact: false })).toBeVisible();
      const demoToken = await fillForm(page, demoOrigin);
      const submit = page.getByRole("button", { name: "Talebi Gönder" });
      await submit.click();
      await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı." })).toBeVisible();
      assert.deepEqual(await counts(demoToken), { inquiries: 0, events: 0, jobs: 0 });

      // Demo only renders the built form. The browser POST is bridged within this test
      // to the real signed handler and repository, with no production network calls.
      await page.route(demoOrigin + INGRESS_MUTATION_PATH, async route => {
        const form = new URLSearchParams(route.request().postData() ?? "");
        form.set("cf-turnstile-response", "synthetic-challenge");
        const body = new TextEncoder().encode(form.toString());
        const payload: IngressPayload = [
          INGRESS_VERSION, "current", INGRESS_ENVIRONMENT, "prj_limitmark", "dpl_reviewed", now,
          "POST", "https", "limitmark.com", INGRESS_MUTATION_PATH, "", INGRESS_MUTATION_CONTENT_TYPE, INGRESS_BODY_ENCODING,
          body.length, await sha256Base64url(body), INGRESS_IDENTITY_VERSION, encodeBase64url(new Uint8Array(32).fill(1)),
          encodeBase64url(crypto.getRandomValues(new Uint8Array(16))),
        ];
        const response = await handlePublicInquiry(new Request(origin + INGRESS_MUTATION_PATH, {
          method: "POST", body,
          headers: { origin, host: "limitmark.com", "x-forwarded-host": "limitmark.com", "x-limitmark-origin-secret": originSecret,
            "content-type": INGRESS_MUTATION_CONTENT_TYPE, "content-encoding": INGRESS_BODY_ENCODING,
            [INGRESS_HEADER]: await createIngressEnvelope(payload, pair.privateKey) },
        }), deps);
        if (attempt === "drop-response") {
          assert.equal(response.status, 200);
          await route.abort("failed");
          return;
        }
        await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body: await response.text() });
      });

      const token = await fillForm(page, demoOrigin);
      const alert = page.getByRole("main").getByRole("alert");
      const confirmation = page.getByRole("heading", { name: "Talebinizi aldık.", exact: true });
      const noWrites = { inquiries: 0, events: 0, jobs: 0 };
      const oneWrite = { inquiries: 1, events: 1, jobs: 1 };
      const outcomes = [
        ["rejected", "Talep gönderilemedi.", noWrites],
        ["disconnected", "Gönderim sonucu belirsiz.", noWrites],
        ["lost-ack", "Gönderim sonucu belirsiz.", oneWrite],
        ["drop-response", "Gönderim sonucu belirsiz.", oneWrite],
        ["rejected", "Gönderim sonucu belirsiz.", oneWrite],
      ] as const;
      for (const [mode, heading, expected] of outcomes) {
        attempt = mode;
        const matchesPost = (request: BrowserRequest) => request.url() === demoOrigin + INGRESS_MUTATION_PATH;
        const finished = mode === "drop-response"
          ? page.waitForEvent("requestfailed", matchesPost)
          : page.waitForEvent("requestfinished", matchesPost);
        await submit.click();
        await finished;
        await expect(submit).toBeEnabled();
        await expect(alert.getByRole("heading")).toHaveText(heading);
        await expect(confirmation).toHaveCount(0);
        await expect(page.locator("#name")).toHaveValue("Sentetik Başvuru");
        await expect(page.locator('input[name="submissionToken"]')).toHaveValue(token);
        assert.deepEqual(await counts(token), expected, mode);
      }

      attempt = "available";
      await submit.click();
      await expect(confirmation).toBeVisible();
      await expect(confirmation.locator("..")).toBeFocused();
      await expect(submit).toHaveCount(0);
      assert.deepEqual(await counts(token), oneWrite);

      const fresh = await fillForm(page, demoOrigin);
      assert.notEqual(fresh, token);
      await submit.click();
      await expect(confirmation).toBeVisible();
      assert.deepEqual(await counts(fresh), oneWrite);
      console.log("Passed: direct GET, demo, rejection, DB disconnect, lost acknowledgement, dropped response, retry and fresh commit.");
    } finally {
      await browser.close();
    }
  } finally {
    await client.end();
  }
}

verify().catch(error => { console.error(error); process.exitCode = 1; });
