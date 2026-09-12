import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { fieldLimits } from "../../src/lib/request-schema";

async function fillValidRequest(page: Page) {
  await page.locator("#name").fill("Örnek Talep");
  await page.locator("#email").fill("qa@example.test");
  await page.locator("#system").fill("Hazırlık ortamımızdaki uygulama");
  await page.locator("#objective").fill("Kontrollü yük altında erişim davranışı");
  await page.locator("#environment").selectOption("staging");
  await page.locator('input[value="authorized"]').check();
}

test("empty, whitespace and malformed email errors can be corrected with keyboard submission", async ({ page }) => {
  await page.goto("/test-talep-et");
  const submit = page.getByRole("button", { name: "Talebi Gönder", exact: true });
  await submit.click();
  const summary = page.getByRole("main").getByRole("alert");
  await expect(summary.getByRole("link")).toHaveCount(6);
  await expect(page.getByRole("radiogroup", { name: "Bu sistem için test yetkiniz", exact: true })).toHaveAttribute("aria-invalid", "true");
  expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze()).violations).toEqual([]);
  await page.locator("#name").fill("   ");
  await page.locator("#system").fill("\n  \n");
  await page.locator("#objective").fill("  ");
  await submit.click();
  await expect(summary.getByRole("link")).toHaveCount(6);
  const ordinary = `Çağrı O'Neil "Deneme" & <ölçüm> 日本語 🧪`;
  await page.locator("#name").fill(` ${ordinary} `);
  await page.locator("#system").fill(`${ordinary}\nikinci satır`);
  await page.locator("#objective").fill(" Ölçüm hakkında bilgi ");
  for (const environment of ["production", "multiple", "unknown", "staging"]) await page.locator("#environment").selectOption(environment);
  for (const authority of ["owner", "authorized", "uncertain", "owner"]) await page.locator(`input[value="${authority}"]`).check();
  await expect(page.locator(".context-note")).toHaveCount(0);
  for (const email of ["invalid", "a@", "@example.test", "a b@example.test", "a@@example.test", "a@example..test"]) {
    await page.locator("#email").fill(email);
    await submit.click();
    await expect(summary.getByRole("link")).toHaveCount(1);
    await expect(page.locator("#email")).toHaveAttribute("aria-invalid", "true");
  }
  await page.locator("#email").fill(" qa@example.test ");
  await page.locator("#name").press("Enter");
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı.", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page).toHaveURL("/test-talep-et");
  await expect(page.locator("form")).toBeVisible();
  await page.goForward();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
});

test("all maximum lengths submit together after repeated optional field toggles", async ({ page }) => {
  await page.goto("/test-talep-et");
  const summary = page.locator(".form-extras summary");
  await summary.click();
  await page.locator("#protection").selectOption("using");
  for (const [field, limit] of Object.entries(fieldLimits)) {
    const value = field === "email" ? `${"a".repeat(limit - 13)}@example.test` : field === "notes" ? "a".repeat(limit - 2) + "\nb" : "ğ".repeat(limit);
    await page.locator(`#${field}`).fill(value);
    await expect(page.locator(`#${field}`)).toHaveAttribute("maxlength", String(limit));
  }
  await page.locator("#environment").selectOption("unknown");
  await page.locator('input[value="authorized"]').check();
  for (let iteration = 0; iteration < 3; iteration++) {
    await page.locator("#protection").selectOption("none");
    await expect(page.locator("#provider")).toHaveCount(0);
    expect(await page.locator("form").evaluate((form) => new FormData(form as HTMLFormElement).has("provider"))).toBe(false);
    await page.locator("#protection").selectOption("using");
    await expect(page.locator("#provider")).toHaveValue("ğ".repeat(160));
    await summary.press("Space");
    await summary.press("Enter");
  }
  await summary.click();
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
});

test("a malformed POST bypassing all browser limits is rejected by the server", async ({ page }) => {
  await page.goto("/test-talep-et");
  await page.locator("#name").fill("SENTINEL");
  await page.locator("#email").fill("qa@example.test");
  await page.locator("#system").fill("SENTINEL");
  await page.locator("#objective").fill("SENTINEL");
  await page.locator("#environment").selectOption("staging");
  await page.locator('input[value="owner"]').check();
  let intercepted = false;
  await page.route("**/api/public-inquiries", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    intercepted = true;
    const body = new URLSearchParams(route.request().postData()!);
    for (const [field, limit] of Object.entries(fieldLimits)) {
      expect(body.has(field), field).toBe(true);
      body.set(field, "a".repeat(limit + 1));
    }
    await route.continue({ postData: body.toString() });
  });
  // Optional provider must be present for the mutation above.
  await page.locator(".form-extras summary").click();
  await page.locator("#protection").selectOption("using");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  const errors = page.getByRole("main").getByRole("alert");
  await expect(errors).toBeVisible();
  expect(intercepted).toBe(true);
  await expect(errors.getByRole("link")).toHaveCount(7);
  for (const field of Object.keys(fieldLimits)) await expect(page.locator(`#${field}`)).toHaveAttribute("aria-invalid", "true");
  await expect(page).not.toHaveURL(/tesekkurler/);
});

test("corrected resubmission clears stale server errors while the action is pending", async ({ page }) => {
  let postCount = 0;
  let releaseSecondPost!: () => void;
  let markSecondPostHeld!: () => void;
  const secondPostHeld = new Promise<void>((resolve) => { markSecondPostHeld = resolve; });
  const releaseSecondPostGate = new Promise<void>((resolve) => { releaseSecondPost = resolve; });

  await page.route("**/api/public-inquiries", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    postCount += 1;
    if (postCount === 1) {
      const body = new URLSearchParams(route.request().postData()!);
      expect(body.has("email")).toBe(true);
      body.set("email", "invalid");
      await route.continue({ postData: body.toString() });
      return;
    }
    markSecondPostHeld();
    await releaseSecondPostGate;
    await route.continue();
  });

  await page.goto("/test-talep-et");
  await fillValidRequest(page);
  const submit = page.locator('button[type="submit"]');
  await submit.click();
  const summary = page.getByRole("main").getByRole("alert");
  await expect(summary.getByRole("link", { name: /^E-posta adresiniz:/ })).toBeVisible();
  await expect(page.locator("#email")).toHaveAttribute("aria-invalid", "true");

  await page.locator("#email").fill("corrected@example.test");
  await submit.click();
  await secondPostHeld;
  try {
    await expect(submit).toBeDisabled();
    await expect(submit).toHaveText("Gönderiliyor…");
    await expect(summary).toHaveCount(0);
    await expect(page.locator("#email")).not.toHaveAttribute("aria-invalid", "true");
    await expect(page.locator("#email-error")).toHaveCount(0);
  } finally {
    releaseSecondPost();
  }
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
});
