import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("the homepage shows closure and the configured email before an inquiry click", async ({ page }) => {
  await page.goto("/#hizmetler");
  const main = page.getByRole("main");
  const notice = "Çevrim içi talepler şu anda kullanılamıyor.";
  for (const section of [page.locator(".hero"), page.locator("#hizmetler"), page.locator("#iletisim")]) {
    await expect(section.getByText(notice, { exact: false })).toBeVisible();
    await expect(section.getByRole("link", { name: "E-posta ile İletişime Geç" })).toHaveAttribute("href", "mailto:inquiries@example.test");
  }
  await expect(main.locator('a[href^="/test-talep-et"]')).toHaveCount(0);
  const faq = page.locator("#sss details").first();
  await faq.locator("summary").press("Enter");
  await expect(faq.getByText("e-postayla paylaşabilirsiniz.", { exact: false })).toBeVisible();
  await expect(faq.getByText("Talep formunda", { exact: false })).toHaveCount(0);
});

test("configured contact destinations remain usable", async ({ page }) => {
  const expected = "inquiries@example.test";
  await page.goto("/test-talep-et");
  const link = page.getByRole("link", { name: "E-posta ile İletişime Geç", exact: true });
  await expect(link).toHaveCount(1);
  await expect(link).toHaveAttribute("href", `mailto:${expected}`);
  await expect(link).toBeVisible();
});

test("closed Vercel Production intake is truthful, inaccessible as a form, and accessible", async ({ page }) => {
  await page.goto("/test-talep-et");
  await expect(page.getByRole("heading", { name: "Çevrim içi talepler şu anda kullanılamıyor." })).toBeVisible();
  await expect(page.getByText("burada hiçbir bilgi kaydedilmez", { exact: false })).toBeVisible();
  await expect(page.locator("form, input, select, textarea")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Talebi Gönder" })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(/Turnstile|rate.?limit|limiter|DATABASE_URL|veritabanı|güvenlik yapılandırması/i);
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations).toEqual([]);
});
