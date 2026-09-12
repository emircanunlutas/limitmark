import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

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
