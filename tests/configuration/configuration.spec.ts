import { test, expect } from "@playwright/test";

test("the built contact configuration renders only usable email destinations", async ({ page }) => {
  const expected = process.env.QA_CONTACT_EXPECTED;
  for (const route of ["/", "/test-talep-et/tesekkurler"]) {
    await page.goto(route);
    const link = page.getByRole("link", { name: "E-posta ile İletişime Geç", exact: true });
    if (expected) {
      await expect(link).toHaveCount(1);
      await expect(link).toHaveAttribute("href", `mailto:${expected}`);
      await expect(link).toBeVisible();
    } else {
      await expect(link).toHaveCount(0);
      await expect(page.locator('a[href^="mailto:"], .closing-contact, .confirmation-contact')).toHaveCount(0);
    }
    await expect(page.getByText("E-posta iletişim adresi henüz paylaşılmadı.", { exact: true })).toHaveCount(0);
  }
});

for (const javaScriptEnabled of [true, false]) {
  test(`production demo guard preserves a request (JavaScript ${javaScriptEnabled})`, async ({ browser, baseURL }) => {
    const context = await browser.newContext({ baseURL, javaScriptEnabled });
    const page = await context.newPage();
    await page.goto("/test-talep-et");
    await page.locator("#name").fill("Örnek QA");
    await page.locator("#email").fill("qa@example.test");
    await page.locator("#system").fill("Hazırlık ortamı");
    await page.locator("#objective").fill("Erişim davranışını öğrenmek istiyoruz.");
    await page.locator("#environment").selectOption("multiple");
    await page.locator('input[value="uncertain"]').check();
    await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
    await expect(page.getByRole("main").getByRole("alert")).toContainText("Bilgileriniz iletilmedi.");
    await expect(page.locator("#name")).toHaveValue("Örnek QA");
    await expect(page.locator("#environment")).toHaveValue("multiple");
    await expect(page.locator('input[value="uncertain"]')).toBeChecked();
    await expect(page).not.toHaveURL(/tesekkurler/);
    await context.close();
  });
}
