import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function fillRequiredFields(page: Page) {
  await page.getByLabel("Adınız", { exact: true }).fill("Örnek Talep");
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("qa@example.test");
  await page.getByLabel("Test etmek istediğiniz sistem", { exact: true }).fill("Hazırlık uygulamamız");
  await page.getByLabel("Testten ne öğrenmek istiyorsunuz?", { exact: true }).fill("Yük altında erişim davranışı");
  await page.getByLabel("Test edilecek ortam", { exact: true }).selectOption("staging");
  await page.getByLabel("Henüz test yetkim yok / yetkimden emin değilim.", { exact: true }).check();
}

for (const width of [375, 1280]) {
  test(`all process rules stay neutral at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/#surec");
    const steps = page.locator(".process-list > li");
    await expect(steps).toHaveCount(5);
    for (const step of await steps.all()) {
      await expect(step).toHaveCSS("border-top-color", "rgb(48, 64, 77)");
      await expect(step).toHaveCSS("border-top-width", "1px");
    }
    await expect(page.locator(".process-list [aria-current], .process-list button, .process-list a")).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Yetkilendirme ve zamanı kesinleştirelim", exact: true })).toBeVisible();
  });

  test(`request submits with optional disclosure initially closed at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/test-talep-et");
    await expect(page.getByText("İsteğe bağlı alanları boş bırakabilirsiniz.", { exact: true })).toBeVisible();
    await expect(page.locator(".form-extras")).not.toHaveAttribute("open");
    await expect(page.getByLabel("Mevcut koruma hakkında bilginiz var mı?", { exact: false })).toBeHidden();
    await expect(page.getByLabel("Tercih ettiğiniz dönem ve diğer notlar", { exact: false })).toBeHidden();
    await fillRequiredFields(page);
    await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
    await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  });

  test(`optional fields retain values through keyboard disclosure toggles at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/test-talep-et");
    await fillRequiredFields(page);
    const disclosure = page.locator(".form-extras");
    const summary = disclosure.locator("summary");
    const symbol = summary.locator(".disclosure-symbol");
    const protection = page.getByLabel("Mevcut koruma hakkında bilginiz var mı?", { exact: false });
    const provider = page.getByLabel("Koruma hizmeti / sağlayıcı", { exact: false });
    const notes = page.getByLabel("Tercih ettiğiniz dönem ve diğer notlar", { exact: false });

    await expect(summary).toHaveText("Ek bilgi ekle (isteğe bağlı)");
    expect(await symbol.evaluate((element) => getComputedStyle(element, "::after").display)).not.toBe("none");
    await summary.press("Enter");
    await expect(disclosure).toHaveAttribute("open", "");
    await expect(protection).toBeVisible();
    await expect(summary).toBeFocused();
    expect(await symbol.evaluate((element) => getComputedStyle(element, "::after").display)).toBe("none");
    expect(await summary.evaluate((element) => parseFloat(getComputedStyle(element).transitionDuration))).toBeLessThan(0.001);
    await page.keyboard.press("Tab");
    await expect(protection).toBeFocused();
    await expect(provider).toHaveCount(0);
    await protection.selectOption("using");
    await provider.fill("Örnek sağlayıcı");
    await notes.fill("Hazırlık ortamını önümüzdeki dönemde değerlendirelim.");
    await protection.selectOption("none");
    await expect(provider).toHaveCount(0);
    await protection.selectOption("using");
    await expect(provider).toHaveValue("Örnek sağlayıcı");

    await summary.press("Space");
    await expect(disclosure).not.toHaveAttribute("open");
    await expect(protection).toBeHidden();
    await expect(provider).toBeHidden();
    await expect(notes).toBeHidden();
    // Hidden disclosure controls stay successful form controls, not disabled fields.
    expect(await page.locator("form").evaluate((form) => {
      const data = new FormData(form as HTMLFormElement);
      return { protection: data.get("protection"), provider: data.get("provider"), notes: data.get("notes") };
    })).toEqual({ protection: "using", provider: "Örnek sağlayıcı", notes: "Hazırlık ortamını önümüzdeki dönemde değerlendirelim." });
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Gizlilik sayfasını", exact: true })).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await summary.press("Enter");
    await expect(provider).toHaveValue("Örnek sağlayıcı");
    await expect(notes).toHaveValue("Hazırlık ortamını önümüzdeki dönemde değerlendirelim.");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(accessibility.violations).toEqual([]);
    await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
    await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  });
}

test("unconfigured email omits links, placeholder copy and empty wrappers everywhere", async ({ page }) => {
  for (const route of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/gizlilik", "/test-yetkilendirmesi"]) {
    await page.goto(route);
    await expect(page.getByText("E-posta iletişim adresi henüz paylaşılmadı.", { exact: true })).toHaveCount(0);
    await expect(page.getByText("E-posta ile İletişime Geç", { exact: true })).toHaveCount(0);
    await expect(page.getByText("Bir düzeltme veya ek bilgi için:", { exact: true })).toHaveCount(0);
    await expect(page.locator('a[href^="mailto:"], .contact-unavailable, .closing-contact, .confirmation-contact')).toHaveCount(0);
  }
});
