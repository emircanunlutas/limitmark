import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("service links preselect an editable service; unknown query safely defaults", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("link", { name: "Web Uygulaması Dayanıklılık Testi — Bu Testi Görüşelim", exact: true }).click();
  await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("web");
  await page.getByLabel("İlgilendiğiniz hizmet").selectOption("network");
  await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("network");
  await page.goto("/test-talep-et?hizmet=unexpected");
  await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("unsure");
});

test("validation is associated, focuses a summary, and preserves form values", async ({ page }) => {
  await page.goto("/test-talep-et");
  await expect(page.locator('input[name="authority"]:checked')).toHaveCount(0);
  await page.getByLabel("Adınız", { exact: true }).fill("Örnek Talep");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toBeFocused();
  await expect(page.getByLabel("Adınız", { exact: true })).toHaveValue("Örnek Talep");
  await expect(page.getByLabel("E-posta adresiniz", { exact: true })).toHaveAttribute("aria-describedby", /email-error/);
  await page.getByRole("main").getByRole("alert").getByRole("link", { name: /^E-posta adresiniz:/ }).click();
  await expect(page.getByLabel("E-posta adresiniz", { exact: true })).toBeFocused();
});

test("uncertain authority and optional protection complete the demo journey", async ({ page }) => {
  await page.goto("/test-talep-et");
  await page.getByLabel("Adınız", { exact: true }).fill("Örnek Talep");
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("qa@example.test");
  await page.getByLabel("Test etmek istediğiniz sistem", { exact: true }).fill("Hazırlık ortamımızdaki uygulama");
  await page.getByLabel("Testten ne öğrenmek istiyorsunuz?", { exact: true }).fill("Kontrollü yük altında erişim davranışı");
  await page.getByLabel("Test edilecek ortam", { exact: true }).selectOption("unknown");
  await page.getByLabel("Henüz test yetkim yok / yetkimden emin değilim.", { exact: true }).check();
  await expect(page.getByText("Talebinizi yine de gönderebilirsiniz.", { exact: false })).toBeVisible();
  await expect(page.getByLabel("Koruma hizmeti / sağlayıcı", { exact: false })).toHaveCount(0);
  await page.getByText("Ek bilgi ekle (isteğe bağlı)", { exact: true }).click();
  await page.getByLabel("Mevcut koruma hakkında bilginiz var mı?", { exact: false }).selectOption("using");
  await page.getByLabel("Koruma hizmeti / sağlayıcı", { exact: false }).fill("Örnek sağlayıcı");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  await expect(page.getByRole("heading", { name: "Talebinizi aldık.", exact: true })).toBeVisible();
  await expect(page.getByText("Bu başvuru bir test başlatmadı", { exact: false })).toBeVisible();
});

test("mobile menu supports keyboard, Escape and navigation; disclosures are independent", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/");
  await page.getByRole("button", { name: "Menü", exact: true }).press("Enter");
  await expect(page.getByRole("navigation", { name: "Ana gezinme" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("navigation", { name: "Ana gezinme" }).getByRole("link", { name: "Hizmetler", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Menü", exact: true })).toBeFocused();
  await page.getByRole("button", { name: "Menü", exact: true }).click();
  await page.getByRole("navigation", { name: "Ana gezinme" }).getByRole("link", { name: "SSS", exact: true }).click();
  await expect(page.getByRole("navigation", { name: "Ana gezinme" })).toBeHidden();
  const summaries = page.locator(".faq-item summary");
  await summaries.nth(0).press("Enter");
  await summaries.nth(1).press("Space");
  await expect(page.locator(".faq-item[open]")).toHaveCount(2);
});

for (const width of [320, 375, 768, 1024, 1280, 1440]) {
  test(`no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    for (const route of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/gizlilik", "/test-yetkilendirmesi"]) {
      await page.goto(route);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), route).toBe(true);
    }
  });
}

test("all primary pages pass automated WCAG A/AA rules", async ({ page }) => {
  for (const route of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/gizlilik", "/test-yetkilendirmesi"]) {
    await page.goto(route);
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    expect(results.violations, route).toEqual([]);
  }
});

test("server validation rejects an invalid request with JavaScript disabled", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, baseURL });
  const page = await context.newPage();
  await page.goto("/test-talep-et");
  await page.getByLabel("Adınız", { exact: true }).fill("   ");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Lütfen işaretli alanları kontrol edin.");
  await expect(page).not.toHaveURL(/tesekkurler/);
  await context.close();
});

test("optional provider remains available to a successful native submission", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, baseURL });
  const page = await context.newPage();
  await page.goto("/test-talep-et");
  await page.getByLabel("Adınız", { exact: true }).fill("Örnek Talep");
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("qa@example.test");
  await page.getByLabel("Test etmek istediğiniz sistem", { exact: true }).fill("Hazırlık ortamımızdaki uygulama");
  await page.getByLabel("Testten ne öğrenmek istiyorsunuz?", { exact: true }).fill("Kontrollü yük altında erişim davranışı");
  await page.getByLabel("Test edilecek ortam", { exact: true }).selectOption("staging");
  await page.getByLabel("Sistem sahibinden test için açık yetkim var.", { exact: true }).check();
  await page.getByText("Ek bilgi ekle (isteğe bağlı)", { exact: true }).click();
  await page.getByLabel("Mevcut koruma hakkında bilginiz var mı?", { exact: false }).selectOption("using");
  const provider = page.getByLabel("Koruma hizmeti / sağlayıcı", { exact: false });
  await expect(provider).toBeVisible();
  await provider.fill("Örnek sağlayıcı");
  await Promise.all([
    page.waitForNavigation({ waitUntil: "load" }),
    page.getByRole("button", { name: "Talebi Gönder", exact: true }).click(),
  ]);
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  await context.close();
});

test("layout remains usable with enlarged text and reduced motion", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 900 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const route of ["/", "/test-talep-et"]) {
    await page.goto(route);
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  }
});

test("internal links resolve and section anchors exist", async ({ page, request }) => {
  const routes = new Set<string>();
  for (const route of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/gizlilik", "/test-yetkilendirmesi"]) {
    await page.goto(route);
    const hrefs = await page.locator("a[href]").evaluateAll((links) => links.map((link) => link.getAttribute("href") ?? ""));
    for (const href of hrefs) {
      if (!href.startsWith("/") && !href.startsWith("#")) continue;
      const target = new URL(href, page.url());
      routes.add(target.pathname + target.search);
      if (target.hash && target.pathname === route) await expect(page.locator(target.hash)).toHaveCount(1);
    }
  }
  for (const route of routes) expect((await request.get(route)).status(), route).toBe(200);
});
