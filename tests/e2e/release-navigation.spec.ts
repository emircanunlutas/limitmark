import { test, expect } from "@playwright/test";

test("routes, history, refresh, all CTA targets and anchors remain consistent", async ({ page, request }) => {
  test.setTimeout(60_000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  const internalFailures: string[] = [];
  page.on("requestfailed", (failure) => {
    if (failure.url().startsWith("http://127.0.0.1:3100") && !failure.failure()?.errorText.includes("ERR_ABORTED")) internalFailures.push(`${failure.url()}: ${failure.failure()?.errorText}`);
  });
  // Complete pending prefetches before deliberate full-document unloads. WebKit
  // reports canceled prefetches during unload as access-control errors.
  async function visit(route: string) {
    await page.waitForLoadState("networkidle");
    await page.goto(route);
    await page.waitForLoadState("networkidle");
  }
  for (const width of [375, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    for (const anchor of ["hizmetler", "surec", "metodoloji", "sss", "iletisim", "sonuclar"]) {
      await visit("/gizlilik");
      await visit(`/#${anchor}`);
      const heading = page.locator(`#${anchor} h2`);
      await expect(heading).toBeVisible();
      await expect.poll(async () => {
        const box = await heading.boundingBox();
        const header = await page.locator(".site-header").boundingBox();
        return box!.y >= header!.y + header!.height;
      }).toBe(true);
      await page.reload();
      await page.waitForLoadState("networkidle");
      await expect(heading).toBeVisible();
    }
  }
  await visit("/");
  const destinations = await page.locator("a[href]").evaluateAll((links) => [...new Set(links.map((link) => link.getAttribute("href") ?? ""))]);
  for (const href of destinations) {
    if (!href.startsWith("/") && !href.startsWith("#")) continue;
    const target = new URL(href, "http://127.0.0.1:3100");
    expect((await request.get(target.pathname + target.search)).status()).toBe(200);
  }
  await page.getByRole("link", { name: "Web Uygulaması Dayanıklılık Testi — Bu Testi Görüşelim", exact: true }).click();
  await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("web");
  await page.waitForLoadState("networkidle");
  await page.getByRole("link", { name: "Gizlilik sayfasını", exact: true }).click();
  await expect(page).toHaveURL("/gizlilik");
  await page.waitForLoadState("networkidle");
  await page.goBack();
  await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("web");
  await page.waitForLoadState("networkidle");
  await page.goForward();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Gizlilik");
  for (const route of ["/test-talep-et", "/test-talep-et/tesekkurler", "/test-yetkilendirmesi"]) {
    await visit(route);
    await page.reload();
    await page.waitForLoadState("networkidle");
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  }
  expect(errors).toEqual([]);
  expect(internalFailures).toEqual([]);
});

test("404 and malformed service queries do not produce an exception or unexpected selection", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  for (const route of ["/missing-page", "/test-talep-et/missing", "/%3Cnot-a-route%3E"]) {
    expect((await page.goto(route))?.status()).toBe(404);
    await expect(page.getByRole("heading", { name: "Sayfa bulunamadı.", exact: true })).toBeVisible();
    await page.getByRole("link", { name: "Ana Sayfaya Dön", exact: true }).click();
    await expect(page).toHaveURL("/");
  }
  for (const query of ["hizmet=web&hizmet=network", "hizmet=%3Cscript%3E", "hizmet=", "hizmet=WEB"]) {
    await page.goto(`/test-talep-et?${query}`);
    await expect(page.getByLabel("İlgilendiğiniz hizmet")).toHaveValue("unsure");
  }
  expect(errors).toEqual([]);
});

test("keyboard skip link, menu exit, focus restoration and error links are usable", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/");
  await page.keyboard.press("Tab");
  await expect(page.getByRole("link", { name: "İçeriğe geç", exact: true })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();
  const toggle = page.getByRole("button", { name: "Menü", exact: true });
  await toggle.press("Enter");
  const navigation = page.getByRole("navigation", { name: "Ana gezinme" });
  await navigation.getByRole("link", { name: "Test Talep Et", exact: true }).press("Tab");
  await expect(navigation).toBeHidden();
  await toggle.press("Enter");
  await page.keyboard.press("Escape");
  await expect(toggle).toBeFocused();
  await toggle.press("Enter");
  await navigation.getByRole("link", { name: "Test Talep Et", exact: true }).press("Enter");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).press("Enter");
  await expect(page.getByRole("main").getByRole("alert")).toBeFocused();
  await page.getByRole("main").getByRole("alert").getByRole("link", { name: /^Adınız:/ }).press("Enter");
  const input = page.getByLabel("Adınız", { exact: true });
  await expect(input).toBeFocused();
  await expect(input).toHaveAttribute("aria-invalid", "true");
  await expect(input).toHaveAttribute("aria-describedby", "name-error");
  expect(await input.evaluate((element) => getComputedStyle(element).outlineStyle)).not.toBe("none");
  const box = await input.boundingBox();
  const header = await page.locator(".site-header").boundingBox();
  expect(box!.y).toBeGreaterThanOrEqual(header!.height);
});
