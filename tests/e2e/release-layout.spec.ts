import { test, expect } from "@playwright/test";

test("expanded layout and mobile menu fit all target sizes", async ({ page }) => {
  for (const [width, height] of [[320, 568], [360, 740], [375, 812], [390, 844], [430, 932], [768, 1024], [1024, 768], [1280, 900], [1440, 900], [1920, 1080], [667, 320], [320, 1400]]) {
    await page.setViewportSize({ width, height });
    await page.goto("/");
    await page.locator(".technical-disclosure summary").click();
    for (const summary of await page.locator(".faq-item summary").all()) await summary.click();
    if (width < 1024) await page.getByRole("button", { name: "Menü", exact: true }).click();
    expect(await page.evaluate(() => document.documentElement.scrollWidth), `${width}x${height}`).toBeLessThanOrEqual(width);
    if (width < 1024) {
      const menu = page.getByRole("navigation", { name: "Ana gezinme" });
      const box = await menu.boundingBox();
      expect(box).not.toBeNull();
      expect(box!.y + box!.height).toBeLessThanOrEqual(height + 1);
      await menu.getByRole("link", { name: "Test Talep Et", exact: true }).click();
    } else await page.goto("/test-talep-et");
    await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
    await page.locator(".form-extras summary").click();
    const overflow = await page.locator("body *").evaluateAll((elements) => elements.filter((element) => element.getBoundingClientRect().right > innerWidth || element.scrollWidth > element.clientWidth + 1).map((element) => `${element.tagName}.${element.className}: right=${element.getBoundingClientRect().right}, scroll=${element.scrollWidth}, client=${element.clientWidth}`));
    expect(await page.evaluate(() => document.documentElement.scrollWidth), `form ${width}x${height}\n${overflow.join("\n")}`).toBeLessThanOrEqual(width);
  }
});

test("200 percent text at the narrowest width keeps controls and menu usable", async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await page.goto("/");
  await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
  await page.getByRole("button", { name: "Menü", exact: true }).click();
  const overflowing = await page.locator("body *").evaluateAll((elements) => elements.filter((element) => element.getBoundingClientRect().right > window.innerWidth).map((element) => `${element.tagName}.${element.className}: ${element.getBoundingClientRect().right}`));
  expect(await page.evaluate(() => document.documentElement.scrollWidth), overflowing.join("\n")).toBeLessThanOrEqual(320);
  await page.getByRole("navigation", { name: "Ana gezinme" }).getByRole("link", { name: "Test Talep Et", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Test Talep Et", exact: true })).toBeVisible();
  await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
  await page.locator(".form-extras summary").press("Enter");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});
