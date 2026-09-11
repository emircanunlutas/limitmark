import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

test("production pages have no runtime errors and retain usable geometry after fonts load", async ({ page, baseURL }, testInfo) => {
  const errors: string[] = [];
  const failedResponses: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error" || message.type() === "warning") errors.push(message.text());
  });
  page.on("response", (response) => {
    if (response.url().startsWith(baseURL!) && response.status() >= 400) failedResponses.push(`${response.status()} ${response.url()}`);
  });
  for (const width of [1440, 375]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.evaluate(() => document.fonts.ready);
    await page.screenshot({ path: testInfo.outputPath(`home-${width}.png`) });
    await page.locator("#surec").scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`process-${width}.png`) });
    await page.goto("/test-talep-et");
    await page.waitForLoadState("networkidle");
    await page.evaluate(() => document.fonts.ready);
    await page.locator(".form-extras summary").press("Enter");
    await page.locator("#protection").selectOption("using");
    await page.locator("#provider").fill("Örnek sağlayıcı");
    await page.locator("#notes").fill("Bu yalnızca sentetik QA verisidir.");
    await page.locator(".form-extras").scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath(`optional-${width}.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    expect((await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze()).violations).toEqual([]);
    await testInfo.attach(`resources-${width}.json`, {
      body: JSON.stringify(await page.evaluate(() => performance.getEntriesByType("resource").map((entry) => {
        const resource = entry as PerformanceResourceTiming;
        return { name: resource.name, type: resource.initiatorType, encodedBytes: resource.encodedBodySize };
      })), null, 2), contentType: "application/json",
    });
  }
  expect(errors).toEqual([]);
  expect(failedResponses).toEqual([]);
});
