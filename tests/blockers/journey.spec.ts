import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { assertFallback, blockReason, installAudit, isOptionalPrefetchCancellation, type Profile } from "./blocker-harness";

async function settle(page: Page) {
  // Let requests settle; verified speculative cancellations remain in the audit.
  await page.waitForLoadState("networkidle");
}

async function fillValidRequest(page: Page) {
  await page.goto("/test-talep-et");
  await settle(page);
  await page.locator("#name").fill("Çağrı Öztürk");
  await page.locator("#email").fill("qa@example.test");
  await page.locator("#system").fill("Hazırlık ortamı");
  await page.locator("#objective").fill("Kontrollü yük altında erişim davranışı");
  await page.locator("#environment").selectOption("staging");
  await page.locator('input[value="uncertain"]').check();
}

test("blocked third parties do not prevent recovery from a failed submission transport", async ({ context, page, baseURL }, info) => {
  const audit = await installAudit(context, page, baseURL!, "third-party-and-tracking", info, { failFirstSubmission: true });
  try {
    await page.setViewportSize({ width: 375, height: 812 });
    await fillValidRequest(page);
    await page.locator(".form-extras summary").press("Enter");
    await page.locator("#protection").selectOption("using");
    await page.locator("#provider").fill("Örnek sağlayıcı");
    const submit = page.getByRole("button", { name: "Talebi Gönder", exact: true });
    await submit.click();
    const alert = page.getByRole("main").getByRole("alert");
    await expect(alert).toContainText("Talebiniz iletilemedi.");
    await expect(alert).toBeFocused();
    await expect(page).toHaveURL("/test-talep-et");
    await expect(submit).toBeEnabled();
    await expect(page.locator("#name")).toHaveValue("Çağrı Öztürk");
    await expect(page.locator("#provider")).toHaveValue("Örnek sağlayıcı");
    await expect(page.locator("#environment")).toHaveValue("staging");
    await assertLayout(page);
    await submit.click();
    await expect(page).toHaveURL("/test-talep-et/tesekkurler");
    await settle(page);
    await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı.", exact: true })).toBeVisible();
    expect(audit.requests.filter((request) => request.method === "POST")).toHaveLength(2);
    expect(audit.blocked.some((request) => request.reason === "third-party")).toBe(true);
    audit.assertHealthy();
  } finally { await audit.save(); }
});

for (const profile of ["observe", "third-party-and-tracking"] as const) {
test(`${profile}: without JavaScript preserves server validation and native submission`, async ({ browser, baseURL }, info) => {
  const context = await browser.newContext({ baseURL, javaScriptEnabled: false, viewport: { width: 320, height: 900 }, serviceWorkers: "block" });
  const page = await context.newPage();
  const audit = await installAudit(context, page, baseURL!, profile, info, { javaScriptDisabled: true });
  try {
    await fillValidRequest(page);
    await page.locator(".form-extras summary").press("Enter");
    await page.locator("#notes").fill("Sentetik QA notu");
    await page.locator("#email").fill("invalid");
    await Promise.all([
      page.waitForNavigation({ waitUntil: "load" }),
      page.getByRole("button", { name: "Talebi Gönder", exact: true }).click(),
    ]);
    await expect(page.getByRole("main").getByRole("alert")).toContainText("Lütfen işaretli alanları kontrol edin.");
    await expect(page.locator("#email")).toHaveAttribute("aria-invalid", "true");
    await expect(page.locator("#name")).toHaveValue("Çağrı Öztürk");
    await expect(page.locator("#notes")).toHaveValue("Sentetik QA notu");
    await assertLayout(page);
    await page.locator("#email").fill("qa@example.test");
    await Promise.all([
      page.waitForNavigation({ waitUntil: "load" }),
      page.getByRole("button", { name: "Talebi Gönder", exact: true }).click(),
    ]);
    await expect(page).toHaveURL("/test-talep-et/tesekkurler");
    await settle(page);
    await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı.", exact: true })).toBeVisible();
    expect(audit.requests.filter((request) => request.method === "POST")).toHaveLength(2);
    if (profile !== "observe") expect(audit.blocked.some((request) => request.reason === "third-party")).toBe(true);
    audit.assertHealthy();
  } finally { await audit.save(); await context.close(); }
});
}

async function assertLayout(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.getByRole("main")).toBeVisible();
}

test("simulation rules block representative tracker names but allow the real first-party path", ({ baseURL }) => {
  const origin = baseURL!;
  for (const path of ["/analytics.js", "/api/telemetry", "/tracking/pixel.gif", "/collect", "/ads/banner.js", "/beacon"]) {
    expect(blockReason("tracking-only", origin + path, "fetch", origin), path).toBe("tracker-like");
  }
  for (const address of ["https://www.google-analytics.com/g/collect", "https://www.googletagmanager.com/gtm.js", "https://cdn.segment.com/v1.js"]) {
    expect(blockReason("tracking-only", address, "script", origin)).toBe("tracker-like");
  }
  for (const path of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/gizlilik", "/test-yetkilendirmesi", "/_next/static/chunks/abc123.js", "/_next/static/chunks/def456.css", "/?hizmet=web&_rsc=abc123", "/download", "/header.js"]) {
    expect(blockReason("third-party-and-tracking", origin + path, "fetch", origin), path).toBeNull();
  }
  expect(blockReason("third-party-and-tracking", "https://fonts.googleapis.com/css2?family=Inter", "stylesheet", origin)).toBe("third-party");
  expect(blockReason("font-files", "https://fonts.gstatic.com/font.woff2", "font", origin)).toBe("font-file");
  const prefetch = { method: "GET", type: "fetch", prefetch: true, error: "net::ERR_ABORTED" };
  expect(isOptionalPrefetchCancellation(prefetch)).toBe(true);
  for (const change of [{ method: "POST" }, { type: "document" }, { prefetch: false }, { error: "net::ERR_CONNECTION_REFUSED" }, { error: "net::ERR_BLOCKED_BY_CLIENT" }]) {
    expect(isOptionalPrefetchCancellation({ ...prefetch, ...change })).toBe(false);
  }
});

test("unblocked inventory identifies external dependencies and resource names", async ({ context, page, baseURL }, info) => {
  const audit = await installAudit(context, page, baseURL!, "observe", info);
  try {
    for (const route of ["/", "/test-talep-et", "/test-talep-et/tesekkurler"]) {
      await page.goto(route);
      await settle(page);
      await page.evaluate(() => document.fonts.ready);
      await assertLayout(page);
    }
    const origin = new URL(baseURL!).origin;
    const external = audit.requests.filter((request) => new URL(request.url).origin !== origin);
    expect(external.length).toBeGreaterThan(0);
    for (const request of external) {
      expect(["fonts.googleapis.com", "fonts.gstatic.com"]).toContain(new URL(request.url).hostname);
      expect(["stylesheet", "font"]).toContain(request.type);
    }
    expect(audit.requests.filter((request) => blockReason("tracking-only", request.url, request.type, origin)), "Observed tracker-like names").toEqual([]);
    audit.observations.externalOrigins = [...new Set(external.map((request) => new URL(request.url).origin))];
    audit.assertHealthy();
  } finally { await audit.save(); }
});

const scenarios: { profile: Profile; width: number; optional: boolean }[] = [
  ...(["observe", "tracking-only", "third-party-and-tracking", "font-files"] as const).flatMap((profile) => [1440, 375].map((width) => ({ profile, width, optional: true }))),
  { profile: "third-party-and-tracking", width: 320, optional: false },
];

for (const { profile, width, optional } of scenarios) {
  test(`${profile}: complete journey at ${width}px, optional fields ${optional ? "populated" : "closed"}`, async ({ context, page, baseURL }, info) => {
    const audit = await installAudit(context, page, baseURL!, profile, info);
    try {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/");
      await settle(page);
      await assertLayout(page);
      await expect(page.getByRole("heading", { level: 1 })).toContainText("Ölçün.");
      if (profile !== "tracking-only" && profile !== "observe") audit.observations.fallback = await assertFallback(page);
      await page.screenshot({ path: info.outputPath("homepage.png") });

      const navigation = page.getByRole("navigation", { name: "Ana gezinme" });
      if (width < 1024) {
        await page.getByRole("button", { name: "Menü", exact: true }).press("Enter");
        await expect(navigation).toBeVisible();
        await page.keyboard.press("Escape");
        await expect(page.getByRole("button", { name: "Menü", exact: true })).toBeFocused();
      }
      for (const [label, anchor] of [["Hizmetler", "hizmetler"], ["Süreç", "surec"], ["Metodoloji", "metodoloji"], ["SSS", "sss"]]) {
        if (width < 1024) await page.getByRole("button", { name: "Menü", exact: true }).click();
        await navigation.getByRole("link", { name: label, exact: true }).click();
        await expect(page).toHaveURL(new RegExp(`#${anchor}$`));
        const heading = page.locator(`#${anchor} h2`);
        await expect(heading).toBeVisible();
        expect((await heading.boundingBox())!.y).toBeGreaterThanOrEqual((await page.locator(".site-header").boundingBox())!.height);
        if (width < 1024) await expect(navigation).toBeHidden();
      }
      await page.locator(".technical-disclosure summary").press("Enter");
      await expect(page.locator(".technical-disclosure")).toHaveAttribute("open", "");
      await page.locator(".faq-item summary").nth(0).press("Enter");
      await page.locator(".faq-item summary").nth(1).press("Space");
      await expect(page.locator(".faq-item[open]")).toHaveCount(2);
      await assertLayout(page);
      await settle(page);

      await page.getByRole("link", { name: "Web Uygulaması Dayanıklılık Testi — Bu Testi Görüşelim", exact: true }).click();
      await expect(page.locator("#service")).toHaveValue("web");
      await page.locator("#service").selectOption("network");
      await settle(page);
      const submit = page.getByRole("button", { name: "Talebi Gönder", exact: true });
      await submit.click();
      await expect(page.getByRole("main").getByRole("alert")).toBeFocused();
      await expect(page.locator("#name")).toHaveAttribute("aria-invalid", "true");
      await page.locator("#name").fill("Çağrı Öztürk");
      await page.locator("#email").fill("not-an-email");
      await submit.click();
      await expect(page.locator("#name")).toHaveValue("Çağrı Öztürk");
      await expect(page.locator("#email")).toHaveAttribute("aria-invalid", "true");
      await page.locator("#email").fill("qa@example.test");
      await page.locator("#system").fill("Kuruluşumuza ait hazırlık uygulaması");
      await page.locator("#objective").fill("Kontrollü yük altında erişim davranışı");
      await page.locator("#environment").selectOption("staging");
      await page.locator('input[value="uncertain"]').check();
      await expect(page.locator(".context-note")).toBeVisible();
      const extras = page.locator(".form-extras");
      await expect(extras).not.toHaveAttribute("open");
      if (optional) {
        await extras.locator("summary").press("Enter");
        await page.locator("#protection").selectOption("using");
        await page.locator("#provider").fill("Örnek sağlayıcı");
        await page.locator("#notes").fill("Gizli erişim bilgisi içermeyen sentetik QA notu.");
        await page.locator("#protection").selectOption("none");
        await expect(page.locator("#provider")).toHaveCount(0);
        await page.locator("#protection").selectOption("using");
        await expect(page.locator("#provider")).toHaveValue("Örnek sağlayıcı");
        await extras.locator("summary").press("Space");
        await extras.locator("summary").press("Enter");
        await expect(page.locator("#notes")).toHaveValue("Gizli erişim bilgisi içermeyen sentetik QA notu.");
      }
      await assertLayout(page);
      audit.assertHealthy(); // Check application behavior before injecting Axe.
      // Probe evidence: at the same y=45.5 both the unblocked and blocked Firefox
      // pages report the sticky header as a radio neighbor. Assess the controls
      // in their actionable viewport, retaining all Axe rules and the full page.
      await page.locator("#authority").evaluate((group) => group.scrollIntoView({ block: "center" }));
      for (const value of ["owner", "authorized", "uncertain"]) {
        const input = page.locator(`input[value="${value}"]`);
        const label = page.locator(".radio-option").filter({ has: input });
        expect((await label.boundingBox())!.height).toBeGreaterThanOrEqual(44);
        await label.click();
        await expect(input).toBeChecked();
      }
      await page.locator("#authority").evaluate((group) => group.scrollIntoView({ block: "center" }));
      audit.observations.radioGeometry = await page.locator('input[value="owner"]').evaluate((input) => {
        const rect = input.getBoundingClientRect();
        const label = input.closest("label")!.getBoundingClientRect();
        return { input: rect.toJSON(), label: label.toJSON(), centerHit: document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2)?.outerHTML };
      });
      const accessibility = await audit.runAxe(() => new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze());
      audit.observations.axeViolations = accessibility.violations;
      audit.observations.axeIncomplete = accessibility.incomplete.map((result) => ({ id: result.id, impact: result.impact, nodeCount: result.nodes.length }));
      expect(accessibility.violations).toEqual([]);
      await page.screenshot({ path: info.outputPath("form.png") });
      await submit.click();
      await expect(page).toHaveURL("/test-talep-et/tesekkurler");
      await settle(page);
      await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı.", exact: true })).toBeVisible();
      await expect(page.getByText("gerçek bir talep oluşturulmadı", { exact: false })).toBeVisible();
      expect(audit.requests.filter((request) => request.method === "POST" && new URL(request.url).pathname === "/test-talep-et")).toHaveLength(1);
      await page.reload();
      await settle(page);
      await assertLayout(page);

      await page.getByRole("navigation", { name: "Bilgilendirme" }).getByRole("link", { name: "Gizlilik", exact: true }).click();
      await expect(page.getByRole("heading", { level: 1 })).toHaveText("Gizlilik");
      await settle(page);
      await page.getByRole("navigation", { name: "Alt gezinme" }).getByRole("link", { name: "Hizmetler", exact: true }).click();
      await expect(page).toHaveURL(/\/#hizmetler$/);
      await expect(page.locator("#hizmetler h2")).toBeVisible();
      await settle(page);
      if (profile === "third-party-and-tracking") expect(audit.blocked.some((request) => new URL(request.url).hostname === "fonts.googleapis.com")).toBe(true);
      if (profile === "font-files") expect(audit.blocked.some((request) => request.type === "font")).toBe(true);
      audit.assertHealthy();
    } finally { await audit.save(); }
  });
}
