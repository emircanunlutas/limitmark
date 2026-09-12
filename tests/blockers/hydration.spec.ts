import { test, expect } from "@playwright/test";
import { installAudit } from "./blocker-harness";

for (const profile of ["observe", "third-party-and-tracking"] as const) {
  test(`${profile}: native draft survives delayed hydration and the next edit`, async ({ context, page, baseURL }, info) => {
    const audit = await installAudit(context, page, baseURL!, profile, info, { delayedHydration: true });
    let releaseScripts: () => void = () => {};
    const scriptsReady = new Promise<void>((resolve) => { releaseScripts = resolve; });
    let heldScripts = 0;
    // Hold first-party scripts without blocking the native server-rendered form.
    // This is a deterministic timing probe, separate from the privacy rules.
    await context.route("**/*", async (route) => {
      if (route.request().resourceType() === "script" && new URL(route.request().url()).origin === new URL(baseURL!).origin) {
        heldScripts++;
        await scriptsReady;
      }
      await route.fallback();
    });
    try {
      await page.setViewportSize({ width: 375, height: 900 });
      await page.goto("/test-talep-et", { waitUntil: "commit" });
      const draft = {
        name: "Çağrı Öztürk", email: "qa@example.test", system: "Hazırlık sistemi",
        objective: "Kontrollü erişim\nÖlçüm", notes: "Sentetik erken giriş notu",
      };
      await page.locator(".form-extras summary").press("Enter");
      for (const [field, value] of Object.entries(draft)) await page.locator(`#${field}`).fill(value);
      await page.locator("#service").selectOption("network");
      await page.locator("#environment").selectOption("staging");
      await page.locator('input[value="uncertain"]').check();
      await page.locator("#protection").selectOption("using");
      await expect(page.locator("#provider")).toHaveCount(0); // Still native, before React.
      expect(heldScripts).toBeGreaterThan(0);
      releaseScripts();
      await page.waitForLoadState("networkidle");
      // The conditional provider is visible only when hydrated state adopts the
      // native selection. Editing another field must not wipe the earlier draft.
      await expect(page.locator("#provider")).toBeVisible();
      await expect(page.locator(".context-note")).toBeVisible();
      await page.locator("#company").fill("Sentetik kuruluş");
      for (const [field, value] of Object.entries(draft)) await expect(page.locator(`#${field}`)).toHaveValue(value);
      await expect(page.locator("#service")).toHaveValue("network");
      await expect(page.locator("#environment")).toHaveValue("staging");
      await expect(page.locator('input[value="uncertain"]')).toBeChecked();
      await expect(page.locator("#protection")).toHaveValue("using");
      await page.locator("#provider").fill("Örnek sağlayıcı");
      await page.locator("#protection").selectOption("none");
      await expect(page.locator("#provider")).toHaveCount(0);
      await page.locator("#protection").selectOption("using");
      await expect(page.locator("#provider")).toHaveValue("Örnek sağlayıcı");
      await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
      await expect(page).toHaveURL("/test-talep-et/tesekkurler");
      await page.waitForLoadState("networkidle");
      await expect(page.getByRole("heading", { name: "Demo akışı tamamlandı.", exact: true })).toBeVisible();
      expect(audit.requests.filter((request) => request.method === "POST")).toHaveLength(1);
      if (profile !== "observe") expect(audit.blocked.some((request) => request.reason === "third-party")).toBe(true);
      audit.observations.heldScripts = heldScripts;
      audit.assertHealthy();
    } finally {
      releaseScripts();
      await audit.save();
    }
  });
}
