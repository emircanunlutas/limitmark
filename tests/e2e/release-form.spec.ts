import { test, expect, type Page } from "@playwright/test";

async function fillRequest(page: Page) {
  await page.goto("/test-talep-et");
  await page.getByLabel("Adınız", { exact: true }).fill("Çağrı Öztürk");
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("qa@example.test");
  await page.getByLabel("Test etmek istediğiniz sistem", { exact: true }).fill("Hazırlık ortamı");
  await page.getByLabel("Testten ne öğrenmek istiyorsunuz?", { exact: true }).fill("Erişim davranışını öğrenmek istiyoruz.");
  await page.getByLabel("Test edilecek ortam", { exact: true }).selectOption("staging");
  await page.getByLabel("Henüz test yetkim yok / yetkimden emin değilim.", { exact: true }).check();
}

test("a fresh render gets a new token while client-side validation preserves its token", async ({ page }) => {
  await page.goto("/test-talep-et");
  const tokenField = page.locator('input[name="submissionToken"]');
  const firstToken = await tokenField.inputValue();
  expect(firstToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
  await expect(tokenField).toHaveValue(firstToken);
  await page.reload();
  await expect(tokenField).not.toHaveValue(firstToken);
  expect(await tokenField.inputValue()).toMatch(/^[A-Za-z0-9_-]{43}$/);
});

test("maximum-length multiline text is accepted consistently by client and server", async ({ page }) => {
  await fillRequest(page);
  await page.getByLabel("Test etmek istediğiniz sistem", { exact: true }).fill("a".repeat(998) + "\nb");
  await page.getByLabel("Testten ne öğrenmek istiyorsunuz?", { exact: true }).fill("ç".repeat(1998) + "\nğ");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
});

test("a failed submission transport preserves the form and permits retry", async ({ page }) => {
  await fillRequest(page);
  const submissionToken = await page.locator('input[name="submissionToken"]').inputValue();
  expect(submissionToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  await page.route("**/test-talep-et", async (route) => {
    if (route.request().method() === "POST") await route.abort("failed");
    else await route.continue();
  });
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
  await expect(page.getByLabel("Adınız", { exact: true })).toHaveValue("Çağrı Öztürk");
  await expect(page.locator('input[name="submissionToken"]')).toHaveValue(submissionToken);
  await page.unroute("**/test-talep-et");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
});

test("server validation without JavaScript retains valid entries for correction", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, baseURL });
  const page = await context.newPage();
  await fillRequest(page);
  const submissionToken = await page.locator('input[name="submissionToken"]').inputValue();
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("invalid");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
  await expect(page.getByLabel("Adınız", { exact: true })).toHaveValue("Çağrı Öztürk");
  await expect(page.getByLabel("Test etmek istediğiniz sistem", { exact: true })).toHaveValue("Hazırlık ortamı");
  await expect(page.locator('input[name="submissionToken"]')).toHaveValue(submissionToken);
  await page.getByLabel("E-posta adresiniz", { exact: true }).fill("qa@example.test");
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  await context.close();
});

test("rapid duplicate clicks create only one in-flight submission", async ({ page }) => {
  await fillRequest(page);
  let posts = 0;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/test-talep-et", async (route) => {
    if (route.request().method() === "POST") { posts++; await held; }
    await route.continue();
  });
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).dblclick();
  await expect(page.getByRole("button", { name: "Gönderiliyor…", exact: true })).toBeDisabled();
  expect(posts).toBeLessThanOrEqual(1);
  release();
  await expect(page).toHaveURL("/test-talep-et/tesekkurler");
  expect(posts).toBe(1);
});

test("a server validation response does not reset unrelated selects and radios", async ({ page }) => {
  await fillRequest(page);
  await page.route("**/test-talep-et", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    const body = route.request().postData()!;
    expect(body).toContain("\r\nstaging\r\n");
    await route.continue({ postData: body.replace("\r\nstaging\r\n", "\r\ninvalid-environment\r\n") });
  });
  await page.getByRole("button", { name: "Talebi Gönder", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
  await expect(page.getByLabel("Test edilecek ortam", { exact: true })).toHaveValue("staging");
  await expect(page.getByLabel("Henüz test yetkim yok / yetkimden emin değilim.", { exact: true })).toBeChecked();
});
