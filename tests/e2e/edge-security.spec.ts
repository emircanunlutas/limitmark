import { expect, test } from "@playwright/test";

test("security headers and sensitive-route cache policies survive the production server", async ({ request }) => {
  for (const path of ["/", "/test-talep-et", "/test-talep-et/tesekkurler", "/admin", "/admin/inquiries/00000000-0000-4000-8000-000000000001"]) {
    const response = await request.get(path);
    const headers = response.headers();
    expect(headers["content-security-policy"]).toBe("frame-ancestors 'none'; object-src 'none'; base-uri 'self'");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers["permissions-policy"]).toBe("camera=(), microphone=(), geolocation=()");
    if (path !== "/") {
      expect(headers["cache-control"]).toContain("no-store");
      expect(headers["cdn-cache-control"]).toBe("no-store");
    }
    if (path.startsWith("/admin")) expect(response.status()).toBe(404);
  }
});

test("direct-origin admin remains denied despite Host and Cloudflare spoofing", async ({ request }) => {
  const response = await request.get("/admin", { headers: {
    host: "admin.limitmark.com", "x-forwarded-host": "admin.limitmark.com",
    "cf-connecting-ip": "203.0.113.9", "x-limitmark-origin-secret": "A".repeat(43),
    "cf-access-jwt-assertion": "forged.token.value",
  } });
  expect(response.status()).toBe(404);
  expect(response.headers()["cache-control"]).toContain("no-store");
});

test("real Server Action retains the same-origin check behind a preserved public host", async ({ browser, request, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.goto(`${baseURL}/test-talep-et`);
  // useActionState emits bound-action metadata; replay the actual rendered
  // native form fields instead of assuming an unbound $ACTION_ID convention.
  const hidden = await page.locator('input[type="hidden"]').evaluateAll((inputs) =>
    Object.fromEntries(inputs.map((input) => [(input as HTMLInputElement).name, (input as HTMLInputElement).value])));
  expect(Object.keys(hidden).some((name) => name.startsWith("$ACTION_"))).toBe(true);
  const multipart = { ...hidden, name: "Synthetic QA", email: "qa@example.test",
    service: "web", system: "Staging", objective: "Verify origin boundary", environment: "staging", authority: "authorized" };
  for (const host of ["limitmark.com", "www.limitmark.com"]) {
    const response = await request.post("/test-talep-et", { multipart, maxRedirects: 0,
      headers: { host, "x-forwarded-host": host, origin: `https://${host}` } });
    expect(response.status()).toBe(303);
    expect(response.headers()["location"]).toBe("/test-talep-et/tesekkurler");
    expect(response.headers()["cache-control"]).toContain("no-store");
  }
  for (const origin of ["https://attacker.example", "null"]) {
    const response = await request.post("/test-talep-et", { multipart, maxRedirects: 0,
      headers: { host: "limitmark.com", "x-forwarded-host": "limitmark.com", origin } });
    expect(response.status()).toBeGreaterThanOrEqual(400);
    expect(response.headers()["location"]).toBeUndefined();
  }
  const oversized = await request.post("/test-talep-et", { multipart: { ...multipart, notes: "x".repeat(40_000) }, maxRedirects: 0,
    headers: { host: "limitmark.com", "x-forwarded-host": "limitmark.com", origin: "https://limitmark.com" } });
  expect(oversized.status()).toBeGreaterThanOrEqual(400);
  expect(oversized.headers()["location"]).toBeUndefined();
  await context.close();
});
