import { expect, test } from "@playwright/test";

const secret = "A".repeat(43);
const trusted = { host: "limitmark.com", "x-forwarded-host": "limitmark.com", "x-limitmark-origin-secret": secret };

test("enabled origin boundary denies direct and spoofed requests on the built server", async ({ request }) => {
  const cases: Record<string, string>[] = [
    {}, { host: "limitmark.com", "x-forwarded-host": "limitmark.com" },
    { host: "limitmark.com", "cf-connecting-ip": "203.0.113.9", "cf-ray": "synthetic" },
    { ...trusted, "x-limitmark-origin-secret": "wrong" },
    { ...trusted, "x-forwarded-host": "limitmark.com, attacker.example" },
    { ...trusted, host: "deployment.vercel.app", "x-forwarded-host": "deployment.vercel.app" },
    { "x-middleware-subrequest": "src/proxy:src/proxy:src/proxy:src/proxy:src/proxy" },
  ];
  for (const headers of cases) {
    const response = await request.get("/test-talep-et", { headers });
    expect(response.status()).toBe(404);
    expect(response.headers()["cache-control"]).toContain("no-store");
    expect(response.headers()["cdn-cache-control"]).toBe("no-store");
    expect(await response.text()).toBe("");
  }
  const action = await request.post("/test-talep-et", { headers: { "next-action": "synthetic" }, data: "[]" });
  expect(action.status()).toBe(404);
});

test("authenticated origin navigation works without reflecting its credential or enabling persistence", async ({ request }) => {
  for (const host of ["limitmark.com", "www.limitmark.com"]) {
    const response = await request.get("/test-talep-et", { headers: { ...trusted, host, "x-forwarded-host": host } });
    expect(response.status()).toBe(200);
    const html = await response.text();
    expect(html).toContain('name="submissionToken"');
    expect(html).not.toContain(secret);
    expect(html).not.toContain("challenges.cloudflare.com/turnstile");
    expect(JSON.stringify(response.headers())).not.toContain(secret);
    expect(response.headers()["cache-control"]).toContain("no-store");
  }
});

test("admin remains independently denied and its immutable assets remain reachable", async ({ request }) => {
  const response = await request.get("/admin", { headers: { host: "admin.limitmark.com" } });
  expect(response.status()).toBe(404);
  expect(response.headers()["cache-control"]).toContain("no-store");
  const publicPage = await request.get("/", { headers: trusted });
  expect(publicPage.status()).toBe(200);
  const asset = (await publicPage.text()).match(/src="([^" ]*\/_next\/static\/[^" ]+\.js)"/)?.[1];
  expect(asset).toBeTruthy();
  const assetResponse = await request.get(asset!, { headers: { host: "admin.limitmark.com" } });
  expect(assetResponse.status()).toBe(200);
});
