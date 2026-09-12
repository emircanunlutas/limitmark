import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/configuration",
  workers: 1,
  globalTimeout: 60_000,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:3100", trace: "retain-on-failure", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3100",
    url: "http://127.0.0.1:3100",
    reuseExistingServer: false,
    env: {
      VERCEL: "1",
      VERCEL_ENV: "production",
      CONTACT_EMAIL: "inquiries@example.test",
      ALLOW_DEMO_SUBMISSIONS: "true",
      REQUEST_SUBMISSION_MODE: "postgres",
      ENABLE_PERSISTENT_SUBMISSIONS: "true",
      DATABASE_URL: "deliberately-malformed",
    },
  },
});
