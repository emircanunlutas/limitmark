import { defineConfig, devices } from "@playwright/test";

// Run against a build made with the CONTACT_EMAIL value under test.
// Unlike the demo journey suite, this server deliberately has no demo opt-in.
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
    env: { ALLOW_DEMO_SUBMISSIONS: "false", REQUEST_SUBMISSION_MODE: "demo" },
  },
});
