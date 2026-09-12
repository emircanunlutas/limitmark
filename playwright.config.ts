import { defineConfig, devices } from "@playwright/test";

const development = process.env.QA_DEV === "true";
const port = development ? 3000 : 3100;
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  workers: 1,
  globalTimeout: 300_000,
  reporter: "list",
  use: {
    baseURL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ].filter((project) => project.name === "chromium" || process.env.QA_CROSS_BROWSER === "true"),
  webServer: {
    command: `node node_modules/next/dist/bin/next ${development ? "dev" : "start"} --hostname 127.0.0.1 --port ${port}`,
    url: baseURL,
    reuseExistingServer: development,
    env: { ALLOW_DEMO_SUBMISSIONS: "true", REQUEST_SUBMISSION_MODE: "demo", PUBLIC_DEMO_ORIGIN: baseURL },
  },
});
