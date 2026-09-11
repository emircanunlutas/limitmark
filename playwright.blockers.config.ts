import { defineConfig } from "@playwright/test";
import baseline from "./playwright.config";

// Keep each run's diagnostics; later E2E runs may clear the default test-results.
const runDirectory = process.env.QA_BLOCKER_RUN_DIRECTORY ??= `artifacts/blocker-runs/${new Date().toISOString().replace(/[.:]/g, "-")}`;

export default defineConfig({
  ...baseline,
  testDir: "./tests/blockers",
  outputDir: `${runDirectory}/tests`,
  globalTimeout: 240_000,
  reporter: [["list"], ["json", { outputFile: `${runDirectory}/report.json` }]],
  use: { ...baseline.use, baseURL: "http://127.0.0.1:3100", serviceWorkers: "block" },
  webServer: {
    command: "node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3100",
    url: "http://127.0.0.1:3100",
    reuseExistingServer: false,
    env: { ALLOW_DEMO_SUBMISSIONS: "true", REQUEST_SUBMISSION_MODE: "demo" },
  },
});
