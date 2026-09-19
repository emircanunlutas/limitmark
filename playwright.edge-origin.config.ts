import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/edge-origin",
  workers: 1,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:3101" },
  webServer: {
    command: "node node_modules/next/dist/bin/next start --hostname 127.0.0.1 --port 3101",
    port: 3101,
    reuseExistingServer: false,
    env: {
      PUBLIC_ORIGIN_PROTECTION: "required",
      PUBLIC_ORIGIN_SECRET: "A".repeat(43),
      VERCEL: "1", VERCEL_ENV: "production",
      REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "false",
      TURNSTILE_MODE: "disabled",
      CRON_SECRET: "B".repeat(43),
      DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
    },
  },
});
