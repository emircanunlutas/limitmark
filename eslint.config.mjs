import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  {
    // The field-lab tooling is local-only and must never become an application dependency.
    files: ["src/**/*.{ts,tsx}", "workers/**/*.ts", "operator/**/*.ts", "deployment/**/*.ts", "scripts/**/*.ts", "next.config.ts", "drizzle.config.ts"],
    rules: {
      "no-restricted-imports": ["error", { patterns: [{ group: ["**/lab", "**/lab/**"], message: "lab/ is local-only tooling and must never be imported by application, worker, operator or deployment code." }] }],
    },
  },
  globalIgnores([".next/**", "next-env.d.ts", ".npm-cache/**", ".playwright/**", ".wrangler/**", "artifacts/**", "test-results/**", "playwright-report/**"]),
]);
