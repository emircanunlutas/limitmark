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
      "no-restricted-imports": ["error", { patterns: [
        { group: ["**/lab", "**/lab/**"], message: "lab/ is local-only tooling and must never be imported by application, worker, operator or deployment code." },
        { group: ["**/defense", "**/defense/**"], message: "defense/ is an isolated runtime boundary; application and control-plane code must never import it." },
      ] }],
    },
  },
  {
    // The Defense Plane is an isolated runtime boundary: it may import only its own files and node: built-ins.
    files: ["defense/**/*.ts"],
    rules: {
      "no-restricted-imports": ["error", { patterns: [{ group: ["@/*", "**/src", "**/src/**", "**/operator", "**/operator/**", "**/scripts", "**/scripts/**", "**/deployment", "**/deployment/**", "**/workers", "**/workers/**", "**/lab", "**/lab/**"], message: "defense/ must not import src/, operator/, scripts/, deployment/, workers/ or lab/." }] }],
    },
  },
  globalIgnores([".next/**", "next-env.d.ts", ".npm-cache/**", ".playwright/**", ".wrangler/**", "artifacts/**", "test-results/**", "playwright-report/**"]),
]);
