import { defineConfig } from "drizzle-kit";

const migrationUrl = process.env.DATABASE_MIGRATION_URL;
if (!migrationUrl) throw new Error("DATABASE_MIGRATION_URL is required for migration commands");

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/lib/db/schema.ts",
  out: "./drizzle",
  dbCredentials: { url: migrationUrl },
  strict: true,
  verbose: true,
});
