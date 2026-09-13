import assert from "node:assert/strict";
import test from "node:test";
import { getAdminDatabaseConfiguration } from "../src/lib/admin-database-config";
import { resolveAdminDataRepository } from "../src/lib/admin-inquiry-data";
import { getDatabaseRuntimeConfiguration } from "../src/lib/database-runtime-config";
import { getPersistenceConfiguration } from "../src/lib/persistence-config";

const database = {
  DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
  DATABASE_POOL_MAX: "2",
};
const production = { ...database, VERCEL: "1", VERCEL_ENV: "production", VERCEL_PROJECT_ID: "prj_shared_p",
  VERCEL_DEPLOYMENT_ID: "dpl_shared_p", VERCEL_AUTOMATION_BYPASS_SECRET: "platform-injected-B-public" };

test("admin customer-data configuration requires exact Vercel Production", async () => {
  for (const environment of [
    { ...production, VERCEL_ENV: "preview" },
    { ...production, VERCEL_ENV: "development" },
    { ...production, VERCEL_ENV: undefined },
    { ...production, VERCEL: undefined },
  ]) {
    assert.deepEqual(getAdminDatabaseConfiguration(environment), { enabled: false, reason: "deployment-boundary" });
    let constructions = 0;
    const repository = await resolveAdminDataRepository(environment, async () => {
      constructions += 1;
      return { read: true };
    });
    assert.equal(repository, null);
    assert.equal(constructions, 0);
  }
});

test("authorized Production data construction depends on DB availability, not public intake", async () => {
  assert.deepEqual(getDatabaseRuntimeConfiguration(database), {
    available: true, databaseUrl: database.DATABASE_URL, poolMax: 2,
  });
  assert.deepEqual(getPersistenceConfiguration({
    ...production, REQUEST_SUBMISSION_MODE: "postgres", ENABLE_PERSISTENT_SUBMISSIONS: "false",
  }), { enabled: false, reason: "gate" });
  assert.deepEqual(getAdminDatabaseConfiguration({
    ...production, REQUEST_SUBMISSION_MODE: "demo", ENABLE_PERSISTENT_SUBMISSIONS: "false",
  }), { enabled: true, databaseUrl: database.DATABASE_URL, poolMax: 2 });

  let constructions = 0;
  const repository = await resolveAdminDataRepository(production, async (configuration) => {
    constructions += 1;
    return { configuration, read: true, mutate: true };
  });
  assert.equal(constructions, 1);
  assert.deepEqual(repository, {
    configuration: { databaseUrl: database.DATABASE_URL, poolMax: 2 }, read: true, mutate: true,
  });
});

test("admin data construction fails safely when the database is unavailable", async () => {
  let constructed = false;
  const repository = await resolveAdminDataRepository(
    { VERCEL: "1", VERCEL_ENV: "production", DATABASE_URL: "malformed" },
    async () => { constructed = true; return {}; },
  );
  assert.equal(repository, null);
  assert.equal(constructed, false);
});
