import assert from "node:assert/strict";
import test from "node:test";
import { getDatabaseClientOptions } from "../src/lib/db/database.server";

test("laboratory database options require a CA and verify the configured hostname", () => {
  assert.deepEqual(getDatabaseClientOptions(5, {
    ca: "-----BEGIN CERTIFICATE-----\nlab-ca\n-----END CERTIFICATE-----",
    servername: "10.80.0.10",
  }), {
    max: 5,
    idle_timeout: 20,
    connect_timeout: 5,
    prepare: false,
    ssl: {
      ca: "-----BEGIN CERTIFICATE-----\nlab-ca\n-----END CERTIFICATE-----",
      rejectUnauthorized: true,
      servername: "10.80.0.10",
    },
  });
});

test("the default database options do not silently enable or disable TLS", () => {
  assert.deepEqual(getDatabaseClientOptions(5), {
    max: 5,
    idle_timeout: 20,
    connect_timeout: 5,
    prepare: false,
  });
});
