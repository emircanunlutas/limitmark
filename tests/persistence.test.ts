import assert from "node:assert/strict";
import test from "node:test";
import { createPayloadFingerprint } from "../src/lib/payload-fingerprint";
import { getPersistenceConfiguration } from "../src/lib/persistence-config";
import { requestSchema } from "../src/lib/request-schema";
import { readSubmissionToken } from "../src/lib/submission-token";

const request = requestSchema.parse({
  name: "Örnek Talep",
  email: "qa@example.test",
  company: "Örnek Kuruluş",
  service: "web",
  system: "Hazırlık sistemi\r\nİkinci satır",
  objective: "Dayanıklılığı anlamak",
  environment: "staging",
  authority: "authorized",
  protection: "none",
  provider: "silinmesi gereken değer",
  notes: "  kısa not  ",
});

test("canonical fingerprints are stable and use authoritative normalized values", () => {
  const reordered = requestSchema.parse({
    notes: "kısa not",
    authority: "authorized",
    objective: "Dayanıklılığı anlamak",
    system: "Hazırlık sistemi\nİkinci satır",
    name: "Örnek Talep",
    protection: "none",
    provider: "başka bir stale değer",
    environment: "staging",
    service: "web",
    company: "Örnek Kuruluş",
    email: "qa@example.test",
  });
  const fingerprint = createPayloadFingerprint(request);
  assert.match(fingerprint, /^[0-9a-f]{64}$/);
  assert.equal(createPayloadFingerprint(reordered), fingerprint);
  assert.notEqual(createPayloadFingerprint({ ...request, objective: "Farklı amaç" }), fingerprint);
});

test("PostgreSQL persistence requires mode, explicit gate, and valid server configuration", () => {
  const complete = {
    REQUEST_SUBMISSION_MODE: "postgres",
    ENABLE_PERSISTENT_SUBMISSIONS: "true",
    DATABASE_URL: "postgresql://runtime:synthetic@db.example.test/app",
  };
  assert.deepEqual(getPersistenceConfiguration({}), { enabled: false, reason: "mode" });
  assert.deepEqual(getPersistenceConfiguration({ ...complete, ENABLE_PERSISTENT_SUBMISSIONS: "false" }), { enabled: false, reason: "gate" });
  for (const DATABASE_URL of [undefined, "", "not-a-url", "https://db.example.test/app", "postgresql://db.example.test/app", "postgresql://user:pass@/app"])
    assert.deepEqual(getPersistenceConfiguration({ ...complete, DATABASE_URL }), { enabled: false, reason: "database-url" });
  for (const DATABASE_POOL_MAX of ["0", "11", "2.5", "many"])
    assert.deepEqual(getPersistenceConfiguration({ ...complete, DATABASE_POOL_MAX }), { enabled: false, reason: "pool-size" });
  assert.deepEqual(getPersistenceConfiguration(complete), { enabled: true, databaseUrl: complete.DATABASE_URL, poolMax: 5 });
  assert.deepEqual(getPersistenceConfiguration({ ...complete, DATABASE_POOL_MAX: "2" }), { enabled: true, databaseUrl: complete.DATABASE_URL, poolMax: 2 });
});

test("submission token extraction accepts exactly one opaque 256-bit base64url value", () => {
  const token = "A".repeat(42) + "_";
  const form = new FormData();
  form.set("submissionToken", token);
  assert.equal(readSubmissionToken(form), token);
  form.append("submissionToken", "B".repeat(43));
  assert.equal(readSubmissionToken(form), null);
  for (const value of ["short", "a".repeat(44), "a".repeat(42) + "+", "a".repeat(42) + "="]) {
    const invalid = new FormData();
    invalid.set("submissionToken", value);
    assert.equal(readSubmissionToken(invalid), null);
  }
});
