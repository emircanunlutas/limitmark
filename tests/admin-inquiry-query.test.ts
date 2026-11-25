import assert from "node:assert/strict";
import test from "node:test";
import {
  ADMIN_INQUIRY_MAX_PAGE,
  ADMIN_INQUIRY_SEARCH_MAX_LENGTH,
  buildAdminInquiryHref,
  buildAdminInquiryReturnContext,
  escapeLikeLiteral,
  normalizeAdminInquiryQuery,
  parseAdminInquiryReturnContext,
} from "../src/lib/admin-inquiry-query";

test("malformed and absurd page values normalize to bounded safe pages", () => {
  for (const page of [undefined, "", "nope", "-2", "1.5", "1e20", ["2", "3"]]) {
    assert.equal(normalizeAdminInquiryQuery({ page }).page, 1);
  }
  assert.equal(normalizeAdminInquiryQuery({ page: "2" }).page, 2);
  assert.equal(normalizeAdminInquiryQuery({ page: "999999999999999999999999" }).page, 1);
  assert.equal(normalizeAdminInquiryQuery({ page: "9999999" }).page, ADMIN_INQUIRY_MAX_PAGE);
});

test("status uses an explicit allowlist and search is trimmed and length bounded", () => {
  const realStatuses = ["received", "in_review", "awaiting_scope", "proposal_sent", "approved", "completed", "declined", "archived"] as const;
  for (const status of realStatuses) assert.equal(normalizeAdminInquiryQuery({ status }).status, status);
  for (const status of ["scheduled", "received' OR true --", "RECEIVED", ["received"]]) {
    assert.equal(normalizeAdminInquiryQuery({ status }).status, null);
  }
  const query = normalizeAdminInquiryQuery({ q: `  ${"x".repeat(500)}  ` });
  assert.equal(query.search.length, ADMIN_INQUIRY_SEARCH_MAX_LENGTH);
  assert.equal(normalizeAdminInquiryQuery({ q: "   " }).search, "");
});

test("LIKE wildcard characters are escaped and pagination links preserve encoded filters", () => {
  assert.equal(escapeLikeLiteral(String.raw`50%_off\today`), String.raw`50\%\_off\\today`);
  assert.equal(
    buildAdminInquiryHref({ page: 3, status: "in_review", search: "name+tag@example.test & 50%" }),
    "/admin?q=name%2Btag%40example.test+%26+50%25&status=in_review&page=3",
  );
});

test("detail return context carries only the status and a page from an unsearched listing", () => {
  const context = (values: Parameters<typeof normalizeAdminInquiryQuery>[0]) =>
    buildAdminInquiryReturnContext(normalizeAdminInquiryQuery(values));
  assert.equal(context({}), null);
  assert.equal(context({ page: "3" }), "all.3");
  assert.equal(context({ status: "received", page: "2" }), "received.2");
  assert.equal(context({ status: "received", page: "2", q: "customer@example.test" }), "received.1");
  assert.equal(context({ page: "2", q: "customer@example.test" }), null);

  for (const [token, href] of [
    ["received.1", "/admin?status=received"],
    ["in_review.2", "/admin?status=in_review&page=2"],
    ["all.3", "/admin?page=3"],
    ["archived.10000", "/admin?status=archived&page=10000"],
  ]) {
    assert.deepEqual(parseAdminInquiryReturnContext(token), { token, href });
  }
});

test("detail return context rejects invalid, duplicate and noncanonical values", () => {
  for (const value of [
    undefined, "", ["received.2", "received.1"], "received.0", "received.01", "received.10001",
    "received.2\n", "received.-1", "received.2.1", "RECEIVED.2", "scheduled.2",
    "https://example.test", "//example.test", "/admin?status=received", "received.2&q=customer@example.test",
  ]) {
    assert.equal(parseAdminInquiryReturnContext(value), null);
  }
});
