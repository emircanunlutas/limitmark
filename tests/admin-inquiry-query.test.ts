import assert from "node:assert/strict";
import test from "node:test";
import {
  ADMIN_INQUIRY_MAX_PAGE,
  ADMIN_INQUIRY_SEARCH_MAX_LENGTH,
  buildAdminInquiryHref,
  escapeLikeLiteral,
  normalizeAdminInquiryQuery,
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
