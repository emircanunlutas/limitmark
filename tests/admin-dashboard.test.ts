import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function routeSources() {
  return Promise.all([
    readFile(new URL("../src/app/admin/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../src/app/admin/inquiries/[id]/page.tsx", import.meta.url), "utf8"),
  ]);
}

test("list and detail routes each authorize before repository access", async () => {
  const [listSource, detailSource] = await routeSources();
  for (const source of [listSource, detailSource]) {
    const authorization = source.indexOf("await authorize();");
    const repository = source.indexOf("await getRepository()");
    assert.notEqual(authorization, -1);
    assert.notEqual(repository, -1);
    assert.ok(authorization < repository);
  }
  assert.ok(detailSource.indexOf("await authorize();") < detailSource.indexOf("await params"));
  assert.ok(detailSource.indexOf("uuidPattern.test(id)") < detailSource.indexOf("await getRepository()"));
});

test("customer and note values remain JSX text with no HTML renderer or internal projections", async () => {
  const [listSource, detailSource] = await routeSources();
  assert.match(detailSource, /<p>\{detail\.inquiry\.system\}<\/p>/);
  assert.match(detailSource, /<p>\{note\.content\}<\/p>/);
  assert.doesNotMatch(listSource + detailSource, /dangerouslySetInnerHTML|submissionToken|payloadFingerprint|notificationOutbox/);
});

test("database unavailable has an explicit outage state distinct from an empty result", async () => {
  const [listSource, detailSource] = await routeSources();
  assert.match(listSource, /Inquiry data unavailable/);
  assert.match(detailSource, /Inquiry data unavailable/);
  assert.match(listSource, /No inquiries found/);
  assert.notEqual(listSource.indexOf("if (!repository)"), listSource.indexOf("if (!result.items.length)"));
});

test("admin route source is dynamic, private, customer-free in metadata, and disables detail prefetch", async () => {
  const [listSource, detailSource] = await routeSources();
  for (const source of [listSource, detailSource]) {
    assert.match(source, /export const dynamic = "force-dynamic"/);
    assert.match(source, /robots: \{ index: false, follow: false \}/);
    assert.match(source, /await authorize\(\)/);
  }
  assert.match(listSource, /prefetch=\{false\}/);
  assert.doesNotMatch(listSource, /title:.*(?:name|email|company|objective)/i);
  assert.doesNotMatch(detailSource, /title:.*(?:name|email|company|objective)/i);
});
