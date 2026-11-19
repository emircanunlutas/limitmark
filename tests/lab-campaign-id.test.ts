import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { parseFieldArguments } from "../lab/defense/ba0-field-run";
import { CAMPAIGN_ID_MAX_LENGTH, CAMPAIGN_ID_PATTERN, isCampaignId } from "../lab/defense/campaign-id";
import { campaignIdPattern } from "../lab/defense/generator-report";
import { assertEvidenceSafe } from "../lab/evidence/redact";

// N-2: a campaign id is at most 31 characters, refused at argument parsing instead of failing late in the evidence scanner.
const id = (length: number) => ("a1b2c3d4e5-".repeat(5)).slice(0, length).replace(/-$/u, "x");
const field = (campaign: string) => () => parseFieldArguments(["--target", "sut-lab", "--level", "ba0-l7-c1", "--campaign", campaign]);

test("boundary: 30 and 31 characters are accepted, 32 is refused, at both the helper and the field CLI", () => {
  assert.equal(CAMPAIGN_ID_MAX_LENGTH, 31);
  for (const length of [6, 30, 31]) { assert.equal(isCampaignId(id(length)), true, String(length)); assert.doesNotThrow(field(id(length)), String(length)); }
  for (const length of [32, 33, 41]) { assert.equal(isCampaignId(id(length)), false, String(length)); assert.throws(field(id(length)), /--campaign must be a plain label/u, String(length)); }
});

test("malformed ids are refused: empty, short, uppercase, leading hyphen, underscore, space, dot, slash, equals, non-string, non-ASCII", () => {
  for (const bad of ["", "abcde", "ABCDEF-run", "-leading-hyphen", "under_score-run", "with space", "dot.dot.dot", "a/b/c/d/e/f", "name=value", "turkce-ğüşiöç"]) {
    assert.equal(isCampaignId(bad), false, JSON.stringify(bad));
    if (bad.length > 0 && !bad.startsWith("--")) assert.throws(field(bad), /--campaign/u, JSON.stringify(bad));
  }
  for (const bad of [undefined, null, 31, {}, ["abcdefg"]]) assert.equal(isCampaignId(bad), false);
});

test("compatibility: every previously valid id of length <= 31 is still valid; the shared pinned pattern is untouched and a superset", () => {
  for (const known of ["first-gcp-n2-salvo-r2", "gcp-field-002", "m1-run-1-20261108", "abcdef", "0abcde"]) { assert.equal(isCampaignId(known), true, known); assert.equal(campaignIdPattern.test(known), true, known); }
  assert.equal(campaignIdPattern.source, "^[a-z0-9][a-z0-9-]{5,40}$", "generator-report.ts (byte-pinned) is unchanged");
  assert.equal(CAMPAIGN_ID_PATTERN.test(id(32)), false);
  assert.equal(campaignIdPattern.test(id(32)), true, "the old pattern still accepts 32..41 characters; only the argument parsers are stricter");
});

test("the limit matches the evidence scanner: 31 passes assertEvidenceSafe, 32 is the first refused length", () => {
  assert.doesNotThrow(() => assertEvidenceSafe({ campaignId: id(31) }));
  assert.throws(() => assertEvidenceSafe({ campaignId: id(32) }), /long token-like string/u);
});

test("both argument-parsing sites use the single definition (no remaining 6-to-41 rule at a parse site)", () => {
  const run = readFileSync(path.join(__dirname, "..", "lab", "run.ts"), "utf8");
  const fieldRun = readFileSync(path.join(__dirname, "..", "lab", "defense", "ba0-field-run.ts"), "utf8");
  for (const [name, source] of [["lab/run.ts", run], ["lab/defense/ba0-field-run.ts", fieldRun]] as const) {
    assert.match(source, /isCampaignId\(/u, name);
    assert.doesNotMatch(source, /\{5,40\}/u, `${name}: no 41-character rule`);
  }
  assert.doesNotMatch(run, /campaignIdPattern/u);
});
