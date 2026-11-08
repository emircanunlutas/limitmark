/**
 * The campaign id of a BA0 field level: a plain label chosen by the operator, recorded in the evidence, never an input to any decision.
 *
 * Maximum 31 characters. The evidence scanner (lab/evidence/redact.ts) refuses any 32+ character [A-Za-z0-9_+/=-] string as a "long token-like
 * string", so a 32..41 character id used to pass argument parsing and then fail late, after the level had run. This is the single definition both
 * argument-parsing sites use; the shared `campaignIdPattern` in generator-report.ts (byte-pinned) is left untouched and is a superset of this one.
 */
export const CAMPAIGN_ID_MAX_LENGTH = 31;
export const CAMPAIGN_ID_PATTERN = /^[a-z0-9][a-z0-9-]{5,30}$/;
export const CAMPAIGN_ID_RULE = "a plain label (lowercase letters, digits, hyphens; 6 to 31 characters)";
export const isCampaignId = (value: unknown): value is string => typeof value === "string" && CAMPAIGN_ID_PATTERN.test(value);
