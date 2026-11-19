/**
 * Canonical M1 evidence identity. One record names the exact run every M1 result must be about.
 *
 * AUTHORITATIVE fields (read from the finalized, inventory-verified server package, never from a directory name or from the result being bound):
 *   runId                manifest.json `runId` (the EvidenceRun id; the directory name must EQUAL it, but is not the source)
 *   campaignId           server-level.json `campaignId`      (core.json level.campaignId must equal it)
 *   levelId              server-level.json `levelId`         (core.json level.id must equal it)
 *   gitSha               server-level.json `gitSha`          (manifest.json git.gitSha must equal it)
 *   paramsSha256         server-level.json `paramsFingerprintSha256` (core.json parameters.sha256 must equal it)
 *   paramsId/Version     core.json parameters.id / parameters.version (the parameter CONTRACT; sha256 of the canonical set is `paramsSha256`)
 *   workloadSha256       server-level.json `workloadFingerprintSha256` = fixture identity (core.json workloadSha256 must equal it)
 * DERIVED field:
 *   finalizationSha256   sha256 of the SHA256SUMS bytes: names the exact finalized package (every artifact hash and the manifest hash are inside it)
 * `identityDigest` = sha256 of the canonical JSON of the nine fields; it is a convenience for comparison, never an input to a decision.
 *
 * A result that carries no identity block, a malformed one, or one that differs from the package identity in any field cannot be combined with others: the
 * consumer reports the missing producer contract and fails closed. Nothing is defaulted or inferred.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { verifyMandatoryInventory } from "./inventory";

import { canonicalJson } from "../evidence/manifest";

export const IDENTITY_FIELDS = ["runId", "campaignId", "levelId", "gitSha", "paramsSha256", "paramsId", "paramsVersion", "workloadSha256", "finalizationSha256"] as const;
export type M1Identity = { runId: string; campaignId: string; levelId: string; gitSha: string; paramsSha256: string; paramsId: string; paramsVersion: number; workloadSha256: string; finalizationSha256: string };

const ID = /^[A-Za-z0-9._-]{1,120}$/u; const HEX40 = /^[0-9a-f]{40}$/u; const HEX64 = /^[0-9a-f]{64}$/u;
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** Strict structural check of an identity block found in some result. */
export function parseIdentity(value: unknown): M1Identity | null {
  if (!isRecord(value) || Object.keys(value).length !== IDENTITY_FIELDS.length) return null;
  const v = value;
  if (typeof v.runId !== "string" || !ID.test(v.runId) || typeof v.campaignId !== "string" || !ID.test(v.campaignId) || typeof v.levelId !== "string" || !ID.test(v.levelId)) return null;
  if (typeof v.gitSha !== "string" || !HEX40.test(v.gitSha) || typeof v.paramsSha256 !== "string" || !HEX64.test(v.paramsSha256)) return null;
  if (typeof v.paramsId !== "string" || !ID.test(v.paramsId) || typeof v.paramsVersion !== "number" || !Number.isSafeInteger(v.paramsVersion) || v.paramsVersion < 1) return null;
  if (typeof v.workloadSha256 !== "string" || !HEX64.test(v.workloadSha256) || typeof v.finalizationSha256 !== "string" || !HEX64.test(v.finalizationSha256)) return null;
  return { runId: v.runId, campaignId: v.campaignId, levelId: v.levelId, gitSha: v.gitSha, paramsSha256: v.paramsSha256, paramsId: v.paramsId, paramsVersion: v.paramsVersion, workloadSha256: v.workloadSha256, finalizationSha256: v.finalizationSha256 };
}

export const identityDigest = (identity: M1Identity): string => createHash("sha256").update(canonicalJson(identity)).digest("hex");
/** The names of the fields in which two identities differ (empty when equal). */
export const identityDifferences = (a: M1Identity, b: M1Identity): string[] => IDENTITY_FIELDS.filter((field) => a[field] !== b[field]);

export type PackageIdentity = { identity: M1Identity | null; problems: string[] };

/** Derives the identity of a finalized server package from its verified bytes. Any inventory problem, missing artifact or cross-artifact disagreement yields no identity. */
export function identityFromPackage(directory: string): PackageIdentity {
  const problems: string[] = [];
  const inventory = verifyMandatoryInventory(directory, ["server-level.json", "core.json", "manifest.json"]);
  problems.push(...inventory.problems);
  const parse = (name: string): Record<string, unknown> | null => { const data = inventory.bytes.get(name); if (data === undefined) { problems.push(`missing:${name}`); return null; } try { const v = JSON.parse(data.toString("utf8")); return isRecord(v) ? v : null; } catch { return null; } };
  const server = parse("server-level.json"); const core = parse("core.json"); const manifest = parse("manifest.json");
  const sumsPath = path.join(directory, "SHA256SUMS");
  if (!existsSync(sumsPath)) problems.push("missing:SHA256SUMS");
  if (server === null || core === null || manifest === null || problems.length > 0) return { identity: null, problems: problems.length > 0 ? problems : ["malformed"] };
  const coreLevel = isRecord(core.level) ? core.level : {}; const params = isRecord(core.parameters) ? core.parameters : {}; const git = isRecord(manifest.git) ? manifest.git : {};
  const candidate = {
    runId: manifest.runId, campaignId: server.campaignId, levelId: server.levelId, gitSha: server.gitSha, paramsSha256: server.paramsFingerprintSha256,
    paramsId: params.id, paramsVersion: params.version, workloadSha256: server.workloadFingerprintSha256, finalizationSha256: createHash("sha256").update(readFileSync(sumsPath)).digest("hex"),
  };
  const identity = parseIdentity(candidate);
  if (identity === null) return { identity: null, problems: ["identity_fields_malformed"] };
  if (coreLevel.campaignId !== identity.campaignId) problems.push("campaign_disagrees_across_artifacts");
  if (coreLevel.id !== identity.levelId) problems.push("level_disagrees_across_artifacts");
  if (git.gitSha !== identity.gitSha) problems.push("git_disagrees_across_artifacts");
  if (params.sha256 !== identity.paramsSha256) problems.push("parameters_disagree_across_artifacts");
  if (core.workloadSha256 !== identity.workloadSha256) problems.push("fixture_disagrees_across_artifacts");
  if (path.basename(directory) !== identity.runId) problems.push("directory_name_is_not_the_manifest_run_id");
  return problems.length > 0 ? { identity: null, problems } : { identity, problems: [] };
}

/** The additive block every M1 result artifact carries: the identity of the package it evaluated, or an explicit absence. */
export function identityBlock(directory: string): { identity: M1Identity | null; identitySha256: string | null; identityProblems: string[] } {
  const { identity, problems } = identityFromPackage(directory);
  return { identity, identitySha256: identity === null ? null : identityDigest(identity), identityProblems: problems.slice(0, 8).map((problem) => problem.replace(/[_:]/gu, ".")) };
}
