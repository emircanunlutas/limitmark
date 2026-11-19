import type { ExpectedObservation } from "./observation-profile";
/**
 * Additive RESULT PROVENANCE contract for the M1 component results (tally, receipts, overlay, observation, provenance). A `resultProvenance` block is written INTO each
 * result artifact by its writer and is checked by the unified acceptance evaluator against the bytes it reads itself. It is reproducible-evaluation metadata, NOT
 * authentication: nothing here is signed, the producer claim is explicitly unverified, and a forged block can never substitute for the recomputation acceptance performs.
 *
 *   contract            fixed string
 *   component           which result this is (must equal the component slot it is presented in)
 *   evaluator           { contract, sources: [{ path, gitBlobId }] } : the git blob ids (sha1 of "blob <n>\0" + bytes) of the evaluator source files AS READ from the working tree
 *   inputs              [{ role, sha256 }] : the exact bytes each input had when the result was written (role set is fixed per component, see `expectedRoles`)
 *   evaluatedAt         ISO timestamp of the writer (informational; never a freshness proof)
 *   producerClaim       { claimed, verified: false } : a label of the writer; verified is always false
 *   outputSha256        sha256 of the canonical JSON of the artifact WITHOUT this block (so there is no circular dependency)
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { REPOSITORY_ROOT } from "../evidence/manifest";

export const RESULT_PROVENANCE_CONTRACT = "m1-result-provenance-v1";
export const RESULT_COMPONENTS = ["overlay", "tally", "receipts", "observation", "provenance"] as const;
export type ResultComponent = (typeof RESULT_COMPONENTS)[number];
export const PRODUCER_CLAIM = Object.freeze({ claimed: "local.evaluator.process", verified: false });

/** Evaluator source files per component: every module whose logic decides the result. */
export const EVALUATOR_SOURCES: Record<ResultComponent, readonly string[]> = {
  overlay: ["lab/defense/ba0-m1-reconcile.ts", "lab/defense/m1-status-contract.ts", "lab/defense/reconcile.ts", "lab/defense/generator-report.ts", "lab/m1/result-provenance.ts"],
  tally: ["lab/defense/ba0-m1-tally-check.ts", "lab/defense/m1-tally-check.ts", "lab/m1/inventory.ts", "lab/m1/result-provenance.ts"],
  receipts: ["lab/defense/ba0-m1-receipt-check.ts", "lab/defense/m1-receipt-check.ts", "lab/m1/inventory.ts", "lab/m1/result-provenance.ts"],
  observation: ["lab/m1/observation-check.ts", "lab/m1/observation-bundle.ts", "lab/m1/observation-completeness.ts", "lab/m1/results.ts", "lab/m1/result-provenance.ts"],
  provenance: ["lab/provenance/prototype.ts", "lab/m1/results.ts", "lab/m1/result-provenance.ts"],
};
export const EVALUATOR_CONTRACT: Record<ResultComponent, string> = {
  overlay: "m1-status-overlay", tally: "m1-tally-check-v1", receipts: "m1-receipt-check-v1", observation: "m1-observation-check-v1", provenance: "m1-provenance-check-v1",
};

export type InputSources = { packageDirectory: string; generatorReportPath?: string | null; observerDirectory?: string | null; retainedDirectory?: string | null; maxHeartbeatGapMs?: number | null; expectedObservation?: ExpectedObservation | null };
export type InputRole = { role: string; sha256: string | null };

const sha256 = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");
const digestOf = (file: string | null | undefined): string | null => { if (file === null || file === undefined) return null; try { return existsSync(file) ? sha256(readFileSync(file)) : null; } catch { return null; } };

/** The roles (and only these) a component's result must declare, with the digests of the bytes read NOW. A role whose file is absent has `sha256: null`. */
export function observedInputs(component: ResultComponent, sources: InputSources): InputRole[] {
  const pkg = (name: string): string => path.join(sources.packageDirectory, name);
  const observer = (name: string): string | null => (sources.observerDirectory ? path.join(sources.observerDirectory, name) : null);
  const retained = (name: string): string | null => (sources.retainedDirectory ? path.join(sources.retainedDirectory, name) : null);
  const roles: InputRole[] = [{ role: "package.finalization", sha256: digestOf(pkg("SHA256SUMS")) }];
  switch (component) {
    case "tally": roles.push({ role: "package.journal", sha256: digestOf(pkg("ledger-journal-field.ndjson")) }); break;
    case "receipts": roles.push({ role: "package.journal", sha256: digestOf(pkg("ledger-journal-field.ndjson")) }); if (sources.generatorReportPath) roles.push({ role: "generator.report", sha256: digestOf(sources.generatorReportPath) }); break;
    case "overlay": roles.push({ role: "package.server.level", sha256: digestOf(pkg("server-level.json")) }, { role: "generator.report", sha256: digestOf(sources.generatorReportPath) }); break;
    case "observation": roles.push({ role: "observer.canary", sha256: digestOf(observer("canary-results.json")) }, { role: "observer.receipts", sha256: digestOf(observer("origin-receipts.ndjson")) }, { role: "observer.meta", sha256: digestOf(observer("observation-meta.json")) }, { role: "observer.declaration", sha256: digestOf(observer("collector-declaration.json")) }); break;
    case "provenance": roles.push({ role: "retained.commitment", sha256: digestOf(retained("commitment.json")) }, { role: "retained.beacons", sha256: digestOf(retained("beacons.ndjson")) }, { role: "retained.final", sha256: digestOf(retained("final.json")) }); break;
  }
  return roles.sort((a, b) => (a.role < b.role ? -1 : 1));
}

export function gitBlobId(bytes: Buffer): string { return createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"); }
export function evaluatorSources(component: ResultComponent): { path: string; gitBlobId: string }[] {
  return EVALUATOR_SOURCES[component].map((relative) => ({ path: relative, gitBlobId: `git.blob.${gitBlobId(readFileSync(path.join(REPOSITORY_ROOT, relative)))}` }));
}

/** Canonical JSON: object keys sorted at every level, arrays in order. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") return `{${Object.keys(value as object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  return JSON.stringify(value);
}
export const outputDigest = (body: Record<string, unknown>): string => {
  const { resultProvenance: _ignored, ...rest } = body; void _ignored;
  return sha256(canonicalJson(JSON.parse(JSON.stringify(rest))));
};

export type ResultProvenance = {
  contract: typeof RESULT_PROVENANCE_CONTRACT; component: ResultComponent; evaluator: { contract: string; sources: { path: string; gitBlobId: string }[] };
  inputs: InputRole[]; evaluatedAt: string; producerClaim: { claimed: string; verified: false }; outputSha256: string;
};

/** Adds the provenance block to a result body. The digest covers the body as it will be serialized (JSON round trip), so it can be re-derived from the file bytes. */
export function withResultProvenance(component: ResultComponent, body: Record<string, unknown>, sources: InputSources, now: Date): Record<string, unknown> {
  const normalized = JSON.parse(JSON.stringify(body)) as Record<string, unknown>;
  const block: ResultProvenance = {
    contract: RESULT_PROVENANCE_CONTRACT, component, evaluator: { contract: EVALUATOR_CONTRACT[component], sources: evaluatorSources(component) },
    inputs: observedInputs(component, sources), evaluatedAt: now.toISOString(), producerClaim: { ...PRODUCER_CLAIM }, outputSha256: outputDigest(normalized),
  };
  return { ...normalized, resultProvenance: block };
}
