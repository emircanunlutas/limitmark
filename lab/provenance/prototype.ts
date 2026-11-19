/**
 * LOCAL PROTOTYPE of independent evidence provenance for an M1 package. Disposable fixtures only; no keys, no signatures, no network, no cloud.
 *
 * Records retained OUTSIDE the server evidence directory by a separate party (here: a separate directory, which only models separation):
 *   commitment.json  the pre-run commitment: campaign, level, code-pinned parameter fingerprint and git SHA, written before the run. `commitmentSha256` seals its other fields.
 *   beacons.ndjson   the generator-side hash chain. During the run the server tells the generator "journal prefix of N bytes has digest D"; the generator appends
 *                    link_n = sha256(link_{n-1} : n : runId : N : D), link_0 = commitmentSha256. The server never writes this file.
 *   final.json       the finalization record: run id, last beacon index, chain head, digest of the server's SHA256SUMS, journal digest.
 *
 * The verifier reports SIX SEPARATE LEVELS and never collapses them:
 *   byteIntegrity            the package matches its own checksums (strict inventory)       -> VERIFIED | FAILED
 *   artifactCompleteness     every mandatory artifact is present and inventoried            -> VERIFIED | FAILED
 *   runBinding               commitment, beacons, final record and evidence name ONE run    -> VERIFIED | FAILED | ABSENT
 *   producerIdentity         git SHA / engine / environment the package CLAIMS about itself -> CLAIMED_UNVERIFIED (never verified here)
 *   independentCorroboration the retained records are consistent with the package           -> CONSISTENT | FAILED | ABSENT
 *   authenticity             -> UNVERIFIED, always
 * and two fixed claims: `authenticated: false`, `independent: false`. Agreement between two LOCAL files proves only that they agree. If one actor controls both the package and
 * the retained records, it can rewrite both consistently and this verifier will report CONSISTENT; that is exactly why authenticity stays UNVERIFIED and independence is never
 * inferred from the data. Independence is a property of custody (different principal, host and write path), which no file content can establish.
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { verifyMandatoryInventory, MANDATORY_ARTIFACTS } from "../defense/ba0-m1-tally-check";
import { canonicalJson, verifyEvidenceDirectory } from "../evidence/manifest";

export const PROVENANCE_SCHEMA = "m1-provenance-prototype-v1";
const sha = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");

export type CommitmentFields = { campaignId: string; levelId: string; paramsSha256: string; gitSha: string; committedAt: string; nonce: string };
export type Commitment = CommitmentFields & { schema: typeof PROVENANCE_SCHEMA; commitmentSha256: string };
export type Beacon = { n: number; runId: string; bytes: number; journalDigest: string; link: string };
export type FinalRecord = { schema: typeof PROVENANCE_SCHEMA; runId: string; lastN: number; chainHead: string; sumsDigest: string; journalSha256: string };

export const commitmentSeal = (fields: CommitmentFields): string => sha(canonicalJson({ schema: PROVENANCE_SCHEMA, ...fields }));
const linkOf = (previous: string, n: number, runId: string, bytes: number, digest: string): string => sha(`${previous}:${n}:${runId}:${bytes}:${digest}`);

/** The party that holds the retained records. It is the only writer of the three files. */
export class RetainedRecords {
  constructor(readonly directory: string) { mkdirSync(directory, { recursive: true }); }
  private get commitmentPath(): string { return path.join(this.directory, "commitment.json"); }
  private get beaconPath(): string { return path.join(this.directory, "beacons.ndjson"); }
  private get finalPath(): string { return path.join(this.directory, "final.json"); }

  commit(fields: CommitmentFields): Commitment {
    if (existsSync(this.commitmentPath)) throw new Error("a commitment already exists in this retained store");
    const commitment: Commitment = { schema: PROVENANCE_SCHEMA, ...fields, commitmentSha256: commitmentSeal(fields) };
    writeFileSync(this.commitmentPath, `${JSON.stringify(commitment)}\n`, { flag: "wx" });
    return commitment;
  }
  private head(): { n: number; link: string } {
    const commitment = JSON.parse(readFileSync(this.commitmentPath, "utf8")) as Commitment;
    if (!existsSync(this.beaconPath)) return { n: 0, link: commitment.commitmentSha256 };
    const lines = readFileSync(this.beaconPath, "utf8").split("\n").filter(Boolean);
    const last = JSON.parse(lines[lines.length - 1]) as Beacon;
    return { n: last.n, link: last.link };
  }
  /** Called with what the SERVER announced: the length of its journal and the digest of that prefix. */
  beacon(runId: string, announcedBytes: number, announcedDigest: string): Beacon {
    const { n, link } = this.head();
    const beacon: Beacon = { n: n + 1, runId, bytes: announcedBytes, journalDigest: announcedDigest, link: linkOf(link, n + 1, runId, announcedBytes, announcedDigest) };
    appendFileSync(this.beaconPath, `${JSON.stringify(beacon)}\n`);
    return beacon;
  }
  /** Called with the digest of the finalized SHA256SUMS the server announced. */
  finalize(runId: string, sumsDigest: string, journalSha256: string): FinalRecord {
    const { n, link } = this.head();
    const record: FinalRecord = { schema: PROVENANCE_SCHEMA, runId, lastN: n, chainHead: link, sumsDigest, journalSha256 };
    writeFileSync(this.finalPath, `${JSON.stringify(record)}\n`, { flag: "wx" });
    return record;
  }
}

export type Level = "VERIFIED" | "FAILED" | "ABSENT" | "CLAIMED_UNVERIFIED" | "CONSISTENT" | "UNVERIFIED";
export type ProvenanceReport = {
  schema: typeof PROVENANCE_SCHEMA;
  levels: { byteIntegrity: Level; artifactCompleteness: Level; runBinding: Level; producerIdentity: Level; independentCorroboration: Level; authenticity: Level };
  claimedProducer: { gitSha: string | null; engine: string | null };
  problems: string[];
  claims: { authenticated: false; independent: false };
  /** CONSISTENT_WITH_RECORDS is the strongest statement this verifier can make. */
  overall: "CONSISTENT_WITH_RECORDS" | "FAILED" | "INCOMPLETE";
};

const readJson = (file: string): unknown => { try { return JSON.parse(readFileSync(file, "utf8")); } catch { return undefined; } };
const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

/** Separate verifier: reads the package and the retained records, writes nothing. */
export function verifyProvenance(evidenceDirectory: string, retainedDirectory: string): ProvenanceReport {
  const problems: string[] = [];
  const levels: ProvenanceReport["levels"] = { byteIntegrity: "VERIFIED", artifactCompleteness: "VERIFIED", runBinding: "VERIFIED", producerIdentity: "CLAIMED_UNVERIFIED", independentCorroboration: "CONSISTENT", authenticity: "UNVERIFIED" };
  const fail = (level: "byteIntegrity" | "artifactCompleteness" | "runBinding" | "independentCorroboration", problem: string): void => { levels[level] = "FAILED"; problems.push(`${level}:${problem}`); };
  const absent = (level: "runBinding" | "independentCorroboration", problem: string): void => { if (levels[level] !== "FAILED") levels[level] = "ABSENT"; problems.push(`${level}:${problem}`); };

  // ---- byte integrity and completeness (strict inventory, every consumed byte checksummed)
  const inventory = verifyMandatoryInventory(evidenceDirectory, MANDATORY_ARTIFACTS);
  let tampered: string[] = [];
  try { tampered = verifyEvidenceDirectory(evidenceDirectory); } catch { fail("byteIntegrity", "sums_unreadable"); }
  for (const name of tampered) fail("byteIntegrity", `checksum:${name}`);
  for (const problem of inventory.problems) fail("byteIntegrity", problem);
  for (const name of MANDATORY_ARTIFACTS) if (!inventory.bytes.has(name)) fail("artifactCompleteness", `missing_or_unverified:${name}`);

  const parse = (name: string): Record<string, unknown> | undefined => { const data = inventory.bytes.get(name); if (data === undefined) return undefined; try { const v = JSON.parse(data.toString("utf8")); return isRecord(v) ? v : undefined; } catch { return undefined; } };
  const manifest = parse("manifest.json"); const serverLevel = parse("server-level.json"); const accounting = parse("accounting.json");
  const git = manifest && isRecord(manifest.git) ? manifest.git : undefined;
  const claimedProducer = { gitSha: typeof git?.gitSha === "string" ? git.gitSha : null, engine: typeof manifest?.engine === "string" ? manifest.engine : null };

  // ---- retained records
  const commitment = readJson(path.join(retainedDirectory, "commitment.json"));
  const final = readJson(path.join(retainedDirectory, "final.json"));
  let beacons: Beacon[] | null = null;
  try { beacons = readFileSync(path.join(retainedDirectory, "beacons.ndjson"), "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as Beacon); } catch { beacons = null; }
  if (!isRecord(commitment)) absent("runBinding", "commitment_absent");
  if (beacons === null) absent("independentCorroboration", "beacons_absent");
  if (!isRecord(final)) absent("independentCorroboration", "final_absent");

  const c = isRecord(commitment) ? (commitment as unknown as Commitment) : null;
  const f = isRecord(final) ? (final as unknown as FinalRecord) : null;
  if (c !== null) {
    const { commitmentSha256, schema, ...fields } = c; void schema;
    if (c.schema !== PROVENANCE_SCHEMA || commitmentSha256 !== commitmentSeal(fields as CommitmentFields)) fail("runBinding", "commitment_seal_mismatch");
    // run binding: one campaign, level, parameter set, source revision and ONE run
    if (!serverLevel || !manifest) absent("runBinding", "level_evidence_unavailable");
    else {
      if (serverLevel.campaignId !== c.campaignId) fail("runBinding", "campaign_mismatch");
      if (serverLevel.levelId !== c.levelId) fail("runBinding", "level_mismatch");
      if (serverLevel.paramsFingerprintSha256 !== c.paramsSha256) fail("runBinding", "parameters_mismatch");
      if (serverLevel.gitSha !== c.gitSha || git?.gitSha !== c.gitSha) fail("runBinding", "git_mismatch");
      if (typeof manifest.startedAt !== "string" || !(Date.parse(c.committedAt) <= Date.parse(manifest.startedAt))) fail("runBinding", "commitment_not_before_run");
      if (typeof manifest.runId !== "string" || path.basename(evidenceDirectory) !== manifest.runId) fail("runBinding", "run_id_mismatch_directory");
    }
  }
  const runId = typeof manifest?.runId === "string" ? manifest.runId : null;
  if (beacons !== null && runId !== null && beacons.some((beacon) => beacon.runId !== runId)) fail("runBinding", "beacon_run_id_mismatch");
  if (f !== null && runId !== null && f.runId !== runId) fail("runBinding", "final_run_id_mismatch");

  // ---- independent corroboration: chain, prefix digests of the journal, final digests
  if (c !== null && beacons !== null && f !== null) {
    const journal = existsSync(path.join(evidenceDirectory, "ledger-journal-field.ndjson")) ? readFileSync(path.join(evidenceDirectory, "ledger-journal-field.ndjson")) : null;
    if (journal === null) absent("independentCorroboration", "journal_absent");
    if (beacons.length === 0) absent("independentCorroboration", "no_beacons");
    let previous = c.commitmentSha256; let lastBytes = 0;
    beacons.forEach((beacon, index) => {
      if (beacon.n !== index + 1) fail("independentCorroboration", `beacon_sequence:${index + 1}`);
      if (beacon.link !== linkOf(previous, beacon.n, beacon.runId, beacon.bytes, beacon.journalDigest)) fail("independentCorroboration", `chain_broken:${index + 1}`);
      if (beacon.bytes < lastBytes) fail("independentCorroboration", `journal_prefix_shrinks:${index + 1}`);
      if (journal !== null && (beacon.bytes > journal.length || sha(journal.subarray(0, beacon.bytes)) !== beacon.journalDigest)) fail("independentCorroboration", `journal_prefix_mismatch:${index + 1}`);
      previous = beacon.link; lastBytes = beacon.bytes;
    });
    if (f.lastN !== beacons.length) fail("independentCorroboration", "final_beacon_count");
    if (f.chainHead !== previous) fail("independentCorroboration", "final_chain_head");
    const sums = existsSync(path.join(evidenceDirectory, "SHA256SUMS")) ? readFileSync(path.join(evidenceDirectory, "SHA256SUMS")) : null;
    if (sums === null || f.sumsDigest !== sha(sums)) fail("independentCorroboration", "finalization_digest_mismatch");
    const journalSha = isRecord(accounting?.journal) ? (accounting!.journal as Record<string, unknown>).journalSha256 : undefined;
    if (journal === null || f.journalSha256 !== sha(journal) || journalSha !== f.journalSha256) fail("independentCorroboration", "final_journal_digest_mismatch");
    if (journal !== null && lastBytes !== journal.length) fail("independentCorroboration", "journal_tail_not_covered");
  }

  const failed = Object.values(levels).includes("FAILED");
  const incomplete = !failed && Object.values(levels).includes("ABSENT");
  return { schema: PROVENANCE_SCHEMA, levels, claimedProducer, problems, claims: { authenticated: false, independent: false }, overall: failed ? "FAILED" : incomplete ? "INCOMPLETE" : "CONSISTENT_WITH_RECORDS" };
}
