/**
 * Provenance lifecycle for a disposable LOCAL field run, built on lab/provenance/prototype.ts. The session is the GENERATOR-SIDE party:
 *   begin()      writes the pre-run commitment into the retained store BEFORE the run exists (campaign, level, parameter fingerprint, git SHA, time, nonce)
 *   started()    the run announces its id and journal; from then on the session reads the journal prefix on a timer and appends hash-chain beacons
 *   finalized()  the run announces its finalized directory; the session records the last beacon and the finalization record (digest of SHA256SUMS, journal digest)
 *   verify()     runs the separate verifier over the package and the retained store
 *
 * HONESTY: in this local arrangement the run announces itself (the beacons are read from the server's own journal file), so the beacons are SELF-REPORTED by the server process
 * and are not independent observations. What the retained store adds is that rewriting the package afterwards contradicts records the server no longer controls, if the store really
 * is outside the server's write path. The retained directory here only models that separation. No keys are created, nothing is signed, nothing leaves this machine.
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { RetainedRecords, verifyProvenance, type ProvenanceReport } from "../provenance/prototype";

const sha = (data: Buffer | string): string => createHash("sha256").update(data).digest("hex");

export type ProvenancePlan = { campaignId: string; levelId: string; paramsSha256: string; gitSha: string };
/** The hook object the field run calls through its optional `provenance` seam. */
export type ProvenanceHooks = { started(info: { runId: string; directory: string; journalPath: string }): void; finalized(directory: string): void };

export class ProvenanceSession implements ProvenanceHooks {
  readonly retained: RetainedRecords;
  private runId: string | null = null;
  private journalPath: string | null = null;
  private lastBytes = 0;
  private timer: NodeJS.Timeout | null = null;
  private beacons = 0;

  constructor(retainedDirectory: string, private readonly intervalMs = 150) { this.retained = new RetainedRecords(retainedDirectory); }

  /** Must be called before the run starts. */
  begin(plan: ProvenancePlan, now = new Date()): void {
    this.retained.commit({ ...plan, committedAt: now.toISOString(), nonce: randomBytes(8).toString("hex") });
  }
  started(info: { runId: string; directory: string; journalPath: string }): void {
    this.runId = info.runId; this.journalPath = info.journalPath;
    this.timer = setInterval(() => { try { this.beaconPrefix(); } catch { /* a missed beacon leaves a shorter chain; the verifier requires the final one */ } }, this.intervalMs);
    this.timer.unref();
  }
  private journal(): Buffer { return this.journalPath !== null && existsSync(this.journalPath) ? readFileSync(this.journalPath) : Buffer.alloc(0); }
  /** Announces the longest prefix that ends on a complete line, when it grew. */
  private beaconPrefix(): void {
    if (this.runId === null) return;
    const journal = this.journal(); const cut = journal.lastIndexOf(10) + 1;
    if (cut <= this.lastBytes) return;
    this.retained.beacon(this.runId, cut, sha(journal.subarray(0, cut))); this.lastBytes = cut; this.beacons++;
  }
  finalized(directory: string): void {
    if (this.timer !== null) clearInterval(this.timer);
    if (this.runId === null) return;
    const journal = this.journal();
    if (journal.length !== this.lastBytes || this.beacons === 0) { this.retained.beacon(this.runId, journal.length, sha(journal.subarray(0, journal.length))); this.lastBytes = journal.length; this.beacons++; }
    this.retained.finalize(this.runId, sha(readFileSync(path.join(directory, "SHA256SUMS"))), sha(journal));
  }
  verify(evidenceDirectory: string): ProvenanceReport { return verifyProvenance(evidenceDirectory, this.retained.directory); }
}
