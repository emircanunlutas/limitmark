import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { EvidenceRun, collectEnvironment, collectGitState } from "../../lab/evidence/manifest";
import { connectionsOf, externalOf, ledgerArtifact, levelEvidence, planeFinOf, receiptFins, remoteWorkload, tallyOf, workload, type E } from "./m1-tally-fixture";

/** Options for a finalized, checksummed server-evidence directory written the way the field run writes it (only the artifacts criterion 9 reads). */
export type EvidenceOptions = {
  canary?: E[]; remote?: E[]; final?: boolean; omitTally?: boolean;
  /** Replaces the journal text AFTER its digest was recorded for the unmodified text (a tampered journal). */
  journalMutator?: (text: string) => string;
  overflow?: boolean;
  /** Events the journal holds (default: the canary events). */
  journalEvents?: E[];
  /** Events the kind ledger and plane stats describe (default: canary + remote). */
  ledgerEvents?: E[];
  /** Replace (value) or omit (null) a JSON artifact by name; applied on top of the default content. */
  artifacts?: Record<string, unknown>;
  /** Exact text for an artifact (duplicate keys, truncation); written directly, unregistered like the journal file. */
  rawArtifacts?: Record<string, string>;
  /** Rewrites the serialized text of a default artifact (for example to inject a duplicate key) before it is written verbatim. */
  rawTransform?: Record<string, (text: string) => string>;
  /** Rewrites each journal line BEFORE the journal digest is recorded (the recorded digest then matches the rewritten journal). */
  journalLine?: (line: string, index: number) => string;
  /** Mutates the default content of one JSON artifact in place before it is written. */
  mutate?: Record<string, (content: Record<string, unknown>) => void>;
};

export function writeFieldLikeEvidence(root: string, options: EvidenceOptions = {}): string {
  const canary = options.canary ?? workload();
  const remote = options.remote ?? remoteWorkload();
  const all = options.ledgerEvents ?? [...canary, ...remote];
  const evidence = new EvidenceRun("field-level", "ba0-l7-c1", new Date(), root);
  const git = collectGitState();
  const tick = { type: "tick", role: "plane", tickSeq: 9, tMonoMs: 1, final: options.final ?? true, data: { outcomes: options.omitTally ? null : tallyOf([...canary, ...remote]) } };
  const fins = receiptFins(remote);
  const level = levelEvidence(remote, 3, git.gitSha);
  const journal = options.journalEvents ?? canary;
  let text = journal.map((event, index) => { const line = JSON.stringify({ src: "p", rid: `r${index}`, seq: index + 1, k: event.kind }); return options.journalLine ? options.journalLine(line, index) : line; }).join("\n") + "\n";
  const recordedSha = createHash("sha256").update(text).digest("hex");
  if (options.journalMutator) text = options.journalMutator(text);
  const defaults: Record<string, unknown> = {
    "telemetry.json": { ring: { plane: [{ ...tick, tickSeq: 8, final: false, data: { outcomes: null } }, tick], boundary: [], app: [] } },
    "external.json": { counters: externalOf(remote) },
    "kind-ledger.json": ledgerArtifact(all),
    "processes.json": { plane: planeFinOf(all.length), boundary: fins.boundaryFin, app: fins.appFin },
    "connections.json": connectionsOf(3),
    "server-level.json": level.serverLevel,
    "core.json": level.core,
    "accounting.json": { anomalyTotal: 0, journal: { lines: journal.length, bytes: text.length, journalSha256: recordedSha, overflow: options.overflow ?? false } },
  };
  for (const [name, mutate] of Object.entries(options.mutate ?? {})) mutate(defaults[name] as Record<string, unknown>);
  for (const [name, content] of Object.entries(options.artifacts ?? {})) { if (content === null) delete defaults[name]; else defaults[name] = content; }
  const transformed = Object.keys(options.rawTransform ?? {});
  for (const name of [...Object.keys(options.rawArtifacts ?? {}), ...transformed]) if (!transformed.includes(name)) delete defaults[name];
  const transformedText: Record<string, string> = {};
  for (const name of transformed) { transformedText[name] = options.rawTransform![name](JSON.stringify(defaults[name])); delete defaults[name]; }
  for (const [name, content] of Object.entries(defaults)) evidence.addJsonArtifact(name, content);
  for (const [name, raw] of Object.entries({ ...(options.rawArtifacts ?? {}), ...transformedText })) fs.writeFileSync(path.join(evidence.directory, name), raw);
  fs.writeFileSync(path.join(evidence.directory, "ledger-journal-field.ndjson"), text);
  evidence.finalize({ git, environment: collectEnvironment(), target: null, workload: null, ceilings: null, thresholds: null, engine: "test", result: "SERVER-COMPLETE", resultReasons: [], metrics: {} });
  return evidence.id;
}
