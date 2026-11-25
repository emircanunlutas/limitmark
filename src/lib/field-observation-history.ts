import { comparisonLimits } from "./compare-field-runs";
import { readFieldHealth, type RecordedRun, type ReviewResult } from "./read-field-health";

export const historyLimits = { observations: 8, bytes: 4 * 1024 * 1024, filesPerObservation: 64 } as const;
export type Observation = { id: number; bytes: number; result: ReviewResult | "reading" };
type Snapshot = { entries: Observation[]; notice: string; reservedBytes: number; pendingReads: number };
const empty: Snapshot = { entries: [], notice: "", reservedBytes: 0, pendingReads: 0 };

// Charge superseded reads until their promises settle. Browser File reads and SHA-256
// cannot always be cancelled while in flight. No File objects enter the snapshot.
export class ObservationHistory {
  private snapshot = empty;
  private nextId = 1;
  private pending = new Set<Observation>();
  private listeners = new Set<() => void>();
  getSnapshot = () => this.snapshot;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private publish(entries: Observation[], notice = "") {
    this.snapshot = { entries, notice, reservedBytes: this.reservedBytes(entries), pendingReads: this.pending.size };
    this.listeners.forEach(listener => listener());
  }
  private reservedBytes(entries: Observation[]) {
    const reserved = new Set([...this.pending, ...entries]);
    return Array.from(reserved).reduce((sum, entry) => sum + entry.bytes, 0);
  }
  remove(id: number) {
    this.publish(this.snapshot.entries.filter(entry => entry.id !== id));
  }
  clear() {
    this.publish([]);
  }
  select(files: ArrayLike<File>, replaceId?: number): number | undefined {
    const { entries } = this.snapshot;
    const replacing = entries.find(entry => entry.id === replaceId);
    const refuse = (message: string) => {
      this.publish(entries, message);
      return undefined;
    };
    if (!files.length || (replaceId !== undefined && !replacing)) return;
    if (!replacing && entries.length >= historyLimits.observations)
      return refuse("History is full. Remove or replace an observation.");
    if (files.length > historyLimits.filesPerObservation)
      return refuse("Too many files. Select up to 64 files from one run.");
    if (this.pending.size >= historyLimits.observations)
      return refuse("Eight reads are still in progress. Try again after a read finishes.");
    const selected = Array.from(files);
    const bytes = selected.reduce((sum, file) => sum + file.size, 0);
    const total = bytes + this.reservedBytes(entries.filter(entry => entry !== replacing));
    if (total > historyLimits.bytes)
      return refuse("The selection exceeds the 4 MiB history budget. Remove an observation or wait for pending reads.");
    const entry: Observation = { id: replacing?.id ?? this.nextId++, bytes, result: "reading" };
    this.pending.add(entry);
    this.publish(replacing ? entries.map(item => item === replacing ? entry : item) : [...entries, entry]);
    void this.read(entry, selected);
    return entry.id;
  }
  private async read(entry: Observation, files: File[]) {
    let result: ReviewResult;
    try {
      result = await readFieldHealth(files, Date.now());
    } catch {
      result = { state: "Unknown", detail: "The selected evidence could not be reviewed." };
    } finally {
      this.pending.delete(entry);
    }
    const { entries, notice } = this.snapshot;
    this.publish(entries.map(item => item === entry ? { ...entry, result } : item), notice);
  }
}

export function reviewedRun(entry?: Observation) {
  const result = entry?.result;
  return result && result !== "reading" && result.state === "Reviewed" ? result.review : undefined;
}

type RecordEntry = { id: number; run: RecordedRun; identityLimits: string[] };
export function observationTimeline(entries: readonly Observation[]) {
  const records: RecordEntry[] = entries.flatMap(entry => {
    const run = reviewedRun(entry);
    return run ? [{ id: entry.id, run, identityLimits: [] }] : [];
  });
  records.sort((a, b) => Date.parse(a.run.endedAt) - Date.parse(b.run.endedAt) ||
    Date.parse(a.run.startedAt) - Date.parse(b.run.startedAt) || a.id - b.id);
  for (const record of records) {
    const peers = records.filter(other => other !== record);
    if (peers.some(peer => peer.run.manifestDigest === record.run.manifestDigest))
      record.identityLimits.push("Duplicate manifest in history.");
    if (!record.run.runKey) record.identityLimits.push("Run identity unavailable.");
    else if (peers.some(peer => peer.run.runKey === record.run.runKey && peer.run.manifestDigest !== record.run.manifestDigest))
      record.identityLimits.push("Conflicting manifests claim this run identity.");
  }
  return records;
}

export function historicalPairLimits(first: RecordEntry, second: RecordEntry) {
  return comparisonLimits(first.run, second.run, [...first.identityLimits, ...second.identityLimits]);
}

export function recurringFindings(records: readonly RecordEntry[]) {
  const categories = new Map<string, { title: string; observations: number[] }>();
  for (const { id, run, identityLimits } of records) {
    if (identityLimits.length) continue;
    for (const finding of run.findings) {
      // These two categories have different per-run titles depending on the observed facts.
      const title = finding.id === "interruptions" ? "External request interruptions" :
        finding.id === "canary-evidence" ? "Canary evidence quality" : finding.title;
      const category = categories.get(finding.id) ?? { title, observations: [] };
      if (!category.observations.includes(id)) category.observations.push(id);
      categories.set(finding.id, category);
    }
  }
  return [...categories.values()].filter(category => category.observations.length > 1);
}
