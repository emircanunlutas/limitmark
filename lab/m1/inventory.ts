import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";

// Strict, shared evidence-inventory verification (moved verbatim from ba0-m1-tally-check.ts so that lab/m1 can use it without an import cycle).
/** Every artifact criterion 9 consumes. Each must be listed in SHA256SUMS and in manifest.json, and is read exactly once: the verified bytes are the bytes parsed. */
export const MANDATORY_ARTIFACTS = ["telemetry.json", "kind-ledger.json", "processes.json", "external.json", "server-level.json", "core.json", "accounting.json", "connections.json", "manifest.json"] as const;
const SUM_LINE = /^([0-9a-f]{64}) {2}([a-z0-9][a-z0-9.-]{0,60}\.json)$/u;

export type VerifiedInventory = { problems: string[]; bytes: Map<string, Buffer> };

/**
 * R-5. Parses SHA256SUMS strictly and cross-checks it with manifest.json. Problems (never silently tolerated): malformed or non-canonical lines, duplicate names, names that alias
 * each other (case-insensitive), path components, an inventory that disagrees with the manifest's own artifact list, an unlisted .json file on disk, a mandatory artifact that is
 * present but unlisted, and any checksum that does not match the bytes read. A mandatory artifact that is absent from both disk and inventory is NOT a problem here: the evaluator
 * rejects its absence with its own reason. Only bytes whose checksum matched are returned.
 */
export function verifyMandatoryInventory(directory: string, required: readonly string[] = MANDATORY_ARTIFACTS): VerifiedInventory {
  const problems: string[] = [];
  const bytes = new Map<string, Buffer>();
  const listed = new Map<string, string>();
  const canonical = new Set<string>();
  let sums: string;
  try { sums = readFileSync(path.join(directory, "SHA256SUMS"), "utf8"); } catch { return { problems: ["SHA256SUMS:unreadable"], bytes }; }
  const lines = sums.endsWith("\n") ? sums.slice(0, -1).split("\n") : sums.split("\n");
  for (const line of lines) {
    const match = SUM_LINE.exec(line);
    if (match === null) { problems.push("SHA256SUMS:malformed_line"); continue; }
    const [, hash, name] = match;
    const key = name.toLowerCase();
    if (listed.has(name)) problems.push(`SHA256SUMS:duplicate:${name}`);
    else if (canonical.has(key)) problems.push(`SHA256SUMS:alias:${name}`);
    listed.set(name, hash); canonical.add(key);
  }
  let manifestArtifacts: unknown;
  try { manifestArtifacts = (JSON.parse(readFileSync(path.join(directory, "manifest.json"), "utf8")) as { artifacts?: unknown }).artifacts; } catch { manifestArtifacts = undefined; }
  if (!Array.isArray(manifestArtifacts)) problems.push("manifest.json:artifacts_unreadable");
  else {
    const fromManifest = new Map<string, string>();
    for (const entry of manifestArtifacts as { name?: unknown; sha256?: unknown }[]) {
      if (entry === null || typeof entry !== "object" || typeof entry.name !== "string" || typeof entry.sha256 !== "string") { problems.push("manifest.json:malformed_entry"); continue; }
      if (fromManifest.has(entry.name)) problems.push(`manifest.json:duplicate:${entry.name}`);
      fromManifest.set(entry.name, entry.sha256);
    }
    for (const [name, hash] of fromManifest) if (listed.get(name) !== hash) problems.push(`inventory_conflict:${name}`);
    for (const name of listed.keys()) if (name !== "manifest.json" && !fromManifest.has(name)) problems.push(`inventory_conflict:${name}`);
  }
  try {
    for (const entry of readdirSync(directory)) if (entry.endsWith(".json") && !listed.has(entry)) problems.push(`unlisted_artifact:${entry}`);
  } catch { problems.push("directory:unreadable"); }
  for (const name of required) {
    const file = path.join(directory, name);
    if (!existsSync(file)) continue;
    const hash = listed.get(name);
    if (hash === undefined) { problems.push(`unlisted_mandatory:${name}`); continue; }
    try {
      if (!lstatSync(file).isFile()) { problems.push(`not_a_regular_file:${name}`); continue; }
      const data = readFileSync(file);
      if (createHash("sha256").update(data).digest("hex") !== hash) { problems.push(`checksum_mismatch:${name}`); continue; }
      bytes.set(name, data);
    } catch { problems.push(`unreadable:${name}`); }
  }
  return { problems, bytes };
}

