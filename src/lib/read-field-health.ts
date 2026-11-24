import { assessFieldRun, reviewManifestSchema, type Artifact, type FieldHealthReview } from "./field-health";

export const fieldReviewFiles = ["SHA256SUMS", "manifest.json", "external.json", "canary.json"] as const;
type Name = typeof fieldReviewFiles[number];
type InputFile = Pick<File, "name" | "size" | "arrayBuffer">;
export type ReviewResult = { state: "Reviewed"; review: FieldHealthReview } | { state: "Unknown" | "Unavailable"; detail: string };
const limits: Record<Name, number> = { SHA256SUMS: 16_384, "manifest.json": 128 * 1024, "external.json": 1024 * 1024, "canary.json": 128 * 1024 };

function decode(bytes: ArrayBuffer): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function checksumList(bytes: ArrayBuffer): Map<string, string> {
  const hashes = new Map<string, string>();
  for (const line of decode(bytes).trimEnd().split(/\r?\n/)) {
    const match = /^([a-f0-9]{64})  ([a-z0-9][a-z0-9.-]*\.json)$/.exec(line);
    if (!match || hashes.has(match[2])) throw new Error("checksum-list");
    hashes.set(match[2], match[1]);
  }
  return hashes;
}

async function sha256(bytes: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** Only the four named files are opened. Paths, manifest-supplied names and raw values never reach the view. */
export async function readFieldHealth(files: readonly InputFile[], now: number): Promise<ReviewResult> {
  const selected = new Map<Name, InputFile>();
  for (const name of fieldReviewFiles) {
    const matches = files.filter(file => file.name === name);
    if (matches.length > 1) return { state: "Unknown", detail: `Multiple copies of ${name} were selected. Choose one run.` };
    if (matches.length === 1) {
      if (matches[0].size > limits[name]) return { state: "Unknown", detail: `${name} exceeds the review size limit.` };
      selected.set(name, matches[0]);
    }
  }
  const sums = selected.get("SHA256SUMS");
  const manifestFile = selected.get("manifest.json");
  if (!sums || !manifestFile) return { state: "Unavailable", detail: "Select manifest.json and SHA256SUMS from a finalized field run." };

  async function read(file: InputFile) {
    try { return await file.arrayBuffer(); } catch { return null; }
  }
  try {
    const [sumBytes, manifestBytes] = await Promise.all([read(sums), read(manifestFile)]);
    if (!sumBytes || !manifestBytes) return { state: "Unavailable", detail: "The manifest or checksum list could not be read. Select the files again." };
    const hashes = checksumList(sumBytes);
    if (hashes.get("manifest.json") !== await sha256(manifestBytes)) return { state: "Unknown", detail: "The manifest checksum disagrees. Select files from the same finalized run." };
    const manifest = reviewManifestSchema.safeParse(JSON.parse(decode(manifestBytes)));
    if (!manifest.success) return { state: "Unknown", detail: "This manifest is incomplete or uses an unsupported field-run format." };
    const index = new Map(manifest.data.artifacts.map(entry => [entry.name, entry]));
    if (index.size !== manifest.data.artifacts.length || index.size + 1 !== hashes.size || index.has("manifest.json") ||
      manifest.data.artifacts.some(entry => hashes.get(entry.name) !== entry.sha256)) return { state: "Unknown", detail: "The manifest inventory and checksum list disagree." };

    async function artifact(name: "external.json" | "canary.json"): Promise<Artifact> {
      const file = selected.get(name);
      const entry = index.get(name);
      if (!entry && file) return { kind: "unknown", detail: `${name} does not belong to this manifest.` };
      if (!entry) return { kind: "unavailable", detail: `The runner did not publish ${name}.` };
      if (!file) return { kind: "unavailable", detail: `Select ${name} from this run to supply the missing observations.` };
      const bytes = await read(file);
      if (!bytes) return { kind: "unavailable", detail: `${name} could not be read. Select the file again.` };
      if (bytes.byteLength !== entry.bytes || await sha256(bytes) !== entry.sha256) return { kind: "unknown", detail: `${name} differs from the manifest. Check the original run files.` };
      try { return { kind: "present", value: JSON.parse(decode(bytes)) }; }
      catch { return { kind: "unknown", detail: `${name} is malformed.` }; }
    }

    const [external, canary] = await Promise.all([artifact("external.json"), artifact("canary.json")]);
    const review = assessFieldRun(manifest.data, external, canary, now);
    return review ? { state: "Reviewed", review } : { state: "Unknown", detail: "The run dates, server outcome, or supplied observations conflict. Verify the original run and the review clock." };
  } catch {
    return { state: "Unknown", detail: "The evidence could not be verified. Check the file format and use a browser with secure SHA-256 support." };
  }
}
