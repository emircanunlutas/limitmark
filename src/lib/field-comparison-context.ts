import { z } from "zod";

// Parse each dimension separately. Zod's fixed object shapes give equivalent
// records a stable field order before hashing. Only digests leave this module.
const label = z.string().min(1).max(200);
const positive = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const dimensions = {
  target: z.strictObject({ id: label, class: label, scheme: label, port: positive.max(65535), ownership: label }),
  workload: z.strictObject({ id: label, phases: z.array(z.strictObject({
    name: label, durationSeconds: positive, ratePerSecond: positive, concurrency: positive, timeoutMs: positive,
  })).min(1).max(128) }),
  thresholds: z.strictObject({ id: label, version: positive, sha256: z.string().regex(/^[a-f0-9]{64}$/) }),
  ceilings: z.strictObject({ level: label, workers: positive, maxTotalRequests: positive, maxRequestsPerSecond: positive, durationSeconds: positive }),
};
export type ContextDimension = keyof typeof dimensions;
export const contextLabels: Record<ContextDimension, string> = {
  target: "Target", workload: "Workload and phases", thresholds: "Threshold profile", ceilings: "Observation limits",
};

export async function sha256(bytes: ArrayBuffer) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

function fingerprint(value: unknown) {
  return sha256(new TextEncoder().encode(JSON.stringify(value)).buffer);
}

const revision = z.object({ gitSha: z.string().regex(/^[0-9a-f]{40}$/).refine(sha => !/^0+$/.test(sha)), dirty: z.literal(false) });
const environment = z.strictObject({
  os: label, kernelRelease: label, arch: label, nodeVersion: label, dockerVersion: label.nullable(),
  postgresVersion: label.nullable(), cpuCount: positive, memoryMegabytes: positive,
});

const canaryProtocol = z.object({
  journey: z.strictObject({ steps: z.array(label).min(1).max(64), completeFlowRequired: z.boolean() }),
  jcr: z.array(z.object({ lane: label, phase: label, attempted: z.number().int().nonnegative() })).min(1).max(64),
});

export async function readComparisonContext(manifest: Record<string, unknown>, canary: unknown) {
  const id = z.string().regex(/^\d{8}T\d{6}Z-[a-z0-9-]{1,40}-[a-f0-9]{6}$/).safeParse(manifest.runId);
  const keys = Object.keys(dimensions) as ContextDimension[];
  const entries = await Promise.all(keys.map(async key => {
    const parsed = dimensions[key].safeParse(manifest[key]);
    return [key, parsed.success ? await fingerprint(parsed.data) : null] as const;
  }));
  const git = revision.safeParse(manifest.git), host = environment.safeParse(manifest.environment);
  const protocol = canaryProtocol.safeParse(canary);
  // The order of summary rows is incidental. Journey step order is meaningful.
  const populations = protocol.success ? protocol.data.jcr.map(row => JSON.stringify([row.lane, row.phase, row.attempted > 0])).sort() : [];
  return {
    runKey: id.success ? await fingerprint(id.data) : null,
    revision: git.success ? await fingerprint(git.data) : null,
    environment: host.success ? await fingerprint(host.data) : null,
    canaryProtocol: protocol.success ? await fingerprint([protocol.data.journey, populations]) : null,
    dimensions: Object.fromEntries(entries) as Record<ContextDimension, string | null>,
  };
}
