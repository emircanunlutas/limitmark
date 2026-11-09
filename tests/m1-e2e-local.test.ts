import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { resolveEvidenceDirectory } from "../lab/evidence/manifest";
import { PARAMETERS_DIGEST, buildCommitment, evaluateFreshness, type Commitment, type CommitmentInput } from "../lab/m1/commitment";
import { runCli } from "../lab/m1/cli";
import { identityFromPackage } from "../lab/m1/identity";
import { OBSERVER_FILES, SEAL_FILE } from "../lab/m1/seal";
import { buildWorld, disposeWorld, testRoot, type World } from "./support/m1-world";

// END-TO-END LOCAL DRY RUN of the qualification workflow with disposable local fixtures and processes only (loopback observation processes, a synthetic server package, no network,
// no cloud, no production endpoint). Per run: identity -> pre-run commitment -> observers -> canary journey -> collector declaration -> export and seal -> inventory and provenance ->
// unified acceptance recomputed from the authoritative inputs. Then three distinct runs -> campaign. The best possible result is LOCAL_REPEATABILITY_PASS; QUALIFIED is unreachable.
// This is NOT remote qualification and is not substitutable for it.

const root = testRoot("e2e");
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "m1-e2e-"));
const GAP = 1_000; const H = 3_600_000; const T0 = 1_800_000_000_000;
type Kit = { world: World; slot: number; runId: string; campaignId: string; commitmentFile: string; digest: string; sealed: string; ids: Record<string, string>; accepted: string };
const kits: Kit[] = [];

async function cli(args: string[]): Promise<{ code: number; out: Record<string, unknown> & { outcome: string; reasons: string[]; record: string | null; details: Record<string, unknown> } }> {
  const lines: string[] = [];
  const code = await runCli(args, { stdout: (line) => lines.push(line), evidenceRoot: root });
  return { code, out: JSON.parse(lines[lines.length - 1]!) };
}
const rootArgs = ["--evidence-root", root];
function commitmentFor(world: World, slot: number): { file: string; digest: string; commitment: Commitment } {
  const identity = identityFromPackage(resolveEvidenceDirectory(world.serverId, root)).identity!;
  const start = T0 + slot * 3 * H;
  const input: CommitmentInput = {
    campaignId: identity.campaignId, runId: identity.runId, commit: identity.gitSha, treeClean: true, parametersId: "ba0-field-v1", parametersDigest: PARAMETERS_DIGEST, fixtureDigest: "e".repeat(64),
    target: { ipv4: "10.10.0.5", authorizedFromMs: start - H, authorizedUntilMs: start + 2 * H }, window: { startMs: start, endMs: start + 300_000 },
    instance: { id: `local-instance-${slot}`, createdMs: start - 30 * 60_000, imageId: "local-image", bootId: `local-boot-${slot}` }, counters: { admitted: 0, shed: 0, forwarded: 0 },
    canaryThresholdsFixed: true, retentionDays: 30, previousTeardownMs: slot === 1 ? null : T0 + (slot - 1) * 3 * H + 30 * 60_000,
  };
  const built = buildCommitment(input); assert.equal(built.outcome, "VALID", built.reasons.join(","));
  const file = path.join(scratch, `commitment-${slot}.json`);
  fs.writeFileSync(file, JSON.stringify({ commitment: built.commitment, digest: built.digest }));
  return { file, digest: built.digest!, commitment: built.commitment! };
}
async function prepare(world: World, slot: number): Promise<Kit> {
  const identity = identityFromPackage(resolveEvidenceDirectory(world.serverId, root)).identity!;
  const commitment = commitmentFor(world, slot);
  assert.equal((await cli(["commitment", "--commitment", commitment.file, "--server", world.serverId, ...rootArgs])).code, 0);
  const sealed = path.join(scratch, `sealed-${slot}`);
  const sealRun = await cli(["seal", "--observer-dir", world.observerDirectory, "--destination", sealed, "--server", world.serverId, "--commitment", commitment.file, ...rootArgs]);
  assert.equal(sealRun.code, 0, JSON.stringify(sealRun.out));
  return { world, slot, runId: identity.runId, campaignId: identity.campaignId, commitmentFile: commitment.file, digest: commitment.digest, sealed, ids: {}, accepted: "" };
}
async function record(kit: Kit, observerDir: string): Promise<void> {
  const observed = await cli(["observe", "--server", kit.world.serverId, "--observer-dir", observerDir, "--max-heartbeat-gap-ms", String(GAP), ...rootArgs]);
  const provenance = await cli(["provenance", "--server", kit.world.serverId, "--retained-dir", kit.world.retainedDirectory, ...rootArgs]);
  kit.ids = { ...(kit.world.ids as Record<string, string>), observation: observed.out.record!, provenance: provenance.out.record! };
}
const acceptArgs = (kit: Kit, observerDir: string, extra: string[] = []): string[] => ["accept", "--server", kit.world.serverId, "--generator-report", kit.world.reportPath, "--observer-dir", observerDir, "--retained-dir", kit.world.retainedDirectory,
  "--max-heartbeat-gap-ms", String(GAP), ...Object.entries(kit.ids).flatMap(([name, id]) => ["--result", `${name}=${id}`]), ...extra, ...rootArgs];

test.before(async () => {
  for (const slot of [1, 2, 3]) {
    const kit = await prepare(await buildWorld(root, { slot }), slot);
    await record(kit, kit.sealed);
    kits.push(kit);
  }
});
test.after(() => { for (const kit of kits) disposeWorld(kit.world); fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(scratch, { recursive: true, force: true }); });

const runsFile = (selected: Kit[], observerDirs: string[] = selected.map((k) => k.sealed)): string => {
  const file = path.join(scratch, `runs-${Math.random().toString(16).slice(2, 8)}.json`);
  fs.writeFileSync(file, JSON.stringify(selected.map((k, i) => ({ serverId: k.world.serverId, reportPath: k.world.reportPath, observerDirectory: observerDirs[i], retainedDirectory: k.world.retainedDirectory, resultIds: k.ids, acceptanceId: k.accepted || undefined, commitmentFile: k.commitmentFile }))));
  return file;
};
const campaign = (selected: Kit[], observerDirs?: string[], extra: string[] = ["--require-seal"]) => cli(["campaign", "--runs-file", runsFile(selected, observerDirs), "--max-heartbeat-gap-ms", String(GAP), ...extra, ...rootArgs]);
const copyDir = (from: string, name: string): string => { const to = path.join(scratch, name); fs.cpSync(from, to, { recursive: true }); return to; };

test("DRY RUN, positive: three distinct local runs reach LOCAL_REPEATABILITY_PASS through the CLI, and nothing reaches QUALIFIED", async () => {
  for (const kit of kits) {
    const verified = await cli(["verify-seal", "--directory", kit.sealed, "--server", kit.world.serverId, "--commitment", kit.commitmentFile, ...rootArgs]);
    assert.deepEqual([verified.code, verified.out.outcome, verified.out.details.producerAuthentication], [0, "VERIFIED", "none"], "byte consistency verified; producer authentication is a separate, unanswered question");
    const completeness = await cli(["completeness", "--server", kit.world.serverId, "--observer-dir", kit.sealed, "--max-heartbeat-gap-ms", String(GAP), ...rootArgs]);
    assert.deepEqual([completeness.code, completeness.out.outcome], [0, "PASS"], completeness.out.reasons.join(","));
    const accepted = await cli(acceptArgs(kit, kit.sealed, ["--require-seal", "--commitment", kit.commitmentFile]));
    assert.deepEqual([accepted.code, accepted.out.outcome], [0, "LOCALLY_CONSISTENT"], JSON.stringify(accepted.out.reasons));
    assert.equal(accepted.out.details.qualification, false);
    kit.accepted = accepted.out.record!;
  }
  const commitments = kits.map((k) => { const read = JSON.parse(fs.readFileSync(k.commitmentFile, "utf8")) as { commitment: Commitment; digest: string }; return { commitment: read.commitment, digest: read.digest }; });
  assert.equal(evaluateFreshness(commitments).outcome, "FRESH", "three distinct instances, boots and runs, ordered and non-overlapping");
  const result = await campaign(kits);
  assert.deepEqual([result.code, result.out.outcome, result.out.details.qualification], [0, "LOCAL_REPEATABILITY_PASS", false], JSON.stringify(result.out.reasons));
  assert.notEqual(result.out.outcome, "QUALIFIED");
  // determinism: the same inputs give the same machine-readable result (only the record id differs)
  const again = await campaign(kits);
  assert.deepEqual({ ...again.out, record: null }, { ...result.out, record: null });
});

test("DRY RUN, negative: observer evidence modified after sealing prevents acceptance and the campaign", async () => {
  const tampered = copyDir(kits[1]!.sealed, "tampered-after-seal");
  const canaryFile = path.join(tampered, "canary-results.json");
  const canary = JSON.parse(fs.readFileSync(canaryFile, "utf8")) as { steps: { ok: boolean; status: number; latencyMs: number }[] };
  canary.steps[0]!.ok = true; canary.steps[1]!.latencyMs = 1; fs.writeFileSync(canaryFile, JSON.stringify(canary));
  const verified = await cli(["verify-seal", "--directory", tampered, "--server", kits[1]!.world.serverId, "--commitment", kits[1]!.commitmentFile, ...rootArgs]);
  assert.deepEqual([verified.code, verified.out.outcome], [10, "FAILED"]);
  assert.ok(verified.out.reasons.includes("m1.seal.file_modified.canary-results.json"));
  const accepted = await cli(acceptArgs(kits[1]!, tampered, ["--require-seal", "--commitment", kits[1]!.commitmentFile]));
  assert.deepEqual([accepted.code, accepted.out.outcome], [10, "REJECT"]);
  const result = await campaign(kits, [kits[0]!.sealed, tampered, kits[2]!.sealed]);
  assert.equal(result.code, 10); assert.notEqual(result.out.outcome, "LOCAL_REPEATABILITY_PASS");
});

test("DRY RUN, negative: re-sealing modified evidence cannot rescue it (the result recomputed from the new bytes disagrees with the recorded result)", async () => {
  const forged = copyDir(kits[1]!.sealed, "resealed-forgery");
  const receiptsFile = path.join(forged, "origin-receipts.ndjson");
  const lines = fs.readFileSync(receiptsFile, "utf8").split("\n").filter(Boolean); lines.pop();
  fs.writeFileSync(receiptsFile, `${lines.join("\n")}\n`);
  fs.rmSync(path.join(forged, SEAL_FILE));
  const sealed = path.join(scratch, "resealed-forgery-sealed");
  const resealed = await cli(["seal", "--observer-dir", forged, "--destination", sealed, "--server", kits[1]!.world.serverId, "--commitment", kits[1]!.commitmentFile, ...rootArgs]);
  assert.equal(resealed.code, 0, "the byte seal is internally consistent: it only proves the bytes did not change after sealing");
  const accepted = await cli(acceptArgs(kits[1]!, sealed, ["--require-seal", "--commitment", kits[1]!.commitmentFile]));
  assert.notEqual(accepted.out.outcome, "LOCALLY_CONSISTENT"); assert.notEqual(accepted.code, 0);
  const result = await campaign(kits, [kits[0]!.sealed, sealed, kits[2]!.sealed]);
  assert.notEqual(result.out.outcome, "LOCAL_REPEATABILITY_PASS"); assert.notEqual(result.code, 0);
});

test("DRY RUN, negative: missing evidence, a missing seal, a missing declaration, replay and cross-run substitution cannot produce a positive result", async () => {
  const k = kits[0]!;
  // a run without its collector declaration: completeness fails closed
  const noDeclaration = copyDir(k.sealed, "no-declaration"); fs.rmSync(path.join(noDeclaration, "collector-declaration.json")); fs.rmSync(path.join(noDeclaration, SEAL_FILE));
  const c1 = await cli(["completeness", "--server", k.world.serverId, "--observer-dir", noDeclaration, "--max-heartbeat-gap-ms", String(GAP), ...rootArgs]);
  assert.notEqual(c1.code, 0, JSON.stringify(c1.out));
  // sealing requires every observer file
  const sealMissing = await cli(["seal", "--observer-dir", noDeclaration, "--destination", path.join(scratch, "never"), "--server", k.world.serverId, "--commitment", k.commitmentFile, ...rootArgs]);
  assert.notEqual(sealMissing.code, 0); assert.ok(sealMissing.out.reasons.includes("m1.seal.source_missing.collector-declaration.json"));
  // no seal where one is required
  const unsealed = copyDir(k.sealed, "unsealed"); fs.rmSync(path.join(unsealed, SEAL_FILE));
  const a1 = await cli(acceptArgs(k, unsealed, ["--require-seal", "--commitment", k.commitmentFile]));
  assert.notEqual(a1.code, 0); assert.ok(a1.out.reasons.includes("m1.seal.absent"));
  // cross-run substitution: run 2's sealed evidence presented for run 1
  const a2 = await cli(acceptArgs(k, kits[1]!.sealed, ["--require-seal", "--commitment", k.commitmentFile]));
  assert.notEqual(a2.code, 0); assert.ok(a2.out.reasons.some((r) => r.startsWith("m1.seal.run_mismatch") || r.startsWith("m1.seal.commitment_mismatch")), a2.out.reasons.join(","));
  // replay: the same sealed evidence listed for two runs of a campaign
  const replay = await campaign([kits[0]!, kits[1]!, kits[2]!], [kits[0]!.sealed, kits[0]!.sealed, kits[2]!.sealed]);
  assert.notEqual(replay.code, 0); assert.notEqual(replay.out.outcome, "LOCAL_REPEATABILITY_PASS");
  // a heartbeat limit the evidence cannot meet, and a missing limit
  const strict = await cli(["completeness", "--server", k.world.serverId, "--observer-dir", k.sealed, "--max-heartbeat-gap-ms", "1", ...rootArgs]);
  assert.equal(strict.code, 10, "a limit the heartbeats cannot meet is a rejection, not a tolerance");
  const noLimit = await cli(["completeness", "--server", k.world.serverId, "--observer-dir", k.sealed, ...rootArgs]);
  assert.equal(noLimit.code, 64);
  // a supplied PASS artifact is not trusted: an acceptance run for a different component set cannot lift a run with a missing result
  const partial = await cli(acceptArgs({ ...k, ids: { overlay: k.ids.overlay! } }, k.sealed, ["--require-seal", "--commitment", k.commitmentFile]));
  assert.notEqual(partial.out.outcome, "LOCALLY_CONSISTENT"); assert.notEqual(partial.code, 0);
});

test("CLI contract: usage errors exit 64, unknown servers exit 30, commitment problems exit 10, and the sealed directory holds exactly the observer files", async () => {
  assert.equal((await cli(["nonsense"])).code, 64);
  assert.equal((await cli(["observe", "--server", "x", "--observer-dir", scratch, "--unknown", "1"])).code, 64);
  assert.equal((await cli(["observe", "--server", "x", "--server", "y", "--observer-dir", scratch, ...rootArgs])).code, 64);
  assert.equal((await cli(["accept", "--server", "no-such-run", "--generator-report", scratch, "--observer-dir", scratch, "--retained-dir", scratch, "--max-heartbeat-gap-ms", "1000", ...rootArgs])).code, 30);
  assert.equal((await cli(["completeness", "--server", "no-such-run", "--observer-dir", scratch, "--max-heartbeat-gap-ms", "abc", ...rootArgs])).code, 64);
  const bad = path.join(scratch, "bad-commitment.json");
  const read = JSON.parse(fs.readFileSync(kits[0]!.commitmentFile, "utf8")) as { commitment: { treeClean: boolean }; digest: string };
  fs.writeFileSync(bad, JSON.stringify({ commitment: { ...read.commitment, treeClean: false }, digest: read.digest }));
  const dirty = await cli(["commitment", "--commitment", bad, ...rootArgs]);
  assert.deepEqual([dirty.code, dirty.out.outcome], [10, "INVALID"]);
  fs.writeFileSync(bad, JSON.stringify({ commitment: read.commitment, digest: "0".repeat(64) }));
  assert.ok((await cli(["commitment", "--commitment", bad, ...rootArgs])).out.reasons.includes("m1.cli.commitment_digest_mismatch"));
  fs.writeFileSync(bad, "{not json");
  assert.equal((await cli(["commitment", "--commitment", bad, ...rootArgs])).code, 30);
  assert.deepEqual(fs.readdirSync(kits[0]!.sealed).sort(), [...OBSERVER_FILES, SEAL_FILE].sort());
  // the real process: exit code and a single deterministic line
  const spawned = spawnSync(process.execPath, ["--import", "tsx", "--conditions=react-server", path.join(__dirname, "..", "lab", "m1", "cli.ts"), "commitment", "--commitment", bad], { encoding: "utf8" });
  assert.equal(spawned.status, 30); assert.equal(spawned.stdout.trim().split("\n").length, 1); assert.equal((JSON.parse(spawned.stdout) as { outcome: string }).outcome, "ERROR");
});

test("DRY RUN, teardown: no observation process outlives its run, and disposing the worlds removes every local directory the run created", () => {
  const alive = (pid: number): boolean => { try { process.kill(pid, 0); return true; } catch { return false; } };
  for (const kit of kits) {
    const meta = JSON.parse(fs.readFileSync(path.join(kit.sealed, "observation-meta.json"), "utf8")) as { processes: Record<string, number> };
    for (const [name, pid] of Object.entries(meta.processes)) if (name !== "harness") assert.equal(alive(pid), false, `${name} (${pid}) must have exited`);
  }
  const directories = kits.flatMap((kit) => [kit.world.observerDirectory, kit.world.retainedDirectory, kit.world.reportDirectory]);
  for (const kit of kits) disposeWorld(kit.world);
  for (const directory of directories) assert.equal(fs.existsSync(directory), false, `${directory} removed`);
});
