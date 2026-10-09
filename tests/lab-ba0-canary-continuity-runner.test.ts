import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { test } from "node:test";
import { BA0_FIELD_C2_SALVO_V1, FIELD_LEVELS, ba0FieldFingerprint } from "../lab/defense/field-thresholds";
import { runFieldLevel, type AuthorizationLike, type FieldRunSeams } from "../lab/defense/ba0-field-run";
import { CANARY_CONTINUITY_SCHEMA } from "../lab/defense/canary-continuity";
import { DISPOSABLE_MARKER_CONTENT, type FieldEnvironment } from "../lab/defense/field-preflight";
import { assertEvidenceSafe } from "../lab/evidence/redact";
import { REPOSITORY_ROOT } from "../lab/evidence/manifest";
import { FakeProc, SSHD } from "./support/fake-proc";

/**
 * F-02: the REAL runner on loopback with the REAL reviewed salvo parameters (BA0_FIELD_C2_SALVO_V1, unscaled, no `salvo.reviewed_schedule` change), ended early by the
 * existing `abort` seam right after ARMED (the baseline canary has already run). It exercises
 * runFieldLevel -> buildCanaryContinuity -> writeFieldEvidence -> manifest -> SHA256SUMS. No external peer, no cloud host: every socket is 127.0.0.1.
 */
/** A /proc whose plane socket disappears when the real listener does (as in lab-ba0-field-run.test.ts). */
class LiveProc extends FakeProc {
  planeOpen = true;
  planeInode = -1;
  override readText(file: string): string | null {
    if (file === "/proc/net/tcp" && !this.planeOpen && this.planeInode > 0) {
      const text = super.readText(file);
      return text === null ? null : text.split("\n").filter((line) => !line.includes(` ${this.planeInode} `)).join("\n");
    }
    return super.readText(file);
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function freePort(): Promise<number> {
  const probe = net.createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", () => resolve()));
  const port = (probe.address() as net.AddressInfo).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

test("salvo level: a real early-aborted run writes a schema-valid, scanner-safe, manifested and checksummed canary-continuity.json without touching the verdict", { timeout: 180_000 }, async () => {
  assert.equal(FIELD_LEVELS["ba0-l7-c2-salvo"].thresholds, BA0_FIELD_C2_SALVO_V1, "the reviewed salvo parameters, unscaled");
  const port = await freePort();
  const proc = new LiveProc();
  proc.addProcess(process.pid).addProcess(SSHD);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  const evidenceRoot = path.join(REPOSITORY_ROOT, "artifacts", "lab", `evidence-test-${process.pid}-${Math.random().toString(16).slice(2, 8)}`);
  fs.mkdirSync(evidenceRoot, { recursive: true });
  const lockFile = path.join(evidenceRoot, "field-run.lock");
  const ufw = ["Status: active", "", "[ 1] 22/tcp                     ALLOW IN    198.51.100.7", `[ 2] ${port}/tcp                  ALLOW IN    203.0.113.9`, ""].join("\n");
  const env: FieldEnvironment = {
    platform: "linux", reader: proc, pid: process.pid, readMarker: () => DISPOSABLE_MARKER_CONTENT, unitState: async () => "inactive", ufwStatus: async () => ufw, localIpv4Addresses: () => ["127.0.0.1"],
  };
  const authorization: AuthorizationLike = {
    target: { id: "sut-test", class: "lab-remote", scheme: "http", host: "127.0.0.1", port, allowedPaths: ["/"], allowedMethods: ["GET", "POST"], origin: `http://127.0.0.1:${port}` },
    authorizedUntilMs: null, assertStillAuthorized: () => undefined,
  };
  const controller = new AbortController();
  const seams: FieldRunSeams = {
    env, authorization, git: { gitSha: "a".repeat(40), dirty: false, dirtyFileCount: 0, untrackedFileCount: 0 }, treeIsClean: true, allowLoopbackIngress: true, skipPlatformCheck: true,
    evidenceRoot, lockFile, abort: controller.signal,
    onIngressClosed: () => { proc.planeOpen = false; },
    onTopology: (info) => {
      const { plane, boundary, app } = info.pids;
      for (const pid of [plane, boundary, app]) if (pid !== undefined) proc.addProcess(pid);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.control, inode: 11 }, [process.pid]);
      proc.planeInode = 12;
      proc.addSocket({ family: 4, ip: info.ingress.ip, port: info.ingress.port, inode: 12 }, [plane!]);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.boundary, inode: 13 }, [boundary!]);
      proc.addSocket({ family: 4, ip: "127.0.0.1", port: info.ports.app, inode: 14 }, [app!]);
      assert.equal(info.ingress.ip, "127.0.0.1", "loopback only: no external network request is possible");
    },
    onArmed: () => { setTimeout(() => controller.abort(), 400); },
  };
  try {
    const outcome = await runFieldLevel({ targetId: "sut-test", levelId: "ba0-l7-c2-salvo", campaignId: "selftest-campaign" }, seams);
    // Real salvo level selection and an authoritative verdict that is the operational abort, not influenced by the diagnostic.
    assert.equal(outcome.status, "aborted");
    assert.equal(outcome.bundle!.firstReason?.code, "operator_abort");
    assert.equal(outcome.bundle!.parameters.sha256, ba0FieldFingerprint(BA0_FIELD_C2_SALVO_V1).sha256);
    assert.ok(outcome.bundle!.salvo !== undefined, "the salvo observer was selected by the level id");
    assert.deepEqual(outcome.write!.failed, [], "no artifact was refused by the evidence scanner");
    assert.ok(outcome.write!.written.includes("canary-continuity.json"));
    assert.equal(outcome.write!.written.at(-1), "canary-continuity.json", "written last, after salvo-diagnostics.json");

    const dir = outcome.evidenceDirectory!;
    const artifact = JSON.parse(fs.readFileSync(path.join(dir, "canary-continuity.json"), "utf8")) as { schema: string; status: string; influencesVerdict: boolean; input: { accepted: number; rejected: number; journeysSupplied: number }; rows: { phase: string; lane: string; journeys: number }[] };
    assert.equal(artifact.schema, CANARY_CONTINUITY_SCHEMA);
    assert.equal(artifact.status, "ok");
    assert.equal(artifact.influencesVerdict, false);
    assert.equal(artifact.input.rejected, 0, "genuine runJourney output is never rejected by the validator");
    assert.ok(artifact.input.accepted > 0 && artifact.input.accepted === artifact.input.journeysSupplied, "the baseline canary journeys were aggregated");
    assert.ok(artifact.rows.filter((row) => row.phase === "baseline").some((row) => row.journeys > 0));
    assert.doesNotThrow(() => assertEvidenceSafe(artifact, "$artifact(canary-continuity.json)"));

    // Manifest inclusion and SHA-256 integrity.
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf8")) as { result: string; artifacts?: { name?: string; path?: string; sha256?: string }[] };
    const digest = createHash("sha256").update(fs.readFileSync(path.join(dir, "canary-continuity.json"))).digest("hex");
    assert.ok(JSON.stringify(manifest).includes("canary-continuity.json"), "listed in the manifest");
    assert.ok(JSON.stringify(manifest).includes(digest), "the manifest carries the file's SHA-256");
    const sums = fs.readFileSync(path.join(dir, "SHA256SUMS"), "utf8").split("\n");
    assert.ok(sums.some((line) => line.startsWith(digest) && line.endsWith("canary-continuity.json")), "SHA256SUMS matches");
    for (const line of sums.filter((entry) => entry.trim() !== "")) {
      const [sum, ...name] = line.split(/\s+/);
      assert.equal(createHash("sha256").update(fs.readFileSync(path.join(dir, name.join(" ").replace(/^\*/, "")))).digest("hex"), sum, line);
    }

    // The authoritative artifacts do not carry the diagnostic and are unchanged in shape.
    for (const name of ["core.json", "server-level.json", "canary.json"]) assert.ok(!fs.readFileSync(path.join(dir, name), "utf8").includes("canary-continuity"), name);
    assert.equal((JSON.parse(fs.readFileSync(path.join(dir, "core.json"), "utf8")) as { finalVerdict: string }).finalVerdict, "not_decided_here");
    await sleep(300);
  } finally { fs.rmSync(evidenceRoot, { recursive: true, force: true }); }
});
