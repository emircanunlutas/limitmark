/**
 * HARNESS-ONLY verdict override for the BA0 collapse experiments (C1, C2). This is the only implementation of
 * `defense/core/override-port.ts`. It exists only under `lab/`, is constructed only by `plane-collapse-main.ts` (the harness's own plane
 * entry), and is never imported by anything under `defense/`, `src/`, `workers/`, `operator/`, `scripts/` or `deployment/`.
 *
 * A layer ALWAYS evaluates for real first. When an arm matches, the harness delivers a different verdict than the layer computed and the
 * shadow (what the layer really decided) is recorded; the delivered verdict is permanently labelled `basis: "simulated"` by the front.
 *
 * Arms are one-shot and created only over the harness's IPC pipe. A request alone can never create one. A match requires ALL of:
 *   - the correlation nonce the harness generated for this request,
 *   - the digest of the exact reviewed fixture bytes (method, target, body), recomputed here from what the plane received,
 *   - the kernel-assigned remote port of the connection the harness opened for it (not request content),
 *   - an unconsumed arm that has not expired.
 * The nonce is client-controlled, which is exactly why it is never sufficient. Arm ids are CSPRNG values and appear in evidence only as a
 * short hash tag. The override can change only a layer's verdict: it holds no key, no proof and no handle on canonicalization, the Boundary
 * or the App.
 */
import { createHash } from "node:crypto";
import type { LaneDecision } from "../../../defense/core/lanes";
import type { SimulatedOverride, VerdictOverridePort } from "../../../defense/core/override-port";
import type { LayerOutcome, LayerRequest } from "../../../defense/core/types";

export const MAX_OUTSTANDING_ARMS = 16;

export type ArmSpec = { armId: string; layer: "l1" | "l2"; nonce: string; fixtureDigest: string; remotePort: number; ttlMs: number };
export type ArmStats = {
  armed: number;
  consumed: number;
  refused: number;
  /** Armed, not consumed, and past their expiry. */
  expired: number;
  /** Armed, not consumed, not yet expired. */
  outstanding: number;
  applied: { armTag: string; layer: "l1" | "l2" }[];
};

/** Digest of a request's reviewed identity: its method, its target and its body bytes. Request content narrows a match; it never creates one. */
export function fixtureDigestOf(request: { method: string; target: string; body: Uint8Array | null }): string {
  const hash = createHash("sha256").update(`${request.method}\n${request.target}\n`);
  if (request.body !== null) hash.update(request.body);
  return hash.digest("hex");
}

export const armTagOf = (armId: string): string => createHash("sha256").update(`arm:${armId}`).digest("hex").slice(0, 8);

type Arm = ArmSpec & { expiresAt: number; consumed: boolean };

export class CollapseOverride implements VerdictOverridePort {
  private readonly arms = new Map<string, Arm>();
  private armedCount = 0;
  private refusedCount = 0;
  private readonly applied: ArmStats["applied"] = [];

  /** Returns false (and counts it) when the outstanding-arm cap is reached or the spec is malformed. */
  arm(spec: ArmSpec, now: number = performance.now()): boolean {
    const outstanding = [...this.arms.values()].filter((arm) => !arm.consumed && arm.expiresAt >= now).length;
    const valid = typeof spec.armId === "string" && spec.armId.length >= 16 && /^[0-9a-f]{64}$/.test(spec.fixtureDigest) && Number.isInteger(spec.remotePort) && spec.remotePort > 0
      && spec.nonce.length === 22 && spec.ttlMs > 0 && spec.ttlMs <= 10_000 && !this.arms.has(spec.armId);
    if (!valid || outstanding >= MAX_OUTSTANDING_ARMS) { this.refusedCount++; return false; }
    this.arms.set(spec.armId, { ...spec, expiresAt: now + spec.ttlMs, consumed: false });
    this.armedCount++;
    return true;
  }

  private take(layer: "l1" | "l2", context: { request: LayerRequest; nonce: string; remotePort: number | undefined }): Arm | null {
    if (context.nonce.length === 0 || context.remotePort === undefined) return null;
    const now = performance.now();
    const digest = fixtureDigestOf(context.request);
    for (const arm of this.arms.values()) {
      if (arm.consumed || arm.layer !== layer || arm.expiresAt < now) continue;
      if (arm.nonce !== context.nonce || arm.remotePort !== context.remotePort || arm.fixtureDigest !== digest) continue;
      arm.consumed = true;
      this.applied.push({ armTag: armTagOf(arm.armId), layer });
      return arm;
    }
    return null;
  }

  l1(context: { request: LayerRequest; nonce: string; remotePort: number | undefined; outcome: LayerOutcome }): SimulatedOverride | null {
    if (context.outcome.kind !== "reject") return null;
    return this.take("l1", context) ? { shadow: `reject:${context.outcome.reason}` } : null;
  }

  l2(context: { request: LayerRequest; nonce: string; remotePort: number | undefined; decision: LaneDecision }): SimulatedOverride | null {
    const { decision } = context;
    if (decision.outcome !== "shed" && decision.outcome !== "admitted") return null;
    if (!this.take("l2", context)) return null;
    return { shadow: `${decision.outcome}:${decision.lane ?? "none"}${decision.shedReason ? `:${decision.shedReason}` : ""}` };
  }

  stats(): ArmStats {
    const now = performance.now();
    const all = [...this.arms.values()];
    return {
      armed: this.armedCount, consumed: all.filter((arm) => arm.consumed).length, refused: this.refusedCount,
      expired: all.filter((arm) => !arm.consumed && arm.expiresAt < now).length, outstanding: all.filter((arm) => !arm.consumed && arm.expiresAt >= now).length,
      applied: [...this.applied],
    };
  }
}
