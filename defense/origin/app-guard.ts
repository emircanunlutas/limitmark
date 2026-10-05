/**
 * The Protected App's own admission edge. It is an INDEPENDENT instance of the same ordered admission the Boundary runs: its own key
 * (K_B public, plus K_P public for the lineage), its own audience, its own replay state and its own counters. It accepts only a
 * Boundary-to-App (BA) proof that carries the Plane's Plane-to-Boundary (PB) proof as lineage. A PB alone admits nothing here, and this
 * process holds no private key at all.
 *
 * On admission it returns the request as plain FACTS built from the VERIFIED CLAIMS, so the application interprets exactly the
 * representation the Defense Plane approved and never a header view of its own.
 */
import type { KeyObject } from "node:crypto";
import { admitHopRequest, newAdmissionStats, type BaAdmissionConfig } from "../core/hop-admission";
import type { BaClaims } from "../core/hop-proof";
import { ClockFence, ReplayGuard, type ReplayStats } from "../core/replay-guard";
import type { AppGuard } from "./synthetic-origin";

export type AppGuardOptions = {
  keyB: KeyObject; kidB: string;
  keyP: KeyObject; kidP: string;
  appId: string; boundaryId: string;
  replayCapacity: number;
  bodyDeadlineMs: number;
  now?: () => number;
  mono?: () => number;
};

export type AppGuardStats = { replay: ReplayStats; contentReadsStarted: number; contentBytesRead: number; clockStepMs: number; clockStep: boolean };

export function createAppGuard(options: AppGuardOptions): { guard: AppGuard; stats(): AppGuardStats } {
  const wall = options.now ?? (() => Date.now());
  const mono = options.mono ?? (() => performance.now());
  // Two entries per admitted request (the BA and the lineage PB), so the set is sized for both.
  const replay = new ReplayGuard(options.replayCapacity * 2, mono);
  const fence = new ClockFence(wall, mono);
  const admissionStats = newAdmissionStats();
  const config: BaAdmissionConfig = {
    role: "ba", keyB: options.keyB, kidB: options.kidB, keyP: options.keyP, kidP: options.kidP, appId: options.appId, boundaryId: options.boundaryId,
    guard: replay, fence, now: wall, bodyDeadlineMs: options.bodyDeadlineMs, stats: admissionStats,
  };
  const guard: AppGuard = async (req) => {
    const outcome = await admitHopRequest(config, {
      method: req.method ?? "", url: req.url ?? "", rawHeaders: req.rawHeaders, stream: req,
      crossCheck: (claims) => claims.pairs.every(([name, value]) => req.headers[name] === value) && (["content-type", "host", "origin"] as const).every((name) => req.headers[name] === undefined || claims.pairs.some(([key]) => key === name)),
    });
    if (!outcome.ok) return { ok: false, reason: outcome.reason, nonce: outcome.nonce };
    const ba = outcome.claims as BaClaims;
    const pair = (name: string) => ba.request.pairs.find(([key]) => key === name)?.[1];
    return {
      ok: true,
      identity: { nonce: outcome.nonce, hop: outcome.hop, pbTag: outcome.pbTag, baTag: outcome.baTag ?? "" },
      facts: { method: ba.request.method, url: ba.request.target, contentType: pair("content-type"), origin: pair("origin"), host: pair("host"), body: ba.request.method === "POST" ? outcome.body : null },
    };
  };
  return { guard, stats: () => ({ replay: replay.stats(), contentReadsStarted: admissionStats.contentReadsStarted, contentBytesRead: admissionStats.contentBytesRead, clockStepMs: fence.stepMs(), clockStep: fence.stepDetected() }) };
}
