/**
 * Slice 2: the ordered admission procedure shared by the Origin Boundary (role "pb") and the Protected App (role "ba"). One
 * implementation, two independent INSTANCES (separate processes, keys, replay state, counters): the independence is of process, state and
 * observation, not of code (a stated common-mode limit).
 *
 * Order (cheap and unauthenticated-safe first; nothing asynchronous before the replay reservation):
 *   1. proof header presence/duplication     (BA role also requires the PB lineage header)
 *   2. closed header-set scan                (unbound, duplicate, framing, value)
 *   3. strict proof decode                   (size, canonical encoding, role, shape)
 *   4. kid, audience, lifetime, freshness, verifier-start fence
 *   5. method, exact target, canonical header pairs, declared length  == what the proof says
 *   6. Ed25519 signature                     (BA role then verifies the lineage PB: window, equality, signature)
 *   7. atomic replay reservation             (synchronous; RESERVED)
 *   8. bounded body read, SHA-256 == proof   (the first asynchronous step; any failure BURNS the reservation)
 *   9. commit
 * No body byte is read and no replay entry exists before step 6 succeeded.
 */
import type { Readable } from "node:stream";
import type { KeyObject } from "node:crypto";
import {
  BA_MAX_LIFETIME_MS, HOP_SKEW_MS, PB_MAX_LIFETIME_MS, checkProofWindow, decodeProof, proofTag, sealVerifiedPb, verifyProofSignature,
  type BaClaims, type Claims, type PbClaims, type RequestClaims, type VerifiedPb,
} from "./hop-proof";
import { ClockFence, ReplayGuard, type ReserveRequest } from "./replay-guard";
import { EMPTY_BODY_SHA256, MAX_SEMANTIC_BODY, MEASUREMENT_PATTERN, samePairs, scanHopHeaders, sha256B64 } from "./semantic-request";
import type { ObReason } from "./types";

export type AdmissionRole = "pb" | "ba";

type Shared = { guard: ReplayGuard; fence: ClockFence; now: () => number; bodyDeadlineMs: number; stats?: AdmissionStats };
export type PbAdmissionConfig = Shared & { role: "pb"; keyP: KeyObject; kidP: string; boundaryId: string };
export type BaAdmissionConfig = Shared & { role: "ba"; keyB: KeyObject; kidB: string; keyP: KeyObject; kidP: string; appId: string; boundaryId: string };
export type AdmissionConfig = PbAdmissionConfig | BaAdmissionConfig;

/** Retention of a replay entry: the longest a proof can still be accepted, plus a margin. Monotonic clock. */
export const RETAIN_PB_MS = PB_MAX_LIFETIME_MS + 2 * HOP_SKEW_MS + 1_000;
export const RETAIN_BA_MS = BA_MAX_LIFETIME_MS + 2 * HOP_SKEW_MS + 1_000;

export type AdmissionStats = { contentReadsStarted: number; contentBytesRead: number };
export const newAdmissionStats = (): AdmissionStats => ({ contentReadsStarted: 0, contentBytesRead: 0 });

export type AdmissionRequest = {
  method: string;
  url: string;
  rawHeaders: readonly string[];
  stream: Readable;
  /**
   * Last check before the commit: the runtime's own (merged) view of the bound headers must equal the verified claims. Closed set plus
   * single occurrence makes the two views identical; if they ever differ the request is `ob.canon_error` and the reservation is burned.
   */
  crossCheck?: (claims: RequestClaims) => boolean;
};

export type Admitted = {
  ok: true;
  role: AdmissionRole;
  /** The signed correlation id (measurement only). */
  nonce: string;
  hop: number;
  pbTag: string;
  /** Null at the Boundary (it issues the BA); the BA's tag at the App. */
  baTag: string | null;
  claims: Claims;
  request: RequestClaims;
  body: Buffer;
  /** The verified Plane proof, exactly as received. At the Boundary it is the capability the BA issuer needs; at the App it is lineage. */
  pb: VerifiedPb;
};
export type Refused = { ok: false; reason: ObReason; nonce: string | null };
export type AdmissionOutcome = Admitted | Refused;

type BodyResult = { status: "complete"; body: Buffer } | { status: "incomplete" } | { status: "overflow" };

function readBody(stream: Readable, expected: number, deadlineMs: number, stats?: AdmissionStats): Promise<BodyResult> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let done = false;
    const finish = (result: BodyResult) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      stream.off("data", onData); stream.off("end", onEnd); stream.off("close", onClose); stream.off("error", onClose);
      resolve(result);
    };
    const onData = (chunk: Buffer) => {
      total += chunk.length;
      if (stats) stats.contentBytesRead += chunk.length;
      if (total > expected) { chunks.length = 0; finish({ status: "overflow" }); return; }
      chunks.push(chunk);
    };
    const onEnd = () => finish(total === expected ? { status: "complete", body: Buffer.concat(chunks) } : { status: "incomplete" });
    const onClose = () => finish({ status: "incomplete" });
    const timer = setTimeout(() => finish({ status: "incomplete" }), deadlineMs);
    stream.on("data", onData); stream.on("end", onEnd); stream.on("close", onClose); stream.on("error", onClose);
  });
}

const sameRequest = (a: RequestClaims, b: RequestClaims): boolean =>
  a.method === b.method && a.target === b.target && samePairs(a.pairs, b.pairs) && a.bodyLen === b.bodyLen && a.bodySha256 === b.bodySha256;

/** Never throws: any unexpected failure is `ob.canon_error`, and a reservation is burned unless it was committed. */
export async function admitHopRequest(config: AdmissionConfig, request: AdmissionRequest): Promise<AdmissionOutcome> {
  const scan = scanHopHeaders(request.rawHeaders, request.method);
  const tag = scan.nonces.length === 1 && MEASUREMENT_PATTERN.test(scan.nonces[0]) ? scan.nonces[0] : null;
  const refuse = (reason: ObReason, nonce: string | null = tag): Refused => ({ ok: false, reason, nonce });
  try {
    // 1. proof presence
    const own = config.role === "pb" ? scan.pb : scan.ba;
    if (own.length === 0) return refuse("ob.proof_missing");
    if (own.length > 1) return refuse("ob.proof_duplicate");
    // The Boundary accepts exactly one proof header. The App's header is not part of its closed set, so it is not "ignored": it is refused.
    if (config.role === "pb" && scan.ba.length > 0) return refuse("ob.header_unbound");
    if (config.role === "ba") {
      if (scan.pb.length === 0) return refuse("ob.lineage_missing");
      if (scan.pb.length > 1) return refuse("ob.proof_duplicate");
    }
    // 2. closed header set
    if (scan.violation !== null) return refuse(scan.violation);

    // 3. decode
    const decoded = decodeProof(own[0], config.role);
    if (!decoded.ok) return refuse(decoded.reason);
    const claims = decoded.value.claims;
    const ownKey = config.role === "pb" ? config.keyP : config.keyB;
    const ownKid = config.role === "pb" ? config.kidP : config.kidB;
    const ownAud = config.role === "pb" ? config.boundaryId : config.appId;

    // 4. window
    const nowMs = config.now();
    const window = checkProofWindow(claims, { keys: new Map([[ownKid, ownKey]]), aud: ownAud, nowMs, fenceMs: config.fence.fenceMs });
    if (window !== null) return refuse(window);

    // 5. wire == claims
    const wanted = claims.request;
    if (request.method !== wanted.method) return refuse("ob.method_mismatch");
    if (request.url !== wanted.target) return refuse("ob.target_mismatch");
    if (!samePairs(scan.pairs, wanted.pairs)) return refuse("ob.header_mismatch");
    if (wanted.method === "POST" && Number(scan.contentLengths[0]) !== wanted.bodyLen) return refuse("ob.length_mismatch");

    // 6. signatures
    if (!verifyProofSignature(config.role, decoded.value, ownKey)) return refuse("ob.signature_invalid");
    const nonce = claims.corr;
    // A refusal is attributed to the request's OWN measurement tag when it has one: a replay reuses the original's signed correlation id, and must not be
    // pinned on the original request. The admitted path (no tag on the plane's own requests) uses the signed id.
    const authNonce = tag ?? nonce;
    let pbClaims: PbClaims;
    let pbHeader: string;
    if (config.role === "pb") {
      pbClaims = claims as PbClaims;
      pbHeader = own[0];
    } else {
      const ba = claims as BaClaims;
      pbHeader = scan.pb[0];
      const lineage = decodeProof(pbHeader, "pb");
      if (!lineage.ok) return refuse(lineage.reason, authNonce);
      pbClaims = lineage.value.claims as PbClaims;
      const lineageWindow = checkProofWindow(pbClaims, { keys: new Map([[config.kidP, config.keyP]]), aud: config.boundaryId, nowMs, fenceMs: config.fence.fenceMs });
      if (lineageWindow !== null) return refuse(lineageWindow, authNonce);
      if (ba.pbJti !== pbClaims.jti || ba.pbSha256 !== sha256B64(Buffer.from(pbHeader, "utf8")) || ba.hop !== pbClaims.hop || ba.corr !== pbClaims.corr || !sameRequest(ba.request, pbClaims.request)) {
        return refuse("ob.lineage_mismatch", authNonce);
      }
      if (!verifyProofSignature("pb", lineage.value, config.keyP)) return refuse("ob.signature_invalid", authNonce);
    }

    // 7. atomic, synchronous reservation (no await since the signature check above)
    const wants: ReserveRequest[] = config.role === "pb"
      ? [{ key: `pb:${pbClaims.jti}`, retainMs: RETAIN_PB_MS }]
      : [{ key: `ba:${claims.jti}`, retainMs: RETAIN_BA_MS }, { key: `ln:${pbClaims.jti}`, retainMs: RETAIN_PB_MS }];
    const reserved = config.guard.reserve(wants);
    if (!reserved.ok) return refuse(reserved.reason === "full" ? "ob.replay_cache_full" : "ob.replayed", authNonce);
    const ticket = reserved.ticket;
    try {
      // 8. bounded body, digest
      let body: Buffer = Buffer.alloc(0);
      if (wanted.bodyLen > MAX_SEMANTIC_BODY) return refuse("ob.length_mismatch", authNonce);
      if (wanted.bodyLen > 0) {
        if (config.stats) config.stats.contentReadsStarted++;
        const read = await readBody(request.stream, wanted.bodyLen, config.bodyDeadlineMs, config.stats);
        if (read.status === "incomplete") return refuse("ob.content_incomplete", authNonce);
        if (read.status === "overflow") return refuse("ob.length_mismatch", authNonce);
        body = read.body;
      }
      if ((wanted.bodyLen === 0 ? EMPTY_BODY_SHA256 : sha256B64(body)) !== wanted.bodySha256) return refuse("ob.digest_mismatch", authNonce);
      if (request.crossCheck && !request.crossCheck(wanted)) return refuse("ob.canon_error", authNonce);
      // 9. commit
      ticket.commit();
      return {
        ok: true, role: config.role, nonce, hop: claims.hop, pbTag: proofTag("pb", pbClaims.jti), baTag: config.role === "ba" ? proofTag("ba", claims.jti) : null,
        claims, request: wanted, body, pb: sealVerifiedPb(pbClaims, pbHeader),
      };
    } finally {
      if (!ticket.isSettled) ticket.burn();
    }
  } catch {
    return refuse("ob.canon_error");
  }
}
