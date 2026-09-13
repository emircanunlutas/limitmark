import {
  ADMISSION_MAC_HEADER,
  ADMISSION_KEY_ID_HEADER,
  ADMISSION_MAX_BODY_BYTES,
  ADMISSION_POST_PATH,
  ADMISSION_PRE_PATH,
  ADMISSION_RPC_CONTENT_TYPE,
  ADMISSION_RPC_MAX_SKEW_MS,
  decodeAdmissionRpcPayload,
  verifyAdmissionRpcMac,
} from "../../src/lib/admission-protocol";
import type { PublicInquiryAdmissionAuthority } from "./authority";
import { authenticateVercelOidc, type VercelOidcPolicy, type VercelOidcSignatureVerifier } from "./auth";

export const ADMISSION_RELEASE_OVERLAP_MAX_MS = 5 * 60_000;
export type AdmissionServiceRelease = {
  role: "current" | "previous";
  releaseId: string;
  keyId: string;
  rpcKey: CryptoKey;
  activatedAtMs: number;
  retireAtMs?: number;
};
type AdmissionAuthorityCalls = {
  claimPre(input: Parameters<PublicInquiryAdmissionAuthority["claimPre"]>[0]): ReturnType<PublicInquiryAdmissionAuthority["claimPre"]> | Promise<ReturnType<PublicInquiryAdmissionAuthority["claimPre"]>>;
  consumePost(input: Parameters<PublicInquiryAdmissionAuthority["consumePost"]>[0]): ReturnType<PublicInquiryAdmissionAuthority["consumePost"]> | Promise<ReturnType<PublicInquiryAdmissionAuthority["consumePost"]>>;
};

function configuredReleasesAreValid(releases: readonly AdmissionServiceRelease[]): boolean {
  if (releases.length < 1 || releases.length > 2 || releases.filter((release) => release.role === "current").length !== 1 ||
      new Set(releases.map((release) => release.releaseId)).size !== releases.length || new Set(releases.map((release) => release.keyId)).size !== releases.length) return false;
  const current = releases.find((release) => release.role === "current")!;
  if (current.retireAtMs !== undefined || !Number.isSafeInteger(current.activatedAtMs) || current.activatedAtMs < 0) return false;
  return releases.every((release) => /^[A-Za-z0-9_.:-]{1,128}$/u.test(release.releaseId) && /^[A-Za-z0-9_-]{1,64}$/u.test(release.keyId) &&
    Number.isSafeInteger(release.activatedAtMs) && release.activatedAtMs >= 0 && (release.role === "current" ||
      release.activatedAtMs < current.activatedAtMs && Number.isSafeInteger(release.retireAtMs) && release.retireAtMs! > current.activatedAtMs &&
      release.retireAtMs! - current.activatedAtMs <= ADMISSION_RELEASE_OVERLAP_MAX_MS));
}

async function readBounded(request: Request): Promise<Uint8Array> {
  if (!request.body) throw new Error("rpc-body");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.length;
      if (length > ADMISSION_MAX_BODY_BYTES) throw new Error("rpc-size");
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  const claimed = request.headers.get("content-length");
  if (claimed !== null && (!/^(?:0|[1-9][0-9]*)$/.test(claimed) || Number(claimed) !== length)) throw new Error("rpc-length");
  return body;
}

export function createAdmissionService(configuration: {
  releases: readonly AdmissionServiceRelease[];
  oidcPolicy: VercelOidcPolicy;
  oidcVerifier: VercelOidcSignatureVerifier;
  authority: AdmissionAuthorityCalls;
  now?: () => number;
}) {
  return async function handle(request: Request): Promise<Response> {
    try {
      if (!configuredReleasesAreValid(configuration.releases)) return Response.json({ decision: "unavailable" }, { status: 503 });
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.search || request.method !== "POST" ||
          url.pathname !== ADMISSION_PRE_PATH && url.pathname !== ADMISSION_POST_PATH ||
          request.headers.get("content-type") !== ADMISSION_RPC_CONTENT_TYPE || request.headers.get("content-encoding") !== null) {
        return Response.json({ decision: "unavailable" }, { status: 404 });
      }
      const authorization = request.headers.get("authorization") ?? "";
      if (!authorization.startsWith("Bearer ") || authorization.indexOf("Bearer ") !== authorization.lastIndexOf("Bearer ")) return Response.json({ decision: "unavailable" }, { status: 401 });
      const nowMs = (configuration.now ?? Date.now)();
      if (!await authenticateVercelOidc(authorization.slice(7), configuration.oidcVerifier, configuration.oidcPolicy, nowMs)) return Response.json({ decision: "unavailable" }, { status: 401 });
      const body = await readBounded(request);
      const keyId = request.headers.get(ADMISSION_KEY_ID_HEADER) ?? "";
      const release = configuration.releases.find((candidate) => candidate.keyId === keyId);
      if (!release || nowMs < release.activatedAtMs || release.retireAtMs !== undefined && nowMs >= release.retireAtMs) return Response.json({ decision: "unavailable" }, { status: 401 });
      const mac = request.headers.get(ADMISSION_MAC_HEADER) ?? "";
      if (!await verifyAdmissionRpcMac(url.pathname, body, mac, release.rpcKey)) return Response.json({ decision: "unavailable" }, { status: 401 });
      const payload = decodeAdmissionRpcPayload(body);
      if (payload[1] !== release.releaseId || Math.abs(nowMs - payload[3]) > ADMISSION_RPC_MAX_SKEW_MS) return Response.json({ decision: "unavailable" }, { status: 401 });
      if (url.pathname === ADMISSION_PRE_PATH) {
        if (payload[7] !== "-") return Response.json({ decision: "unavailable" }, { status: 400 });
        // Envelope freshness is rechecked by the authority using its own clock.
        if (payload[8] === 0) return Response.json({ decision: "unavailable" }, { status: 400 });
        const decision = await configuration.authority.claimPre({ releaseId: payload[1], clientPseudonym: payload[4], requestBinding: payload[5], nonce: payload[6], issuedAtMs: payload[8] });
        return Response.json(decision, { status: 200 });
      }
      if (payload[7] === "-" || payload[8] !== 0) return Response.json({ decision: "unavailable" }, { status: 400 });
      return Response.json(await configuration.authority.consumePost({ releaseId: payload[1], clientPseudonym: payload[4], requestBinding: payload[5], nonce: payload[6], permit: payload[7] }), { status: 200 });
    } catch {
      return Response.json({ decision: "unavailable" }, { status: 503 });
    }
  };
}
