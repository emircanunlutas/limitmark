import { decodeCanonicalBase64url, toArrayBuffer } from "./ingress-protocol";

export const INGRESS_SIGNING_KEY_OVERLAP_MAX_MS = 5 * 60_000;
export type IngressSigningKey = {
  role: "current" | "next";
  keyId: string;
  publicKey: string;
  activatesAtMs: number;
  retiresAtMs?: number;
};

export function parseIngressSigningKeyRollout(value: string | undefined): readonly IngressSigningKey[] | null {
  if (!value || value.length > 2_048) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 2 || parsed.filter((key) => key?.role === "current").length !== 1 ||
        parsed.filter((key) => key?.role === "next").length !== parsed.length - 1) return null;
    const keys = parsed as Array<Record<string, unknown>>;
    if (keys.some((key) => Object.keys(key).sort().join(",") !== (key.role === "current" && parsed.length === 2 ? "activatesAtMs,keyId,publicKey,retiresAtMs,role" : "activatesAtMs,keyId,publicKey,role") ||
        typeof key.keyId !== "string" || !/^[A-Za-z0-9_-]{1,32}$/u.test(key.keyId) || typeof key.publicKey !== "string" ||
        !Number.isSafeInteger(key.activatesAtMs) || (key.activatesAtMs as number) < 0)) return null;
    for (const key of keys) decodeCanonicalBase64url(key.publicKey as string, 32);
    if (new Set(keys.map((key) => key.keyId)).size !== keys.length || new Set(keys.map((key) => key.publicKey)).size !== keys.length) return null;
    if (keys.length === 2) {
      const current = keys.find((key) => key.role === "current")!;
      const next = keys.find((key) => key.role === "next")!;
      if (!Number.isSafeInteger(current.retiresAtMs) || (next.activatesAtMs as number) <= (current.activatesAtMs as number) ||
          (current.retiresAtMs as number) <= (next.activatesAtMs as number) ||
          (current.retiresAtMs as number) - (next.activatesAtMs as number) > INGRESS_SIGNING_KEY_OVERLAP_MAX_MS) return null;
    }
    return keys as unknown as readonly IngressSigningKey[];
  } catch { return null; }
}

export async function importActiveIngressSigningKeys(value: string | undefined, nowMs: number): Promise<ReadonlyMap<string, CryptoKey>> {
  const rollout = parseIngressSigningKeyRollout(value);
  if (!rollout || !Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("ingress-key-rollout");
  const active = rollout.filter((key) => key.activatesAtMs <= nowMs && (key.retiresAtMs === undefined || nowMs < key.retiresAtMs));
  if (active.length < 1 || active.length > 2) throw new Error("ingress-key-window");
  const imported = new Map<string, CryptoKey>();
  for (const key of active) imported.set(key.keyId, await crypto.subtle.importKey("raw", toArrayBuffer(decodeCanonicalBase64url(key.publicKey, 32)), { name: "Ed25519" }, false, ["verify"]));
  return imported;
}
