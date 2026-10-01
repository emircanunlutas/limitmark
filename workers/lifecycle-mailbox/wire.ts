import { parseStrictJson } from "../../operator/lifecycle-submitter";
import { isOpaqueEnvelope } from "../../operator/attested-relay";
import type { R2Bucket, R2ObjectBody } from "@cloudflare/workers-types";

export const CONTROL_LIMIT = 1_024;
export const RESULT_LIMIT = 8_192;
export const WIRE_VERSION = 1;
export type ControlRequest = { version: 1; digest: string; nonce: string };

export function parseControl(bytes: Uint8Array): ControlRequest {
  if (!bytes.length || bytes.length > CONTROL_LIMIT) throw new Error("control-size");
  const source = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  if (source.charCodeAt(0) === 0xfeff) throw new Error("control-bom");
  const value = parseStrictJson(source);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("control-schema");
  const request = value as Record<string, unknown>;
  if (Object.keys(request).length !== 3 || request.version !== WIRE_VERSION ||
      typeof request.digest !== "string" || !/^[a-f0-9]{64}$/u.test(request.digest) ||
      typeof request.nonce !== "string" || !/^[a-f0-9]{32}$/u.test(request.nonce)) throw new Error("control-schema");
  return request as ControlRequest;
}

export async function readBounded(object: R2ObjectBody | null, maximum: number): Promise<Uint8Array | null> {
  if (!object) return null;
  if (object.size > maximum) throw new Error("object-size");
  const reader = object.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximum) throw new Error("object-size");
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export function boundedResult(value: object): Uint8Array {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  if (bytes.byteLength > RESULT_LIMIT) throw new Error("result-size");
  return bytes;
}

/**
 * Non-authoritative marker on an object that holds Authority-signed envelope bytes. It lets a relay skip rewriting an envelope it
 * already published; no reader consults it. A storage attacker who sets, removes or forges it can only cause a rewrite or a skip
 * of unsigned/stale data: the reader derives every positive semantic from the verified envelope bytes alone.
 */
export const SIGNED_RESULT_METADATA = Object.freeze({ limitmarkResult: "r06-signed-envelope-v2" });

/** Stores the Authority's EXACT envelope bytes as the object body: no wrapper, no JSON, no re-serialization, no inspection beyond
 * the transport bound. A stale unsigned diagnostic (or any object not marked as signed) is replaced; a published envelope is kept. */
export async function publishSignedEnvelope(bucket: R2Bucket, key: string, envelope: Uint8Array): Promise<void> {
  if (!isOpaqueEnvelope(envelope)) throw new Error("result-envelope-invalid");
  const existing = await bucket.head(key);
  if (existing && existing.customMetadata?.limitmarkResult === SIGNED_RESULT_METADATA.limitmarkResult) return;
  const written = await bucket.put(key, envelope, { customMetadata: { ...SIGNED_RESULT_METADATA } });
  if (!written || typeof written !== "object" || written.key !== key) throw new Error("result-publication-unconfirmed");
}
