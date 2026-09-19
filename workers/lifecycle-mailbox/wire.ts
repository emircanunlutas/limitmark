import { parseStrictJson } from "../../operator/lifecycle-submitter";
import type { R2ObjectBody } from "@cloudflare/workers-types";

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
