import { INGRESS_MAX_BODY_BYTES } from "./ingress-protocol";
import { fieldLabels } from "./request-schema";
import { submissionTokenField } from "./submission-token";
import { turnstileResponseField } from "./turnstile";

const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const allowedFields = new Set([...Object.keys(fieldLabels), submissionTokenField, turnstileResponseField]);

export async function readBoundedPublicInquiryBody(request: Request): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      length += result.value.length;
      if (length > INGRESS_MAX_BODY_BYTES) throw new Error("public-body-overflow");
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const claimed = request.headers.get("content-length");
  if (claimed !== null && (!/^(?:0|[1-9][0-9]*)$/.test(claimed) || Number(claimed) !== length)) throw new Error("public-body-length");
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return bytes;
}

function decodePart(value: string): string {
  if (/%(?![0-9a-fA-F]{2})/u.test(value)) throw new Error("public-form-percent");
  try { return decodeURIComponent(value.replace(/\+/g, " ")); } catch { throw new Error("public-form-utf8"); }
}

export function parseStrictUrlEncodedForm(body: Uint8Array): FormData {
  let text: string;
  try { text = decoder.decode(body); } catch { throw new Error("public-body-utf8"); }
  const form = new FormData();
  if (text === "") return form;
  const seen = new Set<string>();
  for (const pair of text.split("&")) {
    const separator = pair.indexOf("=");
    const name = decodePart(separator < 0 ? pair : pair.slice(0, separator));
    const value = decodePart(separator < 0 ? "" : pair.slice(separator + 1));
    if (!allowedFields.has(name)) throw new Error("public-form-field");
    if (seen.has(name)) throw new Error("public-form-duplicate");
    seen.add(name);
    form.set(name, value);
  }
  return form;
}
