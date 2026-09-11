import { createHash } from "node:crypto";
import type { TestRequest } from "./request-schema";

const canonicalFields = [
  "name", "email", "company", "service", "system", "objective", "environment",
  "authority", "protection", "provider", "notes",
] as const satisfies readonly (keyof TestRequest)[];

export function createPayloadFingerprint(request: TestRequest): string {
  const canonicalValues = canonicalFields.map((field) => request[field]);
  return createHash("sha256").update(JSON.stringify(canonicalValues), "utf8").digest("hex");
}
