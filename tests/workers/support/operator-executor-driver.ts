import { ADMISSION_AUTHORITY_ID } from "../../../workers/admission-service/authority";
import type { AuthorityInitializationCommand } from "../../../workers/admission-service/operator-command";

type DriverEnvironment = {
  EXECUTOR: {
    submitInitializationArtifact(sealedJson: string): Promise<unknown>;
    submitRotationArtifact(sealedJson: string): Promise<unknown>;
  };
  ADMISSION_SERVICE: {
    initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string): Promise<unknown>;
  };
  ACK_PROXY?: { getDispatchCount(): Promise<number> };
  AUTHORITY: { getByName(name: string): { claimPre(input: unknown): Promise<unknown>; consumePost(input: unknown): Promise<unknown> } };
};

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
/** HTTP cannot carry a Uint8Array as JSON; an envelope is reported as hex for the driving test, which decodes it back to bytes. */
function serialize(result: unknown): unknown {
  const record = (result ?? {}) as Record<string, unknown>;
  if (!(record.envelope instanceof Uint8Array)) return result;
  const { envelope, ...rest } = record;
  return { ...rest, envelopeHex: toHex(envelope as Uint8Array) };
}

// Test-only local driver. It is not referenced by any Production config.
const operatorExecutorDriver = {
  async fetch(request: Request, env: DriverEnvironment): Promise<Response> {
    try {
      const path = new URL(request.url).pathname;
      if (request.method === "GET" && path === "/dispatch-count" && env.ACK_PROXY) {
        return Response.json({ count: await env.ACK_PROXY.getDispatchCount() });
      }
      if (request.method !== "POST") return new Response(null, { status: 404 });
      const raw = await request.text();
      if (raw.length > 8_192) return new Response(null, { status: 413 });
      const body = JSON.parse(raw) as { sealedJson?: string; command?: AuthorityInitializationCommand; signature?: string; input?: unknown };
      switch (path) {
        case "/submit-initialize": return Response.json(serialize(await env.EXECUTOR.submitInitializationArtifact(body.sealedJson ?? "")));
        case "/submit-rotate": return Response.json(serialize(await env.EXECUTOR.submitRotationArtifact(body.sealedJson ?? "")));
        case "/direct-signature-check": return Response.json(serialize(await env.ADMISSION_SERVICE.initializeAuthorityFromOperatorAttested(body.command!, body.signature ?? "")));
        case "/pre": return Response.json(await env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).claimPre(body.input));
        case "/post": return Response.json(await env.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).consumePost(body.input));
        default: return new Response(null, { status: 404 });
      }
    } catch (error) {
      const code = error instanceof Error ? error.message : "driver-error";
      return Response.json({ error: code }, { status: 400 });
    }
  },
};

export default operatorExecutorDriver;
