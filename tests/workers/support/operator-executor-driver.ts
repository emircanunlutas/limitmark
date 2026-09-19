import { ADMISSION_AUTHORITY_ID } from "../../../workers/admission-service/authority";
import type { AuthorityInitializationCommand } from "../../../workers/admission-service/operator-command";

type DriverEnvironment = {
  EXECUTOR: {
    submitInitializationArtifact(sealedJson: string): Promise<unknown>;
    submitRotationArtifact(sealedJson: string): Promise<unknown>;
  };
  ADMISSION_SERVICE: {
    initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string): Promise<unknown>;
  };
  ACK_PROXY?: { getDispatchCount(): Promise<number> };
  AUTHORITY: { getByName(name: string): { claimPre(input: unknown): Promise<unknown>; consumePost(input: unknown): Promise<unknown> } };
};

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
        case "/submit-initialize": return Response.json(await env.EXECUTOR.submitInitializationArtifact(body.sealedJson ?? ""));
        case "/submit-rotate": return Response.json(await env.EXECUTOR.submitRotationArtifact(body.sealedJson ?? ""));
        case "/direct-signature-check": return Response.json(await env.ADMISSION_SERVICE.initializeAuthorityFromOperator(body.command!, body.signature ?? ""));
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
