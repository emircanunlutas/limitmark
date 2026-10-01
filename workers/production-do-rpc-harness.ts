import type { ExecutionContext } from "@cloudflare/workers-types";
import { DurableObject } from "cloudflare:workers";
import { ADMISSION_AUTHORITY_ID } from "./admission-service/authority";
import { ProductionAdmissionAuthority } from "./admission-service/index";
import type { AuthorityInitializationCommand, AuthorityReleaseRotationCommand } from "./admission-service/operator-command";
import { submitSealedLifecycleArtifact } from "../operator/lifecycle-submitter";

export { AuthorityLifecycleOnly, ProductionAdmissionAuthority } from "./admission-service/index";

type HarnessEnvironment = {
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  ADMISSION_CURRENT_RPC_KEY: string;
  AUTHORITY: {
    getByName(name: string): {
      claimPre(input: Parameters<ProductionAdmissionAuthority["claimPre"]>[0]): Promise<unknown>;
      consumePost(input: Parameters<ProductionAdmissionAuthority["consumePost"]>[0]): Promise<unknown>;
    };
  };
};
type OperatorEntrypoint = {
  initializeAuthorityFromOperatorAttested(command: AuthorityInitializationCommand, signature: string): Promise<unknown>;
  rotateAuthorityReleaseFromOperatorAttested(command: AuthorityReleaseRotationCommand, signature: string): Promise<unknown>;
};

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
/** HTTP cannot carry a Uint8Array as JSON; the envelope is reported as hex for the driving test, which decodes it back to bytes. */
function serialize(result: unknown): unknown {
  const record = (result ?? {}) as Record<string, unknown>;
  if (!(record.envelope instanceof Uint8Array)) return result;
  const { envelope, ...rest } = record;
  return { ...rest, envelopeHex: toHex(envelope as Uint8Array) };
}

// Local workerd integration only. Production routing never uses this entrypoint.
const productionRpcHarness = {
  async fetch(request: Request, environment: HarnessEnvironment, context: ExecutionContext): Promise<Response> {
    if (request.method === "GET" && new URL(request.url).pathname === "/health") {
      environment.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID);
      return Response.json({
        harness: "production-do-rpc",
        binding: "AUTHORITY",
        boundClass: ProductionAdmissionAuthority.name,
        extendsDurableObject: Object.getPrototypeOf(ProductionAdmissionAuthority.prototype) === DurableObject.prototype,
        authorityName: ADMISSION_AUTHORITY_ID,
        dataRpc: ["claimPre", "consumePost"],
        lifecycleRpc: ["initializeAuthorityFromOperatorAttested", "rotateAuthorityReleaseFromOperatorAttested"],
        oldLocalHarnessFallback: false,
      });
    }
    if (request.method !== "POST" || request.headers.get("x-local-production-rpc-test") !== "phase5c-i2") {
      return new Response(null, { status: 404 });
    }
    try {
      const text = await request.text();
      if (text.length > 4_096) return new Response(null, { status: 413 });
      const body = JSON.parse(text) as { command?: never; signature?: string; input?: never };
      const stub = environment.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID);
      const operator = (context.exports as unknown as { AuthorityLifecycleOnly: OperatorEntrypoint }).AuthorityLifecycleOnly;
      switch (new URL(request.url).pathname) {
        case "/__local-production-rpc/submit-initialize":
          return Response.json(serialize(await submitSealedLifecycleArtifact(new TextEncoder().encode(text), "initialize", operator,
            environment.AUTHORITY_OPERATOR_PUBLIC_KEY)));
        case "/__local-production-rpc/submit-rotate":
          return Response.json(serialize(await submitSealedLifecycleArtifact(new TextEncoder().encode(text), "rotate-release", operator,
            environment.AUTHORITY_OPERATOR_PUBLIC_KEY)));
        case "/__local-production-rpc/initialize":
          return Response.json(serialize(await operator.initializeAuthorityFromOperatorAttested(body.command!, body.signature ?? "")));
        case "/__local-production-rpc/rotate":
          return Response.json(serialize(await operator.rotateAuthorityReleaseFromOperatorAttested(body.command!, body.signature ?? "")));
        case "/__local-production-rpc/pre":
          return Response.json(await stub.claimPre(body.input!));
        case "/__local-production-rpc/post":
          return Response.json(await stub.consumePost(body.input!));
        default:
          return new Response(null, { status: 404 });
      }
    } catch {
      return Response.json({ decision: "unavailable" }, { status: 400 });
    }
  },
};

export default productionRpcHarness;
