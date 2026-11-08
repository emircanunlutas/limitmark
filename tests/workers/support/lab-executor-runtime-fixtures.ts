import { WorkerEntrypoint } from "cloudflare:workers";

// Test-only local fixtures for the lab operator-executor runtime test. Nothing here is referenced by any deployment configuration, holds a secret, or
// reaches a network. The stub stands in for the lab admission lifecycle entrypoint ONLY to count and shape what the executor sends to it.

type StubEnvironment = { MODE: string };
let dispatches = 0;
let last: { environment: unknown; authorityId: unknown; operation: unknown } | null = null;

export class StubAdmission extends WorkerEntrypoint<StubEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  getDispatchCount(): number { return dispatches; }
  getLast(): unknown { return last; }
  async initializeAuthorityFromOperatorAttested(command: unknown[], signature: string) {
    dispatches++;
    last = { environment: command[2], authorityId: command[3], operation: command[1] };
    if (this.env.MODE === "throw") throw new Error("injected-transport-failure");
    if (this.env.MODE === "garbage") return { status: "APPLIED", extra: signature.length };
    return { status: "ATTESTED", relayDisposition: "APPLIED", envelope: new Uint8Array([1, 2, 3]) };
  }
}

type Executor = { submitInitializationArtifact(sealed: string): Promise<unknown> };
type DriverEnvironment = {
  EXECUTOR_LAB: Executor; EXECUTOR_PRODUCTION_ENV: Executor; EXECUTOR_THROWING: Executor; EXECUTOR_GARBAGE: Executor;
  STUB_OK: { getDispatchCount(): Promise<number>; getLast(): Promise<unknown> };
  STUB_THROW: { getDispatchCount(): Promise<number> };
  STUB_GARBAGE: { getDispatchCount(): Promise<number> };
};

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
function serialize(result: unknown): unknown {
  const record = (result ?? {}) as Record<string, unknown>;
  if (!(record.envelope instanceof Uint8Array)) return result;
  const { envelope, ...rest } = record;
  return { ...rest, envelopeHex: toHex(envelope as Uint8Array) };
}

/** Drives the real lab executor over real workerd service bindings. One RPC method name per request; results and thrown messages are reported verbatim. */
const driver = {
  async fetch(request: Request, env: DriverEnvironment): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/count") {
        return Response.json({ ok: await env.STUB_OK.getDispatchCount(), throwing: await env.STUB_THROW.getDispatchCount(), garbage: await env.STUB_GARBAGE.getDispatchCount(), last: await env.STUB_OK.getLast() });
      }
      if (request.method !== "POST") return new Response(null, { status: 404 });
      const body = JSON.parse(await request.text()) as { sealedJson?: string };
      const target = { lab: env.EXECUTOR_LAB, productionEnv: env.EXECUTOR_PRODUCTION_ENV, throwing: env.EXECUTOR_THROWING, garbage: env.EXECUTOR_GARBAGE }[url.searchParams.get("executor") ?? "lab"];
      if (!target) return new Response(null, { status: 404 });
      if (url.pathname === "/submit-initialize") return Response.json({ result: serialize(await target.submitInitializationArtifact(body.sealedJson ?? "")) });
      if (url.pathname === "/submit-rotate") {
        // Calling an undeclared RPC method throws at invocation (a proxy trap), so it must be called directly, inside try/catch.
        return Response.json({ result: await (target as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>).submitRotationArtifact(body.sealedJson ?? "") });
      }
      return new Response(null, { status: 404 });
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error) });
    }
  },
};

export default driver;
