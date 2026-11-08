// Drives the read-only guard entrypoint exactly as the observer's service binding can: one RPC method name per request, arguments fixed.
type Environment = { GUARD_READER: Record<string, (...args: unknown[]) => Promise<unknown>> };
export default {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const url = new URL(request.url);
    const method = url.searchParams.get("method") ?? "";
    const body = await request.text();
    try {
      const result = await env.GUARD_READER[method](body);
      return Response.json({ ok: true, result });
    } catch (error) { return Response.json({ ok: false, error: error instanceof Error ? error.message : "error" }); }
  },
};
