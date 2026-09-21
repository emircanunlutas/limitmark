export type LiveReadonlyHarnessEnvironment = {
  LIFECYCLE_READER: { inspectLifecycle(digest: string): Promise<object> };
};

const digestPattern = /^[a-f0-9]{64}$/u;

/** Local-only Gate 4B bridge. Never deployed; no route, no workers_dev, no
 * preview URL (see wrangler.staging-admission-live-readonly.local.jsonc). Its
 * only capability is the single `remote: true` LIFECYCLE_READER binding
 * declared in that config, which `wrangler dev` proxies to the already-live
 * limitmark-admission-service-staging Worker's StagingAuthorityLifecycleReadOnly
 * entrypoint -- this file imports nothing else and exposes no write path, so
 * there is no broader RPC surface to reach even by mistake. */
const liveReadonlyHarness = {
  async fetch(request: Request, environment: LiveReadonlyHarnessEnvironment): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/__gate4-live-readonly/inspect" ||
        request.headers.get("x-gate4-live-readonly-harness") !== "phase5c-gate4b")
      return new Response(null, { status: 404 });
    try {
      const text = await request.text();
      if (text.length > 256) return new Response(null, { status: 413 });
      const body = JSON.parse(text) as { digest?: unknown };
      if (typeof body.digest !== "string" || !digestPattern.test(body.digest)) return new Response(null, { status: 400 });
      return Response.json(await environment.LIFECYCLE_READER.inspectLifecycle(body.digest));
    } catch {
      return Response.json({ status: "refused" }, { status: 400 });
    }
  },
};

export default liveReadonlyHarness;
