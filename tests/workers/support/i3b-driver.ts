type Environment = { COUNTING_EXECUTOR: { getDispatchCount(): Promise<number>; submitInitializationArtifact(sealed: string): Promise<unknown>; submitRotationArtifact(sealed: string): Promise<unknown> };
  COUNTING_ADMISSION: { getDispatchCount(): Promise<number> };
  /** Present only in the R06 active-path rig: the same read-only entrypoint the mailbox guard probes through. */
  LIFECYCLE_READER?: { attestAppliedLifecycle(digest: string): Promise<unknown> } };
const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
/** HTTP cannot carry a Uint8Array as JSON; an envelope is reported as hex for the driving test only. */
function serialize(result: unknown): unknown {
  const record = (result ?? {}) as Record<string, unknown>;
  if (!(record.envelope instanceof Uint8Array)) return result;
  const { envelope, ...rest } = record;
  return { ...rest, envelopeHex: toHex(envelope as Uint8Array) };
}
const driver = {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/count") return Response.json({ count: await env.COUNTING_EXECUTOR.getDispatchCount() });
    if (path === "/admission-count") return Response.json({ count: await env.COUNTING_ADMISSION.getDispatchCount() });
    // Direct executor call (bypasses the mailbox and the guard): lets a test observe the Authority's own non-positive answers through the
    // real executor and service-binding hops.
    if (request.method === "POST" && (path === "/executor-initialize" || path === "/executor-rotate")) {
      const sealed = await request.text();
      try {
        return Response.json(serialize(path === "/executor-initialize" ? await env.COUNTING_EXECUTOR.submitInitializationArtifact(sealed) : await env.COUNTING_EXECUTOR.submitRotationArtifact(sealed)));
      } catch (error) { return Response.json({ error: error instanceof Error ? error.message : "executor-error" }, { status: 400 }); }
    }
    // Direct signed pre-claim probe through the real read-only entrypoint (the guard's own call), bypassing the mailbox and the guard.
    if (request.method === "POST" && path === "/reader-attest-applied" && env.LIFECYCLE_READER) {
      const { digest } = await request.json() as { digest: string };
      return Response.json(serialize(await env.LIFECYCLE_READER.attestAppliedLifecycle(digest)));
    }
    return new Response(null, { status: 404 });
  },
};
export default driver;
