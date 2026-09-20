// Test-only driver worker. It holds real service bindings to the actual
// staging executor and staging lifecycle-only admission entrypoint so a Node
// test script can probe their genuine workerd RPC surface (not a mock): does
// a forbidden method exist at all, and does an existing-but-closed method
// perform any mutation. Calling an RPC stub's undeclared method throws at
// invocation time (a Proxy trap), so optional chaining would hide absence;
// every probe therefore calls the method directly inside try/catch.
type StagingExecutorLike = { submitInitializationArtifact(sealed: string): Promise<unknown> };
type StagingAdmissionLifecycleOnlyLike = {
  initializeAuthorityFromOperator(command: unknown, signature: string): Promise<unknown>;
  rotateAuthorityReleaseFromOperator(command: unknown, signature: string): Promise<unknown>;
};
type Environment = { STAGING_EXECUTOR: StagingExecutorLike; STAGING_ADMISSION_LIFECYCLE_ONLY: StagingAdmissionLifecycleOnlyLike };

const driver = {
  async fetch(request: Request, env: Environment): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/probe-executor-rotation") {
      try {
        const stub = env.STAGING_EXECUTOR as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
        const result = await stub.submitRotationArtifact("probe");
        return Response.json({ exposed: true, result });
      } catch (error) {
        return Response.json({ exposed: false, message: String(error) });
      }
    }
    if (path === "/probe-admission-rotation") {
      const result = await env.STAGING_ADMISSION_LIFECYCLE_ONLY.rotateAuthorityReleaseFromOperator(["forged"], "forged");
      return Response.json({ result });
    }
    return new Response(null, { status: 404 });
  },
};

export default driver;
