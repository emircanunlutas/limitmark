type Environment = { COUNTING_EXECUTOR: { getDispatchCount(): Promise<number> };
  COUNTING_ADMISSION: { getDispatchCount(): Promise<number> } };
const driver = {
  async fetch(request: Request, env: Environment): Promise<Response> {
    if (new URL(request.url).pathname === "/count") return Response.json({ count: await env.COUNTING_EXECUTOR.getDispatchCount() });
    if (new URL(request.url).pathname === "/admission-count") return Response.json({ count: await env.COUNTING_ADMISSION.getDispatchCount() });
    return new Response(null, { status: 404 });
  },
};
export default driver;
