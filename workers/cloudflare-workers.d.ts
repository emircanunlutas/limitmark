declare module "cloudflare:workers" {
  import type { DurableObjectState, ExecutionContext } from "@cloudflare/workers-types";

  export abstract class DurableObject<Env = unknown> {
    protected ctx: DurableObjectState;
    protected env: Env;
    constructor(ctx: DurableObjectState, env: Env);
    alarm?(): void | Promise<void>;
    fetch?(request: Request): Response | Promise<Response>;
  }

  export abstract class WorkerEntrypoint<Env = unknown> {
    protected ctx: ExecutionContext;
    protected env: Env;
    constructor(ctx: ExecutionContext, env: Env);
    fetch?(request: Request): Response | Promise<Response>;
  }
}
