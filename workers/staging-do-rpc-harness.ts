import type { ExecutionContext } from "@cloudflare/workers-types";
import { DurableObject } from "cloudflare:workers";
import { ADMISSION_POLICY_EPOCH, STAGING_ADMISSION_AUTHORITY_ID } from "./admission-service/authority";
import { StagingAdmissionAuthority } from "./admission-service/index";
import type { AuthorityInitializationCommand } from "./admission-service/operator-command";

export { StagingAdmissionAuthority, StagingAuthorityLifecycleOnly, StagingAuthorityLifecycleReadOnly } from "./admission-service/index";

type HarnessEnvironment = {
  AUTHORITY_OPERATOR_PUBLIC_KEY: string;
  AUTHORITY: { getByName(name: string): { inspectLifecycle(digest: string): Promise<unknown> } };
};
type ReadOnlyEntrypoint = { inspectLifecycle(digest: string): Promise<unknown> };
type LifecycleOnlyEntrypoint = {
  initializeAuthorityFromOperator(command: AuthorityInitializationCommand, signature: string): Promise<{ status: "initialized" | "already-initialized" | "refused" }>;
  rotateAuthorityReleaseFromOperator(): Promise<{ status: "refused" }>;
};

/** Local workerd integration only (Gate 4A). Never deployed; no route, no
 * workers_dev, no preview URL. This harness deliberately never configures
 * ADMISSION_CURRENT_RPC_KEY -- exactly the posture a real Gate 4 deployment
 * should have (see PHASE5C_I3_PROVISIONING_RUNBOOK.md Gate 4) -- so any
 * attempted call through the lifecycle-only write entrypoint fails closed at
 * the secret-policy gate before ever touching authority storage. No
 * initialize/rotate call reachable from this file, or from the driving
 * integration test, can succeed: this proves the write surface is dormant,
 * not merely unused. Lifecycle initialization remains Gate 7's alone. */
const stagingRpcHarness = {
  async fetch(request: Request, environment: HarnessEnvironment, context: ExecutionContext): Promise<Response> {
    if (request.method === "GET" && new URL(request.url).pathname === "/health") {
      environment.AUTHORITY.getByName(STAGING_ADMISSION_AUTHORITY_ID);
      return Response.json({
        harness: "staging-do-rpc",
        binding: "AUTHORITY",
        boundClass: StagingAdmissionAuthority.name,
        extendsDurableObject: Object.getPrototypeOf(StagingAdmissionAuthority.prototype) === DurableObject.prototype,
        authorityName: STAGING_ADMISSION_AUTHORITY_ID,
        policyEpoch: ADMISSION_POLICY_EPOCH,
        readOnlyRpc: ["inspectLifecycle"],
        dormantLifecycleRpc: ["initializeAuthorityFromOperator", "rotateAuthorityReleaseFromOperator"],
      });
    }
    if (request.method !== "POST" || request.headers.get("x-local-staging-rpc-test") !== "phase5c-gate4a") {
      return new Response(null, { status: 404 });
    }
    try {
      const text = await request.text();
      if (text.length > 4_096) return new Response(null, { status: 413 });
      const body = JSON.parse(text) as { digest?: string; command?: never; signature?: string };
      const exported = context.exports as unknown as {
        StagingAuthorityLifecycleReadOnly: ReadOnlyEntrypoint;
        StagingAuthorityLifecycleOnly: LifecycleOnlyEntrypoint;
      };
      switch (new URL(request.url).pathname) {
        case "/__local-staging-rpc/inspect":
          return Response.json(await exported.StagingAuthorityLifecycleReadOnly.inspectLifecycle(body.digest ?? ""));
        // Reachable only from the driving regression test, which asserts this
        // always fails closed and never completes an initialization.
        case "/__local-staging-rpc/attempt-initialize":
          return Response.json(await exported.StagingAuthorityLifecycleOnly.initializeAuthorityFromOperator(body.command!, body.signature ?? ""));
        case "/__local-staging-rpc/attempt-rotate":
          return Response.json(await exported.StagingAuthorityLifecycleOnly.rotateAuthorityReleaseFromOperator());
        default:
          return new Response(null, { status: 404 });
      }
    } catch {
      return Response.json({ status: "refused" }, { status: 400 });
    }
  },
};

export default stagingRpcHarness;
