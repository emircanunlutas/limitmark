import { StagingAdmissionAuthority, ProductionAdmissionAuthority, type AdmissionServiceEnvironment } from "./admission-service/index";
import { authorityAttestationRuntimeFromEnvironment } from "./admission-service/authority-attestation-config";
import type { AuthorityAttestationRuntime } from "./admission-service/authority-attestation";
import { ADMISSION_AUTHORITY_ID, STAGING_ADMISSION_AUTHORITY_ID } from "./admission-service/authority";

export { AdmissionServiceWorker, AuthorityLifecycleOnly, AuthorityLifecycleReadOnly, StagingAuthorityLifecycleOnly,
  StagingAuthorityLifecycleReadOnly } from "./admission-service/index";

/**
 * R06 SLICE 2C -- local workerd test harness ONLY. Never deployed: it has no route, no workers_dev, no preview URL and is named by no
 * deployment config or template (a source guard pins that). It bundles the REAL Authority Durable Object classes and the REAL lifecycle-only /
 * read-only entrypoints; the only addition is a test-controlled FAULT in front of the real signer so the active path can be driven through
 * "signer not ready" and "signing fails after the transaction committed" (AMBIGUOUS) without touching any active source.
 *
 * The signer itself is built by the ACTIVE environment-binding configuration (authorityAttestationRuntimeFromEnvironment); the test
 * supplies the RFC test vectors through the same binding names a deployment would use. Nothing is defaulted here.
 */
type Fault = "none" | "sign" | "ready";
type Holder = { fault: Fault };

function faultable(role: "production" | "staging", environment: AdmissionServiceEnvironment, holder: Holder): AuthorityAttestationRuntime {
  const base = authorityAttestationRuntimeFromEnvironment(role, environment).signer;
  if (!base) return {};
  return {
    signer: Object.freeze({
      environment: base.environment, authorityId: base.authorityId, policyEpoch: base.policyEpoch, writerKeyFingerprint: base.writerKeyFingerprint,
      async ready(nowMs: number) { if (holder.fault === "ready") throw new Error("injected-ready-failure"); return base.ready(nowMs); },
      async sign(statement: Parameters<typeof base.sign>[0]) { if (holder.fault === "sign") throw new Error("injected-sign-failure"); return base.sign(statement); },
    }),
  };
}

export class FaultableProductionAuthority extends ProductionAdmissionAuthority {
  private readonly holder: Holder;
  constructor(state: ConstructorParameters<typeof ProductionAdmissionAuthority>[0], environment: AdmissionServiceEnvironment) {
    const holder: Holder = { fault: "none" };
    super(state, environment, faultable("production", environment, holder));
    this.holder = holder;
  }
  async setFault(fault: Fault) { this.holder.fault = fault; return fault; }
}

export class FaultableStagingAuthority extends StagingAdmissionAuthority {
  private readonly holder: Holder;
  constructor(state: ConstructorParameters<typeof StagingAdmissionAuthority>[0], environment: AdmissionServiceEnvironment) {
    const holder: Holder = { fault: "none" };
    super(state, environment, faultable("staging", environment, holder));
    this.holder = holder;
  }
  async setFault(fault: Fault) { this.holder.fault = fault; return fault; }
}

type Namespace = { getByName(name: string): { setFault(fault: Fault): Promise<Fault> } };
const harness = {
  async fetch(request: Request, environment: { AUTHORITY: Namespace }): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "POST" || url.pathname !== "/__r06-fault" || request.headers.get("x-r06-active-path-test") !== "2c") return new Response(null, { status: 404 });
    const body = await request.json() as { role: "production" | "staging"; fault: Fault };
    if (!["none", "sign", "ready"].includes(body.fault)) return new Response(null, { status: 400 });
    const name = body.role === "production" ? ADMISSION_AUTHORITY_ID : STAGING_ADMISSION_AUTHORITY_ID;
    return Response.json({ fault: await environment.AUTHORITY.getByName(name).setFault(body.fault) });
  },
};
export default harness;
