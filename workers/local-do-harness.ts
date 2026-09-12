import { PublicInquiryAdmissionAuthority, ADMISSION_AUTHORITY_ID, type DurableStorageLike } from "./admission-service/authority";

type LocalStub = { fetch(request: Request): Promise<Response> };
type LocalNamespace = { getByName(name: string): LocalStub };

export class LocalTestAdmissionAuthority extends PublicInquiryAdmissionAuthority {
  private readonly localStorage: DurableStorageLike;

  constructor(state: { storage: DurableStorageLike }) {
    super(state);
    this.localStorage = state.storage;
  }

  private stateSummary() {
    const count = (query: string) => Array.from(this.localStorage.sql.exec<{ count: number }>(query))[0]?.count ?? -1;
    return {
      preClient: count("SELECT COUNT(*) AS count FROM observations WHERE stage='pre' AND scope='client'"),
      preGlobal: count("SELECT COUNT(*) AS count FROM observations WHERE stage='pre' AND scope='global'"),
      postClient: count("SELECT COUNT(*) AS count FROM observations WHERE stage='post' AND scope='client'"),
      postGlobal: count("SELECT COUNT(*) AS count FROM observations WHERE stage='post' AND scope='global'"),
      nonces: count("SELECT COUNT(*) AS count FROM nonces"),
      postConsumed: count("SELECT COUNT(*) AS count FROM nonces WHERE post_consumed=1"),
    };
  }

  async fetch(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method !== "POST" || request.headers.get("x-local-authority-test") !== "phase5c-i1") return new Response(null, { status: 404 });
      const text = await request.text();
      if (text.length > 2_048) return Response.json({ decision: "unavailable" }, { status: 413 });
      const body = JSON.parse(text) as Record<string, unknown>;
      if (url.pathname === "/__local/init") {
        this.initializeForLocalTest([String(body.releaseId)], Number(body.nowMs));
        return Response.json({ initialized: true });
      }
      if (url.pathname === "/__local/pre") return Response.json(this.claimPre(body as never));
      if (url.pathname === "/__local/post") return Response.json(this.consumePost(body as never));
      if (url.pathname === "/__local/cleanup") return Response.json(this.cleanup());
      if (url.pathname === "/__local/state") return Response.json(this.stateSummary());
      return new Response(null, { status: 404 });
    } catch {
      return Response.json({ decision: "unavailable" }, { status: 400 });
    }
  }
}

const localHarness = {
  async fetch(request: Request, environment: { AUTHORITY: LocalNamespace }): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/health" && request.method === "GET") return new Response("ok");
    // The object name is compiled policy and never comes from the request.
    return environment.AUTHORITY.getByName(ADMISSION_AUTHORITY_ID).fetch(request);
  },
};

export default localHarness;
