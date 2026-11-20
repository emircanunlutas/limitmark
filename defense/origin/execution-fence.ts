import { createHmac, randomUUID, sign, timingSafeEqual, verify, type KeyObject } from "node:crypto";
import http from "node:http";

export const EXECUTION_HEADER = "x-limitmark-execution";
export const TERMINAL_HEADER = "x-limitmark-terminal";
const CONTROL_PATH = "/.limitmark/execution-generation";
const GENERATION_HEADER = "x-limitmark-generation";
const ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const MAC = /^[A-Za-z0-9_-]{43}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

type Generation = { originInstance: string; scope: string; epoch: number; ownershipEpoch?: string };
export type ExecutionGeneration = Readonly<Generation & { ticket: string; requestKey: string }>;
export type BoundaryExecutionOptions = { generation: ExecutionGeneration; originKey: KeyObject };

const message = (label: string, g: Generation, ...fields: unknown[]) =>
  Buffer.from(JSON.stringify([label, g.originInstance, g.scope, g.ownershipEpoch ?? null, g.epoch, ...fields]));
const mac = (key: Uint8Array, data: Buffer) => createHmac("sha256", key).update(data).digest();
const matches = (key: Uint8Array, data: Buffer, tag: string) => MAC.test(tag) && timingSafeEqual(mac(key, data), Buffer.from(tag, "base64url"));
const epochOf = (raw: string) => {
  const epoch = Number(raw);
  return Number.isSafeInteger(epoch) && epoch > 0 && String(epoch) === raw ? epoch : undefined;
};
const validScope = (scope: string) => /^[a-z][a-z0-9-]{0,63}$/.test(scope);
const validOwnership = (epoch: string | undefined) => epoch === undefined || (typeof epoch === "string" && ID.test(epoch));

/** Trusted local owner provisions a unique, increasing epoch for each Boundary instance. */
export function provisionExecutionGeneration(ownerKey: Uint8Array, g: Generation): ExecutionGeneration {
  if (ownerKey.byteLength !== 32 || !ID.test(g.originInstance) || !validScope(g.scope) || !validOwnership(g.ownershipEpoch) ||
      epochOf(String(g.epoch)) === undefined) throw new Error("invalid execution generation");
  return Object.freeze({ ...g, ticket: mac(ownerKey, message("generation-v1", g)).toString("base64url"),
    requestKey: mac(ownerKey, message("request-key-v1", g)).toString("base64url") });
}

function values(req: http.IncomingMessage, header: string): string[] {
  const result: string[] = [];
  for (let index = 0; index < req.rawHeaders.length; index += 2) {
    if (req.rawHeaders[index].toLowerCase() === header) result.push(req.rawHeaders[index + 1]);
  }
  return result;
}

/** The single trusted origin holds this state across Boundary lifetimes. A new origin gets a fresh instance ID. */
export function createExecutionFence(options: { ownerKey: Uint8Array; originKey: KeyObject; scope: string; ownershipEpoch?: string; maxExecutions?: number }) {
  const { originKey, scope, ownershipEpoch } = options;
  const ownerKey = Buffer.from(options.ownerKey);
  const limit = options.maxExecutions ?? 65_536;
  if (ownerKey.length !== 32 || originKey.type !== "private" || originKey.asymmetricKeyType !== "ed25519" || !validScope(scope) || !validOwnership(ownershipEpoch) ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 65_536) throw new Error("invalid origin execution fence");
  const originInstance = randomUUID();
  let epoch = 0;
  let session = "";
  let ready = false;
  let active = 0;
  const seen = new Set<string>();
  const attest = (data: Buffer) => sign(null, data, originKey).toString("base64url");
  function authenticate(envelope: string, ba: string) {
    const [epochText, claimant, id, tag, extra] = envelope.split(".");
    const requested = epochOf(epochText);
    if (requested === undefined || extra !== undefined || !ID.test(claimant) || !ID.test(id) || !tag) return;
    const g = { originInstance, scope, ownershipEpoch, epoch: requested };
    const key = mac(ownerKey, message("request-key-v1", g));
    if (matches(key, message("execute-v1", g, claimant, id, ba), tag)) return { g, claimant, id };
  }

  return Object.freeze({
    originInstance,
    control(req: http.IncomingMessage, res: http.ServerResponse): boolean {
      if (req.url !== CONTROL_PATH) return false;
      const headers = values(req, GENERATION_HEADER);
      const [epochText, claimant, challenge, ticket, proof, extra] = (headers[0] ?? "").split(".");
      const requested = epochOf(epochText);
      const g = { originInstance, scope, ownershipEpoch, epoch: requested ?? 0 };
      if (req.method !== "POST" || headers.length !== 1 || requested === undefined || !ID.test(claimant) || !ID.test(challenge) || extra !== undefined ||
          req.headers["content-length"] !== "0" || req.headers["transfer-encoding"] !== undefined ||
          ticket === undefined || !matches(ownerKey, message("generation-v1", g), ticket) || proof === undefined ||
          !matches(mac(ownerKey, message("request-key-v1", g)), message("claim-v1", g, claimant, challenge), proof)) {
        res.writeHead(403, { "content-length": 0, connection: "close" }).end();
        return true;
      }
      // A higher authenticated epoch fences late requests immediately. Even work from multiple older epochs remains counted.
      if (requested > epoch) { epoch = requested; session = claimant; ready = false; seen.clear(); }
      const ownsGeneration = requested === epoch && claimant === session;
      if (ownsGeneration && active === 0) ready = true;
      const status = ownsGeneration && ready ? 204 : 409;
      res.writeHead(status, { [GENERATION_HEADER]: attest(message("ready-v1", g, claimant, challenge, status)), connection: "close" }).end();
      return true;
    },
    extract(req: http.IncomingMessage): string | undefined {
      // The legacy hop guard keeps its closed header set. Remove only the execution envelope before that guard runs.
      const envelope = values(req, EXECUTION_HEADER);
      if (envelope.length !== 1) return;
      for (let index = 0; index < req.rawHeaders.length; index += 2) {
        if (req.rawHeaders[index].toLowerCase() === EXECUTION_HEADER) { req.rawHeaders.splice(index, 2); break; }
      }
      delete req.headers[EXECUTION_HEADER];
      return envelope[0];
    },
    accept(envelope: string, ba: string): { start(): boolean; finish(): string } | undefined {
      const auth = authenticate(envelope, ba);
      if (!ready || !auth || auth.g.epoch !== epoch || auth.claimant !== session || seen.has(auth.id) || seen.size >= limit) return;
      const { g, claimant: acceptedSession, id } = auth;
      seen.add(id);
      active++;
      let started = false;
      let terminal: string | undefined;
      return {
        start() {
          if (started || terminal !== undefined || !ready || g.epoch !== epoch || acceptedSession !== session) return false;
          started = true;
          return true;
        },
        finish() {
          if (terminal === undefined) {
            terminal = attest(message("terminal-v1", g, acceptedSession, id, ba));
            active--;
          }
          return terminal;
        },
      };
    },
    // Called only after the hop guard commits this exact BA and its PB lineage for the first time.
    // A duplicate may refer to live work. A future epoch has no permanent start fence yet.
    refusedAfterGuard(envelope: string, ba: string): string | undefined {
      const auth = authenticate(envelope, ba);
      if (!auth || auth.g.epoch > epoch) return;
      if (auth.g.epoch === epoch) {
        if (auth.claimant !== session || seen.has(auth.id) || (ready && seen.size < limit)) return;
        // A saturated set stays closed until rotation. Otherwise burn the ID before signing.
        if (seen.size < limit) seen.add(auth.id);
      }
      return "n." + attest(message("never-started-v1", auth.g, auth.claimant, auth.id, ba));
    },
  });
}

export type ExecutionFence = ReturnType<typeof createExecutionFence>;

export function createBoundaryExecution(options: BoundaryExecutionOptions, scope: string, port: number, timeout: number) {
  const g = Object.freeze({ ...options.generation });
  const { originKey } = options;
  if (g.scope !== scope || !ID.test(g.originInstance) || !validOwnership(g.ownershipEpoch) || epochOf(String(g.epoch)) === undefined || !MAC.test(g.ticket) || !MAC.test(g.requestKey) ||
      originKey.type !== "public" || originKey.asymmetricKeyType !== "ed25519") throw new Error("invalid Boundary execution credentials");
  const session = randomUUID();
  const key = Buffer.from(g.requestKey, "base64url");
  const verified = (signature: string | undefined, data: Buffer) => typeof signature === "string" && SIGNATURE.test(signature) &&
    verify(null, data, originKey, Buffer.from(signature, "base64url"));
  return {
    request(ba: string) {
      const id = randomUUID();
      const tag = mac(key, message("execute-v1", g, session, id, ba)).toString("base64url");
      const terminal = (proof: string | undefined) => verified(proof, message("terminal-v1", g, session, id, ba));
      return { header: `${g.epoch}.${session}.${id}.${tag}`, terminal,
        evidence(proof: string | undefined) {
          if (proof?.startsWith("n.")) return verified(proof.slice(2), message("never-started-v1", g, session, id, ba)) ? "never-started" : undefined;
          return terminal(proof) ? "completed" : undefined;
        } };
    },
    reconcile(): Promise<boolean> {
      const challenge = randomUUID();
      const claim = mac(key, message("claim-v1", g, session, challenge)).toString("base64url");
      return new Promise((resolve) => {
        const req = http.request({ host: "127.0.0.1", port, path: CONTROL_PATH, method: "POST", agent: false,
          headers: { "content-length": 0, [GENERATION_HEADER]: `${g.epoch}.${session}.${challenge}.${g.ticket}.${claim}` } }, (res) => {
          res.on("error", () => resolve(false));
          res.resume();
          const proof = res.headers[GENERATION_HEADER];
          res.on("end", () => resolve(res.complete && res.statusCode === 204 && typeof proof === "string" && verified(proof, message("ready-v1", g, session, challenge, 204))));
        });
        const timer = setTimeout(() => { req.destroy(); resolve(false); }, timeout);
        req.once("error", () => resolve(false));
        req.once("close", () => { clearTimeout(timer); resolve(false); });
        req.end();
      });
    },
  };
}
