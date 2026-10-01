import type { ExecutionContext } from "@cloudflare/workers-types";
import { WorkerEntrypoint } from "cloudflare:workers";
import { ProductionAdmissionAuthority, StagingAdmissionAuthority, type AdmissionServiceEnvironment } from "./admission-service/index";
import { createAuthorityAttestationSigner } from "./admission-service/authority-attestation-signer";

/**
 * R06 PRE-2C TRANSPORT GATE -- local workerd test harness ONLY. Never deployed: no route, no workers_dev, no preview URL, not
 * referenced by any production/staging wrangler config. It pushes the REAL Slice 2A attested Authority results across a real
 * workerd Durable Object RPC boundary and a real WorkerEntrypoint (service-binding style) RPC boundary.
 *
 * The Authority classes only subclass the real adapters to (a) inject a signer built from the RFC 8032 test vectors already
 * frozen in tests/fixtures/authority-result-attestation-v2.golden.json (handed in as a local test var; no operational key) and
 * (b) retain an Authority-side copy of the last envelope so the test can compare after the boundary. Result objects returned by
 * the attested methods are returned UNTOUCHED: no Uint8Array is converted to base64/hex/JSON/number[] on any RPC hop. (Hex appears
 * only in the diagnostic observations this harness reports back over plain HTTP.)
 */
type Role = "production" | "staging";
type Environment = AdmissionServiceEnvironment & { ATTESTATION_TEST_KEYS: string };
type RfcKey = { privateKeyPkcs8: string; publicKey: string; fingerprint: string };

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const fromHex = (text: string) => Uint8Array.from(text.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
const PROBE = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];

function testSigner(environment: Environment, role: Role) {
  const key = (JSON.parse(environment.ATTESTATION_TEST_KEYS) as Record<Role, RfcKey>)[role];
  return createAuthorityAttestationSigner({ environment: role, writerKeyFingerprint: key.fingerprint, privateKey: key.privateKeyPkcs8, publicKey: key.publicKey });
}

/** Test-only Authority-side state shared by both subclasses. */
class Probe {
  last: Uint8Array | undefined;
  stored: Uint8Array | undefined;
  /** The Authority-side copy is taken before the result is returned; the result itself is passed through unchanged. */
  retain<T>(result: T): T {
    const envelope = (result as { envelope?: unknown }).envelope;
    if (envelope instanceof Uint8Array) this.last = envelope.slice();
    return result;
  }
  retainedHex() { return this.last ? toHex(this.last) : null; }
  storedHex() { return this.stored ? toHex(this.stored) : null; }
  store(bytes: Uint8Array) { this.stored = bytes; return bytes.byteLength; }
  static view() {
    const backing = new Uint8Array(32).fill(0x55);
    backing.set(PROBE, 13);
    return backing.subarray(13, 13 + PROBE.length);
  }
}

export class TransportProductionAuthority extends ProductionAdmissionAuthority {
  private readonly probe = new Probe();
  constructor(state: ConstructorParameters<typeof ProductionAdmissionAuthority>[0], environment: Environment) {
    super(state, environment, { signer: testSigner(environment, "production") });
  }
  override async initializeFromOperatorAttested(...args: Parameters<ProductionAdmissionAuthority["initializeFromOperatorAttested"]>) {
    return this.probe.retain(await super.initializeFromOperatorAttested(...args));
  }
  override async attestAppliedLifecycle(digest: string) { return this.probe.retain(await super.attestAppliedLifecycle(digest)); }
  override async attestReconciliation(digest: string, nonce: string) { return this.probe.retain(await super.attestReconciliation(digest, nonce)); }
  async probeRetainedHex() { return this.probe.retainedHex(); }
  /** Returns the Authority's own retained array (not a copy) so the test can try to mutate "shared" state through it. */
  async probeRetainedObject() { return this.probe.last; }
  async probeEcho(bytes: Uint8Array) { return bytes; }
  async probeEchoResult(bytes: Uint8Array) { return { status: "ATTESTED" as const, relayDisposition: "APPLIED" as const, envelope: bytes }; }
  /** A view with a non-zero byteOffset into a larger buffer: proves only the view's bytes cross, not the whole backing store. */
  async probeView() { return Probe.view(); }
  async probeStore(bytes: Uint8Array) { return this.probe.store(bytes); }
  async probeStoredHex() { return this.probe.storedHex(); }
}

export class TransportStagingAuthority extends StagingAdmissionAuthority {
  private readonly probe = new Probe();
  constructor(state: ConstructorParameters<typeof StagingAdmissionAuthority>[0], environment: Environment) {
    super(state, environment, { signer: testSigner(environment, "staging") });
  }
  override async initializeFromOperatorAttested(...args: Parameters<StagingAdmissionAuthority["initializeFromOperatorAttested"]>) {
    return this.probe.retain(await super.initializeFromOperatorAttested(...args));
  }
  override async attestAppliedLifecycle(digest: string) { return this.probe.retain(await super.attestAppliedLifecycle(digest)); }
  override async attestReconciliation(digest: string, nonce: string) { return this.probe.retain(await super.attestReconciliation(digest, nonce)); }
  async probeRetainedHex() { return this.probe.retainedHex(); }
  async probeRetainedObject() { return this.probe.last; }
  async probeEcho(bytes: Uint8Array) { return bytes; }
  async probeEchoResult(bytes: Uint8Array) { return { status: "ATTESTED" as const, relayDisposition: "APPLIED" as const, envelope: bytes }; }
  async probeView() { return Probe.view(); }
  async probeStore(bytes: Uint8Array) { return this.probe.store(bytes); }
  async probeStoredHex() { return this.probe.storedHex(); }
}

type AnyStub = Record<string, (...args: unknown[]) => Promise<unknown>>;
type HarnessEnvironment = Environment & {
  AUTHORITY_PRODUCTION: { getByName(name: string): AnyStub };
  AUTHORITY_STAGING: { getByName(name: string): AnyStub };
};
const AUTHORITY_NAMES: Record<Role, string> = { production: "production-public-inquiries-v1", staging: "staging-public-inquiries-v1" };

const describeBytes = (value: Uint8Array) => ({
  isUint8Array: value instanceof Uint8Array,
  tag: Object.prototype.toString.call(value),
  byteLength: value.byteLength,
  byteOffset: value.byteOffset,
  bufferByteLength: value.buffer.byteLength,
  hex: toHex(value),
});

/** What a caller can observe about a received Authority result, without changing it. */
function observe(value: unknown) {
  const record = (value ?? {}) as Record<string, unknown>;
  const envelope = record.envelope;
  return {
    keys: Object.keys(record),
    status: record.status,
    relayDisposition: record.relayDisposition,
    reason: record.reason,
    envelope: envelope === undefined ? undefined : envelope instanceof Uint8Array
      ? describeBytes(envelope) : { isUint8Array: false, tag: Object.prototype.toString.call(envelope), typeofValue: typeof envelope },
  };
}

/** Service-binding hop: a WorkerEntrypoint reached through `ctx.exports` (real workerd entrypoint RPC) that calls the real
 * Durable Object stub (real DO RPC) and hands the result straight back (a second structured-clone crossing). */
export class AttestationTransportCaller extends WorkerEntrypoint<HarnessEnvironment> {
  override fetch(): Response { return new Response(null, { status: 404 }); }
  private stub(role: Role): AnyStub {
    const namespace = role === "production" ? this.env.AUTHORITY_PRODUCTION : this.env.AUTHORITY_STAGING;
    return namespace.getByName(AUTHORITY_NAMES[role]);
  }
  /** Returns the Authority result untouched plus what THIS entrypoint saw right after the Durable Object RPC (hop 1). */
  async callAuthority(role: Role, method: string, args: unknown[]) {
    const result = await this.stub(role)[method](...args);
    return { hop1: observe(result), result };
  }
  async probe(role: Role, method: string, args: unknown[]) { return this.stub(role)[method](...args); }
  /** Uint8Array argument: created by the fetch handler, crosses entrypoint RPC to here, then DO RPC and back. */
  async echoViaDurableObject(role: Role, method: string, bytes: Uint8Array) {
    const received = await this.stub(role)[method](bytes);
    return received;
  }
}

type CallerEntrypoint = {
  callAuthority(role: Role, method: string, args: unknown[]): Promise<{ hop1: ReturnType<typeof observe>; result: unknown }>;
  probe(role: Role, method: string, args: unknown[]): Promise<unknown>;
  echoViaDurableObject(role: Role, method: string, bytes: Uint8Array): Promise<unknown>;
};

const harness = {
  async fetch(request: Request, _environment: HarnessEnvironment, context: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ harness: "attestation-rpc-transport", bindings: ["AUTHORITY_PRODUCTION", "AUTHORITY_STAGING"], testOnly: true });
    }
    if (request.method !== "POST" || request.headers.get("x-local-attestation-transport-test") !== "r06-pre2c") return new Response(null, { status: 404 });
    try {
      const text = await request.text();
      if (text.length > 16_384) return new Response(null, { status: 413 });
      const body = JSON.parse(text) as { role: Role; method?: string; args?: unknown[]; hex?: string };
      const caller = (context.exports as unknown as { AttestationTransportCaller: CallerEntrypoint }).AttestationTransportCaller;
      switch (url.pathname) {
        case "/__local-attestation-transport/call": {
          // `final` is what this fetch handler sees after DO RPC (inside the entrypoint) + entrypoint RPC (entrypoint -> here).
          const { hop1, result } = await caller.callAuthority(body.role, body.method!, body.args ?? []);
          return Response.json({ hop1, final: observe(result), finalIsPlainObject: Object.getPrototypeOf(result) === Object.prototype });
        }
        case "/__local-attestation-transport/echo": {
          const sent = fromHex(body.hex ?? "");
          const received = await caller.echoViaDurableObject(body.role, body.method!, sent);
          const result = received instanceof Uint8Array ? describeBytes(received) : observe(received);
          return Response.json({ sentHex: toHex(sent), sentLengthAfter: sent.byteLength, result });
        }
        case "/__local-attestation-transport/view": {
          const received = await caller.probe(body.role, "probeView", []);
          return Response.json(received instanceof Uint8Array ? describeBytes(received) : { isUint8Array: false });
        }
        case "/__local-attestation-transport/alias": {
          // 1. caller-side mutation of a received attested envelope cannot reach the Authority or a separately retained copy.
          const { result } = await caller.callAuthority(body.role, "attestAppliedLifecycle", body.args ?? []);
          const received = (result as { envelope: Uint8Array }).envelope;
          const authorityHexBefore = await caller.probe(body.role, "probeRetainedHex", []) as string;
          const expectedCopy = fromHex(authorityHexBefore); // independent retained expected bytes
          const sameBeforeMutation = toHex(received) === authorityHexBefore;
          received.fill(0xff);
          const authorityHexAfterMutation = await caller.probe(body.role, "probeRetainedHex", []) as string;
          // 2. the Authority's own retained object, fetched by reference-returning RPC, is also an independent clone.
          const retainedObject = await caller.probe(body.role, "probeRetainedObject", []) as Uint8Array;
          const retainedObjectMatches = toHex(retainedObject) === authorityHexBefore;
          retainedObject.fill(0);
          const authorityHexAfterSecondMutation = await caller.probe(body.role, "probeRetainedHex", []) as string;
          const second = await caller.probe(body.role, "probeRetainedObject", []) as Uint8Array;
          // 3. request direction: a Uint8Array sent to the Authority is copied (not shared, not transferred away).
          const sent = Uint8Array.from(PROBE);
          const storedLength = await caller.probe(body.role, "probeStore", [sent]);
          const sentIntactAfterCall = toHex(sent) === toHex(Uint8Array.from(PROBE)) && sent.buffer.byteLength === PROBE.length;
          sent.fill(0x11);
          return Response.json({
            sameBeforeMutation,
            receivedMutated: toHex(received) === "ff".repeat(received.byteLength),
            expectedCopyIntact: toHex(expectedCopy) === authorityHexBefore,
            authorityUnchangedAfterReceiverMutation: authorityHexAfterMutation === authorityHexBefore,
            retainedObjectMatches,
            authorityUnchangedAfterRetainedObjectMutation: authorityHexAfterSecondMutation === authorityHexBefore,
            secondFetchIntact: toHex(second) === authorityHexBefore,
            distinctBackingStores: retainedObject.buffer !== received.buffer && second.buffer !== retainedObject.buffer,
            sentIntactAfterCall,
            storedLength,
            storedAfterSenderMutation: await caller.probe(body.role, "probeStoredHex", []),
          });
        }
        case "/__local-attestation-transport/retained":
          return Response.json({ hex: await caller.probe(body.role, "probeRetainedHex", []) });
        default:
          return new Response(null, { status: 404 });
      }
    } catch (error) {
      return Response.json({ error: error instanceof Error ? error.message : String(error) }, { status: 400 });
    }
  },
};

export default harness;
