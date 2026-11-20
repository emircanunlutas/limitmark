import { fork, type ChildProcess, type ForkOptions, type SpawnOptions } from "node:child_process";
import { sign, verify, type KeyObject } from "node:crypto";
import { once } from "node:events";
import path from "node:path";
import type { BoundaryBootstrap, OriginBootstrap } from "./fenced-process-main";
import { openLifetime, type Lifetime } from "./fenced-lifetime";
import type { FencedSupervisorOptions } from "./fenced-supervisor";

export type Ownership = { scope: string; epoch: string; previous: string | null; challenge: string };
export type OwnershipGrant = { ownership: Ownership; signature: string };
export type WitnessBootstrap = Omit<FencedSupervisorOptions, "policy" | "trust" | "executionModel" | "lifetime"> & {
  policy: string; app: Omit<OriginBootstrap, "ownerKey" | "signingKey" | "scope">;
  boundary: Omit<BoundaryBootstrap, "policy" | "activation" | "principal" | "audience" | "scheme" | "generation" | "originKey">;
  lifetime: Lifetime;
};
export type OwnerBootstrap = { expected: Ownership; grant?: OwnershipGrant; witnessKey: string };
export type WitnessCommand = { type: "init"; config: WitnessBootstrap } | { type: "acquire"; previous: string | null } |
  { type: "validate"; grant: OwnershipGrant } | { type: "status" | "kill-owner" | "hold-next" | "wait-held" | "shutdown" };
export type WitnessStatus = { epoch: string | null; ownerAlive: boolean; ownerPid: number | null; originAlive: boolean;
  originPid: number | null; originInstance: string | null; port: number | null };
export type WitnessReply = { type: "ready" | "done" | "error" } | { type: "acquired"; grant: OwnershipGrant | null } |
  { type: "validated"; valid: boolean } | { type: "status"; status: WitnessStatus };
export type WitnessRequest = { id: number; command: WitnessCommand };
export type WitnessResponse = { id: number; reply: WitnessReply };

const bytes = (o: Ownership) => Buffer.from(JSON.stringify(["limitmark-witness-v1", o.scope, o.epoch, o.previous, o.challenge]));
export function signOwnership(ownership: Ownership, key: KeyObject): OwnershipGrant {
  return { ownership, signature: sign(null, bytes(ownership), key).toString("base64url") };
}
export function verifyOwnership(grant: OwnershipGrant | undefined, expected: Ownership, key: KeyObject): boolean {
  try {
    const actual = grant?.ownership;
    return !!grant && actual?.scope === expected.scope && actual.epoch === expected.epoch && actual.previous === expected.previous &&
      actual.challenge === expected.challenge && typeof grant.signature === "string" && /^[A-Za-z0-9_-]{86}$/.test(grant.signature) &&
      verify(null, bytes(expected), key, Buffer.from(grant.signature, "base64url"));
  } catch { return false; }
}

export const witnessEntry = path.join(__dirname, "fenced-witness-main.ts");
export function forkWitnessProcess(args: string[] = []) {
  const options: ForkOptions & Pick<SpawnOptions, "windowsHide"> = { execArgv: process.execArgv,
    stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json", windowsHide: true };
  return fork(witnessEntry, args, options);
}

export async function stopWitnessProcess(child: ChildProcess, timeout = 5_000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, "exit", { signal: AbortSignal.timeout(timeout) });
  child.kill("SIGKILL");
  await exited;
}

/** The caller is the trusted launcher and is the only holder of the witness's control channel. */
export async function startTerminationWitness(config: Omit<FencedSupervisorOptions, "executionModel" | "lifetime">) {
  const lifetime = await openLifetime();
  let child: ChildProcess;
  try { child = forkWitnessProcess(); }
  catch (error) { await lifetime.close(); throw error; }
  child.on("error", () => undefined);
  const timeout = 30_000;
  let pending: Promise<WitnessReply> | undefined;
  let failed = false;
  let shutdown: Promise<void> | undefined;
  let sequence = 0;

  function exchange(command: WitnessCommand): Promise<WitnessReply> {
    if (pending || shutdown || failed || !child.connected) return Promise.reject(new Error("termination witness unavailable"));
    pending = send(command).finally(() => { pending = undefined; });
    return pending;
  }

  async function send(command: WitnessCommand): Promise<WitnessReply> {
    const id = ++sequence;
    const abort = new AbortController();
    const expired = new Error("termination witness command timed out");
    const result = Promise.withResolvers<WitnessReply>();
    const deadline = Promise.withResolvers<never>();
    const receive = (message: WitnessResponse) => { if (message?.id === id) result.resolve(message.reply); };
    child.on("message", receive);
    const timer = setTimeout(() => deadline.reject(expired), timeout);
    try {
      const gone = once(child, "disconnect", { signal: abort.signal }).then(() => { throw new Error("termination witness unavailable"); });
      const sendFailure = new Promise<never>((_, reject) => child.send({ id, command } satisfies WitnessRequest, (error) => { if (error) reject(error); }));
      return await Promise.race([result.promise, gone, sendFailure, deadline.promise]);
    } catch (error) {
      // A diagnostic deadline does not establish any change in backend ownership.
      if (error === expired && (command.type === "wait-held" || command.type === "status")) throw expired;
      failed = true;
      throw new Error("termination witness unavailable");
    } finally {
      clearTimeout(timer);
      child.off("message", receive);
      abort.abort();
    }
  }

  const close = () => shutdown ??= (async () => {
    try {
      await pending?.catch(() => undefined);
      if (failed || !child.connected || (await send({ type: "shutdown" })).type !== "done") {
        throw new Error("witness shutdown could not verify ownership release");
      }
    } finally {
      try { await stopWitnessProcess(child); }
      finally { await lifetime.close(); }
    }
  })();

  try {
    const { trust, policy, ...settings } = config;
    const ready = await exchange({ type: "init", config: { ...settings, policy: Buffer.from(policy).toString("base64url"),
      app: trust.appInit(config.limits), boundary: trust.boundaryInit(0, config.limits), lifetime: lifetime.descriptor } });
    if (ready.type !== "ready") throw new Error("termination witness rejected initialization");
  } catch (error) { await close(); throw error; }

  return {
    pid: child.pid,
    async acquire(previous: string | null) {
      const reply = await exchange({ type: "acquire", previous });
      if (reply.type !== "acquired") throw new Error("ownership acquisition failed");
      return reply.grant;
    },
    async status() {
      const reply = await exchange({ type: "status" });
      if (reply.type !== "status") throw new Error("witness status unavailable");
      return reply.status;
    },
    async validate(grant: OwnershipGrant) {
      const reply = await exchange({ type: "validate", grant });
      return reply.type === "validated" && reply.valid;
    },
    async control(type: "kill-owner" | "hold-next" | "wait-held") {
      if ((await exchange({ type })).type !== "done") throw new Error("witness control failed");
    },
    crash: () => stopWitnessProcess(child),
    close,
  };
}
