/** Private launcher IPC owns this witness. Supervision clients get only a witness-signed lease and their fork channel. */
import type { ChildProcess } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { once } from "node:events";
import { importPublicKey } from "../../defense/core/hop-proof";
import { startFencedSupervisor } from "./fenced-supervisor";
import { forkWitnessProcess, signOwnership, stopWitnessProcess, verifyOwnership, type OwnerBootstrap, type OwnershipGrant,
  type WitnessBootstrap, type WitnessCommand, type WitnessReply, type WitnessRequest, type WitnessResponse } from "./fenced-witness";

if (!process.send) throw new Error("termination witness requires private fork IPC");
process.on("disconnect", () => process.exit(1));

if (process.argv[2] === "owner") {
  process.once("message", ({ expected, grant, witnessKey }: OwnerBootstrap) => {
    let valid = false;
    try { valid = verifyOwnership(grant, expected, importPublicKey(witnessKey)); } catch { /* Invalid credentials refuse. */ }
    if (!valid) { process.send!({ type: "denied" }, () => process.exit(1)); return; }
    process.send!({ type: "claim", grant });
  });
} else {
  const keys = generateKeyPairSync("ed25519");
  const witnessKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  type Owner = {
    backend: Awaited<ReturnType<typeof startFencedSupervisor>>;
    grant: OwnershipGrant;
    child?: ChildProcess;
    exited: boolean;
    admitted: boolean;
  };
  let owner: Owner | undefined;
  let bootstrap: WitnessBootstrap | undefined;
  let busy = false;
  let queued: WitnessRequest | undefined;

  async function terminateOrigin(previous: Owner): Promise<void> {
    if (!previous.exited) throw new Error("owner session exit cannot be verified");
    const original = previous.backend.origin;
    await original.stop(true);
    if (!original.verifiedExit) throw new Error("origin exit cannot be verified");
  }

  async function acquire(previous: string | null): Promise<OwnershipGrant | null> {
    const config = bootstrap;
    if (!config || previous !== (owner?.grant.ownership.epoch ?? null) || (owner && !owner.exited)) return null;
    let backend: Owner["backend"];
    if (owner) {
      await terminateOrigin(owner);
      backend = owner.backend;
      await backend.replaceOwner(); // Retain the marker across the entire handoff.
    } else {
      try {
        backend = await startFencedSupervisor({ ...config, policy: Buffer.from(config.policy, "base64url"), executionModel: "process-local-synthetic",
          trust: { appInit: () => config.app, boundaryInit: (appPort, limits) => ({ ...config.boundary, appPort, limits }) } });
      } catch (error) {
        if (error instanceof Error && error.message === "exclusive backend ownership is unavailable") return null;
        throw error;
      }
    }
    const ownership = { scope: backend.scope, epoch: backend.ownershipEpoch, previous, challenge: randomUUID() };
    const next: Owner = { backend, grant: signOwnership(ownership, keys.privateKey), exited: false, admitted: false };
    owner = next;
    try {
      const child = next.child = forkWitnessProcess(["owner"]);
      child.on("error", () => undefined);
      child.once("exit", (code, signal) => { next.exited = code !== null || signal !== null; });
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), config.timeout ?? 5_000);
      try {
        const message = once(child, "message", { signal: abort.signal });
        const gone = once(child, "exit", { signal: abort.signal }).then(() => { throw new Error("owner session exited during ownership check"); });
        const sendFailure = new Promise<never>((_, reject) => child.send({ expected: ownership, grant: next.grant, witnessKey } satisfies OwnerBootstrap,
          (error) => { if (error) reject(error); }));
        const [claim] = await Promise.race([message, gone, sendFailure]);
        if (claim?.type !== "claim" || !verifyOwnership(claim.grant, ownership, keys.publicKey) || next.exited) throw new Error("owner session claim rejected");
      } finally { clearTimeout(timer); abort.abort(); }
      await backend.prepare();
      if (next.exited || !await backend.activate() || next.exited) throw new Error("owner session or Boundary unavailable");
      next.admitted = true;
      return next.grant;
    } catch (error) {
      if (next.child) await stopWitnessProcess(next.child);
      // No grant was published. Only the witness controls provisioning. Close its exact
      // backend and release the marker through the normal verified-origin-exit path.
      await next.backend.close();
      owner = undefined;
      throw error;
    }
  }

  async function handle(command: WitnessCommand): Promise<WitnessReply> {
    switch (command.type) {
      case "init":
        if (bootstrap) throw new Error("witness already initialized");
        bootstrap = command.config;
        return { type: "ready" };
      case "acquire":
        return { type: "acquired", grant: await acquire(command.previous) };
      case "validate":
        return { type: "validated", valid: !!owner && owner.admitted && !owner.exited && verifyOwnership(command.grant, owner.grant.ownership, keys.publicKey) };
      case "status":
        return { type: "status", status: { epoch: owner?.grant.ownership.epoch ?? null, ownerAlive: !!owner?.child && !owner.exited,
          ownerPid: owner?.child?.pid ?? null, originPid: owner?.backend.origin.pid ?? null,
          originAlive: owner?.backend.origin.alive ?? false, originInstance: owner?.backend.origin.instance ?? null,
          port: owner?.admitted && !owner.exited ? owner.backend.port : null } };
      case "kill-owner":
        if (!owner?.child) throw new Error("no owner session");
        await stopWitnessProcess(owner.child);
        return { type: "done" };
      case "hold-next":
        if (!owner) throw new Error("no origin process");
        await owner.backend.origin.holdNext();
        return { type: "done" };
      case "wait-held":
        if (!owner) throw new Error("no origin process");
        await owner.backend.origin.waitHeld();
        return { type: "done" };
      case "shutdown":
        if (owner?.child) await stopWitnessProcess(owner.child);
        if (owner) { await terminateOrigin(owner); await owner.backend.close(); }
        return { type: "done" };
    }
  }

  function respond(id: number, reply: WitnessReply): void {
    if (process.connected) process.send!({ id, reply } satisfies WitnessResponse, (error) => { if (error) process.exit(1); });
  }

  function dispatch({ id, command }: WitnessRequest): void {
    busy = true;
    void handle(command).catch((): WitnessReply => ({ type: "error" })).then((reply) => {
      respond(id, reply);
      busy = false;
      const next = queued;
      queued = undefined;
      if (next) dispatch(next);
    });
  }

  process.on("message", (request: WitnessRequest) => {
    if (!busy) { dispatch(request); return; }
    // A diagnostic can outlive its caller's deadline. Keep the next exchange ordered behind it.
    if (!queued) queued = request;
    else respond(request.id, { type: "error" });
  });
}
