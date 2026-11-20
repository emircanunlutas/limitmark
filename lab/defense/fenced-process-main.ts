/** Local Stage 4 child entry. Bootstrap and test controls are available only over the parent's IPC channel. */
import { createPrivateKey } from "node:crypto";
import { createBoundary, type Boundary } from "../../defense/boundary/boundary";
import type { BoundaryInit } from "../../defense/boundary/protocol";
import { activateCustomerOriginPolicy } from "../../defense/core/capacity-policy";
import type { HttpScheme, PolicyActivationRecord } from "../../defense/core/capacity-port";
import { importPrivateKey, importPublicKey } from "../../defense/core/hop-proof";
import { createAppGuard } from "../../defense/origin/app-guard";
import type { AppInit } from "../../defense/origin/app-protocol";
import { createExecutionFence, type ExecutionGeneration } from "../../defense/origin/execution-fence";
import { createSyntheticOrigin, type SyntheticOrigin } from "../../defense/origin/synthetic-origin";
import { connectLifetime, type Lifetime } from "./fenced-lifetime";

export type OriginBootstrap = Omit<AppInit, "type" | "channel"> & { ownerKey: string; signingKey: string; scope: string; ownershipEpoch?: string; lifetime?: Lifetime };
export type BoundaryBootstrap = Omit<BoundaryInit, "type" | "channel"> & {
  policy: string; activation: PolicyActivationRecord; principal: string; audience: string; scheme: HttpScheme;
  generation: ExecutionGeneration; originKey: string; lifetime?: Lifetime;
};
export type Command = { type: "start-origin"; config: OriginBootstrap } | { type: "start-boundary"; config: BoundaryBootstrap } |
  { type: "reconcile" | "stop" | "hold-next" | "held" | "release" | "stats" };
export type Reply = { type: "origin"; port: number; instance: string } | { type: "started" } |
  { type: "readiness"; port: number | null } | { type: "held"; started: boolean } | { type: "done" } | { type: "error" } |
  { type: "boundary-stats"; stats: ReturnType<Boundary["stats"]> } |
  { type: "origin-stats"; stats: ReturnType<SyntheticOrigin["appStats"]> };

if (!process.send) throw new Error("local fenced child requires supervisor IPC");
let retained = false;
process.on("disconnect", () => { if (!retained) process.exit(1); });

async function retain(lifetime: Lifetime | undefined): Promise<void> {
  if (!lifetime) return;
  const socket = await connectLifetime(lifetime);
  socket.once("close", () => process.exit(1));
  retained = true;
}

let origin: SyntheticOrigin | undefined;
let boundary: (Boundary & { reconcile(): Promise<boolean> }) | undefined;
let boundaryPort: number | undefined;
let busy = false;
let hold: { released: ReturnType<typeof Promise.withResolvers<void>>; started: boolean } | undefined;

async function handle(command: Command): Promise<Reply> {
  switch (command.type) {
    case "start-origin": {
      if (origin || boundary) throw new Error("child is already initialized");
      const config = command.config;
      await retain(config.lifetime);
      const signingKey = createPrivateKey({ key: Buffer.from(config.signingKey, "base64url"), type: "pkcs8", format: "der" });
      const fence = createExecutionFence({ ownerKey: Buffer.from(config.ownerKey, "base64url"), originKey: signingKey,
        scope: config.scope, ownershipEpoch: config.ownershipEpoch });
      const { guard } = createAppGuard({ ...config.limits, kidB: config.kidB, kidP: config.kidP, appId: config.appId, boundaryId: config.boundaryId,
        keyP: importPublicKey(config.publicKeyP), keyB: importPublicKey(config.publicKeyB) });
      origin = createSyntheticOrigin({ instance: "protected", guard, executionFence: fence, onObservation: () => undefined,
        beforeExecution: () => {
          if (!hold || hold.started) return;
          hold.started = true;
          return hold.released.promise;
        } });
      return { type: "origin", port: await origin.listen(), instance: fence.originInstance };
    }
    case "start-boundary": {
      if (origin || boundary) throw new Error("child is already initialized");
      const config = command.config;
      await retain(config.lifetime);
      const policy = activateCustomerOriginPolicy(Buffer.from(config.policy, "base64url"), config.activation);
      boundary = createBoundary({ appPort: config.appPort, keyP: importPublicKey(config.publicKeyP), kidP: config.kidP,
        keyB: importPrivateKey(config.privateKeyB), kidB: config.kidB, appId: config.appId, boundaryId: config.boundaryId, limits: config.limits,
        emit: () => 0, capacity: { policy, principal: config.principal, audience: config.audience, scheme: config.scheme,
          backendRef: policy.manifest.domain.backendRef, execution: { generation: config.generation, originKey: importPublicKey(config.originKey) } } });
      boundaryPort = await boundary.listen();
      return { type: "started" };
    }
    case "reconcile":
      return { type: "readiness", port: boundaryPort && await boundary?.reconcile() ? boundaryPort : null };
    case "hold-next":
      if (!origin || hold) throw new Error("a hold already exists or origin is unavailable");
      hold = { released: Promise.withResolvers<void>(), started: false };
      return { type: "done" };
    case "held":
      if (!hold) throw new Error("no armed hold");
      return { type: "held", started: hold.started };
    case "release":
      if (!hold?.started) throw new Error("no started hold");
      hold.released.resolve();
      hold = undefined;
      return { type: "done" };
    case "stats":
      if (origin) return { type: "origin-stats", stats: origin.appStats() };
      if (boundary) return { type: "boundary-stats", stats: boundary.stats() };
      throw new Error("child has not initialized");
    case "stop":
      hold?.released.resolve();
      await (origin?.close() ?? boundary?.close());
      process.exit(0);
  }
}

process.on("message", ({ id, command }: { id: number; command: Command }) => {
  const replyToParent = (reply: Reply) => {
    if (!process.connected) return;
    try { process.send!({ id, reply }, (error) => { if (error && !retained) process.exit(1); }); }
    catch { if (!retained) process.exit(1); }
  };
  if (busy) { replyToParent({ type: "error" }); return; }
  busy = true;
  void handle(command).catch((): Reply => ({ type: "error" })).then((reply) => {
    busy = false;
    replyToParent(reply);
  });
});
