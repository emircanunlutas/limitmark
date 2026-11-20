import { fork, type ChildProcess, type ForkOptions, type SpawnOptions } from "node:child_process";
import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";
import { mkdir, realpath, rmdir } from "node:fs/promises";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { BoundaryLimits } from "../../defense/boundary/protocol";
import { activateCustomerOriginPolicy } from "../../defense/core/capacity-policy";
import type { PolicyActivationRecord } from "../../defense/core/capacity-port";
import { provisionExecutionGeneration } from "../../defense/origin/execution-fence";
import type { BoundaryBootstrap, Command, OriginBootstrap, Reply } from "./fenced-process-main";
import type { Lifetime } from "./fenced-lifetime";
import type { HopTrustRoot } from "./hop-keys";

const entry = path.join(__dirname, "fenced-process-main.ts");

class FencedChild {
  private readonly child: ChildProcess;
  private busy = false;
  private sequence = 0;
  private gone = false;
  private exited = false;
  private stopping?: Promise<void>;

  constructor(private readonly timeout: number, independentLifetime: boolean) {
    // A launcher lifetime channel, when configured, owns teardown independently of the witness's process group.
    const options: ForkOptions & Pick<SpawnOptions, "windowsHide"> = { execArgv: process.execArgv,
      stdio: ["ignore", "ignore", "ignore", "ipc"], serialization: "json", detached: independentLifetime, windowsHide: true };
    this.child = fork(entry, [], options);
    this.child.on("error", () => undefined);
    // Only Node's exit event on this fork handle is evidence of process termination.
    this.child.once("exit", (code, signal) => { this.exited = code !== null || signal !== null; });
    this.child.once("close", () => { this.gone = true; });
  }

  get pid() { return this.child.pid; }
  get verifiedExit() { return this.exited; }
  get alive() { return !this.stopping && !this.gone && this.child.connected && this.child.exitCode === null && this.child.signalCode === null; }
  onExit(callback: () => void) { this.child.once("close", callback); }

  exchange<K extends Reply["type"]>(command: Command, expected: K): Promise<Extract<Reply, { type: K }>> {
    if (this.busy || this.stopping || !this.alive) return Promise.reject(new Error("fenced child unavailable"));
    this.busy = true;
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      let settled = false;
      const clean = () => {
        if (settled) return false;
        settled = true;
        this.busy = false;
        clearTimeout(timer);
        this.child.off("message", receive);
        this.child.off("close", exit);
        this.child.off("error", fail);
        return true;
      };
      const fail = (error: Error) => { if (clean()) reject(error); };
      const exit = () => fail(new Error("fenced child exited"));
      const receive = (message: { id: number; reply: Reply }) => {
        if (message.id !== id) return;
        const { reply } = message;
        if (reply?.type !== expected) { fail(new Error("fenced child rejected the command")); return; }
        if (clean()) resolve(reply as Extract<Reply, { type: K }>);
      };
      const timer = setTimeout(() => {
        // Read-only diagnostics have no lifecycle disposition. Late replies carry their original ID.
        if (command.type === "reconcile" || command.type === "start-origin" || command.type === "start-boundary") {
          void this.stop(true).catch(() => undefined);
        }
        fail(new Error("fenced child command timed out"));
      }, this.timeout);
      this.child.on("message", receive);
      this.child.once("close", exit);
      this.child.once("error", fail);
      try { this.child.send({ id, command }, (error) => { if (error) fail(error); }); }
      catch (error) { fail(error as Error); }
    });
  }

  stop(force = false): Promise<void> {
    return this.stopping ??= new Promise<void>((resolve, reject) => {
      if (this.gone) { resolve(); return; }
      const kill = () => { this.child.kill("SIGKILL"); };
      const grace = setTimeout(kill, force || this.busy ? 0 : this.timeout);
      const deadline = setTimeout(() => reject(new Error("fenced child did not exit")), 2 * this.timeout);
      this.child.once("close", () => { clearTimeout(grace); clearTimeout(deadline); resolve(); });
      if (force || this.busy) kill();
      else if (this.child.connected) this.child.send({ id: ++this.sequence, command: { type: "stop" } satisfies Command }, (error) => { if (error) kill(); });
    });
  }
}

async function launch<K extends Reply["type"]>(command: Command, expected: K, timeout: number, observe?: (child: FencedChild) => void) {
  const child = new FencedChild(timeout, "config" in command && command.config.lifetime !== undefined);
  observe?.(child);
  try { return { child, reply: await child.exchange(command, expected) }; }
  catch (error) { await child.stop(true); throw error; }
}

export async function startFencedBoundary(config: BoundaryBootstrap, timeout: number) {
  const { child } = await launch({ type: "start-boundary", config }, "started", timeout);
  return {
    get alive() { return child.alive; }, pid: child.pid,
    async reconcile() {
      const { port } = await child.exchange({ type: "reconcile" }, "readiness");
      return typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65_535 && child.alive ? port : null;
    },
    stats: async () => (await child.exchange({ type: "stats" }, "boundary-stats")).stats,
    stop: (force = false) => child.stop(force),
  };
}

async function launchOrigin(config: OriginBootstrap, timeout: number, observe?: (child: FencedChild) => void) {
  const { child, reply } = await launch({ type: "start-origin", config }, "origin", timeout, observe);
  return {
    get alive() { return child.alive; }, get verifiedExit() { return child.verifiedExit; }, pid: child.pid, port: reply.port, instance: reply.instance,
    onExit: (callback: () => void) => child.onExit(callback),
    holdNext: () => child.exchange({ type: "hold-next" }, "done"),
    async waitHeld() {
      const deadline = performance.now() + timeout;
      do {
        if ((await child.exchange({ type: "held" }, "held")).started) return;
        await delay(10);
      } while (performance.now() < deadline);
      throw new Error("timed out waiting for held work");
    },
    release: () => child.exchange({ type: "release" }, "done"),
    stats: async () => (await child.exchange({ type: "stats" }, "origin-stats")).stats,
    stop: (force = false) => child.stop(force),
  };
}

export function startFencedOrigin(config: OriginBootstrap, timeout: number) {
  return launchOrigin(config, timeout);
}

type BoundaryProcess = Awaited<ReturnType<typeof startFencedBoundary>>;

/** One backend within a trusted local ownership namespace. Origin recovery is explicit. */
export type FencedSupervisorOptions = { trust: Pick<HopTrustRoot, "appInit" | "boundaryInit">; policy: Uint8Array; activation: PolicyActivationRecord;
  channel: string; limits: BoundaryLimits; ownershipRoot: string; executionModel?: "process-local-synthetic"; timeout?: number; lifetime?: Lifetime };

export async function startFencedSupervisor(config: FencedSupervisorOptions) {
  const timeout = config.timeout ?? 5_000;
  if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 30_000) throw new RangeError("invalid supervision timeout");
  const policy = Buffer.from(config.policy);
  const activation = { ...config.activation };
  const { manifest } = activateCustomerOriginPolicy(policy, activation);
  const binding = manifest.channels.find(({ id }) => id === config.channel);
  if (!binding) throw new Error("unknown capacity channel");
  const scope = manifest.domain.backendRef;
  const limits = { ...config.limits };
  const processLocal = config.executionModel === "process-local-synthetic";
  const marker = path.join(await realpath(config.ownershipRoot), `${scope}.owner`);
  let ownershipEpoch = randomUUID();
  // The marker is sticky on owner failure. No contender reclaims it using a PID, age or a failed connection.
  try { await mkdir(marker, { mode: 0o700 }); }
  catch (error) { throw new Error("exclusive backend ownership is unavailable", { cause: error }); }

  let observedOrigin: FencedChild | undefined;
  let originForkAttempted = false;
  async function startOwnedOrigin() {
    const ownerKey = randomBytes(32);
    const keys = generateKeyPairSync("ed25519");
    const originKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
    const bootstrap = { ...config.trust.appInit(limits), scope, ownershipEpoch, lifetime: config.lifetime, ownerKey: ownerKey.toString("base64url"),
      signingKey: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url") };
    observedOrigin = undefined;
    originForkAttempted = true;
    const process = await launchOrigin(bootstrap, timeout, (child) => { observedOrigin = child; });
    return { process, ownerKey, originKey };
  }
  const terminationVerified = () => processLocal && observedOrigin?.verifiedExit === true;
  const releaseOwnership = async () => { if (terminationVerified()) await rmdir(marker); };

  let origin: Awaited<ReturnType<typeof startOwnedOrigin>>;
  try { origin = await startOwnedOrigin(); }
  catch (error) {
    if (!originForkAttempted) await rmdir(marker);
    else await releaseOwnership();
    throw error;
  }
  let epoch = 0;
  let current: BoundaryProcess | undefined;
  let pending: BoundaryProcess | undefined;
  let port: number | null = null;
  let operation: Promise<unknown> | undefined;
  let closed = false;
  let shutdown: Promise<void> | undefined;
  const stopBoundaries = async () => { await Promise.all([current?.stop(), pending?.stop()]); };

  function watchOrigin(departing: typeof origin): void {
    departing.process.onExit(() => {
      if (origin !== departing) return;
      port = null;
      void stopBoundaries().catch(() => undefined);
    });
  }
  watchOrigin(origin);

  function run<T>(action: () => Promise<T>, requireLiveOrigin = true): Promise<T> {
    if (operation || closed || (requireLiveOrigin && !origin.process.alive)) return Promise.reject(new Error("fenced supervisor unavailable"));
    const task = action().finally(() => { operation = undefined; });
    operation = task;
    return task;
  }

  function recover(rotateOwnership: boolean): Promise<void> {
    return run(async () => {
      if (origin.process.alive || !terminationVerified()) throw new Error("prior origin termination cannot be verified");
      port = null;
      await stopBoundaries();
      if (closed) throw new Error("fenced supervisor unavailable");
      current = undefined;
      pending = undefined;
      if (rotateOwnership) ownershipEpoch = randomUUID();
      origin = await startOwnedOrigin();
      watchOrigin(origin);
    }, false);
  }

  return {
    scope,
    get ownershipEpoch() { return ownershipEpoch; },
    get origin() { return origin.process; },
    get port() { return !closed && origin.process.alive && current?.alive ? port : null; },
    prepare: () => run(async () => {
      if (pending?.alive) throw new Error("a replacement is already pending");
      await pending?.stop();
      if (closed || !origin.process.alive) throw new Error("origin unavailable during preparation");
      const child = await startFencedBoundary({ ...config.trust.boundaryInit(origin.process.port, limits), policy: policy.toString("base64url"), activation, originKey: origin.originKey, lifetime: config.lifetime,
        principal: binding.principal, audience: binding.audience, scheme: binding.scheme,
        generation: provisionExecutionGeneration(origin.ownerKey, { scope, ownershipEpoch, originInstance: origin.process.instance, epoch: ++epoch }) }, timeout);
      pending = child;
      if (closed || !origin.process.alive) { await child.stop(); throw new Error("origin unavailable during preparation"); }
      return { pid: child.pid, stats: child.stats, stop: child.stop };
    }),
    activate: () => run(async () => {
      if (!pending?.alive) return false;
      port = null;
      const candidate = pending;
      // The claim can fence the old generation even if its response is lost or reports a pending drain.
      // Withdraw the old listener before exposing the origin to that irreversible transition.
      await current?.stop(true);
      current = undefined;
      if (closed || !origin.process.alive) return false;
      const ready = await candidate.reconcile();
      if (ready === null || closed || !origin.process.alive) return false;
      if (closed || !origin.process.alive || !candidate.alive) return false;
      current = candidate;
      pending = undefined;
      port = ready;
      return true;
    }),
    recoverOrigin: () => recover(false),
    replaceOwner: () => recover(true),
    close: () => {
      closed = true;
      port = null;
      return shutdown ??= (async () => {
        await operation?.catch(() => undefined);
        await Promise.all([stopBoundaries(), observedOrigin?.stop()]);
        await releaseOwnership();
      })();
    },
  };
}
