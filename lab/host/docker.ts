/**
 * Thin, shell-free Docker CLI wrapper. Only the lab tooling calls this.
 *
 * Confinement properties
 *  - ONE confinement mechanism: every Docker process the lab starts (the async wrapper, the synchronous version probe for the evidence
 *    manifest, the parity runner's build/run steps) takes its command line and environment from `confinedDockerInvocation` /
 *    `confinedDockerInvocationSync`. tests/lab-confinement.test.ts pins that no other file spawns docker.
 *  - The daemon is chosen EXPLICITLY. Ambient selectors (DOCKER_HOST, DOCKER_CONTEXT, DOCKER_TLS_VERIFY,
 *    DOCKER_CERT_PATH) make the wrapper refuse; it never silently follows them. The CLI's ACTIVE context (from its config file) is
 *    read once and its endpoint must be one of a short allowlist of LOCAL socket / named-pipe paths. Every call then uses that
 *    ENDPOINT (`--host <verified endpoint>`, pinned in DOCKER_HOST too for CLI plugins such as compose/buildx), never a context NAME:
 *    a context edited or switched after verification cannot redirect an already-verified invocation.
 *    (A unix socket that is itself forwarded to a remote daemon, for example by ssh -L, cannot be told apart from a
 *    local one; that remains an operator assumption.)
 *  - Containers are identified by their LABELS (`limitmark.lab=disposable` plus a role), not by a name prefix.
 *    A container is stopped, killed, removed or joined (network namespace) only after its labels were read from the
 *    daemon in that call chain.
 */
import { execFile, execFileSync } from "node:child_process";
import { assertLabContainer, PolicyRefusal } from "../policy/target-policy";

export type DockerResult = { stdout: string; stderr: string };

export class DockerEndpointRefusal extends Error {
  constructor(detail: string) {
    super(`docker endpoint refused: ${detail}`);
    this.name = "DockerEndpointRefusal";
  }
}

/** Selectors that would silently change WHICH daemon a command talks to. */
const FORBIDDEN_AMBIENT = ["DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"] as const;

/** Local endpoints the lab expects: the default Linux socket (rootful/rootless) and Docker Desktop's pipes/sockets. */
const LOCAL_ENDPOINTS: readonly RegExp[] = [
  /^unix:\/\/\/var\/run\/docker\.sock$/,
  /^unix:\/\/\/run\/docker\.sock$/,
  /^unix:\/\/\/run\/user\/\d{1,10}\/docker\.sock$/,
  /^unix:\/\/\/(?:Users|home)\/[A-Za-z0-9._-]{1,64}\/\.docker\/(?:run\/docker\.sock|desktop\/docker\.sock)$/,
  /^npipe:\/\/\/\/\.\/pipe\/(?:docker_engine|dockerDesktopLinuxEngine)$/,
];

export function isLocalDockerEndpoint(host: string): boolean {
  return LOCAL_ENDPOINTS.some((pattern) => pattern.test(host));
}

/** Pure: refuses when the process environment carries a daemon selector. */
export function assertNoAmbientDockerSelection(environment: Record<string, string | undefined>): void {
  for (const name of FORBIDDEN_AMBIENT) {
    if (environment[name] !== undefined && environment[name] !== "") throw new DockerEndpointRefusal(`${name} is set; the lab selects the local daemon itself and will not follow an ambient selector`);
  }
}

/** Environment passed to the docker CLI: nothing that selects a daemon, nothing that is a proxy (the CLI also reads proxies from its config file; see k6.ts). */
export function dockerCliEnvironment(extra: Record<string, string> = {}, base: Record<string, string | undefined> = process.env): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(base)) {
    if (value === undefined) continue;
    // Besides the daemon selectors and proxies: variables that pick a remote BUILDER or re-point compose (BUILDX_BUILDER=<remote>, BUILDKIT_HOST, COMPOSE_*) are dropped too.
    if ((FORBIDDEN_AMBIENT as readonly string[]).includes(name) || /^(?:https?|ftp|all|no)_proxy$/i.test(name) || /^(?:BUILDX_|BUILDKIT_|COMPOSE_)/.test(name)) continue;
    result[name] = value;
  }
  return { ...result, ...extra };
}

type Exec = (args: readonly string[], env: Record<string, string>, timeoutMs: number) => Promise<DockerResult>;

function execDocker(args: readonly string[], env: Record<string, string>, timeoutMs: number, input?: string): Promise<DockerResult> {
  return new Promise((resolve, reject) => {
    const child = execFile("docker", [...args], { env: env as NodeJS.ProcessEnv, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        // stderr from docker never contains our secrets (they travel via environment variables).
        reject(new Error(`docker ${args[0]} ${args[1] ?? ""} failed: ${(stderr || error.message).trim().split("\n").slice(-3).join(" | ")}`));
      } else resolve({ stdout, stderr });
    });
    if (input !== undefined) child.stdin?.end(input);
  });
}

export type VerifiedDockerEndpoint = { context: string; host: string };

/**
 * Resolves and proves the daemon the lab will use. `inspect` is injectable for tests; production reads
 * `docker context inspect` of the CLI's current context.
 */
export async function resolveLocalDockerEndpoint(
  environment: Record<string, string | undefined> = process.env,
  inspect: Exec = (args, env, timeoutMs) => execDocker(args, env, timeoutMs),
): Promise<VerifiedDockerEndpoint> {
  assertNoAmbientDockerSelection(environment);
  const { stdout } = await inspect(["context", "inspect", "--format", "{{.Name}}|{{.Endpoints.docker.Host}}"], dockerCliEnvironment({}, environment), 20_000);
  return parseEndpoint(stdout);
}

function parseEndpoint(output: string): VerifiedDockerEndpoint {
  const [context, host] = output.trim().split("|");
  if (!context || !/^[A-Za-z0-9_.-]{1,64}$/.test(context) || !host) throw new DockerEndpointRefusal("could not read the active docker context");
  if (!isLocalDockerEndpoint(host)) throw new DockerEndpointRefusal(`context "${context}" does not point at a local socket or named pipe the lab expects`);
  return { context, host };
}

let verified: { at: number; key: string; endpoint: VerifiedDockerEndpoint } | null = null;
const VERIFICATION_TTL_MS = 30_000;

export function resetDockerEndpointCache(): void { verified = null; }

function cacheKey(environment: Record<string, string | undefined>): string {
  // DOCKER_CONFIG decides which contexts exist, so a change of it invalidates the verified endpoint.
  return [...FORBIDDEN_AMBIENT, "DOCKER_CONFIG"].map((name) => environment[name] ?? "").join("|");
}

/** Synchronous resolution with the same rules (used only by the evidence version probe). */
export function resolveLocalDockerEndpointSync(
  environment: Record<string, string | undefined> = process.env,
  inspect: (args: readonly string[], env: Record<string, string>) => string = (args, env) => execFileSync("docker", [...args], { env: env as NodeJS.ProcessEnv, timeout: 20_000, encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "ignore"] }),
): VerifiedDockerEndpoint {
  assertNoAmbientDockerSelection(environment);
  return parseEndpoint(inspect(["context", "inspect", "--format", "{{.Name}}|{{.Endpoints.docker.Host}}"], dockerCliEnvironment({}, environment)));
}

async function verifiedEndpoint(): Promise<VerifiedDockerEndpoint> {
  assertNoAmbientDockerSelection(process.env);
  const key = cacheKey(process.env);
  if (verified && verified.key === key && Date.now() - verified.at < VERIFICATION_TTL_MS) return verified.endpoint;
  const endpoint = await resolveLocalDockerEndpoint();
  verified = { at: Date.now(), key, endpoint };
  return endpoint;
}

export type DockerInvocation = { command: "docker"; args: string[]; env: Record<string, string>; endpoint: VerifiedDockerEndpoint };

/** Pure: the command line and environment that bind a docker process to ONE verified endpoint. */
export function bindToEndpoint(endpoint: VerifiedDockerEndpoint, args: readonly string[], extraEnv: Record<string, string> = {}, base: Record<string, string | undefined> = process.env): DockerInvocation {
  return {
    command: "docker",
    // The endpoint itself, not its context's name: nothing the CLI reads from its config afterwards can change where this process connects.
    args: ["--host", endpoint.host, ...args],
    // CLI plugins (compose, buildx) get the daemon from the environment, so it is pinned there as well, to the same verified value.
    env: { ...dockerCliEnvironment(extraEnv, base), DOCKER_HOST: endpoint.host },
    endpoint,
  };
}

/** THE entry point for every asynchronous Docker process (also used by the parity runner's long-running steps). */
export async function confinedDockerInvocation(args: readonly string[], extraEnv: Record<string, string> = {}): Promise<DockerInvocation> {
  return bindToEndpoint(await verifiedEndpoint(), args, extraEnv);
}

/** Synchronous twin for the few places that cannot await. Shares the verification cache. */
export function confinedDockerInvocationSync(
  args: readonly string[], extraEnv: Record<string, string> = {},
  /** Test seam: how the active context is read. */
  resolve: () => VerifiedDockerEndpoint = () => resolveLocalDockerEndpointSync(),
): DockerInvocation {
  assertNoAmbientDockerSelection(process.env);
  const key = cacheKey(process.env);
  if (!(verified && verified.key === key && Date.now() - verified.at < VERIFICATION_TTL_MS)) verified = { at: Date.now(), key, endpoint: resolve() };
  return bindToEndpoint(verified.endpoint, args, extraEnv);
}

/** The daemon's version for the evidence manifest, or null. Never talks to a daemon the lab did not verify as local. */
export function dockerServerVersionSync(): string | null {
  try {
    const invocation = confinedDockerInvocationSync(["version", "--format", "{{.Server.Version}}"]);
    return execFileSync(invocation.command, invocation.args, { env: invocation.env as NodeJS.ProcessEnv, timeout: 10_000, encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch { return null; }
}

export async function docker(args: readonly string[], options: { env?: Record<string, string>; timeoutMs?: number; input?: string } = {}): Promise<DockerResult> {
  const invocation = await confinedDockerInvocation(args, options.env);
  return execDocker(invocation.args, invocation.env, options.timeoutMs ?? 120_000, options.input);
}

export async function containerExists(name: string): Promise<boolean> {
  const { stdout } = await docker(["ps", "-a", "--filter", `name=^${name}$`, "--format", "{{.Names}}"]);
  return stdout.split("\n").map((line) => line.trim()).includes(name);
}

export type ContainerFacts = {
  id: string;
  name: string;
  image: string;
  running: boolean;
  labels: Record<string, string>;
  /** container port ("3000/tcp") -> host bindings */
  ports: Record<string, { HostIp: string; HostPort: string }[] | null>;
  env: string[];
  networkMode: string;
};

/** Reads the daemon's own record of a container (labels, state, bindings, effective environment). */
export async function inspectContainer(nameOrId: string): Promise<ContainerFacts> {
  const { stdout } = await docker(["inspect", "--type", "container", nameOrId]);
  const parsed = JSON.parse(stdout) as {
    Id: string; Name: string; Config: { Image: string; Labels: Record<string, string> | null; Env: string[] | null };
    State: { Running: boolean }; NetworkSettings: { Ports: ContainerFacts["ports"] | null }; HostConfig: { NetworkMode: string };
  }[];
  if (parsed.length !== 1) throw new Error("expected exactly one container");
  const [entry] = parsed;
  return {
    id: entry.Id, name: entry.Name.replace(/^\//, ""), image: entry.Config.Image, running: entry.State.Running,
    labels: entry.Config.Labels ?? {}, ports: entry.NetworkSettings.Ports ?? {}, env: entry.Config.Env ?? [], networkMode: entry.HostConfig.NetworkMode,
  };
}

export async function containerLabels(name: string): Promise<Record<string, string>> {
  return (await inspectContainer(name)).labels;
}

/**
 * Ownership by LABELS read from the daemon: the container must carry `limitmark.lab=disposable` and, when a role is
 * given, `limitmark.lab.role=<role>`. A name that merely starts with the lab prefix is not enough.
 */
export async function inspectLabContainer(name: string, role?: LabRole): Promise<ContainerFacts> {
  const facts = await inspectContainer(name);
  assertLabContainer(facts.name, facts.labels, role);
  return facts;
}

export type LabRole = "postgres" | "app" | "k6" | "parity";

/** Stop/start/kill only containers the lab created (disposable label and the expected role). */
export async function controlLabContainer(action: "stop" | "start" | "kill" | "pause" | "unpause", name: string, role: LabRole = "postgres"): Promise<void> {
  const facts = await inspectLabContainer(name, role);
  // Address the container by its immutable id so the name cannot be re-pointed between check and action.
  await docker([action, facts.id], { timeoutMs: 60_000 });
}

/** Removes a container only after its labels prove the lab owns it; verifies it is really gone. Returns false when it did not exist. */
export async function removeLabContainer(name: string, role: LabRole): Promise<boolean> {
  if (!(await containerExists(name))) return false;
  const facts = await inspectLabContainer(name, role);
  await docker(["rm", "-f", "-v", facts.id], { timeoutMs: 60_000 });
  if (await containerExists(name)) throw new Error(`container ${name} still exists after removal`);
  return true;
}

/**
 * The container must be one the lab created for an application under test, running, and publish exactly
 * 127.0.0.1:<hostPort> -> <containerPort>/tcp. A forwarder cannot also hold that host binding.
 */
export function assertPublishedOnLoopbackOnly(facts: ContainerFacts, hostPort: number, containerPort: number): void {
  if (!facts.running) throw new PolicyRefusal("target-listener-unproven", "the application container is not running");
  const bindings = facts.ports[`${containerPort}/tcp`];
  const ok = Array.isArray(bindings) && bindings.length === 1 && bindings[0].HostIp === "127.0.0.1" && bindings[0].HostPort === String(hostPort);
  if (!ok) throw new PolicyRefusal("target-listener-unproven", `the container does not publish exactly 127.0.0.1:${hostPort}`);
}

/**
 * The ownership check the destination lease repeats: the container must still be THE SAME one that was proven (immutable id, so a different
 * container that now carries the same name does not count), running, and publishing exactly 127.0.0.1:<hostPort>.
 */
export function assertSameLabAppContainer(facts: ContainerFacts, hostPort: number, containerPort: number, expectedId?: string): void {
  if (expectedId !== undefined && facts.id !== expectedId) throw new PolicyRefusal("target-listener-unproven", "the container behind the name is no longer the one that was proven");
  assertPublishedOnLoopbackOnly(facts, hostPort, containerPort);
}
