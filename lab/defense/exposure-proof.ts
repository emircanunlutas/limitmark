/**
 * Field qualification: the continuous EXPOSURE PROOF. Run before the Plane binds (pre_bind), every field tick (running) and again at
 * finalization (final). A violation is fatal: at preflight it refuses the level, during the run it is a STOP.
 *
 * The invariant, in the runner's network namespace:
 *
 *   the ONLY non-loopback LISTEN socket owned by the qualification topology is the exact reviewed Defense Plane IPv4:port.
 *
 * "Owned by the topology" means: the socket's inode is an open fd of the runner or of one of its three children (Plane, Boundary, App).
 * The Boundary and the App, and the runner's own private control origin, may listen on loopback only. A wildcard (IPv4 0.0.0.0, IPv6 ::,
 * the IPv4-mapped wildcard) or any non-loopback IPv6 socket in the topology is a violation, as is a second non-loopback socket, a plane
 * socket on any other address or port, or the same listening inode held by a process outside the topology (an inherited or stale holder).
 *
 * Listeners the topology does NOT own are AMBIENT (sshd, a leftover service). The proof snapshots them before the bind and flags: any
 * non-loopback listener on a forbidden port (the old Field Lab Next service's 3000), any not on the allowlist at preflight, any NEW one
 * during the run, and any listener on the Plane's own port that the topology does not own (a stale listener).
 *
 * WHAT THIS DOES NOT PROVE: it reads host listener state only. It says nothing about the cloud firewall, NAT, a port forwarder on the host,
 * or any network path. A listener held by another user's process is not scanned for inode sharing when /proc forbids reading its fds; the
 * result records how many processes could not be read instead of pretending they were checked. Nothing here is an origin-isolation claim.
 *
 * Output is evidence-safe: counts, ports of ambient listeners, and a closed list of violation codes. It never carries an address.
 */
import type { IngressBind } from "../../defense/core/ingress-class";
import { addressClass, listPids, listeningOnly, parseTcpTable, socketInodesOf, type ProcReader, type TcpEntry } from "./proc-net";

export type ExposureMode = "pre_bind" | "running" | "final";

export const EXPOSURE_VIOLATIONS = [
  "proc_unreadable", "netns_unproven", "netns_mismatch",
  "topology_wildcard_v4", "topology_wildcard_v6", "topology_nonloopback_v6", "topology_nonloopback_service", "plane_extra_listener", "plane_misbound",
  "plane_not_listening", "plane_still_listening", "shared_listener_inode", "foreign_holder",
  "stale_listener_on_plane_port", "ambient_forbidden_port", "ambient_unexpected_listener", "ambient_new_listener",
] as const;
export type ExposureViolation = (typeof EXPOSURE_VIOLATIONS)[number];

export type TopologyPids = { runner: number; plane?: number; boundary?: number; app?: number };

export type ExposureInput = {
  reader: ProcReader;
  mode: ExposureMode;
  pids: TopologyPids;
  /** The reviewed Plane bind. */
  plane: IngressBind;
  /** running: the Plane's listener must exist. final (after the ingress was closed): it must not. Ignored before the bind. */
  expectPlaneListening: boolean;
  /** A close was requested and not yet acknowledged: the Plane's listener may or may not still exist, so neither presence nor absence is checked. */
  planeMayBeClosing?: boolean;
  /** Ports an ambient non-loopback listener may use at preflight (for example sshd). */
  ambientAllowedPorts: readonly number[];
  /** Ports no ambient non-loopback listener may ever use (the old Field Lab service's). */
  forbiddenAmbientPorts: readonly number[];
  /** The ambient non-loopback ports seen at preflight. Given during the run, anything new is a violation. */
  baselineAmbientPorts?: readonly number[];
  /** Scan every readable process for a second holder of a topology listening inode (preflight and final). */
  fullScan: boolean;
};

export type ExposureResult = {
  ok: boolean;
  violations: ExposureViolation[];
  planeSocket: "exact" | "absent" | "misbound";
  topologyListeners: { loopback: number; nonLoopbackExact: number; wildcard: number; nonLoopbackOther: number };
  ambientNonLoopbackPorts: number[];
  foreignHolders: number;
  scan: { pidsScanned: number; pidsUnreadable: number };
  statement: string;
};

/** The limitation every artifact carries. A test pins that no other string over-claims. */
export const EXPOSURE_STATEMENT = "host listener state only: no claim about cloud firewall, NAT, forwarders or network isolation";

const ROLES = ["runner", "plane", "boundary", "app"] as const;
type Role = (typeof ROLES)[number];

export function proveExposure(input: ExposureInput): ExposureResult {
  const violations = new Set<ExposureViolation>();
  const empty = (): ExposureResult => ({
    ok: false, violations: [...violations].sort(), planeSocket: "absent", topologyListeners: { loopback: 0, nonLoopbackExact: 0, wildcard: 0, nonLoopbackOther: 0 },
    ambientNonLoopbackPorts: [], foreignHolders: 0, scan: { pidsScanned: 0, pidsUnreadable: 0 }, statement: EXPOSURE_STATEMENT,
  });
  const { reader, plane } = input;

  const tcp = reader.readText("/proc/net/tcp");
  if (tcp === null) { violations.add("proc_unreadable"); return empty(); }
  // A kernel without IPv6 has no tcp6 table: that is "no IPv6 sockets", not unreadable.
  const tcp6 = reader.readText("/proc/net/tcp6");
  const listeners: TcpEntry[] = [...listeningOnly(parseTcpTable(tcp, 4)), ...(tcp6 === null ? [] : listeningOnly(parseTcpTable(tcp6, 6)))];

  // ---- who owns what
  const pidOf: Partial<Record<Role, number>> = { runner: input.pids.runner, plane: input.pids.plane, boundary: input.pids.boundary, app: input.pids.app };
  const heldBy = new Map<number, Role[]>();
  const topologyPids = new Set<number>();
  const runnerNetns = reader.readLink(`/proc/${input.pids.runner}/ns/net`);
  for (const role of ROLES) {
    const pid = pidOf[role];
    if (pid === undefined) continue;
    topologyPids.add(pid);
    const inodes = socketInodesOf(reader, pid);
    if (inodes === null) { violations.add("proc_unreadable"); continue; }
    for (const inode of inodes) heldBy.set(inode, [...(heldBy.get(inode) ?? []), role]);
    const netns = reader.readLink(`/proc/${pid}/ns/net`);
    if (runnerNetns === null || netns === null) violations.add("netns_unproven");
    else if (netns !== runnerNetns) violations.add("netns_mismatch");
  }

  // ---- the topology's own listeners
  const counts = { loopback: 0, nonLoopbackExact: 0, wildcard: 0, nonLoopbackOther: 0 };
  let planeExact = 0;
  let planeSocket: ExposureResult["planeSocket"] = "absent";
  const ownedInodes = new Set<number>();
  for (const listener of listeners) {
    const roles = heldBy.get(listener.inode);
    if (roles === undefined) continue;
    ownedInodes.add(listener.inode);
    if (roles.length > 1) violations.add("shared_listener_inode");
    // The reviewed plane socket: the plane's own, on exactly the reviewed IPv4 and port (the bind was validated, so it is never a wildcard).
    if (roles.includes("plane") && listener.family === 4 && listener.ip === plane.ip && listener.port === plane.port) { counts.nonLoopbackExact++; planeExact++; continue; }
    const cls = addressClass(listener);
    if (cls === "wildcard") { counts.wildcard++; violations.add(listener.family === 4 ? "topology_wildcard_v4" : "topology_wildcard_v6"); continue; }
    if (cls === "loopback") { counts.loopback++; continue; }
    // non-loopback, non-wildcard
    if (listener.family === 6) { counts.nonLoopbackOther++; violations.add("topology_nonloopback_v6"); continue; }
    counts.nonLoopbackOther++;
    violations.add(roles.includes("plane") ? "plane_misbound" : "topology_nonloopback_service");
  }
  // The plane may hold one exact socket and nothing else non-loopback; any loopback socket it holds is tolerated here only if it is loopback.
  if (planeExact > 1) violations.add("plane_extra_listener");
  if (input.pids.plane !== undefined) {
    if (planeExact === 1) planeSocket = "exact";
    else if (violations.has("plane_misbound")) planeSocket = "misbound";
    if (input.planeMayBeClosing !== true) {
      if (input.expectPlaneListening && planeExact === 0 && planeSocket !== "misbound") violations.add("plane_not_listening");
      if (!input.expectPlaneListening && planeExact > 0) violations.add("plane_still_listening");
    }
  }

  // ---- ambient listeners (not owned by the topology)
  const ambient = new Set<number>();
  for (const listener of listeners) {
    if (ownedInodes.has(listener.inode)) continue;
    if (listener.port === plane.port) violations.add("stale_listener_on_plane_port");
    if (addressClass(listener) === "loopback") continue;
    ambient.add(listener.port);
  }
  const baseline = input.baselineAmbientPorts === undefined ? null : new Set(input.baselineAmbientPorts);
  for (const port of ambient) {
    if (input.forbiddenAmbientPorts.includes(port)) violations.add("ambient_forbidden_port");
    else if (baseline !== null) { if (!baseline.has(port)) violations.add("ambient_new_listener"); }
    else if (!input.ambientAllowedPorts.includes(port)) violations.add("ambient_unexpected_listener");
  }

  // ---- a second holder of a topology listening inode (inherited or stale)
  let foreign = 0;
  const scan = { pidsScanned: 0, pidsUnreadable: 0 };
  if (input.fullScan && ownedInodes.size > 0) {
    for (const pid of listPids(reader)) {
      if (topologyPids.has(pid)) continue;
      const inodes = socketInodesOf(reader, pid);
      if (inodes === null) { scan.pidsUnreadable++; continue; }
      scan.pidsScanned++;
      for (const inode of ownedInodes) if (inodes.has(inode)) { foreign++; break; }
    }
    if (foreign > 0) violations.add("foreign_holder");
  }

  const list = [...violations].sort();
  return { ok: list.length === 0, violations: list, planeSocket, topologyListeners: counts, ambientNonLoopbackPorts: [...ambient].sort((a, b) => a - b), foreignHolders: foreign, scan, statement: EXPOSURE_STATEMENT };
}
