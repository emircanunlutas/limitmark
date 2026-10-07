/**
 * Field qualification: peer classification and the reviewed public-ingress bind. Pure; no I/O.
 *
 * A request's PEER CLASS is a property of the kernel's view of its TCP connection, never of anything the client sent:
 *
 *   local   the peer is this host itself (loopback, or the connection's remote address equals its own local address). Only a process on
 *           this host can complete such a handshake, so only the harness (the canary) is in this class on a disposable VM.
 *   remote  everything else, and anything the kernel did not report. When in doubt a peer is REMOTE (the less trusted class).
 *
 * Remote peers can never choose an authoritative correlation nonce and are never told an internal decision (see the front).
 *
 * The ingress bind is the ONE reviewed non-loopback listener a qualification topology may have: a fixed IPv4 literal and a fixed port.
 * A wildcard, a hostname, an IPv6 literal, a multicast or reserved address and port 0 are all refused here, so no configuration
 * can open the Defense Plane on every interface.
 */
export type PeerClass = "local" | "remote";

export type IngressBind = { readonly ip: string; readonly port: number };

export class IngressRefusal extends Error {
  constructor(detail: string) {
    super(`ingress refused: ${detail}`);
    this.name = "IngressRefusal";
  }
}

const IPV4 = /^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$/;

/** A canonical dotted-quad (no leading zeros, no short forms, no hex/decimal spellings) or null. */
export function parseIpv4(text: string): [number, number, number, number] | null {
  const match = IPV4.exec(text);
  if (!match) return null;
  const octets = [Number(match[1]), Number(match[2]), Number(match[3]), Number(match[4])] as [number, number, number, number];
  return octets.every((octet) => octet <= 255) ? octets : null;
}

/** The address as the kernel spells it, with an IPv4-mapped IPv6 prefix removed; null when absent. */
function normalize(address: string | undefined): string | null {
  if (typeof address !== "string" || address.length === 0) return null;
  const lower = address.toLowerCase();
  return lower.startsWith("::ffff:") && parseIpv4(lower.slice(7)) !== null ? lower.slice(7) : lower;
}

export function isLoopbackAddress(address: string): boolean {
  if (address === "::1") return true;
  const octets = parseIpv4(address);
  return octets !== null && octets[0] === 127;
}

export function peerClassOf(remoteAddress: string | undefined, localAddress: string | undefined): PeerClass {
  const remote = normalize(remoteAddress);
  if (remote === null) return "remote";
  if (isLoopbackAddress(remote)) return "local";
  const local = normalize(localAddress);
  return local !== null && remote === local ? "local" : "remote";
}

const WILDCARDS: readonly string[] = ["0.0.0.0", "255.255.255.255"];

/**
 * Validates the reviewed bind. Loopback is accepted HERE (every Slice-1/2/3 composition and the loopback integration tests bind it);
 * the harness's field policy is what additionally requires a non-loopback address for a field level.
 */
export function validateIngressBind(candidate: unknown): IngressBind {
  if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) throw new IngressRefusal("not an object");
  const keys = Object.keys(candidate).sort();
  if (keys.length !== 2 || keys[0] !== "ip" || keys[1] !== "port") throw new IngressRefusal("exactly ip and port are required");
  const { ip, port } = candidate as { ip: unknown; port: unknown };
  if (typeof ip !== "string") throw new IngressRefusal("ip must be a string");
  if (WILDCARDS.includes(ip)) throw new IngressRefusal("a wildcard bind is forbidden");
  const octets = parseIpv4(ip);
  if (octets === null) throw new IngressRefusal("ip must be a canonical dotted-quad IPv4 literal (no hostname, no IPv6, no short form)");
  if (octets[0] === 0 || octets[0] >= 224) throw new IngressRefusal("this-network, multicast and reserved addresses are forbidden");
  if (octets[0] === 169 && octets[1] === 254) throw new IngressRefusal("link-local addresses are forbidden");
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65_535) throw new IngressRefusal("port must be a fixed integer 1..65535");
  return Object.freeze({ ip, port });
}
