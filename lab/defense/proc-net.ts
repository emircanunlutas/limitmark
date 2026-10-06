/**
 * Field qualification: read-only Linux /proc access and parsers. Pure parsing plus one thin reader.
 *
 * Everything here reads through a `ProcReader`, so the parsers and the exposure proof run unchanged against fixtures on any platform; the
 * real reader (`fsProcReader`) is Linux-only in use (the field runner refuses to run elsewhere). Nothing here ever writes, signals or
 * connects. Output never carries an address into evidence: callers record counts and enum classes only.
 */
import { existsSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import path from "node:path";

export interface ProcReader {
  /** The text of a file, or null when it does not exist or cannot be read. */
  readText(file: string): string | null;
  /** Entries of a directory, or null when it cannot be listed. */
  listDir(dir: string): string[] | null;
  /** The target of a symbolic link, or null. */
  readLink(file: string): string | null;
}

/** A reader over a real /proc (or a copy of one at `root`). Never throws. */
export function fsProcReader(root = "/proc"): ProcReader {
  const resolve = (file: string): string => path.join(root, file.replace(/^\/proc\/?/, ""));
  return {
    readText: (file) => { try { return readFileSync(resolve(file), "utf8"); } catch { return null; } },
    listDir: (dir) => { try { const target = resolve(dir); return existsSync(target) ? readdirSync(target) : null; } catch { return null; } },
    readLink: (file) => { try { return readlinkSync(resolve(file)); } catch { return null; } },
  };
}

export type TcpEntry = { family: 4 | 6; ip: string; port: number; state: string; uid: number; inode: number };

const LISTEN = "0A";

/** `7F000001` -> 127.0.0.1. The kernel prints the four bytes of an IPv4 address as one little-endian 32-bit word. */
function ipv4FromWord(word: string): string | null {
  if (!/^[0-9A-Fa-f]{8}$/.test(word)) return null;
  const bytes = [0, 1, 2, 3].map((index) => parseInt(word.slice(index * 2, index * 2 + 2), 16));
  return `${bytes[3]}.${bytes[2]}.${bytes[1]}.${bytes[0]}`;
}

/** `00000000000000000000000001000000` -> ::1 (four little-endian 32-bit words). Returns the canonical text, with ::ffff:a.b.c.d for a mapped address. */
function ipv6FromWords(hex: string): string | null {
  if (!/^[0-9A-Fa-f]{32}$/.test(hex)) return null;
  const words = [0, 1, 2, 3].map((index) => hex.slice(index * 8, index * 8 + 8));
  const bytes: number[] = [];
  for (const word of words) for (let index = 3; index >= 0; index--) bytes.push(parseInt(word.slice(index * 2, index * 2 + 2), 16));
  if (bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff) return `::ffff:${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  const groups: string[] = [];
  for (let index = 0; index < 16; index += 2) groups.push(((bytes[index] << 8) | bytes[index + 1]).toString(16));
  if (groups.every((group) => group === "0")) return "::";
  if (groups.slice(0, 7).every((group) => group === "0") && groups[7] === "1") return "::1";
  return groups.join(":");
}

/** Parses /proc/net/tcp or /proc/net/tcp6. Malformed lines are skipped, never guessed at. */
export function parseTcpTable(text: string, family: 4 | 6): TcpEntry[] {
  const entries: TcpEntry[] = [];
  const lines = text.split("\n");
  for (let index = 1; index < lines.length; index++) {
    const tokens = lines[index].trim().split(/\s+/);
    if (tokens.length < 10) continue;
    const [address, port] = (tokens[1] ?? "").split(":");
    const ip = family === 4 ? ipv4FromWord(address ?? "") : ipv6FromWords(address ?? "");
    const portNumber = /^[0-9A-Fa-f]{4}$/.test(port ?? "") ? parseInt(port, 16) : NaN;
    const inode = Number(tokens[9]);
    if (ip === null || !Number.isInteger(portNumber) || !Number.isSafeInteger(inode)) continue;
    entries.push({ family, ip, port: portNumber, state: tokens[3], uid: Number(tokens[7]), inode });
  }
  return entries;
}

export const listeningOnly = (entries: readonly TcpEntry[]): TcpEntry[] => entries.filter((entry) => entry.state === LISTEN);

export type AddressClass = "loopback" | "wildcard" | "other";

/** Classifies a listener's bound address. A wildcard is any-address in either family, including the IPv4-mapped IPv6 spelling. */
export function addressClass(entry: Pick<TcpEntry, "family" | "ip">): AddressClass {
  let ip = entry.ip;
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (ip === "0.0.0.0" || ip === "::") return "wildcard";
  if (ip === "::1" || /^127\./.test(ip)) return "loopback";
  return "other";
}

/** `socket:[12345]` -> 12345, anything else -> null. */
export function socketInode(link: string | null): number | null {
  const match = link === null ? null : /^socket:\[(\d+)\]$/.exec(link);
  return match ? Number(match[1]) : null;
}

/** Inodes of every socket a process holds open, or null when its fd table cannot be read. */
export function socketInodesOf(reader: ProcReader, pid: number): Set<number> | null {
  const names = reader.listDir(`/proc/${pid}/fd`);
  if (names === null) return null;
  const inodes = new Set<number>();
  for (const name of names) {
    const inode = socketInode(reader.readLink(`/proc/${pid}/fd/${name}`));
    if (inode !== null) inodes.add(inode);
  }
  return inodes;
}

/** Every numeric process directory under /proc. */
export function listPids(reader: ProcReader): number[] {
  return (reader.listDir("/proc") ?? []).filter((name) => /^[1-9][0-9]*$/.test(name)).map(Number);
}
