/**
 * A fake /proc for the Linux-only field modules (the exposure proof, the sampler). It renders the exact text formats the kernel uses, so the
 * parsers are exercised on realistic input on any platform. It is a TEST fixture: it is not evidence about any real Linux host, and the
 * Linux-only verification suite (which runs these modules against a real /proc) is separate and is not claimed here.
 */
import type { ProcReader } from "../../lab/defense/proc-net";

export type FakeSocket = { family: 4 | 6; ip: string; port: number; inode: number; state?: string; uid?: number };

const hex2 = (value: number): string => value.toString(16).toUpperCase().padStart(2, "0");
/** Four bytes (in address order) -> the kernel's little-endian 32-bit word. */
const word = (bytes: number[]): string => `${hex2(bytes[3])}${hex2(bytes[2])}${hex2(bytes[1])}${hex2(bytes[0])}`;

export function encodeIpv4(ip: string): string {
  return word(ip.split(".").map(Number));
}

export function encodeIpv6(ip: string): string {
  let text = ip;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(text);
  const bytes: number[] = [];
  if (mapped) {
    const v4 = mapped[1].split(".").map(Number);
    bytes.push(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ...v4);
  } else {
    const [head, tail] = text.split("::");
    const groups = (part: string | undefined): number[] => (part ? part.split(":").map((group) => parseInt(group, 16)) : []);
    const left = groups(head);
    const right = text.includes("::") ? groups(tail) : [];
    const all = text.includes("::") ? [...left, ...Array(8 - left.length - right.length).fill(0), ...right] : left;
    for (const group of all) bytes.push(group >> 8, group & 0xff);
    text = "";
  }
  return [0, 4, 8, 12].map((offset) => word(bytes.slice(offset, offset + 4))).join("");
}

const tcpLine = (index: number, socket: FakeSocket): string => {
  const local = socket.family === 4 ? `${encodeIpv4(socket.ip)}:${socket.port.toString(16).toUpperCase().padStart(4, "0")}` : `${encodeIpv6(socket.ip)}:${socket.port.toString(16).toUpperCase().padStart(4, "0")}`;
  const remote = socket.family === 4 ? "00000000:0000" : "00000000000000000000000000000000:0000";
  return `  ${index}: ${local} ${remote} ${socket.state ?? "0A"} 00000000:00000000 00:00000000 00000000  ${String(socket.uid ?? 1000).padStart(4)}        0 ${socket.inode} 1 0000000000000000 100 0 0 10 0`;
};
const TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

export class FakeProc implements ProcReader {
  readonly sockets: FakeSocket[] = [];
  readonly holders = new Map<number, number[]>();
  readonly netns = new Map<number, string | null>();
  readonly unreadablePids = new Set<number>();
  readonly files = new Map<string, string>();
  tcpUnreadable = false;
  tcp6Absent = false;

  addSocket(socket: FakeSocket, holderPids: number[]): this {
    this.sockets.push(socket);
    for (const pid of holderPids) this.holders.set(pid, [...(this.holders.get(pid) ?? []), socket.inode]);
    return this;
  }

  addProcess(pid: number, options: { netns?: string | null; stat?: string; limits?: string } = {}): this {
    if (!this.holders.has(pid)) this.holders.set(pid, []);
    this.netns.set(pid, options.netns === undefined ? "net:[4026531992]" : options.netns);
    if (options.stat !== undefined) this.files.set(`/proc/${pid}/stat`, options.stat);
    if (options.limits !== undefined) this.files.set(`/proc/${pid}/limits`, options.limits);
    return this;
  }

  readText(file: string): string | null {
    if (this.files.has(file)) return this.files.get(file) ?? null;
    if (file === "/proc/net/tcp") return this.tcpUnreadable ? null : [TCP_HEADER, ...this.sockets.filter((socket) => socket.family === 4).map((socket, index) => tcpLine(index, socket))].join("\n") + "\n";
    if (file === "/proc/net/tcp6") return this.tcp6Absent ? null : [TCP_HEADER, ...this.sockets.filter((socket) => socket.family === 6).map((socket, index) => tcpLine(index, socket))].join("\n") + "\n";
    return null;
  }

  listDir(dir: string): string[] | null {
    if (dir === "/proc") return [...this.holders.keys()].map(String).concat(["self", "net", "sys"]);
    const fd = /^\/proc\/(\d+)\/fd$/.exec(dir);
    if (fd) {
      const pid = Number(fd[1]);
      if (this.unreadablePids.has(pid) || !this.holders.has(pid)) return null;
      return (this.holders.get(pid) ?? []).map((_, index) => String(3 + index));
    }
    return null;
  }

  readLink(file: string): string | null {
    const fd = /^\/proc\/(\d+)\/fd\/(\d+)$/.exec(file);
    if (fd) {
      const pid = Number(fd[1]);
      const inode = (this.holders.get(pid) ?? [])[Number(fd[2]) - 3];
      return inode === undefined ? null : `socket:[${inode}]`;
    }
    const ns = /^\/proc\/(\d+)\/ns\/net$/.exec(file);
    if (ns) return this.netns.get(Number(ns[1])) ?? null;
    return null;
  }
}

export const RUNNER = 100;
export const PLANE = 101;
export const BOUNDARY = 102;
export const APP = 103;
export const SSHD = 50;

/** A healthy field topology: the plane on the reviewed address, everything else on loopback, sshd the only ambient listener. */
export function healthyTopology(plane = { ip: "10.0.0.5", port: 8080 }): FakeProc {
  const proc = new FakeProc();
  for (const pid of [RUNNER, PLANE, BOUNDARY, APP, SSHD]) proc.addProcess(pid);
  proc.addSocket({ family: 4, ip: "127.0.0.1", port: 41_000, inode: 1 }, [RUNNER]);
  proc.addSocket({ family: 4, ip: plane.ip, port: plane.port, inode: 2 }, [PLANE]);
  proc.addSocket({ family: 4, ip: "127.0.0.1", port: 41_001, inode: 3 }, [BOUNDARY]);
  proc.addSocket({ family: 4, ip: "127.0.0.1", port: 41_002, inode: 4 }, [APP]);
  proc.addSocket({ family: 4, ip: "0.0.0.0", port: 22, inode: 9 }, [SSHD]);
  proc.addSocket({ family: 6, ip: "::", port: 22, inode: 10 }, [SSHD]);
  return proc;
}
