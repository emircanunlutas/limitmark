/**
 * Field qualification: the harness-side 1-second sampler of the processes the topology owns and of the host. Linux /proc only, read-only,
 * through a `ProcReader` (so the parsers run unchanged on fixtures). It writes nothing, signals nothing and attaches to nothing.
 *
 * What it answers: if performance degrades, which resource ran out first? Per process: CPU, resident memory, open fds against the limit,
 * threads. Host: CPU busy, available memory, network bytes, TCP socket counts, and the kernel's own listen-overflow, listen-drop,
 * retransmit and reset counters. The KERNEL counters are labelled advisory: they count events the application never saw, cannot be
 * attributed to one connection, and some kernel drops have no counter at all.
 *
 * CPU is converted at 100 clock ticks per second (the usual USER_HZ); a different USER_HZ scales the CPU figure and nothing else.
 */
import type { ProcReader } from "./proc-net";

export type PidSample = { alive: boolean; cpuMsDelta: number; rssMb: number; threads: number; fds: number; fdLimit: number | null };

export type HostSample = {
  cpuBusyPct: number;
  memAvailablePct: number;
  memAvailableMb: number;
  rxBytesDelta: number;
  txBytesDelta: number;
  tcpInUse: number;
  tcpTimeWait: number;
  tcpOrphan: number;
  /** Kernel counters since the previous sample. Advisory: see the file comment. */
  kernelAdvisory: { listenOverflows: number; listenDrops: number; retransSegs: number; estabResets: number; attemptFails: number } | null;
};

export type ProcSnapshot = { perRole: Record<string, PidSample>; host: HostSample | null };

const HZ = 100;
const PAGE_BYTES = 4096;

function statFields(text: string): string[] | null {
  const close = text.lastIndexOf(")");
  if (close < 0) return null;
  const rest = text.slice(close + 2).trim().split(/\s+/);
  return rest.length >= 22 ? rest : null;
}

function tableOf(text: string, prefix: string): Record<string, number> | null {
  const lines = text.split("\n").filter((line) => line.startsWith(`${prefix}:`));
  if (lines.length < 2) return null;
  const names = lines[0].split(/\s+/).slice(1);
  const values = lines[1].split(/\s+/).slice(1).map(Number);
  const out: Record<string, number> = {};
  names.forEach((name, index) => { if (Number.isFinite(values[index])) out[name] = values[index]; });
  return out;
}

export class ProcSampler {
  private lastCpu = new Map<string, number>();
  private lastHost: { total: number; idle: number; rx: number; tx: number; kernel: Record<string, number> | null } | null = null;

  constructor(private readonly reader: ProcReader) {}

  private pid(role: string, pid: number): PidSample {
    const stat = this.reader.readText(`/proc/${pid}/stat`);
    const fields = stat === null ? null : statFields(stat);
    if (fields === null) return { alive: false, cpuMsDelta: 0, rssMb: 0, threads: 0, fds: 0, fdLimit: null };
    const ticks = Number(fields[11]) + Number(fields[12]);
    const previous = this.lastCpu.get(role);
    this.lastCpu.set(role, ticks);
    const limits = this.reader.readText(`/proc/${pid}/limits`);
    const limit = limits === null ? null : /^Max open files\s+(\d+|unlimited)/m.exec(limits)?.[1] ?? null;
    return {
      alive: true, cpuMsDelta: previous === undefined ? 0 : Math.max(0, Math.round(((ticks - previous) * 1000) / HZ)), rssMb: Math.round((Number(fields[21]) * PAGE_BYTES) / 1_048_576),
      threads: Number(fields[17]), fds: this.reader.listDir(`/proc/${pid}/fd`)?.length ?? 0, fdLimit: limit === null || limit === "unlimited" ? null : Number(limit),
    };
  }

  private host(): HostSample | null {
    const stat = this.reader.readText("/proc/stat");
    const cpuLine = stat?.split("\n").find((line) => line.startsWith("cpu "));
    const mem = this.reader.readText("/proc/meminfo");
    if (!cpuLine || mem === null) return null;
    const numbers = cpuLine.trim().split(/\s+/).slice(1, 9).map(Number);
    const total = numbers.reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);
    const idle = (numbers[3] ?? 0) + (numbers[4] ?? 0);
    const kb = (name: string): number => Number(new RegExp(`^${name}:\\s+(\\d+)`, "m").exec(mem)?.[1] ?? NaN);
    const memTotal = kb("MemTotal");
    const memAvailable = kb("MemAvailable");
    let rx = 0; let tx = 0;
    for (const line of (this.reader.readText("/proc/net/dev") ?? "").split("\n")) {
      const match = /^\s*([^:\s]+):\s*(.*)$/.exec(line);
      if (!match || match[1] === "lo") continue;
      const columns = match[2].trim().split(/\s+/).map(Number);
      if (columns.length >= 9) { rx += columns[0]; tx += columns[8]; }
    }
    const sockstat = this.reader.readText("/proc/net/sockstat") ?? "";
    const tcpLine = sockstat.split("\n").find((line) => line.startsWith("TCP:")) ?? "";
    const sock = (name: string): number => Number(new RegExp(`\\b${name}\\s+(\\d+)`).exec(tcpLine)?.[1] ?? 0);
    const netstat = this.reader.readText("/proc/net/netstat");
    const snmp = this.reader.readText("/proc/net/snmp");
    const ext = netstat === null ? null : tableOf(netstat, "TcpExt");
    const tcp = snmp === null ? null : tableOf(snmp, "Tcp");
    const kernel: Record<string, number> | null = ext && tcp ? { listenOverflows: ext.ListenOverflows ?? 0, listenDrops: ext.ListenDrops ?? 0, retransSegs: tcp.RetransSegs ?? 0, estabResets: tcp.EstabResets ?? 0, attemptFails: tcp.AttemptFails ?? 0 } : null;
    const previous = this.lastHost;
    this.lastHost = { total, idle, rx, tx, kernel };
    const dTotal = previous ? total - previous.total : 0;
    const dIdle = previous ? idle - previous.idle : 0;
    const delta = (name: string): number => (kernel && previous?.kernel ? Math.max(0, kernel[name] - (previous.kernel[name] ?? 0)) : 0);
    return {
      cpuBusyPct: dTotal > 0 ? Math.round((1000 * (dTotal - dIdle)) / dTotal) / 10 : 0,
      memAvailablePct: Number.isFinite(memTotal) && memTotal > 0 ? Math.round((1000 * memAvailable) / memTotal) / 10 : 0,
      memAvailableMb: Number.isFinite(memAvailable) ? Math.round(memAvailable / 1024) : 0,
      rxBytesDelta: previous ? Math.max(0, rx - previous.rx) : 0, txBytesDelta: previous ? Math.max(0, tx - previous.tx) : 0,
      tcpInUse: sock("inuse"), tcpTimeWait: sock("tw"), tcpOrphan: sock("orphan"),
      kernelAdvisory: kernel ? { listenOverflows: delta("listenOverflows"), listenDrops: delta("listenDrops"), retransSegs: delta("retransSegs"), estabResets: delta("estabResets"), attemptFails: delta("attemptFails") } : null,
    };
  }

  sample(pids: Readonly<Record<string, number>>): ProcSnapshot {
    const perRole: Record<string, PidSample> = {};
    for (const [role, pid] of Object.entries(pids)) perRole[role] = this.pid(role, pid);
    return { perRole, host: this.host() };
  }
}
