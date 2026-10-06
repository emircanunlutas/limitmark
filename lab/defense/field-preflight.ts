/**
 * Field qualification: the PREFLIGHT, run before the Defense Plane binds its public address. Every check fails closed: a check that cannot
 * be performed is a refusal, never a pass. A refusal binds nothing and sends nothing.
 *
 * What it proves about the host (and only the host):
 *   - the platform is Linux and the working tree is clean;
 *   - the disposable-VM marker the lab bootstrap writes is present with its fixed content;
 *   - the reviewed bind address is an address of THIS host (a NAT'd public address that is not on an interface cannot be bound, and that is a
 *     refusal, never a fallback to a wildcard);
 *   - the old Field Lab Next service (`limitmark-lab-app.service`) is not running, nothing non-loopback listens on its port 3000, and the host
 *     firewall has no port-3000 allow rule, so it cannot be a parallel exposed target;
 *   - the firewall allows the Plane port from exactly ONE source, a single /32 (the one authorized generator), and nothing broader;
 *   - the exposure proof's ambient snapshot is clean before anything is bound.
 *
 * It does NOT prove anything about the cloud firewall or the network: the evidence says so.
 */
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import type { IngressBind } from "../../defense/core/ingress-class";
import { fsProcReader, type ProcReader } from "./proc-net";
import { proveExposure, type ExposureResult } from "./exposure-proof";
import type { Ba0FieldThresholds, BudgetGate } from "./field-thresholds";

export const DISPOSABLE_MARKER_FILE = "/etc/limitmark-lab/DISPOSABLE";
export const DISPOSABLE_MARKER_CONTENT = "limitmark-lab-disposable-v1";
export const OLD_SERVICE_UNIT = "limitmark-lab-app.service";

export interface FieldEnvironment {
  platform: NodeJS.Platform;
  reader: ProcReader;
  pid: number;
  /** The content of the disposable marker, or null when it does not exist. */
  readMarker(): string | null;
  /** `systemctl is-active <unit>` stdout (trimmed), or null when it could not be asked. */
  unitState(unit: string): Promise<string | null>;
  /** `ufw status numbered` text, or null when it could not be read. */
  ufwStatus(): Promise<string | null>;
  /** The IPv4 addresses assigned to this host's interfaces. */
  localIpv4Addresses(): string[];
}

function run(command: string, args: string[], timeoutMs = 5_000): Promise<{ stdout: string; code: number | null } | null> {
  return new Promise((resolve) => {
    try {
      execFile(command, args, { timeout: timeoutMs, encoding: "utf8" }, (error, stdout) => {
        const code = error && typeof (error as { code?: unknown }).code === "number" ? ((error as { code: number }).code) : error ? null : 0;
        if (error && code === null) resolve(null);
        else resolve({ stdout: String(stdout), code });
      });
    } catch { resolve(null); }
  });
}

export function realFieldEnvironment(): FieldEnvironment {
  return {
    platform: process.platform,
    reader: fsProcReader("/proc"),
    pid: process.pid,
    readMarker: () => { try { return existsSync(DISPOSABLE_MARKER_FILE) ? readFileSync(DISPOSABLE_MARKER_FILE, "utf8").trim() : null; } catch { return null; } },
    unitState: async (unit) => (await run("systemctl", ["is-active", unit]))?.stdout.trim() ?? null,
    // The lab bootstrap's --ba0-field mode installs a sudoers fragment allowing exactly this read-only command for the lab user.
    ufwStatus: async () => {
      const direct = typeof process.getuid === "function" && process.getuid() === 0;
      const result = direct ? await run("/usr/sbin/ufw", ["status", "numbered"]) : await run("sudo", ["-n", "/usr/sbin/ufw", "status", "numbered"]);
      return result !== null && result.code === 0 ? result.stdout : null;
    },
    localIpv4Addresses: () => Object.values(os.networkInterfaces()).flatMap((list) => (list ?? []).filter((entry) => entry.family === "IPv4").map((entry) => entry.address)),
  };
}

// ---------------------------------------------------------------------------
// UFW parsing
// ---------------------------------------------------------------------------

export type UfwRule = { number: number; to: string; action: string; from: string };
export type UfwStatus = { active: boolean; rules: UfwRule[] };

/** Parses `ufw status numbered`. Returns null when the text is not recognisably ufw output (unreadable is a refusal, not an empty rule set). */
export function parseUfwStatus(text: string): UfwStatus | null {
  const lines = text.split("\n");
  const statusLine = lines.find((line) => /^Status:\s*/.test(line));
  if (!statusLine) return null;
  const active = /^Status:\s*active/i.test(statusLine);
  const rules: UfwRule[] = [];
  for (const line of lines) {
    const match = /^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?:\s+(?:IN|OUT|FWD))?\s{2,}(.+?)(?:\s+#.*)?\s*$/.exec(line);
    if (match) rules.push({ number: Number(match[1]), to: match[2].trim(), action: match[3], from: match[4].trim() });
  }
  return { active, rules };
}

/** Whether a rule's destination covers `port`: an exact port, a range, or any port (`Anywhere`). */
export function ruleCoversPort(rule: UfwRule, port: number): boolean {
  const to = rule.to.replace(/\s+\(v6\)$/, "");
  if (/^anywhere$/i.test(to)) return true;
  const range = /^(\d{1,5}):(\d{1,5})(?:\/(?:tcp|udp))?$/.exec(to);
  if (range) return Number(range[1]) <= port && port <= Number(range[2]);
  const single = /^(\d{1,5})(?:\/(?:tcp|udp))?$/.exec(to);
  return single !== null && Number(single[1]) === port;
}

/** True when the source is exactly one IPv4 host: a dotted quad, or a /32. */
export function isSingleHostSource(from: string): boolean {
  const source = from.replace(/\s+\(v6\)$/, "");
  return /^(?:\d{1,3}\.){3}\d{1,3}(?:\/32)?$/.test(source);
}

// ---------------------------------------------------------------------------
// The preflight
// ---------------------------------------------------------------------------

export type PreflightCheck = { id: string; ok: boolean; detail: string };
export type PreflightResult = { ok: boolean; checks: PreflightCheck[]; ambientNonLoopbackPorts: number[]; exposure: ExposureResult | null; firewall: { readable: boolean; port3000Rules: number; planePortSources: number } };

export type PreflightInput = {
  env: FieldEnvironment;
  thresholds: Ba0FieldThresholds;
  /** The reviewed bind (the target definition's address and port). */
  plane: IngressBind;
  treeIsClean: boolean;
  budgetGates: readonly BudgetGate[];
  /** Programmatic test seams, never reachable from the CLI or the environment. */
  allowLoopbackIngress?: boolean;
  skipPlatformCheck?: boolean;
};

export async function runFieldPreflight(input: PreflightInput): Promise<PreflightResult> {
  const { env, thresholds, plane } = input;
  const checks: PreflightCheck[] = [];
  const check = (id: string, ok: boolean, detail: string) => checks.push({ id, ok, detail: detail.replace(/=/g, ":").replace(/%/g, " pct") });

  check("platform.linux", input.skipPlatformCheck === true || env.platform === "linux", `platform ${env.platform}`);
  check("tree.clean", input.treeIsClean, input.treeIsClean ? "clean working tree" : "dirty working tree");
  const marker = env.readMarker();
  check("host.disposable_marker", marker === DISPOSABLE_MARKER_CONTENT, marker === null ? "marker missing" : marker === DISPOSABLE_MARKER_CONTENT ? "marker present" : "marker content is not the lab marker");

  // ---- the reviewed bind
  const loopback = /^127\./.test(plane.ip);
  check("bind.not_loopback", input.allowLoopbackIngress === true || !loopback, "the field ingress is a non-loopback address");
  check("bind.port_allowed", plane.port >= 1024 && !thresholds.exposure.forbiddenPlanePorts.includes(plane.port), `port ${plane.port} is unprivileged and not a reserved service port`);
  check("bind.address_is_local", env.localIpv4Addresses().includes(plane.ip), "the reviewed address is assigned to an interface of this host (a NAT'd public address is not)");

  // ---- the budgets
  for (const gate of input.budgetGates) check(`budget.${gate.id}`, gate.ok, gate.detail);

  // ---- the old Field Lab service must not be a parallel exposed target
  const unit = await env.unitState(OLD_SERVICE_UNIT);
  check("old_service.inactive", unit === "inactive" || unit === "failed", unit === null ? "service state could not be read" : `service state ${unit}`);

  // ---- firewall
  const ufwText = await env.ufwStatus();
  const ufw = ufwText === null ? null : parseUfwStatus(ufwText);
  check("firewall.readable", ufw !== null, ufw === null ? "ufw status could not be read" : "ufw status read");
  let port3000Rules = 0;
  let planeSources = 0;
  if (ufw !== null) {
    check("firewall.active", ufw.active, ufw.active ? "ufw is active" : "ufw is not active");
    const allows = ufw.rules.filter((rule) => rule.action === "ALLOW");
    port3000Rules = allows.filter((rule) => thresholds.exposure.forbiddenAmbientPorts.some((port) => ruleCoversPort(rule, port) && !/^anywhere$/i.test(rule.to.replace(/\s+\(v6\)$/, "")))).length;
    check("firewall.no_old_app_port_rule", port3000Rules === 0, `${port3000Rules} allow rule(s) for the old app port`);
    check("firewall.no_allow_all", !allows.some((rule) => /^anywhere$/i.test(rule.to.replace(/\s+\(v6\)$/, ""))), "no allow rule covers every port");
    const forPlane = allows.filter((rule) => ruleCoversPort(rule, plane.port) && !/^anywhere$/i.test(rule.to.replace(/\s+\(v6\)$/, "")));
    const sources = new Set(forPlane.map((rule) => rule.from.replace(/\/32$/, "")));
    planeSources = sources.size;
    check("firewall.plane_port_single_source", forPlane.length > 0 && forPlane.every((rule) => isSingleHostSource(rule.from)) && sources.size === 1, `${forPlane.length} allow rule(s) for the plane port from ${sources.size} distinct source(s); each must be a single host`);
  } else {
    check("firewall.no_old_app_port_rule", false, "unproven: ufw unreadable");
    check("firewall.plane_port_single_source", false, "unproven: ufw unreadable");
  }

  // ---- the exposure proof's ambient snapshot, before anything is bound
  const exposure = proveExposure({
    reader: env.reader, mode: "pre_bind", pids: { runner: env.pid }, plane, expectPlaneListening: false,
    ambientAllowedPorts: thresholds.exposure.ambientAllowedPorts, forbiddenAmbientPorts: thresholds.exposure.forbiddenAmbientPorts, fullScan: false,
  });
  check("exposure.pre_bind_clean", exposure.ok, exposure.ok ? "no unexpected listener before the bind" : `violations ${exposure.violations.join(",")}`);

  return {
    ok: checks.every((entry) => entry.ok), checks, ambientNonLoopbackPorts: exposure.ambientNonLoopbackPorts, exposure,
    firewall: { readable: ufw !== null, port3000Rules, planePortSources: planeSources },
  };
}
