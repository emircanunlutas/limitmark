import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { validateLabLifecycleObserverConfig } from "../deployment/lifecycle-private-contract";

// Validated deployment wrapper for the LAB lifecycle observer. It is a convenience guard, NOT a security boundary: nothing in the repository can stop a person from running
// `wrangler deploy` directly with any config. The boundaries that hold regardless of how the Worker is deployed are (1) the required runtime marker checked by the Worker before
// any storage access, and (2) the Authority's own authorization of the caller (the lab observer is bound only to the lab read-only entrypoint of the lab Authority).
//
//   tsx scripts/lab-observer-deploy.ts            validate only (default; touches nothing)
//   tsx scripts/lab-observer-deploy.ts --execute  validate, then run `wrangler deploy` with the one fixed config path
//
// No other argument is accepted: the config path, account and Worker name cannot be chosen on the command line.

export const LAB_OBSERVER_CONFIG = "deployment/lifecycle-observer.lab.jsonc";
export const LAB_OBSERVER_MAIN = "workers/lab-lifecycle-observer.ts";

const strip = (text: string): string => text.split("\n").filter((line) => !line.trim().startsWith("//")).join("\n");

/** Every Wrangler config under deployment/ whose `main` is the lab observer module (any spelling that resolves to it, or that names it). */
export function observerEntrypointConfigs(root: string): string[] {
  const found: string[] = [];
  const directory = path.join(root, "deployment");
  for (const entry of readdirSync(directory).sort()) {
    if (!/\.jsonc?$/u.test(entry)) continue;
    let main: unknown;
    try { main = (JSON.parse(strip(readFileSync(path.join(directory, entry), "utf8"))) as { main?: unknown }).main; } catch { continue; }
    if (typeof main !== "string") continue;
    const resolved = path.relative(root, path.resolve(directory, main)).split(path.sep).join("/");
    if (resolved === LAB_OBSERVER_MAIN || /lab-lifecycle-observer/u.test(main)) found.push(`deployment/${entry}`);
  }
  return found;
}

/** Throws unless the repository is in the one reviewed lab-observer deployment state. Reads only; never deploys. */
export function validateLabObserverDeployment(root: string): void {
  const configs = observerEntrypointConfigs(root);
  // the rendered config and its template may name the lab observer; any other configuration that does is an alternative entrypoint and is refused
  const unexpected = configs.filter((config) => config !== LAB_OBSERVER_CONFIG);
  if (unexpected.length > 0) throw new Error(`alternative lab observer entrypoint configuration: ${unexpected.join(",")}`);
  const rendered = JSON.parse(strip(readFileSync(path.join(root, LAB_OBSERVER_CONFIG), "utf8"))) as unknown;
  // the wrapper deploys the INACTIVE state only: arming the schedule is a separate decision this wrapper cannot make
  validateLabLifecycleObserverConfig(rendered, false, "STAGING_DEPLOYMENT_INACTIVE");
}

function main(argv: readonly string[]): number {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== "--execute")) { console.error("REFUSED  only --execute is accepted"); return 2; }
  const root = path.resolve(__dirname, "..");
  try { validateLabObserverDeployment(root); } catch (error) { console.error(`REFUSED  ${error instanceof Error ? error.message : "invalid"}`); return 2; }
  console.log("VALID  lab observer configuration (marker, buckets, read-only reader binding, no cron)");
  if (argv[0] !== "--execute") { console.log("validation only; nothing was deployed"); return 0; }
  execFileSync("npx", ["wrangler", "deploy", "--config", LAB_OBSERVER_CONFIG], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  return 0;
}

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === __filename) process.exit(main(process.argv.slice(2)));
