/**
 * Helper for tests/lab-lifetime.test.ts. Starts a long-lived child the way LocalApp does (its own process group on POSIX),
 * registers it for interruption cleanup, prints its pid and then terminates itself in the requested way. The test verifies
 * the child does not survive.
 */
import { spawn } from "node:child_process";
import { trackChildTree } from "../../lab/host/local-app";

const mode = process.argv[2];
const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { detached: process.platform !== "win32", stdio: "ignore", windowsHide: true });
if (!child.pid) throw new Error("no child pid");
trackChildTree(child.pid);
process.stdout.write(`child:${child.pid}\n`, () => {
  if (mode === "exit") process.exit(0);
  else process.kill(process.pid, "SIGTERM");
});
// Keep the event loop alive until the termination above takes effect.
setInterval(() => undefined, 1000);
