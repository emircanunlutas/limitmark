import { startFencedSupervisor } from "../../lab/defense/fenced-supervisor";
import { HopTrustRoot } from "../../lab/defense/hop-keys";

type Config = Omit<Parameters<typeof startFencedSupervisor>[0], "trust" | "policy"> & { policy: string };

process.once("message", (config: Config) => {
  void (async () => {
    let supervisor: Awaited<ReturnType<typeof startFencedSupervisor>>;
    try {
      supervisor = await startFencedSupervisor({ ...config, policy: Buffer.from(config.policy, "base64url"),
        trust: new HopTrustRoot(), executionModel: "process-local-synthetic" });
    } catch (error) {
      const blocked = error instanceof Error && error.message === "exclusive backend ownership is unavailable";
      process.send!(blocked ? "blocked" : "error", () => process.exit(blocked ? 0 : 1));
      return;
    }
    process.on("disconnect", () => { void supervisor.close().finally(() => process.exit(1)); });
    process.once("message", (command) => {
      if (command === "stop") void supervisor.close().then(() => process.exit(0), () => process.exit(1));
    });
    await supervisor.prepare();
    process.send!(await supervisor.activate() ? "ready" : "error");
  })().catch(() => process.send!("error", () => process.exit(1)));
});
