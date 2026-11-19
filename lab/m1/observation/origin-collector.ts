/**
 * Disposable ORIGIN RECEIPT COLLECTOR (local harness entry): a separate process in front of the origin fixture. The recording logic lives in collector-core.ts so the standalone
 * launcher (launch.ts) runs the SAME code. Child process entry; config JSON in argv[2]: { upstreamPort, receiptsFile, runId, campaignId, declarationFile, heartbeatMs,
 * listenHost?, listenPort?, upstreamHost?, heartbeatLogFile? }. Defaults are loopback only.
 */
import { startCollector, type CollectorConfig } from "./collector-core";

if (process.send) {
  const config = JSON.parse(process.argv[2] ?? "{}") as CollectorConfig;
  startCollector(config).then((collector) => {
    process.send?.({ type: "ready", port: collector.port, pid: process.pid });
    process.on("message", (message: { type?: string }) => { if (message.type === "stop") collector.stop().then(() => process.exit(0), () => process.exit(1)); });
  }, () => process.exit(1));
}
