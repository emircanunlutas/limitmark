import assert from "node:assert/strict";
import type { ExpectedLane } from "../../defense/core/ledger";
import { protectedLineageComplete } from "../../defense/core/lineage";
import { trackedHttp } from "./client";
import { Collector } from "./collector";
import { BA0_COLLAPSE_LOCAL_V1 } from "./collapse-thresholds";
import { NextAppProcess } from "./field-processes";
import { HopTrustRoot } from "./hop-keys";
import { AppProcess, BoundaryProcess } from "./origin-processes";
import { PLANE_L2_ENTRY, PlaneProcess } from "./plane-process";

async function run(synthetic: boolean): Promise<void> {
  const collector = new Collector(null);
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const trust = new HopTrustRoot();
  const { hop, l2 } = BA0_COLLAPSE_LOCAL_V1;
  const limits = { replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs };
  const read = (port: number, lane: ExpectedLane, scenario: string, path = "/") => trackedHttp(collector, port, {
    lane, phase: "functional", cls: "canary", scenario, journey: null, step: null, method: "GET",
  }, { method: "GET", path }, 10_000);

  let app: NextAppProcess | AppProcess | undefined;
  let boundary: BoundaryProcess | undefined;
  let plane: PlaneProcess | undefined;
  try {
    const init = trust.appInit(limits);
    app = synthetic ? await AppProcess.start(collector, init) : await NextAppProcess.start(collector, init);
    boundary = await BoundaryProcess.start(collector, trust.boundaryInit(app.port, {
      ...limits, forwardTimeoutMs: 5_000, baLifetimeMs: hop.baLifetimeMs,
    }));
    plane = await PlaneProcess.start(collector, {
      upstreamPort: boundary.port, hop: trust.planeInit(hop.pbLifetimeMs), l2, egressTimeoutMs: 6_000,
    }, 20_000, PLANE_L2_ENTRY);

    const home = await read(plane.port, "protected", "homepage");
    const intake = await read(plane.port, "protected", "intake", "/test-talep-et?hizmet=web");
    for (const page of [home, intake]) {
      assert.equal(page.status, 200);
      assert.equal(page.outcomeHeader, "proxied");
      assert.match(String(page.headers["content-type"]), /^text\/html/u);
      assert.match(String(page.headers["cache-control"]), /no-store/u);
      assert.equal(page.headers["x-content-type-options"], "nosniff");
    }
    const homeHtml = home.body.toString("utf8");
    const intakeHtml = intake.body.toString("utf8");
    if (synthetic) {
      assert(/<h1>Direnç testi<\/h1>/u.test(homeHtml), "Expected the synthetic homepage");
      assert(/<form\b/u.test(intakeHtml), "Expected the synthetic form");
    } else {
      assert(/Dayanıklılığı varsaymayın\./u.test(homeHtml), "Expected the built homepage");
      for (const html of [homeHtml, intakeHtml]) {
        assert(/Çevrim içi talepler şu anda kullanılamıyor\./u.test(html), "Expected the closed-intake notice");
      }
      assert(!/<form\b/u.test(intakeHtml), "Closed intake rendered a form");
    }

    // An ordinary GET sent directly to either protected listener has no
    // lineage. The app guard must refuse it before the Next handler runs.
    const directBoundary = await read(boundary.port, "direct_boundary_rejected", "direct-boundary");
    const directApp = await read(app.port, "direct_app_rejected", "direct-app");
    for (const direct of [directBoundary, directApp]) {
      assert.equal(direct.status, 403);
      assert.equal(direct.body.length, 0);
    }
    const [boundaryFin, appFin] = await Promise.all([boundary.finish(5_000), app.finish(5_000)]);
    assert(boundaryFin?.drained);
    assert(appFin?.drained);
    assert.equal(boundaryFin.stats.admitted, 2);
    assert.equal(boundaryFin.stats.forwardResponded, 2);
    assert.equal(boundaryFin.stats.rejectedByReason["ob.proof_missing"], 1);
    assert.equal(appFin.stats.counters.admitted, 2);
    assert.equal(appFin.stats.counters.executed, 2);
    assert.equal(appFin.stats.counters.stateMutations, 0);
    assert.equal(appFin.stats.counters.refusedByReason["ob.proof_missing"], 1);
    assert.equal(appFin.stats.served.completed, 2);
    assert.equal(appFin.stats.served.aborted, 0);
    assert.equal(appFin.stats.guard.contentReadsStarted, 0);

    // Remove the actual upstream after draining it. The plane must return
    // its own bounded failure and emit no successful downstream lifecycle.
    await boundary.stop();
    const unavailable = await read(plane.port, "protected", "boundary-stopped");
    assert.equal(unavailable.status, 502);
    assert.equal(unavailable.outcomeHeader, "egress_failed");
    assert.match(String(unavailable.headers["cache-control"]), /no-store/u);

    const planeFin = await plane.finish(5_000);
    assert(planeFin?.drained);
    collector.freeze();
    const final = collector.finalize();
    assert.deepEqual(final, { anomalies: [], anomalyTotal: 0 });
    for (const page of [home, intake]) {
      const record = collector.recordFor(page.nonce);
      assert(record);
      assert(protectedLineageComplete({ ...record, expected: "protected" }));
      assert.deepEqual(record.app.map(({ kind }) => kind), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"]);
      assert.equal(record.app.at(-1)?.status, page.status);
    }
    const refusedApp = collector.recordFor(directApp.nonce);
    assert.deepEqual(refusedApp?.app.map(({ kind, reason }) => [kind, reason]), [["APP_REFUSED", "ob.proof_missing"]]);
    const failed = collector.recordFor(unavailable.nonce);
    assert(failed);
    assert(failed.plane.some((event) => event.kind === "EGRESS_FAILED" && event.egressError === "refused"));
    assert.deepEqual(failed.boundary, []);
    assert.deepEqual(failed.app, []);

    console.log(JSON.stringify({
      origin: synthetic ? "synthetic" : "built-next",
      homepage: home.status,
      intake: intake.status,
      intakeState: synthetic ? "synthetic-form" : "closed",
      directBoundary: directBoundary.status,
      directApp: directApp.status,
      boundaryStopped: unavailable.status,
      completedLineages: 2,
      events: { plane: planeFin.channel.emitted, boundary: boundaryFin.channel.emitted, app: appFin.channel.emitted },
      collectorAnomalies: final.anomalyTotal,
    }));
  } finally {
    await plane?.stop();
    await boundary?.stop();
    await app?.stop();
  }
}

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--synthetic")) {
  console.error("Usage: tsx lab/defense/application-integration.ts [--synthetic]");
  process.exitCode = 1;
} else {
  void run(args[0] === "--synthetic").catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  });
}
