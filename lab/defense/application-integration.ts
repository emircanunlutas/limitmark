import assert from "node:assert/strict";
import { statSync } from "node:fs";
import path from "node:path";
import type { ExpectedLane } from "../../defense/core/ledger";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { staticAssetTargets } from "./browser-scope";
import { protectedLineageComplete } from "../../defense/core/lineage";
import { trackedHttp } from "./client";
import { Collector } from "./collector";
import { BA0_COLLAPSE_LOCAL_V1 } from "./collapse-thresholds";
import { NextAppProcess } from "./field-processes";
import { HopTrustRoot } from "./hop-keys";
import { AppProcess, BoundaryProcess } from "./origin-processes";
import { PLANE_L2_ENTRY, PlaneProcess } from "./plane-process";

/**
 * The built application emits five browser security headers (next.config.ts). The plane relays all five, but the accepted (pinned) Origin
 * Boundary relays only X-Content-Type-Options: the other four are the known, reported blocker and must be ABSENT, not silently assumed.
 */
const RELAYED_SECURITY = { "x-content-type-options": "nosniff" } as const;
const BOUNDARY_DROPPED_POLICIES = ["content-security-policy", "x-frame-options", "referrer-policy", "permissions-policy"] as const;

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
    // The built application's exact static assets are admitted; the synthetic origin has none, so its plane admits none.
    const assets = synthetic ? undefined : staticAssetTargets(REPOSITORY_ROOT);
    plane = await PlaneProcess.start(collector, {
      upstreamPort: boundary.port, hop: trust.planeInit(hop.pbLifetimeMs), l2, egressTimeoutMs: 6_000, ...(assets ? { assets } : {}),
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

    // Browser delivery (built mode): one exact immutable stylesheet through the whole chain, the application's own security policies on
    // every relayed response, and a cache-busting variant of the same asset refused by L1.
    let staticAsset: { status: number | null; refusedVariant: number | null } | null = null;
    const lineages = [home, intake];
    if (assets) {
      const css = assets.find((asset) => asset.endsWith(".css"));
      assert(css, "the build has no stylesheet");
      const asset = await read(plane.port, "protected", "static-asset", css);
      assert.equal(asset.status, 200);
      assert.equal(asset.outcomeHeader, "proxied");
      assert.match(String(asset.headers["content-type"]), /^text\/css/u);
      assert.equal(asset.headers["cache-control"], "public, max-age=31536000, immutable");
      assert.equal(asset.body.length, statSync(path.join(REPOSITORY_ROOT, ".next", css.slice("/_next/".length))).size);
      for (const response of [home, intake, asset]) {
        for (const [name, value] of Object.entries(RELAYED_SECURITY)) assert.equal(response.headers[name], value, name);
        for (const name of BOUNDARY_DROPPED_POLICIES) assert.equal(response.headers[name], undefined, name);
      }
      const variant = await read(plane.port, "protected", "static-asset-variant", `${css}?v=1`);
      assert.equal(variant.status, 404);
      assert.equal(variant.outcomeHeader, "rejected");
      staticAsset = { status: asset.status, refusedVariant: variant.status };
      lineages.push(asset);
    }
    const served = synthetic ? 2 : 3;

    // An ordinary GET sent directly to either protected listener has no
    // lineage. The app guard must refuse it before the Next handler runs.
    const directBoundary = await read(boundary.port, "direct_boundary_rejected", "direct-boundary");
    const directApp = await read(app.port, "direct_app_rejected", "direct-app");
    for (const direct of [directBoundary, directApp]) {
      assert.equal(direct.status, 403);
      assert.equal(direct.body.length, 0);
    }
    const appFin = await app.finish(5_000);
    assert(appFin?.drained);
    assert.equal(appFin.stats.counters.admitted, served);
    assert.equal(appFin.stats.counters.executed, served);
    assert.equal(appFin.stats.counters.stateMutations, 0);
    assert.equal(appFin.stats.counters.refusedByReason["ob.proof_missing"], 1);
    assert.equal(appFin.stats.served.completed, served);
    assert.equal(appFin.stats.served.aborted, 0);
    assert.equal(appFin.stats.guard.contentReadsStarted, 0);

    // Stop the actual application after draining it. The live boundary must refuse the forward itself and answer 502 without any application
    // event; the plane relays that response, and the collector must reconcile it from the boundary's evidence (no fabricated origin receipt).
    await app.stop();
    const appStopped = await read(plane.port, "protected", "app-stopped");
    assert.equal(appStopped.status, 502);
    assert.equal(appStopped.body.length, 0);
    assert.match(String(appStopped.headers["cache-control"]), /no-store/u);
    // The boundary drains only after its last event so the collector's emitted-versus-received identity covers the refused forward.
    const boundaryFin = await boundary.finish(5_000);
    assert(boundaryFin?.drained);
    assert.equal(boundaryFin.stats.admitted, served + 1);
    assert.equal(boundaryFin.stats.forwardResponded, served);
    assert.equal(boundaryFin.stats.forwardFailed, 1);
    assert.equal(boundaryFin.stats.rejectedByReason["ob.proof_missing"], 1);

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
    assert.equal(lineages.length, served);
    for (const page of lineages) {
      const record = collector.recordFor(page.nonce);
      assert(record);
      assert(protectedLineageComplete({ ...record, expected: "protected" }));
      assert.deepEqual(record.app.map(({ kind }) => kind), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"]);
      assert.equal(record.app.at(-1)?.status, page.status);
    }
    const refusedApp = collector.recordFor(directApp.nonce);
    assert.deepEqual(refusedApp?.app.map(({ kind, reason }) => [kind, reason]), [["APP_REFUSED", "ob.proof_missing"]]);
    const appDown = collector.recordFor(appStopped.nonce);
    assert(appDown);
    assert.deepEqual(appDown.boundary.map(({ kind, forwardError }) => [kind, forwardError]).filter(([kind]) => kind === "BOUNDARY_FORWARD_FAILED"), [["BOUNDARY_FORWARD_FAILED", "refused"]]);
    assert.deepEqual(appDown.app, []);
    assert.deepEqual(appDown.origin, []);
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
      appStopped: appStopped.status,
      boundaryStopped: unavailable.status,
      completedLineages: served,
      staticAsset,
      securityHeaders: synthetic ? null : { relayed: Object.keys(RELAYED_SECURITY), droppedAtBoundary: BOUNDARY_DROPPED_POLICIES },
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
