/**
 * Browser delivery verification: the built application rendered by a real browser through Plane (L1+L2) -> Origin Boundary -> application
 * proof verifier, compared with the same build served directly in an isolated loopback reference.
 *
 * Every browser request to the chain goes through the measurement-only BrowserRelay, so each one has a ledger record and the collector must
 * reconcile all of them with zero anomalies. Non-loopback requests are blocked in the browser (both modes, identically) and recorded.
 *
 * Usage: node --import tsx lab/defense/browser-delivery.ts <output-directory>
 * Environment: BROWSER_CHANNEL (default "chrome"; "chromium" for a Playwright-managed build) or BROWSER_EXECUTABLE.
 * Set NEXT_PUBLIC_LIMITMARK_DOCUMENT_LINKS=1 for both the build and the harness to verify native public links. The harness derives the mode
 * from the build's observed behaviour and fails if the environment disagrees.
 */
import assert from "node:assert/strict";
import { fork, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { chromium, type Browser, type BrowserContext, type Page } from "@playwright/test";
import { protectedLineageComplete } from "../../defense/core/lineage";
import { REPOSITORY_ROOT } from "../evidence/manifest";
import { assertModeMatchesEnvironment, referenceLinkMode } from "./browser-link-mode";
import { BrowserRelay } from "./browser-relay";
import { AUTHORIZATION_PAGE_TARGET } from "../../defense/core/types";
import { READ_ONLY_PAGE_TARGETS, staticAssetTargets } from "./browser-scope";
import { Collector, type LedgerRecord } from "./collector";
import { BA0_COLLAPSE_LOCAL_V1 } from "./collapse-thresholds";
import { NextAppProcess } from "./field-processes";
import { HopTrustRoot } from "./hop-keys";
import { BoundaryProcess } from "./origin-processes";
import { PLANE_L2_ENTRY, PlaneProcess } from "./plane-process";

const SECURITY_HEADERS = ["content-security-policy", "x-frame-options", "referrer-policy", "permissions-policy", "x-content-type-options"] as const;
const IMMUTABLE = "public, max-age=31536000, immutable";
/** The reported blocker: the accepted (pinned) Origin Boundary relays none of these, so the browser receives them only from the reference. */
const BOUNDARY_DROPPED = ["content-security-policy", "x-frame-options", "referrer-policy", "permissions-policy"] as const;

type ResponseRow = { mode: string; path: string; status: number; type: string; headers: Record<string, string>; prefetch: boolean };
type ConsoleRow = { mode: string; page: string; type: string; text: string };
type PageObservation = {
  path: string; status: number | null; navigation: "document" | "client" | "direct"; title: string; h1: string; textSha256: string;
  bodyFont: string; bodyBackground: string; headerDisplay: string; stylesheets: number; scripts: number; security: Record<string, string | null>;
  clickToUrlMs?: number;
};

const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const pick = (headers: Record<string, string>, names: readonly string[]) => Object.fromEntries(names.map((name) => [name, headers[name] ?? null]));
const isRscTarget = (target: string) => new URLSearchParams(target.split("?")[1]).has("_rsc");

async function freePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as net.AddressInfo;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

function httpRead(port: number, pathname: string): Promise<{ status: number | null; bytes: number | null }> {
  return new Promise((resolve) => {
    const request = http.get({ host: "127.0.0.1", port, path: pathname, agent: false }, (response) => {
      let bytes = 0;
      response.on("data", (chunk: Buffer) => { bytes += chunk.length; });
      response.on("end", () => resolve({ status: response.statusCode ?? null, bytes }));
    });
    request.on("error", () => resolve({ status: null, bytes: null }));
    request.setTimeout(2_000, () => { request.destroy(); resolve({ status: null, bytes: null }); });
  });
}
const httpStatus = async (port: number, pathname: string) => (await httpRead(port, pathname)).status;

/** The same build served directly by `next start` on loopback, with the same credential-free environment the protected app gets. */
async function startReference(): Promise<{ port: number; child: ChildProcess }> {
  const port = await freePort();
  const child = fork(path.join(REPOSITORY_ROOT, "node_modules", "next", "dist", "bin", "next"), ["start", "--hostname", "127.0.0.1", "--port", String(port)], {
    cwd: REPOSITORY_ROOT, stdio: ["ignore", "ignore", "ignore", "ipc"], execArgv: [],
    env: { NODE_ENV: "production", NEXT_TELEMETRY_DISABLED: "1", PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
  });
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await httpStatus(port, "/") === 200) return { port, child };
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  child.kill();
  throw new Error("the reference server did not start");
}

class BrowserRun {
  readonly responses: ResponseRow[] = [];
  readonly consoleRows: ConsoleRow[] = [];
  readonly pageErrors: ConsoleRow[] = [];
  readonly failed: { mode: string; url: string; failure: string }[] = [];
  readonly blocked: { mode: string; url: string }[] = [];
  constructor(readonly browser: Browser) {}

  async context(mode: string): Promise<BrowserContext> {
    // No request interception: Playwright routing would disable the browser's HTTP cache, which is part of what is verified.
    const context = await this.browser.newContext({ viewport: { width: 900, height: 1_000 }, serviceWorkers: "block" });
    context.on("page", (page) => this.watch(mode, page));
    return context;
  }

  readonly pending = new Map<object, { mode: string; url: string }>();

  private watch(mode: string, page: Page): void {
    page.on("request", (request) => this.pending.set(request, { mode, url: request.url() }));
    page.on("requestfinished", (request) => this.pending.delete(request));
    page.on("response", (response) => {
      const url = new URL(response.url());
      if (url.hostname !== "127.0.0.1") return;
      const requestHeaders = response.request().headers();
      const prefetch = requestHeaders["next-router-prefetch"] !== undefined || requestHeaders["next-router-segment-prefetch"] !== undefined;
      this.responses.push({ mode, path: url.pathname + url.search, status: response.status(), type: response.request().resourceType(), headers: response.headers(), prefetch });
    });
    page.on("console", (message) => this.consoleRows.push({ mode, page: new URL(page.url() || "about:blank").pathname, type: message.type(), text: message.text().slice(0, 300) }));
    page.on("pageerror", (error) => this.pageErrors.push({ mode, page: page.url(), type: "pageerror", text: String(error).slice(0, 300) }));
    page.on("requestfailed", (request) => {
      this.pending.delete(request);
      const url = new URL(request.url());
      // Lab isolation: the browser resolves no host but loopback. The application's one cross-origin dependency (a Google Fonts
      // stylesheet @import) therefore fails identically in the reference and through the chain, and is recorded as blocked.
      if (url.hostname !== "127.0.0.1") this.blocked.push({ mode, url: request.url() });
      else this.failed.push({ mode, url: request.url(), failure: request.failure()?.errorText ?? "unknown" });
    });
  }
}

/**
 * "Network idle" is not usable: through the chain the router's refused RSC prefetches (400) are never consumed by the page, so Chrome
 * keeps those fetches open indefinitely. The load event plus a fixed settle window is used for both modes instead.
 */
async function settle(page: Page): Promise<void> {
  await page.waitForLoadState("load");
  await page.waitForTimeout(1_000);
}

async function observe(page: Page, navigation: PageObservation["navigation"], status: number | null, security: Record<string, string | null>): Promise<PageObservation> {
  await settle(page);
  const facts = await page.evaluate(() => {
    const body = getComputedStyle(document.body);
    const header = document.querySelector(".site-header");
    return {
      title: document.title, h1: document.querySelector("h1")?.textContent?.trim() ?? "", text: document.body.innerText,
      bodyFont: body.fontFamily, bodyBackground: body.backgroundColor, headerDisplay: header ? getComputedStyle(header).display : "",
      stylesheets: document.styleSheets.length, scripts: document.scripts.length,
    };
  });
  const url = new URL(page.url());
  return { path: url.pathname + url.search, status, navigation, title: facts.title, h1: facts.h1, textSha256: sha(facts.text), bodyFont: facts.bodyFont, bodyBackground: facts.bodyBackground, headerDisplay: facts.headerDisplay, stylesheets: facts.stylesheets, scripts: facts.scripts, security };
}

/**
 * A document navigation's status. Chrome turns an empty-bodied 4xx/5xx document into a navigation error (ERR_HTTP_RESPONSE_CODE_FAILURE);
 * the response the browser actually received is still observed, and the error text is kept.
 */
async function navigate(page: Page, url: string): Promise<{ status: number | null; bytes: number | null; error: string | null }> {
  let seen: number | null = null;
  const onResponse = (response: import("@playwright/test").Response) => { if (response.url() === url && response.request().isNavigationRequest()) seen = response.status(); };
  page.on("response", onResponse);
  try {
    const response = await page.goto(url);
    return { status: response?.status() ?? null, bytes: response ? (await response.body()).length : null, error: null };
  } catch (error) {
    // The document the browser then shows is its own error page, not the server's body: no byte count is reported for it.
    return { status: seen, bytes: null, error: String((error as Error).message).split("\n")[0] };
  } finally { page.off("response", onResponse); }
}

/** The supported read-only journey: direct loads, hydrated interaction and in-page link navigation. */
async function journey(run: BrowserRun, mode: string, base: string, outDir: string): Promise<{ pages: PageObservation[]; menu: string[]; history: PageObservation[] }> {
  const context = await run.context(mode);
  const page = await context.newPage();
  const pages: PageObservation[] = [];
  const docSecurity = (pathname: string) => {
    const row = run.responses.filter((r) => r.mode === mode && r.type === "document" && r.path === pathname).at(-1);
    return { status: row?.status ?? null, security: pick(row?.headers ?? {}, SECURITY_HEADERS) };
  };
  const load = async (target: string) => {
    const response = await page.goto(base + target, { waitUntil: "load" });
    pages.push(await observe(page, "direct", response?.status() ?? null, pick(response ? await response.allHeaders() : {}, SECURITY_HEADERS)));
  };
  const click = async (selector: string, expected: RegExp, measure = true) => {
    await page.evaluate(() => { (window as unknown as { __lmMarker?: number }).__lmMarker = 1; });
    const started = performance.now();
    const reachedUrl = page.waitForURL(expected, { waitUntil: "commit" }).then(() => performance.now() - started);
    const [clickToUrlMs] = await Promise.all([reachedUrl, page.locator(selector).first().click()]);
    await settle(page);
    const kept = await page.evaluate(() => (window as unknown as { __lmMarker?: number }).__lmMarker === 1);
    const pathname = new URL(page.url()).pathname + new URL(page.url()).search;
    const doc = docSecurity(pathname);
    pages.push({ ...await observe(page, kept ? "client" : "document", kept ? null : doc.status, kept ? {} : doc.security), ...(measure ? { clickToUrlMs } : {}) });
  };

  await load("/");
  await page.screenshot({ path: path.join(outDir, `${mode}-home.png`), fullPage: false });
  // Hydration: the header menu is a client component; only working JavaScript toggles it.
  const toggle = page.locator(".menu-toggle");
  const expanded = async (wanted: string) => {
    await page.waitForFunction((value) => document.querySelector(".menu-toggle")?.getAttribute("aria-expanded") === value, wanted, { timeout: 5_000 }).catch(() => undefined);
    return await toggle.getAttribute("aria-expanded") ?? "";
  };
  const menu = [await toggle.getAttribute("aria-expanded") ?? ""];
  await toggle.click(); menu.push(await expanded("true"));
  await toggle.click(); menu.push(await expanded("false"));

  await click('footer a[href="/gizlilik"]', /\/gizlilik$/);
  await page.screenshot({ path: path.join(outDir, `${mode}-gizlilik.png`), fullPage: false });
  await click("a.brand", /\/$/);
  await toggle.click();
  await click("a.nav-cta", /\/test-talep-et$/);
  // Back and forward through the history this journey built: / -> /gizlilik -> / -> /test-talep-et.
  const history: PageObservation[] = [];
  const step = async (direction: "back" | "forward", expected: RegExp) => {
    const reached = page.waitForURL(expected, { waitUntil: "commit" });
    await Promise.all([reached, direction === "back" ? page.goBack({ waitUntil: "commit" }) : page.goForward({ waitUntil: "commit" })]);
    history.push(await observe(page, "direct", null, {}));
  };
  await step("back", /\/$/);
  await step("back", /\/gizlilik$/);
  await step("forward", /\/$/);
  await step("forward", /\/test-talep-et$/);
  await load("/test-talep-et?hizmet=web");
  await load("/test-talep-et/tesekkurler");
  await click(`footer a[href="${AUTHORIZATION_PAGE_TARGET}"]`, /\/test-yetkilendirmesi$/, false);
  await page.close();
  await context.close();
  return { pages, menu, history };
}

async function main(): Promise<void> {
  const outDir = process.argv[2];
  if (!outDir) throw new Error("Usage: tsx lab/defense/browser-delivery.ts <output-directory>");
  mkdirSync(outDir, { recursive: true });
  if (!existsSync(path.join(REPOSITORY_ROOT, ".next", "BUILD_ID"))) throw new Error("Build the application first (npm run build)");
  const assets = staticAssetTargets(REPOSITORY_ROOT);
  const assetSet = new Set(assets);
  const pageSet = new Set(READ_ONLY_PAGE_TARGETS);
  const scenarioOf = (method: string, target: string) => method === "GET" && pageSet.has(target) ? "page" : method === "GET" && assetSet.has(target) ? "asset" : "unsupported";

  const isolation = ["--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1", "--no-proxy-server"];
  const browser = await chromium.launch(process.env.BROWSER_EXECUTABLE
    ? { executablePath: process.env.BROWSER_EXECUTABLE, args: isolation }
    : { channel: process.env.BROWSER_CHANNEL ?? "chrome", args: isolation });
  const run = new BrowserRun(browser);
  const write = (name: string, data: unknown) => writeFileSync(path.join(outDir, name), typeof data === "string" ? data : `${JSON.stringify(data, null, 2)}\n`);

  // ---- 1. Isolated reference: the same build served directly.
  const reference = await startReference();
  let referenceJourney: Awaited<ReturnType<typeof journey>>;
  try {
    referenceJourney = await journey(run, "reference", `http://127.0.0.1:${reference.port}`, outDir);
  } finally { reference.child.kill(); }

  // ---- 2. The guarded chain.
  const collector = new Collector(null);
  collector.enableOriginStreams();
  collector.enableLaneStreams();
  const trust = new HopTrustRoot();
  const { hop, l2 } = BA0_COLLAPSE_LOCAL_V1;
  const limits = { replayCapacity: hop.replayCapacity, bodyDeadlineMs: hop.bodyDeadlineMs };
  const app = await NextAppProcess.start(collector, trust.appInit(limits));
  let boundary: BoundaryProcess | undefined;
  let plane: PlaneProcess | undefined;
  let relay: BrowserRelay | undefined;
  try {
    boundary = await BoundaryProcess.start(collector, trust.boundaryInit(app.port, { ...limits, forwardTimeoutMs: 5_000, baLifetimeMs: hop.baLifetimeMs }));
    plane = await PlaneProcess.start(collector, { upstreamPort: boundary.port, hop: trust.planeInit(hop.pbLifetimeMs), l2, egressTimeoutMs: 6_000, assets, authorizationPage: true }, 20_000, PLANE_L2_ENTRY);
    relay = new BrowserRelay(collector, plane.port, scenarioOf);
    const base = `http://127.0.0.1:${await relay.listen()}`;

    relay.setPhase("journey");
    const chainJourney = await journey(run, "chain", base, outDir);

    // Unsupported routes and methods, sent by the browser context through the same adapter.
    relay.setPhase("unsupported");
    const context = await run.context("chain-unsupported");
    const page = await context.newPage();
    const navigations: Record<string, number | null> = {};
    for (const target of ["/admin", "/_next/static/chunks/not-in-build.js", "/api/cron/process-notifications"]) {
      navigations[target] = (await navigate(page, base + target)).status;
    }
    const css = assets.find((asset) => asset.endsWith(".css"))!;
    const requests: { method: string; target: string; status: number; body: number }[] = [];
    for (const [method, target, extra] of [
      ["HEAD", "/", {}], ["PUT", "/", {}], ["DELETE", "/", {}], ["OPTIONS", "/", {}], ["POST", css, {}], ["GET", `${css}?v=1`, {}],
      ["GET", "/?_rsc=abc123", { headers: { RSC: "1", "Next-Router-Prefetch": "1" } }], ["GET", "/gizlilik?_rsc=abc123", { headers: { RSC: "1" } }],
      ["POST", "/api/public-inquiries", { headers: { "content-type": "application/x-www-form-urlencoded" }, data: "notes=" }],
    ] as const) {
      const response = await context.request.fetch(base + target, { method, maxRedirects: 0, ...extra });
      requests.push({ method, target, status: response.status(), body: (await response.body()).length });
    }
    // Direct access to the protected listeners from the same browser: no lineage, refused before the application runs.
    const directViews = {
      boundary: await navigate(page, `http://127.0.0.1:${boundary.port}/`),
      app: await navigate(page, `http://127.0.0.1:${app.port}/`),
      appAsset: await navigate(page, `http://127.0.0.1:${app.port}${css}`),
    };
    const direct = Object.fromEntries(Object.entries(directViews).map(([name, view]) => [name, view.status]));
    // The same direct attempts read without a browser: the server's own refusal body is empty.
    const directRaw = { boundary: await httpRead(boundary.port, "/"), app: await httpRead(app.port, "/"), appAsset: await httpRead(app.port, css) };
    assert.deepEqual(Object.values(directRaw), [{ status: 403, bytes: 0 }, { status: 403, bytes: 0 }, { status: 403, bytes: 0 }]);
    // Closing the context force-closes its page. On Linux headless Chromium a separate page.close() after the refused direct
    // navigations above was observed to block for minutes, with nothing in flight.
    await context.close();
    await relay.idle();

    // Application unavailability, observed by the browser: the boundary answers 502 itself, no application event exists.
    const appFin = await app.finish(5_000);
    assert(appFin?.drained);
    await app.stop();
    relay.setPhase("app-stopped");
    const outage = await run.context("chain-outage");
    const outagePage = await outage.newPage();
    const stopped = await navigate(outagePage, base + "/");
    const outageStatus = stopped.status;
    await outage.close();
    await relay.idle();
    const boundaryFin = await boundary.finish(5_000);
    const planeFin = await plane.finish(5_000);
    assert(boundaryFin?.drained && planeFin?.drained);
    collector.freeze();
    const verdict = collector.finalize();

    // ---- 3. Verification.
    const byRid = new Map<string, LedgerRecord>([...collector.allRecords()].map((record) => [record.rid, record]));
    const exchanges = relay.exchanges();
    const kinds = (events: readonly { kind: string }[]) => events.map((event) => event.kind);
    const journeyRsc = exchanges.filter((exchange) => exchange.phase === "journey" && isRscTarget(exchange.target));
    // The mode is read from what the build did (the reference journey's three link clicks are native documents only in a document-link
    // build, and all three must agree: a mixed or incomplete trace is rejected) and must agree with the harness environment, so an evidence run cannot be labelled with a mode the build does not have.
    const referenceClicks = referenceJourney.pages.filter((page) => page.clickToUrlMs !== undefined).map((page) => page.navigation);
    const linkMode = referenceLinkMode(referenceClicks);
    assertModeMatchesEnvironment(linkMode, process.env.NEXT_PUBLIC_LIMITMARK_DOCUMENT_LINKS);
    const documentLinks = linkMode === "document";
    if (documentLinks) {
      for (const journey of [chainJourney, referenceJourney]) {
        assert.deepEqual(journey.pages.slice(1, 4).map((page) => page.navigation), ["document", "document", "document"]);
        assert.equal(journey.pages.at(-1)?.navigation, "document", "footer authorization link");
      }
      assert.deepEqual(journeyRsc, [], "native links emitted an RSC request through the chain");
      assert.deepEqual(run.responses.filter((row) => row.mode === "reference" && isRscTarget(row.path)), [], "native links emitted an RSC request to the reference");
    }
    let proxiedSupported = 0;
    for (const exchange of exchanges) {
      const record = exchange.rid === null ? undefined : byRid.get(exchange.rid);
      assert(record, `no ledger record for ${exchange.method} ${exchange.target}`);
      assert.deepEqual(kinds(record.harness), ["SENT", "CLIENT_COMPLETED"]);
      assert.equal(record.harness[1].status, exchange.status ?? undefined);
      if (exchange.phase === "app-stopped" && exchange.scenario !== "unsupported") {
        assert.equal(exchange.status, 502);
        assert.equal(exchange.bytes, 0);
        assert.deepEqual(record.boundary.filter((event) => event.kind === "BOUNDARY_FORWARD_FAILED").map((event) => event.forwardError), ["refused"]);
        assert.deepEqual([record.app, record.origin], [[], []]);
      } else if (exchange.scenario !== "unsupported") {
        assert.equal(exchange.status, 200, `${exchange.target}`);
        assert.equal(exchange.outcome, "proxied");
        assert(protectedLineageComplete({ ...record, expected: "protected" }));
        assert.deepEqual(kinds(record.app), ["APP_ADMITTED", "APP_EXECUTED", "APP_COMPLETED"]);
        assert.equal(exchange.headers["x-content-type-options"], "nosniff", exchange.target);
        for (const name of BOUNDARY_DROPPED) assert.equal(exchange.headers[name], undefined, `${name} unexpectedly relayed on ${exchange.target}`);
        if (exchange.scenario === "asset") assert.equal(exchange.headers["cache-control"], IMMUTABLE, exchange.target);
        else assert.doesNotMatch(exchange.headers["cache-control"] ?? "", /public|immutable/u, exchange.target);
        proxiedSupported++;
      } else if (exchange.method === "POST" && exchange.target === "/api/public-inquiries") {
        // A write passes L1/L2 and the proofs but the application never executes it.
        assert.equal(exchange.status, 404);
        assert.deepEqual(kinds(record.app), ["APP_ADMITTED", "APP_COMPLETED"]);
      } else {
        assert(record.plane.some((event) => event.kind === "L1_REJECTED"), `${exchange.method} ${exchange.target} was not refused by L1`);
        assert.deepEqual([record.boundary, record.app], [[], []]);
        assert.notEqual(exchange.outcome, "proxied");
      }
    }
    assert.deepEqual(verdict, { anomalies: [], anomalyTotal: 0 });
    assert.equal(appFin.stats.counters.executed, proxiedSupported);
    assert.equal(appFin.stats.counters.stateMutations, 0);
    assert.equal(outageStatus, 502);
    assert.equal(exchanges.find((e) => e.phase === "app-stopped" && e.target === "/")?.bytes, 0);
    assert.deepEqual(direct, { boundary: 403, app: 403, appAsset: 403 });
    for (const status of Object.values(navigations)) assert(status === 404, "unsupported navigation was served");
    const expectedStatus: Record<string, number> = { HEAD: 405, PUT: 405, DELETE: 405, OPTIONS: 405 };
    for (const request of requests) {
      if (request.method in expectedStatus) assert.equal(request.status, expectedStatus[request.method], `${request.method} ${request.target}`);
      else if (request.method === "POST") assert.equal(request.status, request.target === css ? 405 : 404);
      else assert.equal(request.status, request.target.startsWith(css) ? 404 : 400, request.target);
    }

    // Compare the visible result. Navigation and script counts can differ when the build uses Next.js links.
    const comparable = (observations: PageObservation[]) => observations.map(({ path: p, title, h1, textSha256, bodyFont, bodyBackground, headerDisplay, stylesheets }) => ({ p, title, h1, textSha256, bodyFont, bodyBackground, headerDisplay, stylesheets }));
    assert.deepEqual(comparable(chainJourney.pages), comparable(referenceJourney.pages));
    // Back/forward land on the same rendered pages as the clicks that created them, in the chain and in the reference.
    const expectedHistory = [2, 1, 2, 3];
    for (const journey of [chainJourney, referenceJourney]) {
      assert.deepEqual(journey.history.map((page) => page.path), ["/", "/gizlilik", "/", "/test-talep-et"]);
      assert.deepEqual(comparable(journey.history), comparable(expectedHistory.map((index) => journey.pages[index])));
    }
    assert.deepEqual(chainJourney.menu, ["false", "true", "false"]);
    assert.deepEqual(referenceJourney.menu, chainJourney.menu);
    const referenceSecurity = referenceJourney.pages[0].security;
    for (const name of SECURITY_HEADERS) assert(referenceSecurity[name], `the reference emitted no ${name}`);
    const expectedChainSecurity = { ...referenceSecurity, ...Object.fromEntries(BOUNDARY_DROPPED.map((name) => [name, null])) };
    for (const observed of chainJourney.pages) {
      if (observed.navigation === "client") continue;
      assert.equal(observed.status, 200, observed.path);
      assert.deepEqual(observed.security, expectedChainSecurity, observed.path);
    }
    const sameOrigin = (mode: string) => [...new Set(run.responses.filter((r) => r.mode === mode && (r.type === "script" || r.type === "stylesheet")).map((r) => `${r.type} ${r.path} ${r.status}`))].sort();
    assert.deepEqual(sameOrigin("chain"), sameOrigin("reference"));
    const blocked = (mode: string) => [...new Set(run.blocked.filter((b) => b.mode === mode).map((b) => new URL(b.url).host))].sort();
    assert.deepEqual(blocked("chain"), blocked("reference"));
    assert.deepEqual(run.pageErrors, []);
    for (const shot of ["home", "gizlilik"]) {
      const [chain, ref] = ["chain", "reference"].map((mode) => sha(readFileSync(path.join(outDir, `${mode}-${shot}.png`))));
      assert.equal(chain, ref, `the ${shot} rendering differs from the reference`);
    }

    const records = [...collector.allRecords()];
    const summary = {
      build: readFileSync(path.join(REPOSITORY_ROOT, ".next", "BUILD_ID"), "utf8").trim(),
      referenceNavigation: referenceJourney.pages.map(({ path: p, navigation }) => `${navigation} ${p}`),
      browser: browser.version(),
      documentLinks,
      scope: { pages: READ_ONLY_PAGE_TARGETS.length, assets: assets.length },
      journey: chainJourney.pages.map(({ path: p, navigation, status, h1, clickToUrlMs }) => ({ path: p, navigation, status, h1, clickToUrlMs })),
      referenceClicks: referenceJourney.pages.filter((page) => page.clickToUrlMs !== undefined).map(({ path, navigation, clickToUrlMs }) => ({ path, navigation, clickToUrlMs })),
      rsc: {
        browserResponses: run.responses.filter((row) => (row.mode === "reference" || row.mode === "chain") && isRscTarget(row.path))
          .map(({ mode, path, status, prefetch }) => ({ mode, path, status, prefetch })),
        chainJourney: journeyRsc.map(({ rid, target, status, outcome, bytes, latencyMs }) => ({ rid, target, status, outcome, bytes, latencyMs })),
        explicitProbes: exchanges.filter((row) => row.phase === "unsupported" && isRscTarget(row.target))
          .map(({ rid, target, status, outcome, bytes, latencyMs }) => ({ rid, target, status, outcome, bytes, latencyMs })),
      },
      menu: chainJourney.menu,
      history: { chain: chainJourney.history.map(({ path: p, h1 }) => ({ path: p, h1 })), reference: referenceJourney.history.map(({ path: p, h1 }) => ({ path: p, h1 })) },
      exchanges: exchanges.length,
      byScenario: Object.fromEntries(["page", "asset", "unsupported"].map((s) => [s, exchanges.filter((e) => e.scenario === s).length])),
      proxiedSupported, navigations, requests, direct: { browser: directViews, raw: directRaw }, outage: stopped,
      securityHeaders: { reference: referenceSecurity, chain: chainJourney.pages[0].security },
      blockedExternalHosts: blocked("chain"),
      console: Object.fromEntries(["reference", "chain"].map((mode) => [mode, run.consoleRows.filter((row) => row.mode === mode).map((row) => `${row.type}: ${row.text}`)])),
      requestFailed: run.failed.map(({ mode, url, failure }) => ({ mode, url: new URL(url).host + new URL(url).pathname, failure })),
      collector: { anomalies: verdict.anomalyTotal, records: records.length, events: { plane: planeFin.channel.emitted, boundary: boundaryFin.channel.emitted, app: appFin.channel.emitted } },
      app: appFin.stats.counters,
      boundary: { admitted: boundaryFin.stats.admitted, rejected: boundaryFin.stats.rejected, forwardFailed: boundaryFin.stats.forwardFailed, rejectedByReason: Object.fromEntries(Object.entries(boundaryFin.stats.rejectedByReason).filter(([, n]) => n > 0)) },
    };
    write("summary.json", summary);
    write("exchanges.jsonl", exchanges.map((row) => JSON.stringify(row)).join("\n") + "\n");
    write("ledger.jsonl", records.map((record) => JSON.stringify(record)).join("\n") + "\n");
    write("browser.json", { reference: referenceJourney, chain: chainJourney, responses: run.responses, console: run.consoleRows, blocked: run.blocked, failed: run.failed });
    console.log(JSON.stringify(summary, null, 2));
  } finally {
    // Whatever happened, keep what the adapter and the browser observed.
    if (relay) write("exchanges-observed.jsonl", relay.exchanges().map((row) => JSON.stringify(row)).join("\n") + "\n");
    write("browser-observed.json", { responses: run.responses, console: run.consoleRows, blocked: run.blocked, failed: run.failed, pageErrors: run.pageErrors, pending: [...run.pending.values()] });
    await relay?.close();
    await plane?.stop();
    await boundary?.stop();
    await app.stop();
    await browser.close();
  }
}

/** A bounded run: a stalled browser or component fails the verification instead of waiting forever. */
const RUN_BOUND_MS = 300_000;
const watchdog = setTimeout(() => { console.error(`browser delivery exceeded ${RUN_BOUND_MS} ms`); process.exit(2); }, RUN_BOUND_MS);
watchdog.unref();
void main().catch((error: unknown) => { console.error(error); process.exitCode = 1; });
