import { writeFile } from "node:fs/promises";
import { expect, type BrowserContext, type Page, type Request, type TestInfo } from "@playwright/test";

export type Profile = "observe" | "tracking-only" | "third-party-and-tracking" | "font-files";

// Test-only simulation, not an extension detector or an exhaustive filter list.
// Use path boundaries: ordinary names containing "ad" must not become trackers.
const trackingPath = /(?:^|[\/._-])(?:analytics|telemetry|tracking|tracker|beacon|collect|ads?|adserver|pixel)(?:[\/._-]|$)/i;
const trackingHost = /(?:^|\.)(?:google-analytics\.com|googletagmanager\.com|doubleclick\.net|googlesyndication\.com|segment\.(?:io|com)|mixpanel\.com|amplitude\.com|hotjar\.com|clarity\.ms|sentry\.io)$/i;

export function blockReason(profile: Profile, address: string, resourceType: string, origin: string): string | null {
  if (profile === "observe") return null;
  const url = new URL(address);
  if (trackingHost.test(url.hostname) || trackingPath.test(url.pathname) || resourceType === "ping") return "tracker-like";
  if (profile === "third-party-and-tracking" && url.origin !== origin) return "third-party";
  if (profile === "font-files" && resourceType === "font") return "font-file";
  return null;
}

type Phase = "application" | "axe";
type RequestRecord = { url: string; method: string; type: string; reason: string | null; prefetch: boolean; phase: Phase };
type FailureRecord = RequestRecord & { error: string };
type ConsoleRecord = { type: string; text: string; url: string; phase: Phase };

export function isOptionalPrefetchCancellation(request: { method: string; type: string; prefetch: boolean; error: string }) {
  // Verified against control-run traces. A name containing `_rsc` alone is not
  // evidence: require the explicit Next prefetch header, GET/fetch and abort code.
  return request.prefetch && request.method === "GET" && request.type === "fetch"
    && /^(?:net::ERR_ABORTED|NS_BINDING_ABORTED|cancelled|Canceled)$/.test(request.error);
}

export async function installAudit(context: BrowserContext, page: Page, baseURL: string, profile: Profile, info: TestInfo, options: { failFirstSubmission?: boolean; javaScriptDisabled?: boolean; delayedHydration?: boolean } = {}) {
  const origin = new URL(baseURL).origin;
  const requests: RequestRecord[] = [];
  const blocked: RequestRecord[] = [];
  const failures: FailureRecord[] = [];
  const badResponses: { url: string; status: number }[] = [];
  const messages: ConsoleRecord[] = [];
  const pageErrors: string[] = [];
  const navigationFailures: string[] = [];
  const navigations: string[] = [];
  const observations: Record<string, unknown> = {};
  let phase: Phase = "application";
  let injectedFailures = 0;
  const records = new WeakMap<Request, RequestRecord>();

  page.on("console", (message) => messages.push({ type: message.type(), text: message.text(), url: message.location().url, phase }));
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("framenavigated", (frame) => { if (frame === page.mainFrame()) navigations.push(frame.url()); });
  context.on("requestfailed", (request) => {
    const record = { ...(records.get(request) ?? { url: request.url(), method: request.method(), type: request.resourceType(), reason: null, prefetch: request.headers()["next-router-prefetch"] === "1", phase }), error: request.failure()?.errorText ?? "unknown" };
    failures.push(record);
    if (request.isNavigationRequest()) navigationFailures.push(`${record.url}: ${record.error}`);
  });
  context.on("response", (response) => {
    if (response.status() >= 400) badResponses.push({ url: response.url(), status: response.status() });
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    const record = { url: request.url(), method: request.method(), type: request.resourceType(), reason: blockReason(profile, request.url(), request.resourceType(), origin), prefetch: request.headers()["next-router-prefetch"] === "1", phase };
    // Separate, deliberate transport fault to verify retry while privacy blocking
    // remains enabled. This is not a tracker rule or an optional-request failure.
    if (options.failFirstSubmission && injectedFailures === 0 && request.method() === "POST" && request.url() === `${origin}/test-talep-et`) {
      record.reason = "injected-submit-failure";
      injectedFailures++;
    }
    records.set(request, record);
    requests.push(record);
    if (record.reason) {
      blocked.push(record);
      await route.abort(record.reason === "injected-submit-failure" ? "failed" : "blockedbyclient");
    } else await route.continue();
  });

  function consoleClassification(message: ConsoleRecord) {
    // Keep every diagnostic in the artifact. Only a browser network diagnostic
    // correlated with an actually aborted resource is expected; never ignore JS errors.
    const networkDiagnostic = /Failed to load resource|ERR_BLOCKED_BY_CLIENT|access control checks|Cross-Origin Request Blocked:|downloadable font: download failed/i.test(message.text);
    const correlated = blocked.some((request) => message.url === request.url || message.text.includes(request.url));
    if (networkDiagnostic && correlated) return "expected-blocked-resource";
    if (networkDiagnostic && failures.some((request) => isOptionalPrefetchCancellation(request) && (message.url === request.url || message.text.includes(request.url)))) return "optional-prefetch-cancellation";
    // axe-core/axe.js emits this exact warning from its CSSOM preloader catch.
    // Require the analyzer phase AND an actually blocked font stylesheet request
    // made during that phase. The same warning from application code still fails.
    if (message.phase === "axe" && message.type === "warning" && message.text.startsWith("Couldn't load preload assets:")
      && blocked.some((request) => request.phase === "axe" && new URL(request.url).hostname === "fonts.googleapis.com")) return "axe-blocked-css-preload";
    // Reproduced in unblocked no-JS and held-script controls. Firefox attributes
    // the early layout query to Playwright, before application scripts can run.
    if ((options.javaScriptDisabled || options.delayedHydration) && info.project.name === "firefox" && message.url === "debugger eval code"
      && message.type === "warning" && message.text.startsWith('[JavaScript Warning: "Layout was forced before the page was fully loaded.')) return "playwright-layout-probe";
    return "unexpected";
  }

  function isDisabledScript(request: FailureRecord) {
    // Chromium rejects script preloads when JS is explicitly disabled, including
    // in the unblocked control. Never exempt a CSS/document/POST or a JS-on failure.
    return options.javaScriptDisabled && info.project.name === "chromium" && request.method === "GET"
      && request.type === "script" && request.error === "csp";
  }

  async function save() {
    const report = {
      profile, options, browser: info.project.name, viewport: page.viewportSize(),
      requests, blocked, failures, badResponses, pageErrors, navigations, navigationFailures,
      optionalPrefetchCancellations: failures.filter(isOptionalPrefetchCancellation),
      disabledScriptPreloads: failures.filter(isDisabledScript),
      console: messages.map((message) => ({ ...message, classification: consoleClassification(message) })),
      observations,
    };
    const path = info.outputPath("request-audit.json");
    await writeFile(path, JSON.stringify(report, null, 2));
    await info.attach("request-audit", { path, contentType: "application/json" });
  }

  function assertHealthy() {
    expect(pageErrors, "Uncaught browser errors").toEqual([]);
    expect(navigationFailures, "Failed document navigations").toEqual([]);
    expect(failures.filter((request) => new URL(request.url).origin === origin && request.reason !== "injected-submit-failure" && !isOptionalPrefetchCancellation(request) && !isDisabledScript(request)), "Failed first-party critical requests").toEqual([]);
    expect(failures.filter((request) => request.reason === "injected-submit-failure"), "Explicitly injected transport failures").toHaveLength(options.failFirstSubmission ? 1 : 0);
    expect(badResponses, "Unexpected HTTP failures").toEqual([]);
    expect(messages.filter((message) => ["error", "warning"].includes(message.type) && consoleClassification(message) === "unexpected"), "Unexpected console diagnostics (full log retained)").toEqual([]);
    if (!options.javaScriptDisabled) expect(requests.some((request) => new URL(request.url).origin === origin && request.type === "script")).toBe(true);
    expect(requests.some((request) => new URL(request.url).origin === origin && request.type === "stylesheet")).toBe(true);
  }

  async function runAxe<T>(analyze: () => Promise<T>): Promise<T> {
    phase = "axe";
    try { return await analyze(); } finally { phase = "application"; }
  }

  return { requests, blocked, failures, observations, assertHealthy, save, runAxe };
}

export async function assertFallback(page: Page) {
  await page.evaluate(() => document.fonts.ready);
  const metrics = await page.evaluate(() => {
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d")!;
    const sample = "Dayanıklılığı ölçün. Çağrı Öztürk — Wİışğçöü 0123456789";
    context.font = "16px Inter, Arial, sans-serif";
    const configuredWidth = context.measureText(sample).width;
    context.font = "16px Arial, sans-serif";
    return {
      family: getComputedStyle(document.body).fontFamily,
      interLoaded: [...document.fonts].some((font) => font.family.replaceAll('"', "") === "Inter" && font.status === "loaded"),
      configuredWidth, fallbackWidth: context.measureText(sample).width,
    };
  });
  expect(metrics.family).toContain("Arial");
  expect(metrics.interLoaded).toBe(false);
  expect(metrics.configuredWidth).toBeCloseTo(metrics.fallbackWidth, 5);
  return metrics;
}
