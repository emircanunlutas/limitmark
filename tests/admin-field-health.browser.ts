// Run with tsx. Set FIELD_REVIEW_BROWSER to use an installed Chromium executable.
import assert from "node:assert/strict";
import path from "node:path";
import { build } from "esbuild";
import { chromium, expect } from "@playwright/test";
import { changed, now, originals } from "./support/field-health-fixture";

async function verify() {
  const bundle = await build({
    stdin: {
      contents: `import { createRoot } from "react-dom/client";
        import { AdminFieldHealth } from "./src/components/admin-field-health";
        createRoot(document.getElementById("fixture")).render(<AdminFieldHealth />);`,
      resolveDir: path.resolve(__dirname, ".."), loader: "tsx",
    },
    bundle: true, write: false, jsx: "automatic", define: { "process.env.NODE_ENV": '"production"' },
  });
  const browser = await chromium.launch({ executablePath: process.env.FIELD_REVIEW_BROWSER });
  try {
    const page = await browser.newPage({ serviceWorkers: "block" });
    await page.clock.setFixedTime(now + 2 * 86400000);
    // Fulfill the local UI in memory on a secure origin so Web Crypto works without a server.
    const origin = "https://field-review.invalid/";
    const unexpectedRequests: string[] = [];
    await page.route("**/*", route => {
      if (route.request().url() === origin && route.request().isNavigationRequest())
        return route.fulfill({ contentType: "text/html", body: '<main id="fixture"></main>' });
      unexpectedRequests.push(route.request().url());
      return route.abort();
    });
    await page.goto(origin);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const input = page.getByLabel("Field-run evidence files");
    const select = async (files: File[]) => input.setInputFiles(await Promise.all(files.map(async file => ({
      name: file.name, mimeType: "application/octet-stream", buffer: Buffer.from(await file.arrayBuffer()),
    }))));

    const incident = await changed(({ manifest, canary }) => {
      manifest.result = "INVALID"; manifest.metrics.serverSide = "invalid";
      manifest.resultReasons = ["field.l1_false_reject.private-detail", "field.secret-reason"];
      canary.l1FalseRejects = 2; canary.l2NonAdmits = 1;
    });
    await select(incident);
    const findings = page.getByRole("region", { name: "Incident diagnostics" });
    await expect(findings.getByText("Protected request admission", { exact: true })).toBeVisible();
    for (const label of ["Observed facts", "Supported conclusion", "Unresolved", "Administrator follow-up"])
      await expect(findings.getByRole("article").filter({ hasText: "Protected request admission" }).getByText(label, { exact: true })).toBeVisible();
    await expect(findings).toContainText("both stages during this run");
    await expect(page.locator("main")).toContainText("Unrecognized reason entries · 1");
    await expect(page.locator("main")).toContainText("Stale");
    await expect(page.locator("main")).toContainText("Evidence provenance requires a trusted source");
    await expect(page.locator("main")).not.toContainText(/private-detail|secret-reason/);

    await select(await changed(({ manifest }) => { manifest.metrics.externalAccepted++; }));
    await expect(findings).toContainText("Conflicting run records");
    await expect(findings).toContainText("cannot establish which observation is correct");
    await expect(findings).not.toContainText("Protected request admission");

    await select(originals.slice(0, 2));
    await expect(findings).toContainText("Evidence needed for component review");
    await expect(findings).not.toContainText("Protected request admission");
    await select(originals);
    await expect(findings).toContainText("No incident finding");
    await input.setInputFiles([]);
    await expect(findings).toHaveCount(0);
    assert.deepEqual(unexpectedRequests, []);
  } finally {
    await browser.close();
  }
}

verify().catch(error => { console.error(error); process.exitCode = 1; });
