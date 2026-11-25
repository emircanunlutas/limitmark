import { expect, type Locator, type Page } from "@playwright/test";
import { comparisonFiles, now, type EditableFixture } from "./field-health-fixture";

export async function verifyObservationHistory(page: Page, select: (files: File[], input: Locator) => Promise<void>) {
  const history = page.getByRole("region", { name: "Defensive observation history" });
  const add = history.getByLabel("Add observation files");
  const records = history.getByRole("article");
  const baseline = page.getByLabel("Baseline observation from history");
  const comparison = page.getByLabel("Comparison observation from history");
  const pair = page.getByRole("region", { name: "Defensive run comparison" });
  const diagnostics = page.getByRole("region", { name: "Incident diagnostics" });
  const clear = history.getByRole("button", { name: "Clear history" });
  const titles = records.getByRole("heading");
  const fault = ({ manifest, canary }: EditableFixture) => {
    manifest.result = "INVALID";
    manifest.metrics.serverSide = "invalid";
    canary.l1FalseRejects = 1;
  };
  const early = await comparisonFiles("baseline", fault);
  const late = await comparisonFiles("comparison", fault);
  const middle = await comparisonFiles("baseline", ({ manifest }) => {
    manifest.runId = "20260102T115959Z-offline-cccccc";
    manifest.startedAt = new Date(now + 86400000 - 1000).toISOString();
    manifest.endedAt = new Date(now + 86400000).toISOString();
    manifest.target!.id = "different-private-fixture";
  });

  await select(late, add);
  await select(early, add);
  await select(middle.slice(0, 2), add);
  await expect(titles).toHaveText(["Observation 2 · INVALID", "Observation 3 · SERVER-COMPLETE", "Observation 1 · INVALID"]);
  await expect(history).toContainText("Protected request admission · Observations 2, 1");
  await expect(records.nth(1)).toContainText("Different recorded context · Target");
  await expect(records.nth(1)).toContainText("Comparison accounting · insufficient");
  await records.nth(1).getByText(/Evidence coverage ·/).click();
  await expect(records.nth(1)).toContainText("Checksum matched · JSON readable → Unavailable");
  await expect(records.nth(1)).toContainText("L1 request screening · Unavailable");
  await history.getByRole("link", { name: "Review pair 2 and 3" }).click();
  await expect(pair).toContainText("Runs cannot be meaningfully compared");
  await comparison.selectOption("1");
  await expect(pair).toContainText("Persistent");
  await history.getByRole("link", { name: "Review observation 2 alone" }).click();
  await expect(diagnostics).toContainText("Protected request admission");
  await expect(pair).toHaveCount(0);
  await comparison.selectOption("1");

  await select(await comparisonFiles("baseline"), add);
  await expect(records).toHaveCount(4);
  await expect(pair).toContainText("Conflicting manifests claim this run identity");
  await expect(pair).not.toContainText("Same observed condition");
  await expect(history).toContainText("No category recurs");
  await history.getByText("Manage observation 4", { exact: true }).click();
  await history.getByRole("button", { name: "Remove observation 4" }).click();
  await expect(pair).toContainText("Same observed condition");
  await expect(history).toContainText("Protected request admission · Observations 2, 1");

  await history.getByText("Manage observation 3", { exact: true }).click();
  await select([early[0], middle[1]], history.getByLabel("Replace observation 3"));
  await expect(history).toContainText("manifest checksum disagrees");
  await expect(records).toHaveCount(2);
  await expect(pair).toContainText("Same observed condition");
  await select(middle, history.getByLabel("Replace observation 3"));
  await expect(titles.nth(1)).toHaveText("Observation 3 · SERVER-COMPLETE");
  await expect(records.nth(1)).toContainText("Accounting · Reviewed");
  await expect(history).not.toContainText(/private-fixture|offline-aaaaaa/);

  await history.getByText("Manage observation 1", { exact: true }).click();
  await history.getByRole("button", { name: "Remove observation 1" }).click();
  await expect(baseline).toHaveValue("2");
  await expect(comparison).toHaveValue("");
  await expect(diagnostics).toContainText("Protected request admission");
  await clear.click();
  await expect(records).toHaveCount(0);
  await expect(diagnostics).toHaveCount(0);

  // An outstanding read keeps its reservation even after removal or clearing.
  const budget = 4 * 1024 * 1024;
  const padding = budget - early.reduce((sum, file) => sum + file.size, 0);
  const padded = [...early, new File([new Uint8Array(padding)], "ignored.bin")];
  for (const action of ["remove", "clear"]) {
    await page.evaluate(() => {
      const original = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = async function () {
        if (this.name !== "manifest.json") return original.call(this);
        File.prototype.arrayBuffer = original;
        await new Promise<void>(resolve => document.addEventListener("finish-obsolete", () => resolve(), { once: true }));
        throw new Error("Obsolete fixture read");
      };
    });
    await select(padded, add);
    await expect(history).toContainText("Reading field evidence");
    if (action === "clear") await clear.click();
    else await history.getByRole("button", { name: /Remove observation/ }).click();
    await select(late, add);
    await expect(history).toContainText("exceeds the 4 MiB history budget");
    await expect(history).toContainText("4096 KiB of 4 MiB reserved");
    await page.evaluate(() => document.dispatchEvent(new Event("finish-obsolete")));
    await expect(history).toContainText("0 reads in progress");
    await expect(history).toContainText("0 of 8 observations");
    await select(late, add);
    await expect(records).toHaveCount(1);
    await clear.click();
  }

  await select(Array.from({ length: 65 }, (_, i) => new File(["x"], `file-${i}.txt`)), add);
  await expect(history).toContainText("Too many files");
  await expect(history).toContainText("0 of 8 observations");
  for (let i = 0; i < 8; i++) await select(early, add);
  await expect(records).toHaveCount(8);
  await expect(history).toContainText("Duplicate manifest in history");
  await expect(history).toContainText("No category recurs");
  await select(late, add);
  await expect(history).toContainText("History is full");
  await expect(history).toContainText("8 of 8 observations");
  await clear.click();
  await expect(history).toContainText("0 of 8 observations");
}
