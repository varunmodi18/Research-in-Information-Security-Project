import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// docs/BEHAVIOUR.md: the Evaluation page's "Behavioural monitoring (experimental)" section shows the
// committed results artefact, collapsed by default, with its framing, results table and limitations.
test("behavioural monitoring section (experimental)", async ({ page }) => {
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("bm"), kind: "lab", template: "paper" });
  await page.getByRole("link", { name: "Evaluation" }).click();
  const section = page.getByTestId("ev-behaviour");
  await expect(section).toContainText("Behavioural monitoring (experimental)");
  await expect(section).toContainText("experimental · alerts only");
  await expect(page.getByTestId("behaviour-results")).toBeHidden();
  await section.locator("summary").click();
  await expect(page.getByTestId("behaviour-framing")).toContainText("only raises alerts");
  await expect(page.getByTestId("behaviour-framing")).toContainText("do not transfer to real deployments");
  const table = page.getByTestId("behaviour-results");
  await expect(table).toContainText("Excessive rekeying (one CM, interval far below normal)");
  await expect(table).toContainText("near-normal variant");
  await expect(table).toContainText("Lossy forwarding");
  await expect(table).toContainText("z-score baseline");
  await expect(table).toContainText("Isolation Forest");
  await expect(table.locator("tbody tr")).toHaveCount(6);
  await expect(page.getByTestId("behaviour-benign-fa")).toContainText("per 1,000 device-windows");
  await expect(page.getByTestId("behaviour-limitations")).toContainText("Simulated data only");
  await expect(page.getByTestId("behaviour-limitations")).toContainText("Alerts only");
  if (process.env.E2E_SCREENSHOTS) {
    await expect(page.getByTestId("toast")).toHaveCount(0, { timeout: 15_000 });
    await section.screenshot({ path: "e2e/shots/behaviour_section.png" });
    await page.screenshot({ path: "e2e/shots/behaviour_page.png", fullPage: true });
  }
});
