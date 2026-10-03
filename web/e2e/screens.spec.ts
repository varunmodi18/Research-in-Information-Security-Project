import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// Not an acceptance test: captures screenshots for visual review and docs/demo_assets.
test.skip(!process.env.E2E_SCREENSHOTS, "set E2E_SCREENSHOTS=1 to capture screenshots");

test("capture console screens", async ({ page }) => {
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("shot"), kind: "product", template: "small", params: "toy" });
  await page.getByTestId("btn-onboard").click();
  await expect(page.getByTestId("node-CM-0103")).toHaveAttribute("data-status", "active");
  await page.getByTestId("btn-readings").click();
  await page.getByTestId("node-CM-0101").click();
  await page.screenshot({ path: "e2e/shots/topology.png", fullPage: true });
  await page.getByRole("link", { name: "Timeline" }).click();
  await page.getByTestId("frame-HS2").first().click();
  await page.screenshot({ path: "e2e/shots/timeline.png", fullPage: false });
  await page.goBack();
  await page.getByTestId("node-CM-0101").click();
  await page.getByRole("link", { name: "Device details →" }).click();
  await page.screenshot({ path: "e2e/shots/device.png", fullPage: true });
});
