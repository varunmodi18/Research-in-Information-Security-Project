import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// Not an acceptance test: captures screenshots for visual review and docs/demo_assets.
test.skip(!process.env.E2E_SCREENSHOTS, "set E2E_SCREENSHOTS=1 to capture screenshots");

test("capture topology after onboarding", async ({ page }) => {
  await login(page, "operator");
  const name = uniqueName("shot");
  await createNetwork(page, { name, kind: "lab", mode: "original", template: "net" });
  await page.getByTestId("btn-onboard").click();
  await expect(page.getByTestId("node-CM-0303")).toHaveAttribute("data-status", "active");
  await page.getByTestId("node-CM-0101").click();
  await page.screenshot({ path: "e2e/shots/topology.png", fullPage: true });
  await page.goto("/");
  await page.screenshot({ path: "e2e/shots/dashboard.png", fullPage: true });
});
