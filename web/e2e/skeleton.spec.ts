import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// V-E2E-01 (M3-T6): log in, create a lab network, onboard, see every node reach its final
// status and events appear.
test("V-E2E-01 skeleton journey", async ({ page }) => {
  await login(page, "operator");
  const name = uniqueName("lab-paper");
  await createNetwork(page, { name, kind: "lab", mode: "original", template: "paper" });
  await expect(page.getByTestId("mode-banner")).toContainText("Attack laboratory");
  await expect(page.getByTestId("param-set")).toContainText("toy");
  await page.getByTestId("btn-onboard").click();
  for (const node of ["BS-01", "CH-01", "CM-0101"]) {
    await expect(page.getByTestId(`node-${node}`)).toHaveAttribute("data-status", "active");
  }
  await expect(page.getByTestId("live-events")).toContainText("ORIG_AUTH_OK");
  await page.getByRole("link", { name: "Security events" }).click();
  await expect(page.getByTestId("events-table")).toContainText("ORIG_REGISTERED");
});
