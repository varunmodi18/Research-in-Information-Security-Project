import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// V-E2E-06 / J4: Lab comparison -- L3 in both modes, side-by-side verdicts with evidence.
test("V-E2E-06 J4 lab comparison", async ({ page }) => {
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("lab"), kind: "lab", mode: "original", template: "small" });
  await page.getByRole("link", { name: "Lab" }).click();
  await expect(page.getByTestId("mode-banner")).toContainText("Attack laboratory — not a product network");
  await page.getByTestId("run-both-L3").click();
  const original = page.getByTestId("result-L3-original");
  const enhanced = page.getByTestId("result-L3-enhanced");
  await expect(original).toContainText("ATTACK SUCCEEDED");
  await expect(enhanced).toContainText("ATTACK BLOCKED");
  await expect(enhanced).toContainText("BAD_TAG");
  await expect(original).toContainText("as predicted");
  await enhanced.getByRole("link", { name: /Evidence frames/ }).click();
  await expect(page.getByTestId("frames-table")).toContainText("HS2 (injected)");
  await expect(page.getByTestId("frames-table")).toContainText("BAD_TAG");
});
