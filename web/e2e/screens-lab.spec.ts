import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

test.skip(!process.env.E2E_SCREENSHOTS, "set E2E_SCREENSHOTS=1 to capture screenshots");

test("capture lab", async ({ page }) => {
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("lab"), kind: "lab", mode: "original", template: "small" });
  await page.getByRole("link", { name: "Lab" }).click();
  for (const s of ["L3", "L5"]) {
    await page.getByTestId(`run-both-${s}`).click();
    await expect(page.getByTestId(`result-${s}-enhanced`)).toContainText("ATTACK");
  }
  await page.getByTestId("scenario-L3").scrollIntoViewIfNeeded();
  await page.screenshot({ path: "e2e/shots/lab.png", fullPage: false });
});
