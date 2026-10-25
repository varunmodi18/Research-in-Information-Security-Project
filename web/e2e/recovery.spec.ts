import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// docs/RECOVERY.md: operator-approved cluster-head replacement with a ranked recommendation. The
// dialog lists ranked candidates with their score components, needs a typed confirmation, and the
// cluster then shows the promoted member as its CH with every member active. Viewers see but cannot act.
test("recovery dialog: promote the recommended member, viewer read-only", async ({ page, browser }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const name = uniqueName("recover");
  await createNetwork(page, { name, kind: "product", template: "small", params: "toy" });
  await page.getByTestId("btn-onboard").click();
  for (const node of ["CH-01", "CM-0101", "CM-0102", "CM-0103"]) {
    await expect(page.getByTestId(`node-${node}`)).toHaveAttribute("data-status", "active");
  }
  await page.getByTestId("node-CH-01").click();
  const panel = page.getByTestId("recovery-panel");
  await expect(panel).toContainText("Cluster-head replacement");
  await expect(panel).toContainText("no alert");
  await page.getByTestId("btn-recover").click();
  const dialog = page.getByTestId("recovery-dialog");
  await expect(dialog.locator("tbody tr")).toHaveCount(3);
  await expect(dialog.getByTestId("recommended")).toHaveCount(1);
  const recommended = (await dialog.locator("tbody tr").first().locator("td").nth(1).innerText()).replace("recommended", "").trim();
  await expect(dialog.locator("tbody tr").first().getByRole("radio")).toBeChecked();
  const confirm = page.getByRole("button", { name: "Promote and replace" });
  await expect(confirm).toBeDisabled();  // typed confirmation required
  await page.locator("#confirm-input").fill("CH-01");
  await confirm.click();
  await expect(page.getByTestId("toast").filter({ hasText: `${recommended} is the cluster head of CH-01` })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId(`node-${recommended}`)).toHaveAttribute("data-status", "active");
  await expect(page.getByTestId(`node-${recommended}`)).toContainText("CH");
  await expect(page.getByTestId("node-CH-01")).toHaveAttribute("data-status", "revoked");
  for (const cm of ["CM-0101", "CM-0102", "CM-0103"].filter((c) => c !== recommended)) {
    await expect(page.getByTestId(`node-${cm}`)).toHaveAttribute("data-status", "active");
    await expect(page.getByTestId(`node-${cm}`)).toHaveAttribute("data-designation", "ok");
  }
  if (process.env.E2E_SCREENSHOTS) {
    await expect(page.getByTestId("toast")).toHaveCount(0, { timeout: 15_000 });
    await page.screenshot({ path: "e2e/shots/recovery_after.png", fullPage: true });
  }
  const url = page.url();

  // a viewer sees the recovery panel but cannot act
  const viewer = await browser.newPage();
  await login(viewer, "viewer");
  await viewer.goto(url);
  await viewer.getByTestId(`node-${recommended}`).click();
  await expect(viewer.getByTestId("recovery-panel")).toBeVisible();
  await expect(viewer.getByTestId("btn-recover")).toBeDisabled();
  await viewer.close();
});
