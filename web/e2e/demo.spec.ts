import { expect, test, type Page } from "@playwright/test";
import { login } from "./helpers";

// M8-T2 / §7.1: the demo script, start to finish from Admin → Reset demo. Run with
// `npx playwright test e2e/demo.spec.ts --repeat-each 2` for the "twice in a row" check (§7.3 item 4).
// Each step saves its fallback screenshot to docs/demo_assets/ (overwritten on every run).
const ASSETS = "../docs/demo_assets";
const shot = (page: Page, name: string) => page.screenshot({ path: `${ASSETS}/${name}.png` });

test("demo script (§7.1)", async ({ page }) => {
  test.setTimeout(600_000);
  // Preparation: Admin → Reset demo
  await login(page, "admin");
  await page.getByRole("link", { name: "Admin" }).click();
  await page.getByRole("button", { name: "Reset demo…" }).click();
  await page.getByLabel(/Type RESET to confirm/).fill("RESET");
  await page.getByRole("button", { name: "Reset demo", exact: true }).click();
  // the reset is a job: reload the dashboard until both demo networks exist again
  await expect(async () => {
    await page.goto("/");
    await expect(page.getByRole("link", { name: "Vineyard" })).toBeVisible({ timeout: 2_000 });
    await expect(page.getByRole("link", { name: "Lab-Paper" })).toBeVisible({ timeout: 2_000 });
  }).toPass({ timeout: 120_000 });
  await page.getByRole("button", { name: "Sign out" }).click();

  // 1. Product overview
  await login(page, "operator");
  await expect(page.getByRole("link", { name: "Vineyard" })).toBeVisible();
  await shot(page, "01_dashboard");
  await page.getByRole("link", { name: "Vineyard" }).click();
  await expect(page.getByTestId("mode-banner")).toContainText("Product network");
  await expect(page.getByTestId("param-set")).toContainText("demo");
  const nid = new URL(page.url()).pathname.split("/")[2];

  // 2. Onboard
  await page.getByTestId("btn-onboard").click();
  for (const node of ["CH-01", "CH-02", "CH-03", "CM-0101", "CM-0202", "CM-0303"]) {
    await expect(page.getByTestId(`node-${node}`)).toHaveAttribute("data-status", "active", { timeout: 180_000 });
  }
  await expect(page.getByTestId("job-status")).toBeEmpty({ timeout: 60_000 });
  await shot(page, "02_onboarded");
  await page.goto(`/events?network=${nid}`);
  await page.getByLabel("Type").fill("HANDSHAKE_OK");
  await expect(page.getByTestId("events-table").locator("tbody tr")).toHaveCount(21);
  await shot(page, "02_handshake_events");

  // 3. Inspect a handshake: device sessions, then the timeline's frame checks
  await page.goto(`/networks/${nid}/devices/CM-0101`);
  await expect(page.getByTestId("sessions-table")).toContainText("ESTABLISHED");
  await shot(page, "03_device_sessions");
  await page.goto(`/networks/${nid}/timeline`);
  await page.getByTestId("frame-HS2").first().click();
  await expect(page.getByTestId("frame-checks")).toContainText("tag_R valid");
  await expect(page.getByTestId("frame-detail")).toContainText("Key values are never displayed");
  await shot(page, "03_timeline_checks");

  // 4. Secure transmission: periodic readings, decrypted at the BS; ciphertext on the frames page
  await page.goto(`/networks/${nid}/readings`);
  await page.getByTestId("btn-periodic").click();
  await expect(page.getByTestId("readings-table").locator("tbody tr").first()).toBeVisible({ timeout: 120_000 });
  await shot(page, "04_readings");
  await page.getByRole("button", { name: "■ Stop periodic" }).click();
  await page.goto(`/networks/${nid}/frames`);
  await expect(page.getByTestId("frames-table")).toContainText("DATA_CM");
  await shot(page, "04_frames");

  // 5. Lifecycle: revoke CM-0102, then rekey CH-01's cluster
  await page.goto(`/networks/${nid}/devices/CM-0102`);
  await page.getByTestId("btn-revoke").click();
  await page.getByLabel(/Type CM-0102 to confirm/).fill("CM-0102");
  await page.getByRole("button", { name: "Revoke device" }).click();
  await expect(page.getByText("⊘revoked").first()).toBeVisible({ timeout: 120_000 });
  await shot(page, "05_revoked");
  await page.goto(`/networks/${nid}/devices/CH-01`);
  const rekey = page.getByRole("button", { name: /Rekey cluster/ });
  await rekey.click();
  await expect(page.getByText("Rekeying the whole cluster…")).toBeVisible();
  await expect(rekey).toBeEnabled({ timeout: 120_000 }); // disabled while the job runs
  await page.goto(`/events?network=${nid}`);
  await page.getByLabel("Type").fill("KEY_ROTATED");
  await expect(page.getByTestId("events-table").locator("tbody tr").first()).toBeVisible({ timeout: 120_000 });
  await page.getByLabel("Type").fill("DEVICE_REVOKED");
  await expect(page.getByTestId("events-table")).toContainText("CM-0102");
  await page.goto(`/networks/${nid}`);
  await page.getByTestId("btn-readings").click();
  await expect(page.getByTestId("job-status")).toBeEmpty({ timeout: 120_000 });
  await page.goto(`/events?network=${nid}`);
  await page.getByLabel("Type").fill("UNAUTHENTICATED_PEER");
  await expect(page.getByTestId("events-table")).toContainText("CM-0102", { timeout: 60_000 });
  await shot(page, "05_lifecycle_events");

  // 6. Lab: L3 insider impersonation, both modes
  await page.getByRole("link", { name: "Lab" }).click();
  await page.getByTestId("run-both-L3").click();
  await expect(page.getByTestId("result-L3-original")).toContainText("ATTACK SUCCEEDED", { timeout: 120_000 });
  await expect(page.getByTestId("result-L3-enhanced")).toContainText("ATTACK BLOCKED");
  await page.getByTestId("scenario-L3").scrollIntoViewIfNeeded();
  await shot(page, "06_lab_L3");

  // 7. Failure and recovery: L2 tamper
  await page.getByTestId("run-both-L2").click();
  await expect(page.getByTestId("result-L2-enhanced")).toContainText("ATTACK BLOCKED", { timeout: 120_000 });
  await expect(page.getByTestId("result-L2-enhanced")).toContainText("BAD_TAG");
  await page.getByTestId("scenario-L2").scrollIntoViewIfNeeded();
  await shot(page, "07_lab_L2");

  // 8. Evaluation
  await page.getByRole("link", { name: "Evaluation" }).click();
  await expect(page.getByTestId("limitations")).toBeVisible();
  await expect(page.getByTestId("table5")).toContainText("ER-02");
  await shot(page, "08_evaluation");
});
