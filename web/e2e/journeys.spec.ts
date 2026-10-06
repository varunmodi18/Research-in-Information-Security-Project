import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// V-DOC-02: every network page shows the parameter set and its security level.
async function expectParams(page: import("@playwright/test").Page, params: string) {
  await expect(page.getByTestId("param-set")).toContainText(params);
  await expect(page.getByTestId("param-set")).toContainText(/security|INSECURE/);
}

// V-E2E-02 / J1: onboard and transmit (net, enhanced, demo parameters).
test("V-E2E-02 J1 onboard and transmit", async ({ page }) => {
  await login(page, "operator");
  const name = uniqueName("vineyard");
  await createNetwork(page, { name, kind: "product", template: "net", params: "demo" });
  await expect(page.getByTestId("mode-banner")).toContainText("Product network");
  await expectParams(page, "demo");
  await page.getByTestId("btn-onboard").click();
  for (const node of ["BS-01", "CH-01", "CH-02", "CH-03", "CM-0101", "CM-0202", "CM-0303"]) {
    await expect(page.getByTestId(`node-${node}`)).toHaveAttribute("data-status", "active", { timeout: 120_000 });
  }
  await expect(page.getByTestId("job-status")).toBeEmpty({ timeout: 60_000 });
  await page.getByTestId("btn-readings").click();
  await page.getByRole("link", { name: "Readings" }).click();
  await expectParams(page, "demo");
  await expect(page.getByTestId("readings-table").locator("tbody tr")).toHaveCount(9, { timeout: 60_000 });
  const url = new URL(page.url());
  const nid = url.pathname.split("/")[2];
  await page.goto(`/events?network=${nid}&type=HANDSHAKE_OK`);
  await page.getByLabel("Type").fill("HANDSHAKE_OK");
  await expect(page.getByTestId("events-table").locator("tbody tr")).toHaveCount(21);
  await page.getByLabel("Type").fill("DATA_ACCEPTED");
  await expect(page.getByTestId("events-table").locator("tbody tr")).toHaveCount(9);
});

// V-E2E-03 / J2: inspect a handshake in step mode.
test("V-E2E-03 J2 step through a handshake", async ({ page }) => {
  await login(page, "operator");
  const name = uniqueName("stepper");
  await createNetwork(page, { name, kind: "product", template: "paper", params: "toy" });
  await page.getByRole("link", { name: "Timeline" }).click();
  await expectParams(page, "toy");
  await page.getByRole("button", { name: "Start onboarding (step mode)" }).click();
  for (let i = 0; i < 2; i++) {
    await page.getByTestId("btn-step").click();
    await expect(page.getByTestId("btn-step")).toBeEnabled();
  }
  await expect(page.getByTestId("frame-HS2")).toBeVisible();
  await page.getByTestId("frame-HS2").first().click();
  const checks = page.getByTestId("frame-checks");
  await expect(checks).toContainText("sid matches a pending HS1");
  await expect(checks).toContainText("tag_R valid");
  await expect(page.getByTestId("frame-detail")).toContainText("Key values are never displayed");
  await page.getByRole("button", { name: "Run to end" }).click();
  await page.getByRole("link", { name: "← Topology" }).click();
  await expect(page.getByTestId("node-CM-0101")).toHaveAttribute("data-status", "active");
  await page.getByTestId("node-CM-0101").click();
  await page.getByRole("link", { name: "Device details →" }).click();
  await expectParams(page, "toy");
  await expect(page.getByTestId("sessions-table")).toContainText("CM-CH");
  await expect(page.getByTestId("sessions-table")).toContainText("ESTABLISHED");
});

// J2 with the live stream down: completed step jobs must still refresh the timeline (CI race found
// 2026-10-06: the SSE connection opened after the steps had run, so the frames were never refetched).
test("J2 with the live stream down: steps still refresh the timeline (disconnected state)", async ({ page }) => {
  await page.route("**/api/networks/*/stream*", (route) => route.abort());
  await login(page, "operator");
  const name = uniqueName("nostream");
  await createNetwork(page, { name, kind: "product", template: "paper", params: "toy" });
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Reconnecting" })).toBeVisible();
  await page.getByRole("button", { name: "Start onboarding (step mode)" }).click();
  await page.getByTestId("btn-step").click();
  await expect(page.getByTestId("frame-HS1")).toBeVisible();
  await page.getByTestId("btn-step").click();
  await expect(page.getByTestId("frame-HS2")).toBeVisible();
});

// V-E2E-04 / J3: revoke a device.
test("V-E2E-04 J3 revoke", async ({ page }) => {
  await login(page, "operator");
  const name = uniqueName("revoke");
  await createNetwork(page, { name, kind: "product", template: "small", params: "toy" });
  await page.getByTestId("btn-onboard").click();
  await expect(page.getByTestId("node-CM-0102")).toHaveAttribute("data-status", "active");
  const nid = new URL(page.url()).pathname.split("/")[2];
  await page.goto(`/networks/${nid}/devices/CM-0102`);
  await page.getByTestId("btn-revoke").click();
  await expect(page.getByRole("button", { name: "Revoke device" })).toBeDisabled();
  await page.getByLabel(/Type CM-0102 to confirm/).fill("CM-0102");
  await page.getByRole("button", { name: "Revoke device" }).click();
  await expect(page.getByText("⊘revoked").first()).toBeVisible({ timeout: 30_000 });
  await page.goto(`/networks/${nid}`);
  await expect(page.getByTestId("node-CM-0102")).toHaveAttribute("data-status", "revoked");
  await page.getByTestId("btn-readings").click();
  await page.goto(`/events?network=${nid}`);
  await page.getByLabel("Type").fill("UNAUTHENTICATED_PEER");
  await expect(page.getByTestId("events-table")).toContainText("CM-0102", { timeout: 30_000 });
  await page.getByLabel("Type").fill("DEVICE_REVOKED");
  await expect(page.getByTestId("events-table")).toContainText("CM-0102");
});

// Viewers see a restricted state on the readings page (M5-T4, V-WEB-08 in the UI).
test("viewer cannot open readings", async ({ page }) => {
  await login(page, "viewer");
  await page.goto("/networks/1/readings");
  await expect(page.getByText("Restricted")).toBeVisible();
});
