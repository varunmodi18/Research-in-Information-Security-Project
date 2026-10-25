import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// Not an acceptance test: screenshots of the "CH suspected" badge and the recovery dialog. A lab
// network's CH is given the lab-only lossy-forwarding fault through the API (no UI for it).
test.skip(!process.env.E2E_SCREENSHOTS, "set E2E_SCREENSHOTS=1 to capture screenshots");

test("capture recovery screens", async ({ page }) => {
  test.setTimeout(300_000);
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("recovery-shot"), kind: "lab", template: "small", params: "toy" });
  await page.getByTestId("btn-onboard").click();
  await expect(page.getByTestId("node-CM-0103")).toHaveAttribute("data-status", "active");
  await expect(page.getByTestId("job-status")).toBeEmpty({ timeout: 60_000 });
  const nid = new URL(page.url()).pathname.split("/")[2];
  const csrf = (await (await page.request.get("/api/auth/me")).json()).csrf_token as string;
  const job = async (type: string, args: Record<string, unknown>) => {
    const r = await page.request.post(`/api/networks/${nid}/jobs`, {
      headers: { "X-CSRF-Token": csrf }, data: { type, args, idempotency_key: `shot${Date.now()}${Math.random().toString(36).slice(2)}` },
    });
    expect(r.status(), await r.text()).toBe(202);
    const id = (await r.json()).job_id as number;
    await expect.poll(async () => (await (await page.request.get(`/api/jobs/${id}`)).json()).state, { timeout: 60_000 }).toBe("succeeded");
  };
  await job("inject_fault", { device: "CH-01", forward_fraction: 0.3 });
  for (let i = 0; i < 40; i++) {
    await job("send_readings", {});
    await job("step", { count: 15 });
    const status = await (await page.request.get(`/api/networks/${nid}/recovery`)).json();
    if (status.clusters[0].suspected) break;
  }
  await expect(page.getByTestId("suspected-CH-01")).toBeVisible({ timeout: 10_000 });
  await expect(page.getByTestId("toast")).toHaveCount(0, { timeout: 15_000 });
  await page.getByTestId("node-CH-01").click();
  await expect(page.getByTestId("recovery-panel")).toContainText("CH suspected");
  await page.screenshot({ path: "e2e/shots/recovery_suspected.png", fullPage: true });
  await page.getByTestId("btn-recover").click();
  await expect(page.getByTestId("recovery-candidates")).toBeVisible();
  await page.locator("#confirm-input").fill("CH-01");
  await page.screenshot({ path: "e2e/shots/recovery_dialog.png", fullPage: false });
});
