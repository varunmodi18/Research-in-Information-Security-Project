import { expect, test, type Page } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// Follow-up F9: Playwright coverage for F1-F6, and the loading / empty / failure / disconnected
// states of the topology, events and timeline pages.

async function onboardedProduct(page: Page, template = "small"): Promise<{ nid: string; name: string }> {
  const name = uniqueName("f");
  await createNetwork(page, { name, kind: "product", template, params: "toy" });
  await page.getByTestId("btn-onboard").click();
  await expect(page.getByTestId("node-CM-0101")).toHaveAttribute("data-status", "active", { timeout: 60_000 });
  return { nid: new URL(page.url()).pathname.split("/")[2], name };
}

async function revoke(page: Page, nid: string, ident: string) {
  await page.goto(`/networks/${nid}/devices/${ident}`);
  await page.getByTestId("btn-revoke").click();
  await page.getByLabel(new RegExp(`Type ${ident} to confirm`)).fill(ident);
  await page.getByRole("button", { name: "Revoke device" }).click();
}

test("F3 the Revoking… toast is replaced by the outcome; F2 revoked sessions read closed by peer", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page);
  await revoke(page, nid, "CM-0102");
  const toast = page.getByTestId("toast").filter({ hasText: "CM-0102" });
  await expect(toast.last()).toHaveText(/CM-0102 revoked/, { timeout: 30_000 });
  await expect(toast.last()).toHaveAttribute("data-tone", "success");
  await expect(page.getByTestId("toast").filter({ hasText: "Revoking CM-0102…" })).toHaveCount(0);
  await expect(page.getByTestId("toast")).toHaveCount(0, { timeout: 10_000 });  // and it goes away
  await page.reload();
  await expect(page.getByTestId("session-state").first()).toContainText("closed by peer (device revoked)");
  await expect(page.getByTestId("session-state")).toHaveCount(2);
  for (const cell of await page.getByTestId("session-state").all()) await expect(cell).toContainText("closed by peer");
  await expect(page.getByTestId("closed-by-peer-note")).toContainText("not told");
});

test("F1 sessions show the registry epoch they were established in", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page);
  await revoke(page, nid, "CM-0103");
  await expect(page.getByTestId("toast").filter({ hasText: "CM-0103 revoked" })).toBeVisible({ timeout: 30_000 });
  await page.goto(`/networks/${nid}`);
  await expect(page.getByRole("heading").first()).toBeVisible();
  await expect(page.getByText(/registry epoch 1/)).toBeVisible();
  await page.goto(`/networks/${nid}/devices/CM-0101`);
  await page.getByRole("button", { name: /Rekey sessions/ }).click();
  await expect(page.getByTestId("toast").filter({ hasText: "CM-0101 rekeyed" })).toBeVisible({ timeout: 30_000 });
  await page.reload();
  const established = page.getByTestId("sessions-table").locator("tr", { hasText: "✓ ESTABLISHED" });
  await expect(established).toHaveCount(2);
  for (const row of await established.all()) await expect(row.locator("td").nth(4)).toHaveText("1");
});

test("F4 timeline: sticky lane header, horizontal scroll, lane filter", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page, "net");
  await page.goto(`/networks/${nid}/timeline`);
  const header = page.getByTestId("timeline-header");
  await expect(header).toContainText("CM-0303");
  const box = header.locator("xpath=ancestor::div[contains(@class,'overflow-auto')][1]");
  const dims = await box.evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth }));
  expect(dims.sw).toBeGreaterThan(dims.cw);  // 13 lanes do not fit: the diagram scrolls sideways
  await box.evaluate((el) => { el.scrollTop = 600; });
  const top = await box.evaluate((el) => el.getBoundingClientRect().top);
  await expect.poll(async () => Math.round((await header.boundingBox())!.y - top)).toBeLessThan(2);  // still at the top
  await page.getByTestId("lane-filter").locator("summary").click();
  await expect(page.getByTestId("lane-filter")).toContainText("Lanes (13/13)");
  await page.getByLabel("Lane CM-0303").uncheck();
  await expect(page.getByTestId("lane-filter")).toContainText("Lanes (12/13)");
  await expect(header).not.toContainText("CM-0303");
  await expect(header).toContainText("other");
  await page.getByRole("button", { name: "None" }).click();
  await expect(page.getByText("No frames in the selected lanes")).toBeVisible();
});

test("F5 readings show the session id next to seq and mark a rekey", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page, "paper");
  await page.getByTestId("btn-readings").click();
  await page.goto(`/networks/${nid}/devices/CM-0101`);
  await page.getByRole("button", { name: /Rekey sessions/ }).click();
  await expect(page.getByTestId("toast").filter({ hasText: "CM-0101 rekeyed" })).toBeVisible({ timeout: 30_000 });
  await page.goto(`/networks/${nid}/readings`);
  await page.getByRole("button", { name: "Send one round" }).click();
  await expect(page.getByTestId("reading-seq")).toHaveCount(2, { timeout: 30_000 });
  await expect(page.getByTestId("rekey-marker")).toHaveCount(1);
  const seqs = page.getByTestId("reading-seq");
  await expect(seqs.first()).toContainText(/↻1\s*·\s*[0-9a-f]{8}/);  // newest first: seq restarted in a new session
  await expect(seqs.last()).toContainText(/^1\s*·\s*[0-9a-f]{8}/);
  expect(await seqs.first().locator("span[title]").last().getAttribute("title")).toContain("restarts at 1 after a rekey");
});

test("F6 designate a CH, reset the network, and (admin only) delete it", async ({ page }) => {
  test.setTimeout(180_000);
  await login(page, "operator");
  const { nid, name } = await onboardedProduct(page);
  await expect(page.getByTestId("btn-delete-network")).toHaveCount(0);  // operators cannot delete
  await page.getByTestId("btn-designate").click();
  await page.getByLabel("Cluster head identity").fill("CH-01-r1");
  const designate = page.getByRole("button", { name: "Designate", exact: true });
  await expect(designate).toBeDisabled();
  await page.getByLabel(/Type CH-01 to confirm/).fill("CH-01");
  await designate.click();
  await expect(page.getByTestId("toast").filter({ hasText: "CH-01-r1 designated for cluster CH-01" })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("node-CH-01-r1")).toHaveAttribute("data-status", "active");
  await page.getByTestId("btn-reset-network").click();
  await page.getByLabel(new RegExp(`Type ${name} to confirm`)).fill(name);
  await page.getByRole("button", { name: "Reset network", exact: true }).click();
  await expect(page.getByTestId("toast").filter({ hasText: `${name} reset` })).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("node-CH-01-r1")).toHaveCount(0);
  await expect(page.getByTestId("node-CM-0101")).toHaveAttribute("data-status", "provisioned");
  await page.getByRole("button", { name: "Sign out" }).click();
  await login(page, "admin");
  await page.goto(`/networks/${nid}`);
  await page.getByTestId("btn-delete-network").click();
  const del = page.getByRole("button", { name: "Delete network", exact: true });
  await page.getByLabel(new RegExp(`Type ${name} to confirm`)).fill(name + "x");
  await expect(del).toBeDisabled();
  await page.getByLabel(new RegExp(`Type ${name} to confirm`)).fill(name);
  await del.click();
  await expect(page.getByTestId("toast").filter({ hasText: `Network “${name}” deleted` })).toBeVisible();
  await page.goto(`/networks/${nid}`);
  await expect(page.getByRole("alert")).toContainText("Not found");
});

// -- data-view states (§3.7) on topology, events and timeline ------------------------------------

test("states: topology loading, empty feed, failure with retry, disconnected stream", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("st"), kind: "product", template: "paper", params: "toy" });  // nothing run yet
  const nid = new URL(page.url()).pathname.split("/")[2];
  let release: () => void = () => undefined;
  const held = new Promise<void>((r) => { release = r; });
  await page.route(`**/api/networks/${nid}`, async (route) => { await held; await route.continue(); });
  await page.goto(`/networks/${nid}`);
  await expect(page.getByRole("status").filter({ hasText: "Loading…" })).toBeVisible();  // loading
  release();
  await expect(page.getByLabel("Network topology")).toBeVisible();
  await expect(page.getByText("Events stream here while jobs run.")).toBeVisible();  // empty live feed
  await page.unroute(`**/api/networks/${nid}`);
  await page.route(`**/api/networks/${nid}`, (route) =>
    route.fulfill({ status: 500, contentType: "application/problem+json",
      body: JSON.stringify({ type: "about:blank", title: "Server error", status: 500, code: "INTERNAL", detail: "injected" }) }));
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("Server error");  // failure
  await page.unroute(`**/api/networks/${nid}`);
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByLabel("Network topology")).toBeVisible();  // retry recovers
  await page.route("**/api/networks/*/stream*", (r) => r.abort());
  await page.reload();
  await expect(page.getByRole("status").filter({ hasText: "Reconnecting…" })).toBeVisible({ timeout: 30_000 });  // disconnected
});

test("states: events loading, empty, failure, disconnected", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page, "paper");
  let release: () => void = () => undefined;
  const held = new Promise<void>((r) => { release = r; });
  await page.route("**/api/events?*", async (route) => { await held; await route.continue(); });
  await page.goto(`/events?network=${nid}`);
  await expect(page.getByRole("status").filter({ hasText: "Loading…" })).toBeVisible();
  release();
  await expect(page.getByTestId("events-table")).toContainText("HANDSHAKE_OK");
  await page.unroute("**/api/events?*");
  await page.getByLabel("Type").fill("NO_SUCH_EVENT");
  await expect(page.getByText("No events match")).toBeVisible();  // empty
  await page.route("**/api/events?*", (route) =>
    route.fulfill({ status: 500, contentType: "application/problem+json",
      body: JSON.stringify({ type: "about:blank", title: "Server error", status: 500, code: "INTERNAL", detail: "injected" }) }));
  await page.getByLabel("Type").fill("HANDSHAKE_OK");
  await expect(page.getByRole("alert")).toContainText("Server error");  // failure
  await page.unroute("**/api/events?*");
  await page.route("**/api/events?*", (route) => route.abort("internetdisconnected"));
  await page.getByLabel("Type").fill("KEY_CONFIRMED");
  await expect(page.getByRole("alert")).toBeVisible();  // disconnected: the API is unreachable
  await page.unroute("**/api/events?*");
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByTestId("events-table")).toContainText("KEY_CONFIRMED");  // and recovers
});

test("states: timeline loading, empty, failure, disconnected", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("tl"), kind: "product", template: "paper", params: "toy" });
  const nid = new URL(page.url()).pathname.split("/")[2];
  let release: () => void = () => undefined;
  const held = new Promise<void>((r) => { release = r; });
  await page.route(`**/api/networks/${nid}/frames*`, async (route) => { await held; await route.continue(); });
  await page.goto(`/networks/${nid}/timeline`);
  await expect(page.getByRole("status").filter({ hasText: "Loading…" })).toBeVisible();
  release();
  await expect(page.getByText("No frames yet")).toBeVisible();  // empty: nothing onboarded
  await page.unroute(`**/api/networks/${nid}/frames*`);
  await page.route(`**/api/networks/${nid}/frames*`, (route) =>
    route.fulfill({ status: 500, contentType: "application/problem+json",
      body: JSON.stringify({ type: "about:blank", title: "Server error", status: 500, code: "INTERNAL", detail: "injected" }) }));
  await page.reload();
  await expect(page.getByRole("alert")).toContainText("Server error");
  await page.unroute(`**/api/networks/${nid}/frames*`);
  await page.route("**/api/networks/*/stream*", (r) => r.abort());
  await page.reload();
  await expect(page.getByRole("status").filter({ hasText: "Reconnecting…" })).toBeVisible({ timeout: 30_000 });
});

// -- cleanup after review (items 3, 5, 9) -----------------------------------------------------------

test("cleanup 3: a member that is itself revoked is not listed as awaiting re-designation", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  const { nid } = await onboardedProduct(page);
  await revoke(page, nid, "CM-0103");
  await expect(page.getByTestId("toast").filter({ hasText: "CM-0103 revoked" })).toBeVisible({ timeout: 30_000 });
  await revoke(page, nid, "CH-01");
  await expect(page.getByTestId("toast").filter({ hasText: "CH-01 revoked" })).toBeVisible({ timeout: 30_000 });
  await page.goto(`/networks/${nid}`);
  const banner = page.getByTestId("designation-banner");
  await expect(banner).toContainText("CM-0101, CM-0102");
  await expect(banner).not.toContainText("CM-0103");
  await expect(page.getByTestId("node-CM-0101")).toContainText("CH revoked");
  await expect(page.getByTestId("node-CM-0103")).not.toContainText("CH revoked");
  await expect(page.getByTestId("node-CM-0103")).not.toHaveAttribute("data-designation", "ch_revoked_awaiting_redesignation");
});

test("cleanup 5 and 9: device page at 1366 px: named status epoch, one-line peer and sent/recv", async ({ page }) => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1366, height: 768 });
  await login(page, "operator");
  const { nid } = await onboardedProduct(page);
  await revoke(page, nid, "CM-0102");
  await expect(page.getByTestId("toast").filter({ hasText: "CM-0102 revoked" })).toBeVisible({ timeout: 30_000 });
  await page.reload();
  const label = page.getByTestId("device-epoch-label");
  await expect(label).toHaveText("Status changed in registry epoch");
  expect(await label.getAttribute("title")).toContain("Not the same as the Epoch column of the sessions table");
  await expect(page.getByTestId("session-state").first()).toContainText("closed by peer (device revoked)");
  // number of distinct line boxes the cell's text occupies
  const lines = (testId: string) => page.getByTestId(testId).evaluateAll((cells) => cells.map((c) => {
    const r = c.ownerDocument.createRange();
    r.selectNodeContents(c);
    const rects = r.getClientRects();
    const tops = new Set<number>();
    for (let i = 0; i < rects.length; i++) tops.add(Math.round(rects[i].top));
    return tops.size;
  }));
  expect(await lines("session-peer")).toEqual([1, 1]);
  expect(await lines("session-sent-recv")).toEqual([1, 1]);
});
