import { expect, test } from "@playwright/test";
import { createNetwork, login, uniqueName } from "./helpers";

// V-E2E-05 / J5: Evaluation -> run a comparison -> charts, table view, thresholds, RP9 tables,
// formal results and the limitations box. J5 names net/demo/5 seeds; the browser test uses
// paper/toy/1 seed to stay within the E2E time budget (PLAN_ERRATA E-06). The full matrix is
// eval/bench/compare.py, committed under artifacts/eval/.
test("V-E2E-05 J5 evaluate", async ({ page }) => {
  test.setTimeout(120_000);
  await login(page, "operator");
  await createNetwork(page, { name: uniqueName("eval"), kind: "lab", template: "paper" });
  await page.getByRole("link", { name: "Evaluation" }).click();
  await expect(page.getByTestId("limitations")).toContainText("not a proof of cryptographic security");
  await page.getByLabel("Topology").selectOption("paper");
  await page.getByLabel("Parameters").selectOption("toy");
  await page.getByLabel("Seeds").fill("1");
  await page.getByTestId("run-evaluation").click();
  await expect(page.getByTestId("thresholds")).toContainText("pairings per CM during onboarding", { timeout: 90_000 });
  await expect(page.getByTestId("chart-onboarding-toy")).toContainText("MAKA-E");
  await expect(page.getByTestId("chart-cost")).toContainText("Estimate, not a measurement");
  await page.getByTestId("view-table").click();
  await expect(page.getByTestId("comparison-table")).toContainText("RP9 (as priced in Table 2)");
  await expect(page.getByTestId("table5")).toContainText("ER-02");
  await expect(page.getByTestId("table5")).toContainText("AM-04");
  await expect(page.getByTestId("ev-formal")).toContainText(/attack found|not obtained/);
  // follow-up C4: two separate tables, AVISPA (HLPSL) and OFMC 2024 (AnB)
  await expect(page.getByTestId("ev-formal")).toContainText("AVISPA (HLPSL): OFMC, CL-AtSe");
  await expect(page.getByTestId("ev-formal")).toContainText("OFMC 2024 (AnB models)");
  // cleanup item 4: a summary first (one row per model); detailed tables collapsed below it
  await expect(page.getByTestId("summary-rp9_transcribed")).toContainText("3/8");
  await expect(page.getByTestId("summary-maka_e")).toContainText("SAFE (untyped: UNSAFE)");
  await expect(page.getByTestId("summary-maka_e_ake_fs")).toContainText("forward secrecy is not established symbolically beyond 1 session");
  await expect(page.getByTestId("formal-avispa")).toBeHidden();
  await page.getByTestId("formal-details-avispa").locator("summary").click();
  await page.getByTestId("formal-details-anb").locator("summary").click();
  await expect(page.getByTestId("formal-goal-grid")).toContainText("secrecy-sec1");
  const avispa = page.getByTestId("avispa-rp9_transcribed").filter({ hasText: "OFMC (2006/02/13)" });
  await expect(avispa).toContainText("1501 nodes, depth 7");
  await expect(avispa).toContainText("results/avispa/runs/rp9_transcribed.ofmc2006.txt");
  await expect(page.getByTestId("anb-rp9_auth_outsider-2")).toContainText(/without a receiver-side nonce record, replay succeeds; RP9.s replay protection rests entirely on that record, which RP9 does not specify/i);
  await expect(page.getByTestId("ev-levels")).toContainText("demonstration only");
});
