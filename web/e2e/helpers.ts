import { expect, type Page } from "@playwright/test";

export async function login(page: Page, role: "admin" | "operator" | "viewer") {
  await page.goto("/");
  await page.getByLabel("Username").fill(`e2e-${role}`);
  await page.getByLabel("Password").fill(`e2e-${role}-password`);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByTestId("current-user")).toContainText(`e2e-${role}`);
}

export function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}`;
}

export async function createNetwork(page: Page, opts: { name: string; kind: "product" | "lab"; mode?: "enhanced" | "original";
  template?: string; params?: string }) {
  await page.goto("/networks/new");
  await page.getByLabel("Name").fill(opts.name);
  await page.getByLabel(opts.kind === "lab" ? "Lab (attack experiments)" : "Product (MAKA-E only)").check();
  if (opts.mode === "original") await page.getByLabel("RP9 original").check();
  await page.getByLabel("Topology").selectOption(opts.template ?? "paper");
  await page.getByLabel("Parameter set").selectOption(opts.params ?? "toy");
  await page.getByRole("button", { name: "Create and provision" }).click();
  await expect(page.getByRole("heading", { name: opts.name })).toBeVisible();
}
