import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.E2E_PORT ?? 8765);

// V-E2E-*: the built UI served by the real backend (IMPLEMENTATION_PLAN.md §6.3).
export default defineConfig({
  testDir: "./e2e",
  timeout: 180_000,
  expect: { timeout: 60_000 },
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: `http://127.0.0.1:${port}`, trace: "retain-on-failure", viewport: { width: 1366, height: 860 } },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1366, height: 860 } } }],
  webServer: {
    command: "./e2e/serve.sh",
    url: `http://127.0.0.1:${port}/api/health`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: { E2E_PORT: String(port) },
  },
});
