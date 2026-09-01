import { defineConfig, devices } from "@playwright/test";

/**
 * CYVRIX Playwright E2E Configuration — Real Stack
 *
 * Real services (must be running via Docker):
 * - FastAPI: http://localhost:8001
 * - Next.js: http://localhost:3001
 * - PostgreSQL: localhost:5433
 * - Redis: localhost:6380
 * - RQ Worker: running in Docker
 *
 * External services mocked at provider boundaries only:
 * - GitHub API
 * - OSV API
 * - OpenAI API
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ["html", { open: "never" }],
    ["list"],
  ],
  timeout: 300000,
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:3001",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // Do NOT use storageState — we set cookies manually for real auth
    storageState: undefined,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // No webServer config — services run in Docker, managed externally
});
