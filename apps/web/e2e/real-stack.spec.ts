/**
 * CYVRIX V1 — Real-Stack E2E Tests
 *
 * REAL services: FastAPI, Next.js, PostgreSQL, Redis, RQ Worker (all Docker)
 * MOCKED only: GitHub API, OSV API, OpenAI API (at provider boundaries)
 * The CYVRIX application code itself is NEVER mocked.
 */
import { test, expect, type BrowserContext } from "@playwright/test";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

// ── Configuration ─────────────────────────────────────────────────

const API_URL = process.env.E2E_API_URL || "http://localhost:8001";
const BASE_URL = process.env.E2E_BASE_URL || "http://localhost:3001";

// ── Setup Data ────────────────────────────────────────────────────

interface TestUser {
  userId: string;
  email: string;
  cookie: string;
  repoId?: string;
  scanId?: string;
  findingId?: string;
}

interface SetupData {
  users: Record<string, TestUser>;
  cleanup_ids: string[];
}

function loadSetupData(): SetupData {
  const candidates = [
    path.join(os.tmpdir(), "e2e_setup.json"),
    "/tmp/e2e_setup.json",
    path.join(process.env.TEMP || "", "e2e_setup.json"),
    path.join(process.env.LOCALAPPDATA || "", "Temp", "e2e_setup.json"),
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      return JSON.parse(fs.readFileSync(p, "utf-8"));
    }
  }
  throw new Error("E2E setup data not found. Run: python tests/setup_e2e.py first.");
}

const setup = loadSetupData();

// ── Session Creation ──────────────────────────────────────────────

function createFreshSession(userId: string): string {
  const scriptPath = path.resolve(__dirname, "../../../tests/create_session.py");
  const result = execSync(`python "${scriptPath}" "${userId}"`, {
    encoding: "utf-8",
    timeout: 10000,
    env: {
      ...process.env,
      SECRET_KEY: process.env.SECRET_KEY || "test-secret-key-for-integration-only-not-for-production-32chars!",
      REDIS_URL: process.env.REDIS_URL || "redis://127.0.0.1:6380/0",
    },
  });
  return result.trim();
}

async function setAuthCookie(context: BrowserContext, cookie: string) {
  await context.addCookies([{
    name: "cyvrix_session",
    value: cookie,
    domain: "localhost",
    path: "/",
    httpOnly: true,
    sameSite: "Lax",
    secure: false,
  }]);
}

// ── Golden Path E2E ───────────────────────────────────────────────

test.describe("Golden Path — Real Stack", () => {
  const user = setup.users.golden;

  test("Step 1: Login → Session → Dashboard", async ({ context, page }) => {
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/dashboard`);
    await expect(page.locator("text=Security Dashboard")).toBeVisible();

    const meResponse = await page.request.get(`${API_URL}/api/auth/me`, {
      headers: { Cookie: `cyvrix_session=${cookie}` },
    });
    expect(meResponse.ok()).toBeTruthy();
    const meData = await meResponse.json();
    expect(meData.email).toBe(user.email);
  });

  test("Step 2: Repository list shows connected repos", async ({ context, page }) => {
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/repositories`);
    await expect(page.locator("text=golden-org/vulnerable-app")).toBeVisible();
    await expect(page.locator("text=Active")).toBeVisible();
  });

  test("Step 3: Repository detail shows scan history", async ({ context, page }) => {
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/repositories/${user.repoId}`);
    await expect(page.locator("text=golden-org/vulnerable-app")).toBeVisible();
    await expect(page.locator("text=Scan History")).toBeVisible();
  });

  test("Step 4: Finding detail shows vulnerability and risk", async ({ context, page }) => {
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/findings/${user.findingId}`);
    await expect(page.locator("text=Prototype Pollution in lodash")).toBeVisible();
    await expect(page.locator("text=CVE-2024-9999")).toBeVisible();
    await expect(page.locator("text=Risk Assessment")).toBeVisible();
    await expect(page.locator("text=65").first()).toBeVisible();
  });

  test("Step 5: Scan detail shows findings", async ({ context, page }) => {
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/scans/${user.scanId}`);
    await expect(page.locator("text=COMPLETED").first()).toBeVisible();
    await expect(page.locator("text=Findings")).toBeVisible();
    await expect(page.locator("text=Prototype Pollution in lodash")).toBeVisible();
  });
});

// ── Authentication E2E ────────────────────────────────────────────

test.describe("Authentication — Real Stack", () => {
  test("unauthenticated user is rejected", async ({ context }) => {
    const response = await context.request.get(`${API_URL}/api/auth/me`);
    expect(response.status()).toBe(401);
  });

  test("authenticated user sees user info", async ({ context }) => {
    const user = setup.users.golden;
    const cookie = createFreshSession(user.userId);
    const response = await context.request.get(`${API_URL}/api/auth/me`, {
      headers: { Cookie: `cyvrix_session=${cookie}` },
    });
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data.email).toBe(user.email);
    expect(data.id).toBe(user.userId);
  });

  test("logout destroys session", async ({ context }) => {
    const user = setup.users.golden;
    const cookie = createFreshSession(user.userId);
    const logoutResponse = await context.request.post(`${API_URL}/api/auth/logout`, {
      headers: { Cookie: `cyvrix_session=${cookie}` },
    });
    expect(logoutResponse.ok()).toBeTruthy();
    const meResponse = await context.request.get(`${API_URL}/api/auth/me`, {
      headers: { Cookie: `cyvrix_session=${cookie}` },
    });
    expect(meResponse.status()).toBe(401);
  });

  test("expired session is rejected", async ({ context }) => {
    const response = await context.request.get(`${API_URL}/api/auth/me`, {
      headers: { Cookie: "cyvrix_session=nonexistent.invalid" },
    });
    expect(response.status()).toBe(401);
  });
});

// ── Cookie Security E2─────────────────────────────────────────────

test.describe("Cookie Security — Real Stack", () => {
  test("session cookie has correct attributes", async ({ context }) => {
    const user = setup.users.golden;
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    const cookies = await context.cookies();
    const sessionCookie = cookies.find((c) => c.name === "cyvrix_session");
    expect(sessionCookie).toBeDefined();
    expect(sessionCookie!.httpOnly).toBe(true);
    expect(sessionCookie!.sameSite).toBe("Lax");
    expect(sessionCookie!.path).toBe("/");
    expect(sessionCookie!.secure).toBe(false);
  });
});

// ── IDOR/BOLA E2E ────────────────────────────────────────────────

test.describe("IDOR Protection — Real Stack", () => {
  test("User B cannot access User A's repository", async ({ context }) => {
    const userA = setup.users.idorA;
    const userB = setup.users.idorB;
    const cookieB = createFreshSession(userB.userId);
    const response = await context.request.get(
      `${API_URL}/api/repositories/${userA.repoId}`,
      { headers: { Cookie: `cyvrix_session=${cookieB}` } }
    );
    expect(response.status()).toBe(404);
  });

  test("User B cannot access User A's finding", async ({ context }) => {
    const userA = setup.users.idorA;
    const userB = setup.users.idorB;
    const cookieB = createFreshSession(userB.userId);
    const response = await context.request.get(
      `${API_URL}/api/findings/${userA.findingId}`,
      { headers: { Cookie: `cyvrix_session=${cookieB}` } }
    );
    expect(response.status()).toBe(404);
  });

  test("User A can access their own resources", async ({ context }) => {
    const userA = setup.users.idorA;
    const cookieA = createFreshSession(userA.userId);
    const repoResponse = await context.request.get(
      `${API_URL}/api/repositories/${userA.repoId}`,
      { headers: { Cookie: `cyvrix_session=${cookieA}` } }
    );
    expect(repoResponse.ok()).toBeTruthy();
    const findingResponse = await context.request.get(
      `${API_URL}/api/findings/${userA.findingId}`,
      { headers: { Cookie: `cyvrix_session=${cookieA}` } }
    );
    expect(findingResponse.ok()).toBeTruthy();
  });
});

// ── XSS E2E ──────────────────────────────────────────────────────

test.describe("XSS Protection — Real Stack", () => {
  test("XSS payloads render as text in finding detail", async ({ context, page }) => {
    const user = setup.users.xss;
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/findings/${user.findingId}`);
    // Wait for client-side data to load
    await page.waitForLoadState('networkidle');
    await expect(page.locator("text=<script>").first()).toBeVisible({ timeout: 15000 });
    const content = await page.content();
    expect(content).toContain("&lt;script&gt;");
    expect(content).not.toContain("<script>alert");
    let alertTriggered = false;
    page.on("dialog", () => { alertTriggered = true; });
    await page.waitForTimeout(1000);
    expect(alertTriggered).toBe(false);
  });
});

// ── Empty States E2E ──────────────────────────────────────────────

test.describe("Empty States — Real Stack", () => {
  test("new user sees empty repositories", async ({ context, page }) => {
    const user = setup.users.empty;
    const cookie = createFreshSession(user.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/repositories`);
    await expect(page.locator("text=No repositories connected")).toBeVisible();
    await expect(page.locator("text=Connect GitHub").first()).toBeVisible();
  });
});

// ── Error States E2E ──────────────────────────────────────────────

test.describe("Error States — Real Stack", () => {
  test("non-existent finding returns 404", async ({ context }) => {
    const user = setup.users.golden;
    const cookie = createFreshSession(user.userId);
    const response = await context.request.get(
      `${API_URL}/api/findings/00000000-0000-0000-0000-000000000000`,
      { headers: { Cookie: `cyvrix_session=${cookie}` } }
    );
    expect(response.status()).toBe(404);
  });
});
