/**
 * CYVRIX V3.9 — Workflow Console E2E (real stack, real Chromium)
 *
 * Drives the REAL Docker stack (Next.js + FastAPI + PostgreSQL + Redis).
 * Sessions are created with the real session machinery
 * (tests/create_session.py); proposal data is seeded by
 * tests/seed_e2e_approvals.py.
 *
 * These tests assert the V3.9 console properties that matter:
 * - the lifecycle surfaces (authorization/execution/remediation/
 *   verification/rollback) render truthful server state
 * - no client-side execution/rollback authority controls exist
 * - operations and audit are capability-gated (a plain USER is denied)
 * - cross-tenant (IDOR) navigation produces no data leak
 */
import { test, expect, type BrowserContext } from "@playwright/test";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

const BASE_URL = process.env.E2E_BASE_URL || "http://localhost:3001";

interface ApprovalSeed {
  users: Record<
    "approval" | "reject",
    { userId: string; email: string; repoId: string; proposalId: string; proposalDigest: string }
  >;
}

function loadJson<T>(name: string): T {
  const candidates = [path.join(os.tmpdir(), name), `/tmp/${name}`];
  for (const p of candidates) {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf-8")) as T;
  }
  throw new Error(`${name} not found. Run the python setup scripts first.`);
}

const approvals = loadJson<{ approvals: ApprovalSeed }>("e2e_setup.json").approvals;
const approvalUser = approvals.users.approval;
const rejectUser = approvals.users.reject;

function createFreshSession(userId: string): string {
  const scriptPath = path.resolve(__dirname, "../../../tests/create_session.py");
  const result = execSync(`python "${scriptPath}" "${userId}"`, {
    encoding: "utf-8",
    timeout: 15000,
    env: {
      ...process.env,
      SECRET_KEY:
        process.env.SECRET_KEY ||
        "test-secret-key-for-integration-only-not-for-production-32chars!",
      REDIS_URL: process.env.REDIS_URL || "redis://127.0.0.1:6380/0",
    },
  });
  return result.trim();
}

async function setAuthCookie(context: BrowserContext, cookie: string) {
  await context.addCookies([
    {
      name: "cyvrix_session",
      value: cookie,
      domain: "localhost",
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
      secure: false,
    },
  ]);
}

test.describe("V3.9 — action lifecycle console", () => {
  test("renders every lifecycle stage with truthful non-success states", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.proposalId}`);

    // Stage headings exist.
    await expect(page.getByText("Remediation lifecycle")).toBeVisible();
    await expect(page.getByText("Authorize execution")).toBeVisible();
    await expect(page.getByText("Sandbox execution")).toBeVisible();
    await expect(page.getByText("Git / GitHub remediation")).toBeVisible();
    await expect(page.getByText(/^Verification$/)).toBeVisible();
    await expect(page.getByText(/^Rollback$/)).toBeVisible();

    // The lifecycle timeline is present.
    await expect(page.getByRole("list", { name: "Remediation lifecycle" })).toBeVisible();

    // Truthful "nothing happened yet" copy — never a fake success.
    await expect(page.getByText(/Authorizing does not execute anything/i)).toBeVisible();
  });

  test("exposes no client-side execution or forced-rollback controls", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.proposalId}`);

    for (const forbidden of [
      /Execute now/i,
      /Force rollback/i,
      /Approve all/i,
      /Bypass policy/i,
      /Skip verification/i,
    ]) {
      await expect(page.getByRole("button", { name: forbidden })).toHaveCount(0);
    }
  });
});

test.describe("V3.9 — capability-gated consoles", () => {
  test("a plain USER is denied the operations console", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/operations`);
    await expect(page.getByText(/Operator access required/i)).toBeVisible();
  });

  test("a plain USER is denied the audit console", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/audit`);
    await expect(
      page.getByText(/Audit access not granted|Audit unavailable/i)
    ).toBeVisible();
  });
});

test.describe("V3.9 — tenant isolation (IDOR)", () => {
  test("user B cannot read user A's action lifecycle", async ({ context, page }) => {
    const cookie = createFreshSession(rejectUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.proposalId}`);
    await expect(page.getByText(/Action proposal not found/i)).toBeVisible();
    // No lifecycle data leaks to the unauthorized tenant.
    await expect(page.getByText("Authorize execution")).toHaveCount(0);
  });
});
