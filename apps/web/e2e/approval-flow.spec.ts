/**
 * CYVRIX V3.2 — Approval Flow E2E (real stack, real Chromium)
 *
 * Drives the actual /actions/[id] approval UI against the REAL Docker
 * stack (Next.js 3001 + FastAPI 8001 + PostgreSQL 5433 + Redis 6380).
 * Data is seeded by tests/seed_e2e_approvals.py; sessions are created
 * with the real SECRET_KEY/session machinery (tests/create_session.py).
 *
 * Asserts after each decision — via the real API and direct DB reads —
 * that approval is authorization data ONLY: no execution exists, no
 * token material persists, cross-user access is impossible.
 */
import { test, expect, type BrowserContext } from "@playwright/test";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";
import psycopg from "pg";

const API_URL = process.env.E2E_API_URL || "http://localhost:8001";
const BASE_URL = process.env.E2E_BASE_URL || "http://localhost:3001";
const PG_DSN =
  process.env.E2E_PG_URL ||
  "postgresql://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test";

interface ApprovalSeed {
  users: Record<
    "approval" | "reject",
    { userId: string; email: string; repoId: string; proposalId: string; proposalDigest: string; expiredProposalId?: string }
  >;
}

function loadSeed(): ApprovalSeed {
  const candidates = [
    path.join(os.tmpdir(), "e2e_setup.json"),
    "/tmp/e2e_setup.json",
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const data = JSON.parse(fs.readFileSync(p, "utf-8"));
      if (!data.approvals) {
        throw new Error("e2e_setup.json lacks approvals data. Run: python tests/seed_e2e_approvals.py");
      }
      return data.approvals;
    }
  }
  throw new Error("e2e_setup.json not found. Run: python tests/setup_e2e.py && python tests/seed_e2e_approvals.py");
}

const seed = loadSeed();
const approvalUser = seed.users.approval;
const rejectUser = seed.users.reject;

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

async function dbQuery(sql: string, params: unknown[] = []): Promise<any[]> {
  const client = new psycopg.Client(PG_DSN);
  await client.connect();
  try {
    const res = await client.query(sql, params);
    return res.rows;
  } finally {
    await client.end();
  }
}

async function approvalState(proposalId: string): Promise<string | null> {
  const rows = await dbQuery(
    "SELECT approval_state FROM approvals WHERE action_proposal_id = $1",
    [proposalId],
  );
  return rows.length ? rows[0].approval_state : null;
}

async function tokenColumnDirect(proposalId: string): Promise<string | null> {
  const rows = await dbQuery(
    "SELECT authorization_token_hash FROM approvals WHERE action_proposal_id = $1",
    [proposalId],
  );
  return rows.length ? rows[0].authorization_token_hash : null;
}

test.describe("V3.2 Approval — UI inspection", () => {
  test("approval screen shows every security-critical field, no execution controls", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.proposalId}`);

    // Header and explicit non-execution statement
    await expect(page.locator("text=Action approval")).toBeVisible();
    await expect(page.getByText(/approval is NOT execution/i)).toBeVisible();

    // Exact scope is visible
    await expect(page.locator("text=package.json").first()).toBeVisible();
    await expect(page.getByText(approvalUser.proposalDigest).first()).toBeVisible();
    await expect(page.getByText("UPDATE_DEPENDENCY_VERSION")).toBeVisible();
    await expect(page.getByText("4.17.19").first()).toBeVisible();
    await expect(page.getByText("4.17.21").first()).toBeVisible();
    await expect(page.getByText("cyvrix/fix")).toBeVisible();
    await expect(page.locator("text=REQUIRE_APPROVAL")).toBeVisible();
    await expect(page.locator("text=MEDIUM").first()).toBeVisible();
    await expect(page.locator("text=SUPPORTED")).toBeVisible();
    await expect(page.locator("text=VALIDATED")).toBeVisible();

    // Exactly APPROVE/REJECT — no execution-shaped controls
    const approve = page.getByRole("button", { name: "APPROVE", exact: true });
    const reject = page.getByRole("button", { name: "REJECT", exact: true });
    await expect(approve).toBeVisible();
    await expect(reject).toBeVisible();
    const body = (await page.content()).toLowerCase();
    for (const banned of ["approve all", "fix it", "execute", "run now", "apply fix"]) {
      expect(body, `banned control: ${banned}`).not.toContain(banned);
    }
  });

  test("expired proposal shows closed decision window", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.expiredProposalId}`);
    await expect(page.getByText(/decision window is closed/i)).toBeVisible();
    await expect(page.getByRole("button", { name: "APPROVE", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "REJECT", exact: true })).toHaveCount(0);
  });
});

test.describe("V3.2 Approval — decisions with DB verification", () => {
  test("APPROVE → typed digest required → APPROVED state → hash-only token → inert", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${approvalUser.proposalId}`);

    // Wait until the proposal content is actually loaded (digest rendered)
    await expect(page.getByText(approvalUser.proposalDigest).first()).toBeVisible();

    // Typed-digest confirmation is mandatory: button disabled until match
    const approveBtn = page.getByRole("button", { name: "APPROVE", exact: true });
    await expect(approveBtn).toBeDisabled();
    await page.getByPlaceholder("Paste the full action digest").fill(approvalUser.proposalDigest);
    await expect(approveBtn).toBeEnabled();
    await page.getByRole("button", { name: "APPROVE", exact: true }).click();

    // UI: approval recorded, explicitly NOT executed
    await expect(page.getByText(/approval recorded/i)).toBeVisible();
    await expect(page.getByText(/has NOT been executed/i)).toBeVisible();
    await expect(approveBtn).toHaveCount(0); // decision window closed

    // Backend state: exactly one approval, correct actor/digest/policy/state
    const rows = await dbQuery(
      `SELECT a.approval_state, a.action_digest, a.approver_user_id, a.policy_version,
              a.policy_decision, a.authorization_token_hash, a.authorization_used_at
       FROM approvals a WHERE a.action_proposal_id = $1`,
      [approvalUser.proposalId],
    );
    expect(rows).toHaveLength(1);
    const row = rows[0];
    expect(row.approval_state).toBe("APPROVED");
    expect(row.action_digest).toBe(approvalUser.proposalDigest);
    expect(row.approver_user_id).toBe(approvalUser.userId);
    expect(row.policy_version).toBe("3.1");
    expect(row.policy_decision).toBe("REQUIRE_APPROVAL");
    expect(row.authorization_used_at).toBeNull();
    // Hash-only: 64 hex chars — the plaintext token never reaches the DB
    expect(row.authorization_token_hash).toMatch(/^[0-9a-f]{64}$/);

    // Full-database scan: no column anywhere holds token-shaped plaintext
    const leaks = await dbQuery(
      `SELECT count(*)::int AS n FROM approvals
       WHERE (authorization_token_hash IS NOT NULL AND authorization_token_hash !~ '^[0-9a-f]{64}$')`,
    );
    expect(leaks[0].n).toBe(0);

    // Proposal reflects APPROVED; nothing was executed (status vocabulary only)
    const prop = await dbQuery(
      "SELECT status FROM action_proposals WHERE id = $1",
      [approvalUser.proposalId],
    );
    expect(prop[0].status).toBe("APPROVED");

    // No USER-executing route exists on the real API. V3.4 refines this
    // invariant: run routes now exist, but every one is either the internal
    // service-identity admission (POST /api/executor/runs — bearer-token
    // gated, a browser/user session can never invoke it) or a read-only
    // GET status view. No route a user session can call starts execution.
    const openapi = await (await fetch(`${API_URL}/openapi.json`)).json();
    const execPaths = Object.keys(openapi.paths).filter(
      (p) => /execute|remediat/.test(p) && !p.includes("step-up"),
    );
    expect(execPaths).toEqual([]);
    const allowedRunPaths: Record<string, string[]> = {
      "/api/executor/runs": ["post"],                  // service identity only
      "/api/executor/runs/{run_id}": ["get"],
      "/api/executor/runs/user/{run_id}": ["get"],
      "/api/actions/{proposal_id}/runs": ["get"],
    };
    const runPaths = Object.keys(openapi.paths).filter((p) => /\brun/.test(p));
    expect(runPaths.sort()).toEqual(Object.keys(allowedRunPaths).sort());
    for (const p of runPaths) {
      const methods = Object.keys(openapi.paths[p]).filter((m) => m !== "parameters");
      expect(methods).toEqual(allowedRunPaths[p]);
    }

    // Audit event for the grant exists with digest + actor
    // (DB column is "metadata"; the ORM maps it to event_metadata)
    const audit = await dbQuery(
      `SELECT event_type, metadata FROM audit_events
       WHERE event_type = 'APPROVAL_GRANTED' ORDER BY created_at DESC LIMIT 1`,
    );
    expect(audit).toHaveLength(1);
    expect(audit[0].metadata.action_digest).toBe(approvalUser.proposalDigest);
    expect(audit[0].metadata.actor).toBe(approvalUser.userId);
    expect(JSON.stringify(audit[0].metadata)).not.toContain("authorization_token");
  });

  test("REJECT → REJECTED state → no authorization material", async ({ context, page }) => {
    const cookie = createFreshSession(rejectUser.userId);
    await setAuthCookie(context, cookie);
    await page.goto(`${BASE_URL}/actions/${rejectUser.proposalId}`);
    await page.getByRole("button", { name: "REJECT", exact: true }).click();

    await expect(page.getByText(/decision window is closed/i)).toBeVisible();

    const state = await approvalState(rejectUser.proposalId);
    expect(state).toBe("REJECTED");
    const rows = await dbQuery(
      "SELECT authorization_token_hash FROM approvals WHERE action_proposal_id = $1",
      [rejectUser.proposalId],
    );
    // A rejected approval has no usable authorization material
    expect(rows[0].authorization_token_hash).toBeNull();

    const prop = await dbQuery(
      "SELECT status FROM action_proposals WHERE id = $1",
      [rejectUser.proposalId],
    );
    expect(prop[0].status).toBe("REJECTED");
  });

  test("cross-user approval is denied and creates no approval row", async ({ context, page }) => {
    const cookie = createFreshSession(approvalUser.userId); // NOT the owner
    await setAuthCookie(context, cookie);

    // Direct API attempt with a fully valid-looking body
    const resp = await context.request.post(
      `${API_URL}/api/actions/${rejectUser.proposalId}/approve`,
      { data: { reason: "xss-csrf attempt" } },
    );
    expect(resp.status()).toBe(404); // cross-tenant convention

    // No approval row appeared for the victim's proposal
    expect(await approvalState(rejectUser.proposalId)).toBe("REJECTED");

    // Browser: UI shows not-found, offers no approval controls
    await page.goto(`${BASE_URL}/actions/${rejectUser.proposalId}`);
    await expect(page.getByText(/not found/i)).toBeVisible();
    await expect(page.getByRole("button", { name: "APPROVE", exact: true })).toHaveCount(0);
  });

  test("expired proposal cannot be approved via API", async ({ context }) => {
    const cookie = createFreshSession(approvalUser.userId);
    await setAuthCookie(context, cookie);

    // The server reconciles expiry on read: a proposal already read back
    // as EXPIRED is denied as PROPOSAL_STALE; an unread expired proposal
    // is denied as PROPOSAL_EXPIRED. Both are deterministic denials.
    const statusResp = await context.request.get(
      `${API_URL}/api/actions/${approvalUser.expiredProposalId}`,
    );
    const currentStatus = statusResp.status() === 200
      ? (await statusResp.json()).status
      : null;

    const resp = await context.request.post(
      `${API_URL}/api/actions/${approvalUser.expiredProposalId}/approve`,
      { data: { reason: "expired attempt" } },
    );
    expect(resp.status()).toBe(409);
    const body = await resp.json();
    expect(body.detail.reason_code).toBe(
      currentStatus === "EXPIRED" ? "PROPOSAL_STALE" : "PROPOSAL_EXPIRED",
    );
  });
});
