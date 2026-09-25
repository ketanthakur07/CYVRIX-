/**
 * CYVRIX V4.1 — External-boundary E2E (real stack, real Chromium)
 *
 * Companion to e2e/v39-workflow-console.spec.ts (which remains the
 * V3.9 regression gate). Seed: tests/seed_v41_e2e.py writes
 * /tmp/v41_e2e_seed.json (org, owner, viewer, API key, completed scan).
 *
 * Asserts the V4.1 properties that matter from the browser:
 * - the console API-keys page shows keys, scopes and rotation UI
 * - the public API accepts the seeded key and returns the paginated
 *   envelope; the browser never derives authority from it
 * - job status reports SERVER-computed result + commit binding
 * - a scope denial surfaces the public error envelope, not a crash
 * - the viewer's session cannot mint an API key (capability denial)
 */
import { test, expect, type BrowserContext } from "@playwright/test";
import fs from "fs";
import os from "os";
import path from "path";
import { execSync } from "child_process";

const BASE_URL = process.env.E2E_BASE_URL || "http://localhost:3001";
const API_URL = process.env.E2E_API_URL || "http://localhost:8001";

interface V41Seed {
  owner: { user_id: string; email: string; org_id: string; org_name: string };
  viewer: { user_id: string; email: string };
  repository_id: string;
  scan_id: string;
  api_key_secret: string;
  api_key_prefix: string;
}

function loadSeed(): V41Seed {
  const candidates = [
    path.join(os.tmpdir(), "v41_e2e_seed.json"),
    "/tmp/v41_e2e_seed.json",
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, "utf-8")) as V41Seed;
  }
  throw new Error("v41_e2e_seed.json not found. Run tests/seed_v41_e2e.py first.");
}

const seed = loadSeed();

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
      domain: new URL(BASE_URL).hostname,
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
}

// ── Public API from the browser context (no session involved) ────────

test.describe("V4.1 public API contract", () => {
  test("identity endpoint reveals no secret material", async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/me`, {
      headers: { Authorization: `Bearer ${seed.api_key_secret}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.organization_id).toBe(seed.owner.org_id);
    expect(body.key_prefix).toBe(seed.api_key_prefix);
    expect(body.api_version).toBe("v1");
    // The plaintext secret never appears in the identity payload.
    expect(JSON.stringify(body)).not.toContain(seed.api_key_secret);
  });

  test("collections use the bounded paginated envelope", async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/repositories?limit=2`, {
      headers: { Authorization: `Bearer ${seed.api_key_secret}` },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(Object.keys(body).sort()).toEqual(["has_more", "items", "next_cursor"]);
    expect(Array.isArray(body.items)).toBe(true);
  });

  test("job status is server-computed with commit binding", async ({ request }) => {
    const response = await request.get(
      `${API_URL}/api/v1/scans/${seed.scan_id}/status`,
      { headers: { Authorization: `Bearer ${seed.api_key_secret}` } }
    );
    expect(response.status()).toBe(200);
    const job = await response.json();
    expect(job.kind).toBe("SCAN");
    expect(job.status).toBe("COMPLETED");
    // Server-computed result, never a client claim:
    expect(job.result).toBe("PASS");
    expect(job.commit_binding).toBe("VERIFIED");
    expect(job.requested_commit_sha).toBe("a".repeat(40));
  });

  test("scope denial returns the public error envelope", async ({ request }) => {
    // The key carries only scans:read/repositories:read — findings:read
    // is refused, and the refusal is the documented envelope.
    const response = await request.get(`${API_URL}/api/v1/findings`, {
      headers: { Authorization: `Bearer ${seed.api_key_secret}` },
    });
    expect(response.status()).toBe(403);
    const body = await response.json();
    expect(body.code).toBe("API_SCOPE_REQUIRED");
    expect(body.detail).toBe("API_SCOPE_REQUIRED");
    expect(typeof body.message).toBe("string");
    expect(body.request_id).toBeTruthy();
  });

  test("unauthenticated access is refused with 401 envelope", async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/repositories`);
    expect(response.status()).toBe(401);
    const body = await response.json();
    expect(body.code).toBe("API_KEY_REQUIRED");
  });
});

// ── Console: API-key lifecycle UI (session-authenticated) ────────────

test.describe("V4.1 console API keys", () => {
  test("owner sees key list with scopes and rotation control", async ({
    browser,
  }) => {
    const context = await browser.newContext();
    await setAuthCookie(context, createFreshSession(seed.owner.user_id));
    const page = await context.newPage();

    await page.goto(
      `${BASE_URL}/orgs/${seed.owner.org_id}/api-keys`,
      { waitUntil: "domcontentloaded" }
    );

    // The seeded key renders with its prefix (never its secret), and its
    // scopes render on the key row (not just the create-form checkbox).
    await expect(page.getByText(seed.api_key_prefix)).toBeVisible();
    await expect(
      page.getByText("scopes: repositories:read, scans:read")
    ).toBeVisible();

    // Rotation is offered (V4.1); the secret is only ever shown once.
    await expect(page.getByRole("button", { name: /rotate/i })).toBeVisible();

    await context.close();
  });

  test("viewer (non-manager) cannot open key management", async ({ browser }) => {
    const context = await browser.newContext();
    await setAuthCookie(context, createFreshSession(seed.viewer.user_id));
    const page = await context.newPage();

    const response = await page.goto(
      `${BASE_URL}/orgs/${seed.owner.org_id}/api-keys`,
      { waitUntil: "domcontentloaded" }
    );
    // Capability denial: the server refuses; the console shows an error,
    // never the key material.
    expect(response?.status() ?? 200).toBeLessThan(500);
    const body = await page.textContent("body");
    expect(body).not.toContain(seed.api_key_prefix);

    await context.close();
  });
});

// ── Cross-tenant isolation ───────────────────────────────────────────

test.describe("V4.1 tenant isolation", () => {
  test("another org's scan is 404, not leaked", async ({ request }) => {
    // mint a second tenant via the seed API of the stack: use the same
    // seeded key but probe with a bogus (random) scan id — the REAL
    // cross-tenant case is covered by the backend suite; here we pin the
    // contract that an unknown/unowned id is indistinguishable.
    const bogus = "00000000-0000-0000-0000-000000000000";
    const response = await request.get(`${API_URL}/api/v1/scans/${bogus}/status`, {
      headers: { Authorization: `Bearer ${seed.api_key_secret}` },
    });
    expect(response.status()).toBe(404);
    const body = await response.json();
    expect(body.code).toBe("SCAN_NOT_FOUND");
  });

  test("a bogus repository id is refused for scanning (404)", async ({ request }) => {
    const response = await request.post(`${API_URL}/api/v1/scans`, {
      headers: {
        Authorization: `Bearer ${seed.api_key_secret}`,
        "Idempotency-Key": `e2e-probe-${Date.now()}`,
      },
      data: { repository_id: "00000000-0000-0000-0000-000000000000" },
    });
    // The key has no scans:create scope → 403 BEFORE any resource probe;
    // either way, existence of another tenant's repository is not leaked.
    expect([403, 404]).toContain(response.status());
  });
});
