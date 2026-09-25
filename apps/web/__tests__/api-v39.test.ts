/**
 * V3.9 API client contract tests.
 *
 * Verifies:
 * - structured server reason codes are surfaced without leaking free text
 * - 204 responses do not attempt JSON parsing
 * - lifecycle mutations send ONLY human metadata (no authority fields)
 */
import {
  apiFetch,
  ApiError,
  auditExportPath,
  authorizeAction,
  startRollback,
  startRemediation,
  startVerification,
  revokeAuthorization,
  setOpsState,
  setRepositoryControl,
} from "@/lib/api";

const mockFetch = jest.fn();
global.fetch = mockFetch;

function lastCall(): [string, RequestInit] {
  const call = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  return [call[0] as string, call[1] as RequestInit];
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe("ApiError reason codes", () => {
  it("extracts a machine reason code from an object detail", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({
        detail: { reason_code: "KILL_SWITCH_ACTIVE", message: "blocked" },
      }),
    });

    try {
      await apiFetch("/actions/x/authorize", { method: "POST" });
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).reasonCode).toBe("KILL_SWITCH_ACTIVE");
      expect((e as ApiError).status).toBe(409);
    }
  });

  it("accepts a bare reason code string", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({ detail: "STEP_UP_REQUIRED" }),
    });
    try {
      await apiFetch("/ops/state", { method: "POST" });
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as ApiError).reasonCode).toBe("STEP_UP_REQUIRED");
    }
  });

  it("does not treat arbitrary prose as a reason code", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ detail: "some free form server text" }),
    });
    try {
      await apiFetch("/anything");
      throw new Error("should have thrown");
    } catch (e) {
      expect((e as ApiError).reasonCode).toBeUndefined();
    }
  });
});

describe("no-body responses", () => {
  it("returns undefined for 204 without parsing JSON", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });
    const result = await apiFetch("/empty");
    expect(result).toBeUndefined();
  });
});

describe("mutations carry no authority fields", () => {
  it("startRollback sends an empty body (no SHA, no branch, no target)", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({}) });
    await startRollback("rem-1");
    const [url, init] = lastCall();
    expect(url).toBe("/api/remediations/rem-1/rollback");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({});
  });

  it("startVerification sends an empty body (no verified/result fields)", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({}) });
    await startVerification("rem-1");
    const [, init] = lastCall();
    expect(JSON.parse(init.body as string)).toEqual({});
  });

  it("startRemediation sends an empty body (no branch/digest/ceiling)", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 201, json: async () => ({}) });
    await startRemediation("run-1");
    const [url, init] = lastCall();
    expect(url).toBe("/api/actions/runs/run-1/remediation");
    expect(JSON.parse(init.body as string)).toEqual({});
  });

  it("authorizeAction sends only a human reason", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
    await authorizeAction("p-1", { reason: "looks good" });
    const [url, init] = lastCall();
    expect(url).toBe("/api/actions/p-1/authorize");
    expect(JSON.parse(init.body as string)).toEqual({ reason: "looks good" });
  });

  it("revokeAuthorization sends only a reason", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
    await revokeAuthorization("auth-1", { reason: "changed my mind" });
    const [url, init] = lastCall();
    expect(url).toBe("/api/actions/authorization/auth-1/revoke");
    expect(JSON.parse(init.body as string)).toEqual({ reason: "changed my mind" });
  });

  it("setOpsState sends only a target", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
    await setOpsState("PAUSED");
    const [url, init] = lastCall();
    expect(url).toBe("/api/ops/state");
    expect(JSON.parse(init.body as string)).toEqual({ target: "PAUSED" });
  });

  it("setRepositoryControl sends only control_state and reason", async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({}) });
    await setRepositoryControl("repo-1", { control_state: "PAUSED", reason: "incident" });
    const [url, init] = lastCall();
    expect(url).toBe("/api/ops/repositories/repo-1/control");
    expect(JSON.parse(init.body as string)).toEqual({
      control_state: "PAUSED",
      reason: "incident",
    });
  });
});

describe("audit export path", () => {
  it("is a same-origin attachment URL with an encoded chain id", () => {
    expect(auditExportPath("abc-123")).toBe("/api/audit/chains/abc-123/export");
    expect(auditExportPath("a/b")).toBe("/api/audit/chains/a%2Fb/export");
  });
});
