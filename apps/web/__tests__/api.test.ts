/**
 * API client tests — verify error classification and safe messages.
 * Never exposes internal details, tokens, or stack traces.
 */
import { apiFetch, ApiError } from "@/lib/api";

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

beforeEach(() => {
  mockFetch.mockReset();
});

describe("apiFetch", () => {
  it("returns parsed JSON on success", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: "123", name: "test" }),
    });

    const result = await apiFetch("/test");
    expect(result).toEqual({ id: "123", name: "test" });
  });

  it("throws ApiError with safe message on 401", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: "Not authenticated" }),
    });

    await expect(apiFetch("/protected")).rejects.toThrow(ApiError);
    await expect(apiFetch("/protected")).rejects.toThrow(
      "Session expired"
    );
  });

  it("throws ApiError with safe message on 403", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 403,
      json: async () => ({}),
    });

    await expect(apiFetch("/forbidden")).rejects.toThrow("do not have access");
  });

  it("throws ApiError with safe message on 404", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({}),
    });

    await expect(apiFetch("/missing")).rejects.toThrow("not found");
  });

  it("throws ApiError with safe message on 409", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({}),
    });

    await expect(apiFetch("/conflict")).rejects.toThrow("conflicting operation");
  });

  it("throws safe message on network failure", async () => {
    mockFetch.mockRejectedValue(new Error("Network error"));

    await expect(apiFetch("/offline")).rejects.toThrow(
      "Unable to connect to the server"
    );
  });

  it("throws safe message on 500 errors", async () => {
    mockFetch.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: "Internal error" }),
    });

    await expect(apiFetch("/broken")).rejects.toThrow(
      "server encountered an error"
    );
  });

  it("never exposes raw error details to user", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => ({
        detail: "psycopg2.OperationalError: connection refused at port 5432",
      }),
    });

    try {
      await apiFetch("/broken");
      fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      // The safe message should NOT contain database details
      expect((e as ApiError).message).not.toContain("psycopg2");
      expect((e as ApiError).message).not.toContain("5432");
    }
  });
});
