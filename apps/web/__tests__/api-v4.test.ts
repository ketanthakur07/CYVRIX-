/**
 * V4.0 API client contract tests.
 *
 * The client's job is to state the TENANT PRECISELY: the organization
 * travels in the request PATH (a selector the server verifies), never in a
 * request body that the server might treat as authority. These tests pin
 * that shape, and pin that failure reason codes are surfaced without
 * leaking free text.
 */
import {
  acceptOrgInvitation,
  apiFetch,
  ApiError,
  changeMemberRole,
  changeMemberState,
  createApiKey,
  createOrgInvitation,
  createOrganization,
  fetchApiKeys,
  fetchOrgCapabilities,
  fetchOrgInvitations,
  fetchOrgMembers,
  fetchOrgPolicy,
  fetchOrganizations,
  revokeApiKey,
  revokeOrgInvitation,
  updateOrgPolicy,
} from "@/lib/api";

const mockFetch = jest.fn();
global.fetch = mockFetch;

const OK_JSON = (body: unknown) =>
  ({ ok: true, status: 200, json: async () => body }) as unknown as Response;

function lastCall(): [string, RequestInit] {
  const call = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  return [call[0] as string, call[1] as RequestInit];
}

beforeEach(() => {
  mockFetch.mockReset();
});

const ORG = "11111111-1111-1111-1111-111111111111";
const USER = "22222222-2222-2222-2222-222222222222";

describe("organization routes", () => {
  it("lists organizations from /api/orgs", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON([]));
    await fetchOrganizations();
    expect(lastCall()[0]).toBe("/api/orgs");
  });

  it("creates an organization with only a name", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ id: ORG }));
    await createOrganization("Acme");
    const [url, init] = lastCall();
    expect(url).toBe("/api/orgs");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ name: "Acme" });
  });

  it("derives capabilities from the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ capabilities: [] }));
    await fetchOrgCapabilities(ORG);
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/capabilities`);
  });

  it("lists members from the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON([]));
    await fetchOrgMembers(ORG);
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/members`);
  });
});

describe("membership mutation bodies carry no authority", () => {
  it("sends only the target role when changing a role", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ user_id: USER }));
    await changeMemberRole(ORG, USER, "AUDITOR");
    const [url, init] = lastCall();
    expect(url).toBe(`/api/orgs/${ORG}/members/${USER}`);
    expect(init.method).toBe("PATCH");
    // Exactly one field: the new role for the TARGET member.
    expect(JSON.parse(init.body as string)).toEqual({ role: "AUDITOR" });
  });

  it("sends only the target state when changing membership", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ user_id: USER }));
    await changeMemberState(ORG, USER, "SUSPENDED");
    const [url, init] = lastCall();
    expect(url).toBe(`/api/orgs/${ORG}/members/${USER}/state`);
    expect(JSON.parse(init.body as string)).toEqual({ state: "SUSPENDED" });
  });
});

describe("invitations", () => {
  it("creates an invitation scoped to the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ id: "inv", token: "tok" }));
    await createOrgInvitation(ORG, { email: "a@b.c", role: "DEVELOPER" });
    const [url, init] = lastCall();
    expect(url).toBe(`/api/orgs/${ORG}/invitations`);
    expect(JSON.parse(init.body as string)).toEqual({
      email: "a@b.c",
      role: "DEVELOPER",
    });
  });

  it("accepts an invitation by token only (no organization selector)", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ id: ORG }));
    await acceptOrgInvitation("plaintext-token");
    const [url, init] = lastCall();
    expect(url).toBe("/api/invitations/accept");
    // The token is the authority; the caller cannot name the organization.
    expect(JSON.parse(init.body as string)).toEqual({
      token: "plaintext-token",
    });
  });

  it("lists and revokes invitations on the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON([]));
    await fetchOrgInvitations(ORG);
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/invitations`);

    mockFetch.mockResolvedValueOnce(OK_JSON({ id: "inv" }));
    await revokeOrgInvitation(ORG, "inv");
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/invitations/inv/revoke`);
  });
});

describe("policy", () => {
  it("reads and writes the policy on the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ policy: {}, version: 1 }));
    await fetchOrgPolicy(ORG);
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/policy`);

    mockFetch.mockResolvedValueOnce(OK_JSON({ policy: {}, version: 2 }));
    await updateOrgPolicy(ORG, { require_two_approvers: true });
    const [url, init] = lastCall();
    expect(url).toBe(`/api/orgs/${ORG}/policy`);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({
      policy: { require_two_approvers: true },
    });
  });
});

describe("API keys", () => {
  it("lists keys on the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON([]));
    await fetchApiKeys(ORG);
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/api-keys`);
  });

  it("creates a key with name, scopes and optional expiry only", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ id: "k", secret: "s" }));
    await createApiKey(ORG, {
      name: "CI",
      scopes: ["findings:read"],
      expires_at: "2030-01-01T00:00:00.000Z",
    });
    const [url, init] = lastCall();
    expect(url).toBe(`/api/orgs/${ORG}/api-keys`);
    expect(JSON.parse(init.body as string)).toEqual({
      name: "CI",
      scopes: ["findings:read"],
      expires_at: "2030-01-01T00:00:00.000Z",
    });
  });

  it("revokes a key on the organization path", async () => {
    mockFetch.mockResolvedValueOnce(OK_JSON({ id: "k" }));
    await revokeApiKey(ORG, "k");
    expect(lastCall()[0]).toBe(`/api/orgs/${ORG}/api-keys/k/revoke`);
  });
});

describe("tenancy invariant", () => {
  it("never sends organization_id in a request body", async () => {
    const cases: Array<() => Promise<unknown>> = [
      () => createOrganization("Acme"),
      () => changeMemberRole(ORG, USER, "VIEWER"),
      () => changeMemberState(ORG, USER, "ACTIVE"),
      () => createOrgInvitation(ORG, { email: null, role: "VIEWER" }),
      () => revokeOrgInvitation(ORG, "inv"),
      () => acceptOrgInvitation("tok"),
      () => updateOrgPolicy(ORG, {}),
      () => createApiKey(ORG, { name: "x", scopes: ["findings:read"] }),
      () => revokeApiKey(ORG, "k"),
    ];

    for (const run of cases) {
      mockFetch.mockReset();
      mockFetch.mockResolvedValueOnce(OK_JSON({}));
      await run();
      const init = lastCall()[1];
      const body = (init.body as string) ?? "";
      expect(body).not.toContain("organization_id");
      // The tenant is a path segment, so a body must never select it.
      expect(body).not.toMatch(/"(org|tenant)_id"/);
    }
  });
});

describe("org failure reason codes", () => {
  it("surfaces ORG_CAPABILITY_REQUIRED from a 403", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({
        detail: {
          reason_code: "ORG_CAPABILITY_REQUIRED",
          message: "nope",
        },
      }),
    } as unknown as Response);

    await expect(apiFetch("/orgs/x/api-keys")).rejects.toMatchObject({
      status: 403,
      reasonCode: "ORG_CAPABILITY_REQUIRED",
    });
  });

  it("surfaces ORGANIZATION_NOT_FOUND from a 404 without confirming existence", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ detail: "ORGANIZATION_NOT_FOUND" }),
    } as unknown as Response);

    try {
      await fetchOrgMembers(ORG);
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).status).toBe(404);
      expect((e as ApiError).reasonCode).toBe("ORGANIZATION_NOT_FOUND");
    }
  });
});
