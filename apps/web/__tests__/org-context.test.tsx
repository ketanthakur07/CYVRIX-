/**
 * V4.0 tenant context tests.
 *
 * The genuinely security-relevant client behaviour is here: when the
 * selected organization changes, cached tenant data must not survive.
 * Otherwise organization A's findings would render under organization B's
 * name. The remaining tests pin tenant SELECTION rules (never auto-select
 * a non-ACTIVE membership) and the pure helpers that decide both.
 */
import React from "react";
import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

jest.mock("@/lib/auth", () => ({
  useAuth: () => ({ isAuthenticated: true, isLoading: false }),
}));

import {
  OrgProvider,
  useOrg,
  isTenantIndependentQuery,
  pickDefaultOrganization,
  resolveCurrentOrganization,
} from "@/lib/org";
import type { Organization } from "@/lib/types";

function org(over: Partial<Organization>): Organization {
  return {
    id: "org",
    name: "Org",
    slug: "org",
    state: "ACTIVE",
    is_personal: false,
    policy_version: 1,
    role: "VIEWER",
    membership_state: "ACTIVE",
    created_at: null,
    ...over,
  };
}

const PERSONAL = org({
  id: "org-a",
  name: "Personal A",
  slug: "personal-a",
  is_personal: true,
  role: "ORG_OWNER",
});
const SHARED = org({
  id: "org-b",
  name: "Shared B",
  slug: "shared-b",
  role: "AUDITOR",
});
const SUSPENDED = org({
  id: "org-c",
  name: "Suspended C",
  slug: "suspended-c",
  membership_state: "SUSPENDED",
});

describe("pickDefaultOrganization", () => {
  it("prefers the personal organization", () => {
    expect(pickDefaultOrganization([SHARED, PERSONAL])?.id).toBe("org-a");
  });

  it("falls back to the first ACTIVE membership", () => {
    expect(pickDefaultOrganization([SHARED])?.id).toBe("org-b");
  });

  it("never auto-selects a non-ACTIVE membership", () => {
    expect(pickDefaultOrganization([SUSPENDED])).toBeNull();
    expect(pickDefaultOrganization([SUSPENDED, SHARED])?.id).toBe("org-b");
  });

  it("returns null for an empty or missing list", () => {
    expect(pickDefaultOrganization([])).toBeNull();
    expect(pickDefaultOrganization(undefined)).toBeNull();
  });
});

describe("resolveCurrentOrganization", () => {
  it("honours an explicit choice while it is still ACTIVE", () => {
    expect(resolveCurrentOrganization([PERSONAL, SHARED], "org-b")?.id).toBe(
      "org-b"
    );
  });

  it("ignores a choice whose membership is no longer ACTIVE", () => {
    expect(
      resolveCurrentOrganization([PERSONAL, SHARED, SUSPENDED], "org-c")?.id
    ).toBe("org-a");
  });

  it("ignores a choice the caller can no longer see at all", () => {
    expect(resolveCurrentOrganization([PERSONAL, SHARED], "org-gone")?.id).toBe(
      "org-a"
    );
  });

  it("falls back to the default when there is no choice", () => {
    expect(resolveCurrentOrganization([PERSONAL, SHARED], null)?.id).toBe(
      "org-a"
    );
  });
});

describe("isTenantIndependentQuery", () => {
  it("keeps only the caller's own organization list", () => {
    expect(isTenantIndependentQuery(["orgs"])).toBe(true);
    for (const key of [
      ["audit-chains"],
      ["org-members", "org-a"],
      ["org-api-keys", "org-a"],
      ["org-policy", "org-a"],
      ["repositories"],
      ["dashboard"],
      ["org-capabilities", "org-a"],
    ]) {
      expect(isTenantIndependentQuery(key)).toBe(false);
    }
  });
});

// ── Provider behaviour ────────────────────────────────────────────────

function jsonOk(body: unknown) {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

function makeFetchMock() {
  return jest.fn(async (url: string) => {
    if (url.endsWith("/api/orgs")) {
      return jsonOk([PERSONAL, SHARED, SUSPENDED]);
    }
    if (url.includes("/capabilities")) {
      return jsonOk({
        organization_id: url.split("/")[3],
        role: "ORG_OWNER",
        membership_state: "ACTIVE",
        capabilities: ["VIEW_ACTIONS", "MANAGE_MEMBERS"],
      });
    }
    return jsonOk({});
  });
}

function Harness() {
  const { currentOrgId, switchOrg, hasCapability } = useOrg();
  return (
    <div>
      <span data-testid="current">{currentOrgId ?? "none"}</span>
      <span data-testid="can-manage">{String(hasCapability("MANAGE_MEMBERS"))}</span>
      <button onClick={() => switchOrg("org-b")}>switch</button>
    </div>
  );
}

function renderWithClient(queryClient: QueryClient) {
  return render(
    <QueryClientProvider client={queryClient}>
      <OrgProvider>
        <Harness />
      </OrgProvider>
    </QueryClientProvider>
  );
}

describe("OrgProvider", () => {
  let queryClient: QueryClient;

  beforeEach(() => {
    global.fetch = makeFetchMock() as unknown as typeof fetch;
    queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, gcTime: Infinity } },
    });
  });

  it("selects the personal organization by default", async () => {
    renderWithClient(queryClient);
    expect(await screen.findByText("org-a")).toBeTruthy();
  });

  it("exposes server-derived capabilities for the current organization", async () => {
    renderWithClient(queryClient);
    expect(await screen.findByText("true")).toBeTruthy();
  });

  it("drops cached tenant data when the organization changes", async () => {
    // Seed cache entries that belong to organization A.
    queryClient.setQueryData(["orgs"], [PERSONAL, SHARED, SUSPENDED]);
    queryClient.setQueryData(["audit-chains"], [{ chain_id: "a" }]);
    queryClient.setQueryData(["org-members", "org-a"], [{ user_id: "u" }]);
    queryClient.setQueryData(["org-api-keys", "org-a"], [{ id: "k" }]);
    queryClient.setQueryData(["dashboard"], { total_findings: 5 });

    renderWithClient(queryClient);
    await screen.findByText("org-a");

    fireEvent.click(screen.getByText("switch"));

    // Every tenant-scoped entry is gone...
    expect(queryClient.getQueryData(["audit-chains"])).toBeUndefined();
    expect(queryClient.getQueryData(["org-members", "org-a"])).toBeUndefined();
    expect(queryClient.getQueryData(["org-api-keys", "org-a"])).toBeUndefined();
    expect(queryClient.getQueryData(["dashboard"])).toBeUndefined();

    // ...but the caller's own organization list is retained.
    expect(queryClient.getQueryData(["orgs"])).toBeDefined();

    // And the selector now points at the new organization.
    expect(await screen.findByText("org-b")).toBeTruthy();
  });
});
