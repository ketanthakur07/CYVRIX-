"use client";

/**
 * CYVRIX V4.0 — organization (tenant) context.
 *
 * Responsibilities, and the line each one must not cross:
 *
 * 1. Hold the caller's CURRENT organization *selector*. This is a UI
 *    convenience: every request still carries the organization in its
 *    PATH and the server re-verifies the caller's ACTIVE membership. A
 *    tampered selector yields 404/403, never cross-tenant data.
 *
 * 2. Hold the caller's server-derived role + capabilities. These shape
 *    the UI ONLY — `hasCapability` is never a security check. Hiding a
 *    button is not authorization; the server authorizes every route.
 *
 * 3. Drop all cached tenant data when the organization changes. A stale
 *    react-query cache would otherwise show organization A's findings
 *    under organization B's name. This is the one client-side behaviour
 *    that is genuinely security-relevant, so it is implemented explicitly
 *    and covered by tests.
 *
 * Deliberately NOT here:
 *   - any way to set the caller's role or capability;
 *   - any browser storage. The selector lives in memory for the session
 *     only, so nothing tenant-related survives a reload, a logout, or a
 *     shared machine, and a stale id can never be replayed on reload.
 */
import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useMemo,
} from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchOrganizations, fetchOrgCapabilities } from "./api";
import { useAuth } from "./auth";
import { ORG_CAP, effectiveCapabilities } from "./types";
import type { Organization, OrgCapabilities } from "./types";

export const ORG_LIST_QUERY_KEY = ["orgs"] as const;
export const ORG_CAPABILITIES_QUERY_KEY = ["org-capabilities"] as const;

/**
 * Query roots that are NOT tenant-scoped and therefore survive an
 * organization switch. Everything else is treated as tenant data and is
 * removed from the cache, because the safest default is to forget.
 *
 * `orgs` is the caller's own membership list (the same for every org), so
 * keeping it avoids a pointless refetch and a loading flash.
 */
const TENANT_INDEPENDENT_QUERY_ROOTS: readonly string[] = ["orgs"];

export function isTenantIndependentQuery(queryKey: readonly unknown[]): boolean {
  const root = queryKey?.[0];
  return typeof root === "string" && TENANT_INDEPENDENT_QUERY_ROOTS.includes(root);
}

/**
 * Choose the organization to select when the caller has made no explicit
 * choice: prefer a personal organization (the implicit default tenant),
 * otherwise the first ACTIVE membership in server order. A non-ACTIVE
 * membership is never auto-selected.
 */
export function pickDefaultOrganization(
  organizations: Organization[] | undefined
): Organization | null {
  if (!organizations || organizations.length === 0) return null;
  const active = organizations.filter((o) => o.membership_state === "ACTIVE");
  if (active.length === 0) return null;
  return active.find((o) => o.is_personal) ?? active[0];
}

/**
 * Resolve the effective selector: honour an explicit choice only while
 * the caller still holds that organization with an ACTIVE membership;
 * otherwise fall back to the default.
 */
export function resolveCurrentOrganization(
  organizations: Organization[] | undefined,
  selectedId: string | null
): Organization | null {
  if (!organizations || organizations.length === 0) return null;
  if (selectedId) {
    const match = organizations.find((o) => o.id === selectedId);
    if (match && match.membership_state === "ACTIVE") return match;
  }
  return pickDefaultOrganization(organizations);
}

interface OrgContextType {
  organizations: Organization[];
  currentOrgId: string | null;
  currentOrg: Organization | null;
  role: string | null;
  membershipState: string | null;
  capabilities: string[];
  isActiveMember: boolean;
  isLoading: boolean;
  error: unknown;
  switchOrg: (organizationId: string) => void;
  refresh: () => void;
  hasCapability: (capability: string) => boolean;
  canManageMembers: boolean;
  canManageApiKeys: boolean;
  canManagePolicy: boolean;
}

const OrgContext = createContext<OrgContextType | undefined>(undefined);

export function OrgProvider({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const queryClient = useQueryClient();

  const [selectedId, setSelectedId] = useState<string | null>(null);

  const orgsQuery = useQuery({
    queryKey: ORG_LIST_QUERY_KEY,
    queryFn: fetchOrganizations,
    enabled: isAuthenticated,
    staleTime: 5 * 60 * 1000,
  });

  const organizations = useMemo(() => orgsQuery.data ?? [], [orgsQuery.data]);

  const resolved = useMemo(
    () => resolveCurrentOrganization(organizations, selectedId),
    [organizations, selectedId]
  );

  const capsQuery = useQuery({
    queryKey: [...ORG_CAPABILITIES_QUERY_KEY, resolved?.id ?? "none"],
    queryFn: () => fetchOrgCapabilities(resolved!.id),
    enabled: isAuthenticated && !!resolved,
    staleTime: 60 * 1000,
  });

  const caps: OrgCapabilities | undefined = capsQuery.data;

  // A membership only confers capability while ACTIVE. The server already
  // applies this; re-applying it client-side keeps the UI honest for a
  // suspended member whose stale capability payload is still cached.
  const capabilities = useMemo(
    () => effectiveCapabilities(caps?.capabilities, caps?.membership_state),
    [caps]
  );

  const membershipState =
    caps?.membership_state ?? resolved?.membership_state ?? null;

  const switchOrg = useCallback(
    (organizationId: string) => {
      setSelectedId(organizationId);
      // Tenant safety: everything except the caller's own org list is
      // considered organization-scoped and must not survive the switch.
      queryClient.removeQueries({
        predicate: (query) => !isTenantIndependentQuery(query.queryKey),
      });
    },
    [queryClient]
  );

  const refresh = useCallback(() => {
    queryClient.removeQueries({
      predicate: (query) => !isTenantIndependentQuery(query.queryKey),
    });
    void queryClient.invalidateQueries({ queryKey: ORG_LIST_QUERY_KEY });
  }, [queryClient]);

  const capabilitySet = useMemo(() => new Set(capabilities), [capabilities]);
  const hasCapability = useCallback(
    (capability: string) => capabilitySet.has(capability),
    [capabilitySet]
  );

  const value: OrgContextType = {
    organizations,
    currentOrgId: resolved?.id ?? null,
    currentOrg: resolved,
    role: caps?.role ?? resolved?.role ?? null,
    membershipState,
    capabilities,
    isActiveMember: membershipState === "ACTIVE",
    isLoading: authLoading || orgsQuery.isLoading,
    error: orgsQuery.error,
    switchOrg,
    refresh,
    hasCapability,
    canManageMembers: capabilitySet.has(ORG_CAP.MANAGE_MEMBERS),
    canManageApiKeys: capabilitySet.has(ORG_CAP.MANAGE_API_KEYS),
    canManagePolicy: capabilitySet.has(ORG_CAP.MANAGE_POLICY),
  };

  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg() {
  const context = useContext(OrgContext);
  if (context === undefined) {
    throw new Error("useOrg must be used within an OrgProvider");
  }
  return context;
}

interface OrgCapabilityState {
  capabilities: string[];
  role: string | null;
  membershipState: string | null;
  isActiveMember: boolean;
  isLoading: boolean;
  error: unknown;
  hasCapability: (capability: string) => boolean;
}

/**
 * Server-derived capabilities for ONE organization, keyed so the result is
 * shared with the provider when the ids match. Used by an organization's
 * detail pages so they stay correct even when the page's organization is
 * not the currently selected tenant.
 *
 * Again: this shapes the UI only. The server authorizes every route.
 */
export function useOrgCapabilities(
  organizationId: string | undefined
): OrgCapabilityState {
  const query = useQuery({
    queryKey: [...ORG_CAPABILITIES_QUERY_KEY, organizationId ?? "none"],
    queryFn: () => fetchOrgCapabilities(organizationId as string),
    enabled: !!organizationId,
    staleTime: 60 * 1000,
  });

  const capabilities = useMemo(
    () =>
      effectiveCapabilities(
        query.data?.capabilities,
        query.data?.membership_state
      ),
    [query.data]
  );
  const capabilitySet = useMemo(() => new Set(capabilities), [capabilities]);

  return {
    capabilities,
    role: query.data?.role ?? null,
    membershipState: query.data?.membership_state ?? null,
    isActiveMember: query.data?.membership_state === "ACTIVE",
    isLoading: query.isLoading,
    error: query.error,
    hasCapability: (capability: string) => capabilitySet.has(capability),
  };
}
