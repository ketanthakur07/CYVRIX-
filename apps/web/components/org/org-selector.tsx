"use client";

/**
 * V4.0 organization switcher.
 *
 * Switching changes the SELECTOR only. The server re-verifies membership
 * on the next request, and `switchOrg` drops every cached tenant query so
 * no other organization's data can render under the new one.
 */
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Building2 } from "lucide-react";
import { useOrg } from "@/lib/org";
import { ORG_ROLE_LABELS } from "@/lib/types";
import type { OrgRole } from "@/lib/types";

export function OrgSelector() {
  const { organizations, currentOrgId, currentOrg, switchOrg, isLoading } =
    useOrg();
  const router = useRouter();

  if (isLoading) {
    return (
      <div
        className="h-9 w-44 rounded-md bg-gray-200 animate-pulse"
        aria-hidden="true"
      />
    );
  }

  // No memberships yet is a normal, if unusual, state: send the caller to
  // the organization index rather than inventing a tenant.
  if (organizations.length === 0) {
    return (
      <Link
        href="/orgs"
        className="inline-flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-md"
      >
        <Building2 className="h-4 w-4" />
        Create organization
      </Link>
    );
  }

  const label = currentOrg ? currentOrg.name : "Select organization";
  const role = currentOrg?.role;
  const roleLabel =
    role && role in ORG_ROLE_LABELS ? ORG_ROLE_LABELS[role as OrgRole] : role;

  return (
    <div className="flex items-center gap-2">
      <Building2 className="h-4 w-4 text-gray-400" aria-hidden="true" />
      <label className="sr-only" htmlFor="org-selector">
        Current organization
      </label>
      <select
        id="org-selector"
        value={currentOrgId ?? ""}
        onChange={(e) => {
          const next = e.target.value;
          if (!next) return;
          switchOrg(next);
          router.push(`/orgs/${next}`);
        }}
        className="max-w-[14rem] rounded-md border border-gray-300 bg-white px-2 py-1.5 text-sm text-gray-800 focus:border-blue-500 focus:outline-none"
      >
        {organizations.map((org) => (
          <option key={org.id} value={org.id} disabled={org.membership_state !== "ACTIVE"}>
            {org.name}
            {org.membership_state && org.membership_state !== "ACTIVE"
              ? ` — ${org.membership_state.toLowerCase()}`
              : ""}
          </option>
        ))}
      </select>
      {roleLabel && (
        <span
          className="hidden lg:inline text-xs text-gray-500"
          title={`Your role: ${roleLabel}`}
        >
          {roleLabel}
        </span>
      )}
      <span className="sr-only" aria-live="polite">
        Current organization: {label}
      </span>
    </div>
  );
}
