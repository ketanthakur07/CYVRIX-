"use client";

/**
 * V4.0 shared header for an organization's pages.
 *
 * The tabs are shown based on server-derived capabilities, but this is a
 * UX affordance: each page and each API route independently enforces the
 * capability, so a hidden tab is never the reason a request is refused.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Building2, KeyRound, Settings2, Users } from "lucide-react";
import { PageHeader } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toneFor, MEMBERSHIP_TONE, ORG_ROLE_TONE } from "@/lib/workflow";
import { ORG_ROLE_LABELS } from "@/lib/types";
import type { Organization } from "@/lib/types";

export function OrgHeader({
  organization,
  children,
}: {
  organization: Organization;
  children?: React.ReactNode;
}) {
  const pathname = usePathname();
  const base = `/orgs/${organization.id}`;

  const tabs = [
    { href: base, label: "Settings", icon: Settings2, exact: true },
    { href: `${base}/members`, label: "Members", icon: Users },
    { href: `${base}/api-keys`, label: "API keys", icon: KeyRound },
  ];

  const roleLabel =
    organization.role && organization.role in ORG_ROLE_LABELS
      ? ORG_ROLE_LABELS[organization.role as keyof typeof ORG_ROLE_LABELS]
      : organization.role;

  return (
    <div className="mb-6">
      <PageHeader
        backHref="/orgs"
        backLabel="All organizations"
        title={organization.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1">
              <Building2 className="h-3.5 w-3.5" />
              {organization.slug}
            </span>
            {organization.is_personal && <span>· personal organization</span>}
            {organization.state && (
              <Badge tone={toneFor({ ACTIVE: "success", SUSPENDED: "warning", DELETED: "danger" }, organization.state)}>
                {organization.state.toLowerCase()}
              </Badge>
            )}
            {roleLabel && (
              <Badge tone={toneFor(ORG_ROLE_TONE, organization.role)}>
                {roleLabel}
              </Badge>
            )}
            {organization.membership_state &&
              organization.membership_state !== "ACTIVE" && (
                <Badge tone={toneFor(MEMBERSHIP_TONE, organization.membership_state)}>
                  membership {organization.membership_state.toLowerCase()}
                </Badge>
              )}
          </span>
        }
        actions={children}
      />

      <nav aria-label="Organization sections" className="flex items-center gap-1 border-b">
        {tabs.map((tab) => {
          const active = tab.exact
            ? pathname === tab.href
            : pathname.startsWith(tab.href);
          const Icon = tab.icon;
          return (
            <Link
              key={tab.href}
              href={tab.href}
              aria-current={active ? "page" : undefined}
              className={`-mb-px inline-flex items-center gap-2 border-b-2 px-3 py-2 text-sm font-medium transition-colors ${
                active
                  ? "border-blue-600 text-blue-700"
                  : "border-transparent text-gray-600 hover:text-gray-900"
              }`}
            >
              <Icon className="h-4 w-4" />
              {tab.label}
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
