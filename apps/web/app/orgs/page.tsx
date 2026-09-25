"use client";

/**
 * V4.0 organization index.
 *
 * Lists the organizations the caller has a recorded membership in and
 * allows creating a new one. Non-ACTIVE memberships are listed but marked,
 * and are not selectable as the active tenant (see `lib/org.tsx`).
 */
import { useState } from "react";
import Link from "next/link";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Building2, Plus, ArrowRight, Check } from "lucide-react";
import { createOrganization } from "@/lib/api";
import { useOrg, ORG_LIST_QUERY_KEY } from "@/lib/org";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, PageHeader } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { ApiError } from "@/lib/api";
import { toneFor, MEMBERSHIP_TONE, ORG_ROLE_TONE } from "@/lib/workflow";
import { ORG_ROLE_LABELS } from "@/lib/types";

export default function OrganizationsPage() {
  const { organizations, currentOrgId, isLoading, error, refresh, switchOrg } =
    useOrg();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");

  const createMutation = useMutation({
    mutationFn: (orgName: string) => createOrganization(orgName),
    onSuccess: (org) => {
      setName("");
      void queryClient.invalidateQueries({ queryKey: ORG_LIST_QUERY_KEY });
      // Select the organization the caller just created.
      switchOrg(org.id);
    },
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <LoadingBlock />
      </div>
    );
  }

  if (error && !(error instanceof ApiError && error.status === 403)) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <ErrorState
          title="Organizations unavailable"
          error={error}
          onRetry={refresh}
        />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title="Organizations"
        subtitle="Tenant boundaries. Every repository, finding, action and audit chain belongs to exactly one organization."
      />

      <Alert tone="info" className="mb-5" title="Membership is the boundary">
        You see an organization only while your membership is active. A
        suspended or removed membership stops granting access immediately —
        the server re-checks on every request.
      </Alert>

      <Card className="p-4 mb-6">
        <h2 className="text-sm font-semibold text-gray-900 mb-3 flex items-center gap-2">
          <Plus className="h-4 w-4" />
          Create an organization
        </h2>
        <form
          className="flex flex-col sm:flex-row gap-3 sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            if (name.trim().length === 0) return;
            createMutation.mutate(name.trim());
          }}
        >
          <div className="flex-1">
            <label
              htmlFor="new-org-name"
              className="block text-xs text-gray-500 mb-1"
            >
              Name
            </label>
            <input
              id="new-org-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={120}
              placeholder="Acme Security"
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
            />
          </div>
          <Button
            type="submit"
            pending={createMutation.isPending}
            pendingLabel="Creating…"
            disabled={name.trim().length === 0}
          >
            Create
          </Button>
        </form>
        {createMutation.isError && (
          <p className="text-sm text-red-700 mt-3" role="alert">
            {createMutation.error instanceof Error
              ? createMutation.error.message
              : "Could not create the organization."}
          </p>
        )}
      </Card>

      {organizations.length === 0 ? (
        <EmptyState
          icon={<Building2 className="h-8 w-8" />}
          title="No organizations yet"
          description="Create one above to start scanning and remediating repositories."
        />
      ) : (
        <ul className="space-y-3">
          {organizations.map((org) => {
            const isCurrent = org.id === currentOrgId;
            const roleLabel =
              org.role && org.role in ORG_ROLE_LABELS
                ? ORG_ROLE_LABELS[org.role as keyof typeof ORG_ROLE_LABELS]
                : org.role;
            return (
              <li key={org.id}>
                <Card className="p-4 flex items-center justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-gray-900 truncate">
                        {org.name}
                      </span>
                      {isCurrent && (
                        <Badge tone="info">
                          <Check className="h-3 w-3" />
                          current
                        </Badge>
                      )}
                      {org.is_personal && <Badge tone="neutral">personal</Badge>}
                      {roleLabel && (
                        <Badge tone={toneFor(ORG_ROLE_TONE, org.role)}>
                          {roleLabel}
                        </Badge>
                      )}
                      {org.membership_state &&
                        org.membership_state !== "ACTIVE" && (
                          <Badge tone={toneFor(MEMBERSHIP_TONE, org.membership_state)}>
                            {org.membership_state.toLowerCase()}
                          </Badge>
                        )}
                    </div>
                    <p className="text-xs text-gray-500 mt-1 font-mono break-all">
                      {org.slug}
                    </p>
                  </div>
                  <div className="shrink-0 flex items-center gap-2">
                    {org.membership_state === "ACTIVE" && !isCurrent && (
                      <Button
                        variant="secondary"
                        onClick={() => switchOrg(org.id)}
                      >
                        Switch
                      </Button>
                    )}
                    <Link
                      href={`/orgs/${org.id}`}
                      className="inline-flex items-center gap-1 px-3 py-2 text-sm font-medium text-blue-700 hover:text-blue-900"
                    >
                      Open
                      <ArrowRight className="h-4 w-4" />
                    </Link>
                  </div>
                </Card>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
