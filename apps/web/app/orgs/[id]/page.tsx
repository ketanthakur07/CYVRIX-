"use client";

/**
 * V4.0 organization settings — policy and tenant metadata.
 *
 * Policy editing is capability-gated (MANAGE_POLICY). The server keeps an
 * immutable revision per version, so saving here creates a new version
 * rather than rewriting history: an action already evaluated against
 * version N can always be explained against version N.
 */
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, History, Save, ShieldCheck } from "lucide-react";
import { fetchOrgPolicy, updateOrgPolicy } from "@/lib/api";
import { useOrg, useOrgCapabilities } from "@/lib/org";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, DataList, DataRow, Section } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { OrgHeader } from "@/components/org/org-header";
import { ORG_CAP } from "@/lib/types";
import { formatTime } from "@/lib/workflow";

export default function OrganizationSettingsPage() {
  const params = useParams<{ id: string }>();
  const organizationId = params?.id;
  const { organizations, currentOrgId, switchOrg } = useOrg();
  const caps = useOrgCapabilities(organizationId);

  const organization = organizations.find((o) => o.id === organizationId);
  const isCurrent = organizationId === currentOrgId;

  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<string>("");
  const [jsonError, setJsonError] = useState<string | null>(null);

  const policyQuery = useQuery({
    queryKey: ["org-policy", organizationId],
    queryFn: () => fetchOrgPolicy(organizationId as string),
    enabled: !!organizationId && !!organization,
  });

  useEffect(() => {
    if (policyQuery.data) {
      setDraft(JSON.stringify(policyQuery.data.policy ?? {}, null, 2));
      setJsonError(null);
    }
  }, [policyQuery.data]);

  const saveMutation = useMutation({
    mutationFn: (policy: Record<string, unknown>) =>
      updateOrgPolicy(organizationId as string, policy),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["org-policy", organizationId],
      });
      void queryClient.invalidateQueries({ queryKey: ["orgs"] });
    },
  });

  if (!organization) {
    // The organization is not among the caller's memberships. Do not
    // confirm whether it exists — mirror the server's 404-for-non-member.
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <Card className="p-8 text-center">
          <Building2 className="h-8 w-8 text-gray-300 mx-auto mb-2" />
          <p className="font-medium text-gray-700">
            Organization not found
          </p>
          <p className="text-sm text-gray-500 mt-1">
            It either does not exist or your membership is not active.
          </p>
        </Card>
      </div>
    );
  }

  const canEdit = caps.hasCapability(ORG_CAP.MANAGE_POLICY) && isCurrent;

  const onSave = () => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(draft || "{}");
    } catch {
      setJsonError("Policy must be valid JSON.");
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      setJsonError("Policy must be a JSON object.");
      return;
    }
    setJsonError(null);
    saveMutation.mutate(parsed as Record<string, unknown>);
  };

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <OrgHeader organization={organization} />

      <Section
        title="Organization"
        icon={<Building2 className="h-4 w-4" />}
      >
        <DataList columns={2}>
          <DataRow label="Name">{organization.name}</DataRow>
          <DataRow label="Slug" mono>
            {organization.slug}
          </DataRow>
          <DataRow label="State">{organization.state}</DataRow>
          <DataRow label="Type">
            {organization.is_personal ? "Personal" : "Shared"}
          </DataRow>
          <DataRow label="Policy version">
            {organization.policy_version}
          </DataRow>
          <DataRow label="Created">{formatTime(organization.created_at)}</DataRow>
        </DataList>
      </Section>

      <Section
        className="mt-5"
        title="Organization policy"
        icon={<ShieldCheck className="h-4 w-4" />}
        actions={
          policyQuery.data ? (
            <Badge tone="info">
              <History className="h-3 w-3" />
              version {policyQuery.data.version}
            </Badge>
          ) : undefined
        }
      >
        <Alert tone="info" className="mb-4" title="Versioned, never rewritten">
          Saving creates a new policy version. Existing decisions keep
          pointing at the version they were evaluated against.
        </Alert>

        {policyQuery.isLoading ? (
          <LoadingBlock label="Loading policy" />
        ) : policyQuery.isError ? (
          <ErrorState
            title="Policy unavailable"
            error={policyQuery.error}
            onRetry={() => policyQuery.refetch()}
          />
        ) : (
          <>
            {!canEdit && (
              <Alert tone="warning" className="mb-4" title="Read-only">
                {!isCurrent
                  ? "This is not your current organization. Switch to it to edit its policy."
                  : "Your role does not include MANAGE_POLICY."}
              </Alert>
            )}
            <label htmlFor="org-policy" className="block text-xs text-gray-500 mb-1">
              Policy document (JSON)
            </label>
            <textarea
              id="org-policy"
              value={draft}
              readOnly={!canEdit}
              onChange={(e) => setDraft(e.target.value)}
              rows={12}
              spellCheck={false}
              className="w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs focus:border-blue-500 focus:outline-none read-only:bg-gray-50"
            />
            {jsonError && (
              <p className="text-sm text-red-700 mt-2" role="alert">
                {jsonError}
              </p>
            )}
            {saveMutation.isError && (
              <p className="text-sm text-red-700 mt-2" role="alert">
                {saveMutation.error instanceof Error
                  ? saveMutation.error.message
                  : "Could not save the policy."}
              </p>
            )}
            {saveMutation.isSuccess && (
              <Alert tone="success" className="mt-3">
                Policy saved as version {saveMutation.data.version}.
              </Alert>
            )}
            <div className="mt-3 flex items-center gap-2">
              <Button
                onClick={onSave}
                disabled={!canEdit}
                pending={saveMutation.isPending}
                pendingLabel="Saving…"
              >
                <Save className="h-4 w-4" />
                Save policy
              </Button>
              {isCurrent && (
                <span className="text-xs text-gray-500">
                  Server re-checks MANAGE_POLICY on save.
                </span>
              )}
            </div>
          </>
        )}
      </Section>

      {!isCurrent && (
        <div className="mt-5">
          <Button variant="secondary" onClick={() => switchOrg(organization.id)}>
            Make this my current organization
          </Button>
        </div>
      )}
    </div>
  );
}
