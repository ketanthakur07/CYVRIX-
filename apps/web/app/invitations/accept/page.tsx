"use client";

/**
 * V4.0 — accept an organization invitation.
 *
 * The token in the URL is the authority for this one action. It is
 * single-use, expiring and (when the invitation was email-bound) only
 * accepted by a user with the matching email. Acceptance is explicit:
 * there is no auto-accept on page load, so a prefetched or shared link
 * cannot silently join the caller to a tenant.
 */
import { Suspense, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { MailCheck, ShieldAlert } from "lucide-react";
import { acceptOrgInvitation } from "@/lib/api";
import { useOrg, ORG_LIST_QUERY_KEY } from "@/lib/org";
import { useQueryClient } from "@tanstack/react-query";
import { Alert } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, PageHeader } from "@/components/ui/card";
import { LoadingBlock } from "@/components/ui/query-state";

function AcceptInvitationContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const queryClient = useQueryClient();
  const { switchOrg } = useOrg();

  const token = searchParams.get("token") ?? "";
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const accept = async () => {
    setPending(true);
    setError(null);
    try {
      const organization = await acceptOrgInvitation(token);
      await queryClient.invalidateQueries({ queryKey: ORG_LIST_QUERY_KEY });
      switchOrg(organization.id);
      router.push(`/orgs/${organization.id}`);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "The invitation could not be accepted."
      );
      setPending(false);
    }
  };

  if (!token) {
    return (
      <Card className="p-8 text-center">
        <ShieldAlert className="h-8 w-8 text-amber-500 mx-auto mb-2" />
        <p className="font-medium text-gray-800">No invitation token</p>
        <p className="text-sm text-gray-500 mt-1">
          This page needs an invitation link. Ask an organization
          administrator to send one.
        </p>
      </Card>
    );
  }

  return (
    <Card className="p-6">
      <div className="flex items-start gap-3 mb-4">
        <MailCheck className="h-6 w-6 text-blue-600 shrink-0" />
        <div>
          <h2 className="font-semibold text-gray-900">
            Accept your organization invitation
          </h2>
          <p className="text-sm text-gray-500 mt-1">
            You will be added as a member of the inviting organization. Your
            role and its capabilities are decided by the invitation, not by
            anything on this page.
          </p>
        </div>
      </div>

      {error && (
        <Alert tone="danger" className="mb-4" title="Could not accept" role="alert">
          {error}
        </Alert>
      )}

      <Button onClick={accept} pending={pending} pendingLabel="Accepting…">
        Accept invitation
      </Button>
      <p className="text-xs text-gray-500 mt-3">
        The token is single-use. If it has already been used, revoked or has
        expired, the server will refuse it.
      </p>
    </Card>
  );
}

export default function AcceptInvitationPage() {
  return (
    <div className="container mx-auto px-4 py-8 max-w-lg">
      <PageHeader
        title="Organization invitation"
        subtitle="Invitations are single-use and expire."
      />
      <Suspense fallback={<LoadingBlock />}>
        <AcceptInvitationContent />
      </Suspense>
      <p className="text-sm text-gray-500 mt-5">
        <Link href="/orgs" className="text-blue-700 hover:text-blue-900 underline">
          Back to organizations
        </Link>
      </p>
    </div>
  );
}
