"use client";

/**
 * V4.0 members and invitations.
 *
 * Membership changes are capability-gated (MANAGE_MEMBERS) and further
 * constrained by server rules the UI merely reflects: only an owner may
 * grant or revoke the owner role, and the last active owner cannot be
 * demoted or removed. The UI disables those actions; the server refuses
 * them independently.
 */
import { useState } from "react";
import { useParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Mail, ShieldAlert, UserPlus, Users, X } from "lucide-react";
import {
  changeMemberRole,
  changeMemberState,
  createOrgInvitation,
  fetchOrgInvitations,
  fetchOrgMembers,
  revokeOrgInvitation,
} from "@/lib/api";
import { useOrg, useOrgCapabilities } from "@/lib/org";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, Section } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { OrgHeader } from "@/components/org/org-header";
import { SecretReveal } from "@/components/org/secret-reveal";
import {
  ORG_CAP,
  ORG_ROLES,
  ORG_ROLE_DESCRIPTIONS,
  ORG_ROLE_LABELS,
} from "@/lib/types";
import type { OrgInvitationCreated } from "@/lib/types";
import {
  formatTime,
  toneFor,
  MEMBERSHIP_TONE,
  ORG_ROLE_TONE,
  invitationStatusLabel,
  invitationTone,
} from "@/lib/workflow";

export default function OrganizationMembersPage() {
  const params = useParams<{ id: string }>();
  const organizationId = params?.id;
  const { organizations } = useOrg();
  const caps = useOrgCapabilities(organizationId);
  const queryClient = useQueryClient();

  const organization = organizations.find((o) => o.id === organizationId);
  const canManage = caps.hasCapability(ORG_CAP.MANAGE_MEMBERS);
  const isOwner = caps.role === "ORG_OWNER";

  const [email, setEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<string>("VIEWER");
  const [issued, setIssued] = useState<OrgInvitationCreated | null>(null);

  const membersQuery = useQuery({
    queryKey: ["org-members", organizationId],
    queryFn: () => fetchOrgMembers(organizationId as string),
    enabled: !!organizationId && !!organization,
  });

  const invitationsQuery = useQuery({
    queryKey: ["org-invitations", organizationId],
    queryFn: () => fetchOrgInvitations(organizationId as string),
    enabled: !!organizationId && !!organization && canManage,
  });

  const invalidateMembers = () => {
    void queryClient.invalidateQueries({ queryKey: ["org-members", organizationId] });
  };
  const invalidateInvitations = () => {
    void queryClient.invalidateQueries({
      queryKey: ["org-invitations", organizationId],
    });
  };

  const roleMutation = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) =>
      changeMemberRole(organizationId as string, userId, role),
    onSuccess: invalidateMembers,
  });

  const stateMutation = useMutation({
    mutationFn: ({ userId, state }: { userId: string; state: string }) =>
      changeMemberState(organizationId as string, userId, state),
    onSuccess: invalidateMembers,
  });

  const inviteMutation = useMutation({
    mutationFn: () =>
      createOrgInvitation(organizationId as string, {
        email: email.trim() ? email.trim() : null,
        role: inviteRole,
      }),
    onSuccess: (invitation) => {
      setIssued(invitation);
      setEmail("");
      invalidateInvitations();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (invitationId: string) =>
      revokeOrgInvitation(organizationId as string, invitationId),
    onSuccess: invalidateInvitations,
  });

  if (!organization) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <Card className="p-8 text-center">
          <p className="font-medium text-gray-700">Organization not found</p>
          <p className="text-sm text-gray-500 mt-1">
            It either does not exist or your membership is not active.
          </p>
        </Card>
      </div>
    );
  }

  const members = membersQuery.data ?? [];
  const ownerCount = members.filter(
    (m) => m.role === "ORG_OWNER" && m.state === "ACTIVE"
  ).length;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <OrgHeader organization={organization} />

      {issued && (
        <SecretReveal
          label="invitation-token"
          secret={issued.token}
          title="Invitation created"
          hint="Share this single-use token with the invitee. It expires and cannot be shown again."
        />
      )}

      <Section
        title="Members"
        icon={<Users className="h-4 w-4" />}
        actions={
          <Badge tone="neutral">
            {ownerCount} active owner{ownerCount === 1 ? "" : "s"}
          </Badge>
        }
      >
        {membersQuery.isLoading ? (
          <LoadingBlock label="Loading members" />
        ) : membersQuery.isError ? (
          <ErrorState
            title="Members unavailable"
            error={membersQuery.error}
            onRetry={() => membersQuery.refetch()}
          />
        ) : members.length === 0 ? (
          <EmptyState icon={<Users className="h-8 w-8" />} title="No members" />
        ) : (
          <ul className="divide-y">
            {members.map((member) => {
              const isLastOwner =
                member.role === "ORG_OWNER" &&
                member.state === "ACTIVE" &&
                ownerCount <= 1;
              const roleLabel =
                member.role in ORG_ROLE_LABELS
                  ? ORG_ROLE_LABELS[member.role as keyof typeof ORG_ROLE_LABELS]
                  : member.role;
              return (
                <li
                  key={member.user_id}
                  className="py-3 flex flex-wrap items-center justify-between gap-3"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-gray-900 truncate">
                      {member.email ?? member.user_id}
                    </p>
                    <p className="text-xs text-gray-500 font-mono break-all">
                      {member.user_id}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge tone={toneFor(ORG_ROLE_TONE, member.role)}>
                      {roleLabel}
                    </Badge>
                    <Badge tone={toneFor(MEMBERSHIP_TONE, member.state)}>
                      {member.state.toLowerCase()}
                    </Badge>

                    {canManage && (
                      <>
                        <label className="sr-only" htmlFor={`role-${member.user_id}`}>
                          Change role
                        </label>
                        <select
                          id={`role-${member.user_id}`}
                          value={member.role}
                          disabled={
                            roleMutation.isPending ||
                            // Only an owner may grant/revoke the owner role.
                            (!isOwner && member.role === "ORG_OWNER") ||
                            isLastOwner
                          }
                          title={
                            isLastOwner
                              ? "The last active owner cannot be demoted"
                              : undefined
                          }
                          onChange={(e) =>
                            roleMutation.mutate({
                              userId: member.user_id,
                              role: e.target.value,
                            })
                          }
                          className="rounded-md border border-gray-300 px-2 py-1 text-xs disabled:bg-gray-50"
                        >
                          {ORG_ROLES.map((r) => (
                            <option
                              key={r}
                              value={r}
                              disabled={!isOwner && r === "ORG_OWNER"}
                              title={ORG_ROLE_DESCRIPTIONS[r]}
                            >
                              {ORG_ROLE_LABELS[r]}
                            </option>
                          ))}
                        </select>

                        {member.state === "ACTIVE" ? (
                          <Button
                            variant="secondary"
                            disabled={isLastOwner}
                            title={
                              isLastOwner
                                ? "The last active owner cannot be suspended"
                                : undefined
                            }
                            onClick={() =>
                              stateMutation.mutate({
                                userId: member.user_id,
                                state: "SUSPENDED",
                              })
                            }
                          >
                            Suspend
                          </Button>
                        ) : member.state === "SUSPENDED" ? (
                          <Button
                            variant="secondary"
                            onClick={() =>
                              stateMutation.mutate({
                                userId: member.user_id,
                                state: "ACTIVE",
                              })
                            }
                          >
                            Reactivate
                          </Button>
                        ) : null}

                        <Button
                          variant="danger"
                          disabled={isLastOwner}
                          title={
                            isLastOwner
                              ? "The last active owner cannot be removed"
                              : undefined
                          }
                          onClick={() =>
                            stateMutation.mutate({
                              userId: member.user_id,
                              state: "REMOVED",
                            })
                          }
                        >
                          <X className="h-4 w-4" />
                          Remove
                        </Button>
                      </>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        {roleMutation.isError && (
          <p className="text-sm text-red-700 mt-3" role="alert">
            {roleMutation.error instanceof Error
              ? roleMutation.error.message
              : "Could not change the role."}
          </p>
        )}
        {stateMutation.isError && (
          <p className="text-sm text-red-700 mt-3" role="alert">
            {stateMutation.error instanceof Error
              ? stateMutation.error.message
              : "Could not change the membership."}
          </p>
        )}
      </Section>

      <Section
        className="mt-5"
        title="Invitations"
        icon={<Mail className="h-4 w-4" />}
      >
        {!canManage ? (
          <Alert tone="warning" title="Not available">
            Your role does not include MANAGE_MEMBERS.
          </Alert>
        ) : (
          <>
            <form
              className="flex flex-col sm:flex-row gap-3 sm:items-end mb-4"
              onSubmit={(e) => {
                e.preventDefault();
                inviteMutation.mutate();
              }}
            >
              <div className="flex-1">
                <label
                  htmlFor="invite-email"
                  className="block text-xs text-gray-500 mb-1"
                >
                  Email (optional — leave blank for a link-only invitation)
                </label>
                <input
                  id="invite-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  maxLength={320}
                  placeholder="teammate@example.com"
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none"
                />
              </div>
              <div>
                <label
                  htmlFor="invite-role"
                  className="block text-xs text-gray-500 mb-1"
                >
                  Role
                </label>
                <select
                  id="invite-role"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value)}
                  className="rounded-md border border-gray-300 px-2 py-2 text-sm"
                >
                  {ORG_ROLES.filter((r) => isOwner || r !== "ORG_OWNER").map(
                    (r) => (
                      <option key={r} value={r} title={ORG_ROLE_DESCRIPTIONS[r]}>
                        {ORG_ROLE_LABELS[r]}
                      </option>
                    )
                  )}
                </select>
              </div>
              <Button
                type="submit"
                pending={inviteMutation.isPending}
                pendingLabel="Inviting…"
              >
                <UserPlus className="h-4 w-4" />
                Invite
              </Button>
            </form>

            {inviteMutation.isError && (
              <p className="text-sm text-red-700 mb-3" role="alert">
                {inviteMutation.error instanceof Error
                  ? inviteMutation.error.message
                  : "Could not create the invitation."}
              </p>
            )}

            {invitationsQuery.isLoading ? (
              <LoadingBlock label="Loading invitations" />
            ) : invitationsQuery.isError ? (
              <ErrorState
                title="Invitations unavailable"
                error={invitationsQuery.error}
                onRetry={() => invitationsQuery.refetch()}
              />
            ) : (invitationsQuery.data ?? []).length === 0 ? (
              <p className="text-sm text-gray-500">No invitations issued.</p>
            ) : (
              <ul className="divide-y">
                {(invitationsQuery.data ?? []).map((invitation) => {
                  const status = invitationStatusLabel(invitation);
                  const terminal =
                    status === "revoked" ||
                    status === "accepted" ||
                    status === "expired";
                  return (
                    <li
                      key={invitation.id}
                      className="py-3 flex flex-wrap items-center justify-between gap-3 text-sm"
                    >
                      <div className="min-w-0">
                        <p className="text-gray-900 truncate">
                          {invitation.email ?? "link-only invitation"}
                        </p>
                        <p className="text-xs text-gray-500">
                          {invitation.role in ORG_ROLE_LABELS
                            ? ORG_ROLE_LABELS[
                                invitation.role as keyof typeof ORG_ROLE_LABELS
                              ]
                            : invitation.role}
                          {" · expires "}
                          {formatTime(invitation.expires_at)}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge tone={invitationTone(invitation)}>{status}</Badge>
                        {!terminal && (
                          <Button
                            variant="danger"
                            pending={revokeMutation.isPending}
                            disabled={revokeMutation.isPending}
                            onClick={() => revokeMutation.mutate(invitation.id)}
                          >
                            <ShieldAlert className="h-4 w-4" />
                            Revoke
                          </Button>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </>
        )}
      </Section>
    </div>
  );
}
