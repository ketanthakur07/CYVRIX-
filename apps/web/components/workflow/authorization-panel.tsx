"use client";

import { KeyRound, ShieldCheck, ShieldX } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataList, DataRow, Section } from "@/components/ui/card";
import { formatTime, shortDigest, toneFor, AUTHORIZATION_TONE } from "@/lib/workflow";
import type { ActionProposal, Approval, ExecutionAuthorization } from "@/lib/types";

/**
 * V3.3 authorization stage. Presents authorization records the server
 * created. The "authorize" action sends only a human reason; the server
 * re-verifies approval, digest, policy, kill switch and freshness.
 */
export function AuthorizationPanel({
  proposal,
  approval,
  authorizations,
  busy,
  error,
  onAuthorize,
  onRevoke,
}: {
  proposal: ActionProposal;
  approval: Approval | undefined;
  authorizations: ExecutionAuthorization[];
  busy: boolean;
  error: string | null;
  onAuthorize: () => void;
  onRevoke: (authorizationId: string) => void;
}) {
  const live = authorizations.find((a) => a.authorization_state === "AUTHORIZED");
  const latest = authorizations[0];
  const approved = proposal.status === "APPROVED";
  const approvalUsable = approval?.approval_state === "APPROVED";

  const canAuthorize = approved && approvalUsable && !live;

  return (
    <Section
      title="Authorize execution"
      icon={<KeyRound className="h-4 w-4" />}
      actions={
        latest ? (
          <Badge tone={toneFor(AUTHORIZATION_TONE, latest.authorization_state)}>
            {latest.authorization_state}
          </Badge>
        ) : (
          <Badge tone="neutral">NOT_AUTHORIZED</Badge>
        )
      }
    >
      <p className="text-xs text-gray-500 mb-3">
        An authorization is an immutable, digest-bound contract. It is NOT
        execution: nothing runs until the internal executor consumes it. The
        server recomputes the digest and re-evaluates policy on every attempt.
      </p>

      {!latest && (
        <Alert tone="info" title="No authorization exists yet">
          {approved
            ? "Once approved, authorization can be issued for this exact action digest."
            : "Authorize becomes available only after this proposal is APPROVED."}
        </Alert>
      )}

      {latest && (
        <DataList columns={2} className="mt-3">
          <DataRow label="State" mono>
            {latest.authorization_state}
          </DataRow>
          <DataRow label="Policy decision">{latest.policy_decision}</DataRow>
          <DataRow label="Policy version" mono>
            {latest.policy_version}
          </DataRow>
          <DataRow label="Contract version" mono>
            {latest.contract_version}
          </DataRow>
          <DataRow label="Action digest" mono>
            {shortDigest(latest.action_digest)}
          </DataRow>
          <DataRow label="Contract digest" mono>
            {shortDigest(latest.contract_digest)}
          </DataRow>
          <DataRow label="Base commit" mono>
            {shortDigest(latest.base_commit_sha)}
          </DataRow>
          <DataRow label="Target branch" mono>
            {latest.target_branch}
          </DataRow>
          <DataRow label="Created">{formatTime(latest.created_at)}</DataRow>
          <DataRow label="Consumed">{formatTime(latest.consumed_at)}</DataRow>
        </DataList>
      )}

      {error && (
        <Alert tone="danger" className="mt-3" title="Authorization request rejected">
          {error}
        </Alert>
      )}

      <div className="flex gap-3 mt-4">
        {canAuthorize && (
          <Button
            onClick={onAuthorize}
            pending={busy}
            pendingLabel="Authorizing…"
          >
            <ShieldCheck className="h-4 w-4" />
            Authorize this exact action
          </Button>
        )}
        {live && (
          <Button variant="danger" onClick={() => onRevoke(live.id)} disabled={busy}>
            <ShieldX className="h-4 w-4" />
            Revoke authorization
          </Button>
        )}
        {!canAuthorize && !live && approved && !approvalUsable && (
          <Alert tone="warning">
            An APPROVED approval record is required before authorization can be
            issued.
          </Alert>
        )}
      </div>
    </Section>
  );
}
