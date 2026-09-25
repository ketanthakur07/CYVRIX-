"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import Link from "next/link";
import { ExternalLink, GitBranch, ShieldCheck, Undo2 } from "lucide-react";
import {
  fetchRemediation,
  fetchRemediationRollbacks,
  fetchRemediationVerifications,
  startRollback,
  startVerification,
} from "@/lib/api";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import {
  formatTime,
  shortDigest,
  toneFor,
  REMEDIATION_TONE,
  ROLLBACK_TONE,
  VERIFICATION_STATE_TONE,
  VERIFICATION_RESULT_TONE,
} from "@/lib/workflow";

/**
 * V3.5/V3.6 remediation detail. Start-verification and start-rollback are
 * the only mutations; both create records and execute nothing. The
 * rollback target is server-derived — no SHA is ever sent from here.
 */
export default function RemediationPage() {
  const params = useParams();
  const id = params.id as string;
  const queryClient = useQueryClient();
  const [confirmRollback, setConfirmRollback] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const remediationQuery = useQuery({
    queryKey: ["remediation", id],
    queryFn: () => fetchRemediation(id),
  });
  const verificationsQuery = useQuery({
    queryKey: ["remediation-verifications", id],
    queryFn: () => fetchRemediationVerifications(id),
  });
  const rollbacksQuery = useQuery({
    queryKey: ["remediation-rollbacks", id],
    queryFn: () => fetchRemediationRollbacks(id),
  });

  const remediation = remediationQuery.data;
  const verifications = verificationsQuery.data ?? [];
  const rollbacks = rollbacksQuery.data ?? [];

  async function doStart(kind: "verification" | "rollback") {
    setBusy(true);
    setActionError(null);
    try {
      if (kind === "verification") await startVerification(id);
      else await startRollback(id);
      await queryClient.invalidateQueries({ queryKey: ["remediation-verifications", id] });
      await queryClient.invalidateQueries({ queryKey: ["remediation-rollbacks", id] });
      setConfirmRollback(false);
    } catch (e) {
      const reason = (e as { reasonCode?: string }).reasonCode;
      const msg = e instanceof Error ? e.message : "Request failed";
      setActionError(reason ? `${msg} (${reason})` : msg);
    } finally {
      setBusy(false);
    }
  }

  if (remediationQuery.isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <LoadingBlock />
      </div>
    );
  }

  if (remediationQuery.error || !remediation) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <ErrorState
          title="Remediation not available"
          error={remediationQuery.error}
          onRetry={() => remediationQuery.refetch()}
        />
      </div>
    );
  }

  const canVerify = !!remediation.committed_sha && verifications.length === 0;
  const canRollback = !!remediation.pushed_sha && rollbacks.length === 0;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title={`${remediation.repo_owner}/${remediation.repo_name}`}
        subtitle={<span className="font-mono text-xs">{remediation.id}</span>}
        backHref={`/actions/${remediation.action_proposal_id}`}
        backLabel="Back to action"
        actions={
          <Badge tone={toneFor(REMEDIATION_TONE, remediation.remediation_state)}>
            {remediation.remediation_state}
          </Badge>
        }
      />

      {remediation.fail_reason_code && (
        <Alert tone="danger" className="mb-5" title={`Failed: ${remediation.fail_reason_code}`}>
          {remediation.fail_detail ?? "No additional detail was recorded."}
        </Alert>
      )}

      <Section title="Remediation record" icon={<GitBranch className="h-4 w-4" />}>
        <DataList columns={3}>
          <DataRow label="Stage ceiling" mono>{remediation.stage_ceiling}</DataRow>
          <DataRow label="Source branch" mono>{remediation.source_branch}</DataRow>
          <DataRow label="Target branch" mono>{remediation.target_branch}</DataRow>
          <DataRow label="Remediation branch" mono>{remediation.remediation_branch}</DataRow>
          <DataRow label="Base commit" mono>{shortDigest(remediation.base_commit_sha)}</DataRow>
          <DataRow label="Committed SHA" mono>{shortDigest(remediation.committed_sha)}</DataRow>
          <DataRow label="Pushed SHA" mono>{shortDigest(remediation.pushed_sha)}</DataRow>
          <DataRow label="Cleanup status" mono>{remediation.cleanup_status}</DataRow>
          <DataRow label="Created">{formatTime(remediation.created_at)}</DataRow>
          <DataRow label="Finished">{formatTime(remediation.finished_at)}</DataRow>
        </DataList>

        {remediation.pr_url && (
          <a
            href={remediation.pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 mt-3"
          >
            Open PR #{remediation.pr_number ?? "—"} <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </Section>

      <div className="flex flex-wrap items-center gap-3 mt-5">
        {canVerify && (
          <Button onClick={() => doStart("verification")} pending={busy}>
            <ShieldCheck className="h-4 w-4" />
            Start verification
          </Button>
        )}
        {canRollback && (
          <Button variant="danger" onClick={() => setConfirmRollback(true)} disabled={busy}>
            <Undo2 className="h-4 w-4" />
            Start rollback
          </Button>
        )}
      </div>

      {actionError && (
        <Alert tone="danger" className="mt-4" title="Request rejected by the server">
          {actionError}
        </Alert>
      )}

      <div className="mt-6 space-y-5">
        <Section title={`Verifications (${verifications.length})`}>
          {verifications.length === 0 ? (
            <p className="text-sm text-gray-500">No verification records.</p>
          ) : (
            <ul className="divide-y">
              {verifications.map((v) => (
                <li key={v.id} className="py-2 flex items-center justify-between gap-3">
                  <Link href={`/verifications/${v.id}`} className="text-sm text-blue-600 hover:text-blue-800 font-mono">
                    {v.id.slice(0, 8)}
                  </Link>
                  <span className="flex items-center gap-2">
                    <Badge tone={toneFor(VERIFICATION_STATE_TONE, v.verification_state)}>
                      {v.verification_state}
                    </Badge>
                    {v.result && (
                      <Badge tone={toneFor(VERIFICATION_RESULT_TONE, v.result)}>{v.result}</Badge>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title={`Rollbacks (${rollbacks.length})`}>
          {rollbacks.length === 0 ? (
            <p className="text-sm text-gray-500">No rollback records.</p>
          ) : (
            <ul className="divide-y">
              {rollbacks.map((r) => (
                <li key={r.id} className="py-2 flex items-center justify-between gap-3">
                  <Link href={`/rollbacks/${r.id}`} className="text-sm text-blue-600 hover:text-blue-800 font-mono">
                    {r.id.slice(0, 8)}
                  </Link>
                  <Badge tone={toneFor(ROLLBACK_TONE, r.rollback_state)}>{r.rollback_state}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <ConfirmDialog
        open={confirmRollback}
        danger
        title="Start rollback of this remediation?"
        description="This requests a controlled revert of the pushed remediation. The rollback target is derived server-side from the frozen contract."
        consequences={[
          "A rollback record is created and executed by the internal executor.",
          "CYVRIX stops safely (CONFLICT) if the branch moved since the remediation.",
          "There is no force option and no client-supplied target SHA.",
        ]}
        confirmLabel="Start rollback"
        pending={busy}
        onConfirm={() => doStart("rollback")}
        onCancel={() => setConfirmRollback(false)}
      />
    </div>
  );
}
