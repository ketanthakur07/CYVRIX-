"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { ExternalLink, Undo2 } from "lucide-react";
import { fetchRollback } from "@/lib/api";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { formatTime, shortDigest, toneFor, ROLLBACK_TONE } from "@/lib/workflow";

/**
 * V3.6 rollback detail. Read-only: there is no force control and no
 * arbitrary target. CONFLICT is a deliberate safe stop.
 */
export default function RollbackPage() {
  const params = useParams();
  const id = params.id as string;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["rollback", id],
    queryFn: () => fetchRollback(id),
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <LoadingBlock />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <ErrorState title="Rollback not available" error={error} onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title="Rollback"
        subtitle={<span className="font-mono text-xs">{data.id}</span>}
        backHref={`/remediations/${data.git_remediation_id}`}
        backLabel="Back to remediation"
        actions={<Badge tone={toneFor(ROLLBACK_TONE, data.rollback_state)}>{data.rollback_state}</Badge>}
      />

      {data.rollback_state === "CONFLICT" && (
        <Alert tone="warning" className="mb-5" title="CYVRIX stopped to protect newer changes">
          The branch moved or the rollback target became stale. Resolve the
          repository state and create a new remediation if needed. No unsafe
          override exists.
        </Alert>
      )}
      {data.rollback_state === "FAILED" && (
        <Alert tone="danger" className="mb-5" title={`Rollback failed: ${data.fail_reason_code ?? "unknown"}`}>
          {data.fail_detail ?? "No additional detail was recorded."}
        </Alert>
      )}

      <Section title="Rollback record" icon={<Undo2 className="h-4 w-4" />}>
        <DataList columns={3}>
          <DataRow label="Rollback target" mono>{shortDigest(data.rollback_target_sha)}</DataRow>
          <DataRow label="Expected branch SHA" mono>{shortDigest(data.expected_branch_sha)}</DataRow>
          <DataRow label="Revert branch" mono>{data.revert_branch}</DataRow>
          <DataRow label="Revert SHA" mono>{shortDigest(data.revert_sha)}</DataRow>
          <DataRow label="Revert PR" mono>
            {data.revert_pr_number != null ? `#${data.revert_pr_number}` : "—"}
          </DataRow>
          <DataRow label="Cleanup status" mono>{data.cleanup_status}</DataRow>
          <DataRow label="Created">{formatTime(data.created_at)}</DataRow>
          <DataRow label="Finished">{formatTime(data.finished_at)}</DataRow>
        </DataList>

        {data.revert_pr_url && (
          <a
            href={data.revert_pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 mt-3"
          >
            Open revert PR <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </Section>
    </div>
  );
}
