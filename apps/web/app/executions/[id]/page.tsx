"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { Boxes } from "lucide-react";
import { fetchExecutionRun } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { JsonBlock } from "@/components/ui/code-block";
import { Alert } from "@/components/ui/alert";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { formatTime, shortDigest, toneFor, RUN_TONE } from "@/lib/workflow";

/**
 * V3.4 execution-run detail. Bounded server metadata only — no secrets,
 * credentials, workspace content, or unbounded logs.
 */
export default function ExecutionRunPage() {
  const params = useParams();
  const id = params.id as string;

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["execution-run", id],
    queryFn: () => fetchExecutionRun(id),
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
        <ErrorState
          title="Execution run not available"
          error={error}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title="Execution run"
        subtitle={<span className="font-mono text-xs">{data.id}</span>}
        backHref={`/actions/${data.action_proposal_id}`}
        backLabel="Back to action"
        actions={<Badge tone={toneFor(RUN_TONE, data.run_state)}>{data.run_state}</Badge>}
      />

      <Section title="Run record" icon={<Boxes className="h-4 w-4" />}>
        <DataList columns={3}>
          <DataRow label="Execution profile" mono>{data.execution_profile}</DataRow>
          <DataRow label="Cleanup status" mono>{data.cleanup_status}</DataRow>
          <DataRow label="Cleanup detail">{data.cleanup_detail ?? "—"}</DataRow>
          <DataRow label="Action digest" mono>{shortDigest(data.action_digest)}</DataRow>
          <DataRow label="Contract digest" mono>{shortDigest(data.contract_digest)}</DataRow>
          <DataRow label="Diff digest" mono>{shortDigest(data.diff_digest)}</DataRow>
          <DataRow label="Started">{formatTime(data.started_at)}</DataRow>
          <DataRow label="Finished">{formatTime(data.finished_at)}</DataRow>
          <DataRow label="Created">{formatTime(data.created_at)}</DataRow>
        </DataList>

        {data.fail_reason_code && (
          <Alert tone="danger" className="mt-4" title={`Failed: ${data.fail_reason_code}`}>
            {data.fail_detail ?? "No additional detail was recorded."}
          </Alert>
        )}
        {data.cleanup_status && data.cleanup_status !== "CLEAN" && (
          <Alert tone="warning" className="mt-4" title="Teardown not clean">
            {data.cleanup_detail ?? "The sandbox teardown did not report a clean state."}
          </Alert>
        )}
      </Section>

      <div className="mt-5">
        <Section title="Resource profile (server record)">
          <JsonBlock value={data.resource_profile} />
        </Section>
      </div>

      <div className="mt-5">
        <Section title="Bounded run result">
          <JsonBlock value={data.result ?? {}} />
        </Section>
      </div>
    </div>
  );
}
