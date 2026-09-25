"use client";

import { Boxes, ChevronRight } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, Section } from "@/components/ui/card";
import { JsonBlock } from "@/components/ui/code-block";
import { cn } from "@/lib/cn";
import { formatTime, shortDigest, toneFor, RUN_TONE } from "@/lib/workflow";
import type { ExecutionRun } from "@/lib/types";

/**
 * V3.4 sandbox execution history. Read-only: users cannot start an
 * execution (only the internal executor boundary can, and it must
 * present the one-time token). No fake progress is ever shown.
 */
export function ExecutionPanel({
  runs,
  selectedRunId,
  onSelect,
}: {
  runs: ExecutionRun[];
  selectedRunId: string | null;
  onSelect: (runId: string) => void;
}) {
  const selected = runs.find((r) => r.id === selectedRunId) ?? runs[0];

  return (
    <Section
      title="Sandbox execution"
      icon={<Boxes className="h-4 w-4" />}
      actions={
        runs.length > 0 ? (
          <span className="text-xs text-gray-500">{runs.length} run(s)</span>
        ) : undefined
      }
    >
      {runs.length === 0 ? (
        <Alert tone="info" title="Not executed">
          Authorizing does not execute anything. Execution is admitted only by
          the internal executor service after it consumes the one-time token —
          it is not a user action and never appears as a fake progress bar here.
        </Alert>
      ) : (
        <>
          <ul className="divide-y border border-gray-200 rounded-lg mb-4">
            {runs.map((run) => (
              <li key={run.id}>
                <button
                  onClick={() => onSelect(run.id)}
                  className={cn(
                    "w-full flex items-center justify-between gap-3 px-3 py-2 text-left hover:bg-gray-50",
                    selected?.id === run.id && "bg-blue-50"
                  )}
                  aria-current={selected?.id === run.id}
                >
                  <span className="font-mono text-xs text-gray-700 break-all">
                    {run.id.slice(0, 8)} · {formatTime(run.created_at)}
                  </span>
                  <span className="flex items-center gap-2 shrink-0">
                    <Badge tone={toneFor(RUN_TONE, run.run_state)}>{run.run_state}</Badge>
                    <ChevronRight className="h-4 w-4 text-gray-400" />
                  </span>
                </button>
              </li>
            ))}
          </ul>

          {selected && (
            <div>
              <DataList columns={3}>
                <DataRow label="Run state">
                  <Badge tone={toneFor(RUN_TONE, selected.run_state)}>
                    {selected.run_state}
                  </Badge>
                </DataRow>
                <DataRow label="Execution profile" mono>
                  {selected.execution_profile}
                </DataRow>
                <DataRow label="Cleanup status" mono>
                  {selected.cleanup_status}
                </DataRow>
                <DataRow label="Action digest" mono>
                  {shortDigest(selected.action_digest)}
                </DataRow>
                <DataRow label="Contract digest" mono>
                  {shortDigest(selected.contract_digest)}
                </DataRow>
                <DataRow label="Diff digest" mono>
                  {shortDigest(selected.diff_digest)}
                </DataRow>
                <DataRow label="Started">{formatTime(selected.started_at)}</DataRow>
                <DataRow label="Finished">{formatTime(selected.finished_at)}</DataRow>
                <DataRow label="Cleanup detail">{selected.cleanup_detail ?? "—"}</DataRow>
              </DataList>

              {selected.fail_reason_code && (
                <Alert tone="danger" className="mt-3" title={`Execution failed: ${selected.fail_reason_code}`}>
                  {selected.fail_detail ?? "No additional detail was recorded."}
                </Alert>
              )}
              {selected.cleanup_status && selected.cleanup_status !== "CLEAN" && (
                <Alert tone="warning" className="mt-3" title="Sandbox teardown was not clean">
                  {selected.cleanup_detail ??
                    "Teardown did not report a clean state; treat the result with caution."}
                </Alert>
              )}

              <div className="mt-3">
                <p className="text-xs font-medium text-gray-500 mb-1">
                  Bounded run result (server record)
                </p>
                <JsonBlock value={selected.result ?? {}} />
              </div>
            </div>
          )}
        </>
      )}
    </Section>
  );
}
