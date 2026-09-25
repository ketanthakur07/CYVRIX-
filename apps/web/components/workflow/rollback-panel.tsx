"use client";

import Link from "next/link";
import { ExternalLink, Undo2 } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, Section } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import { formatTime, shortDigest, toneFor, ROLLBACK_TONE } from "@/lib/workflow";
import type { RollbackRun } from "@/lib/types";

/**
 * V3.6 rollback stage. There is deliberately no "force rollback" control
 * and no arbitrary target selection — the target is server-derived from
 * the frozen contract. Covers the CONFLICT safe-stop state.
 */
export function RollbackPanel({
  rollbacks,
  selectedId,
  onSelect,
}: {
  rollbacks: RollbackRun[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const selected = rollbacks.find((r) => r.id === selectedId) ?? rollbacks[0];

  return (
    <Section title="Rollback" icon={<Undo2 className="h-4 w-4" />}>
      {rollbacks.length === 0 ? (
        <Alert tone="info" title="No rollback record">
          Rollback restores the pre-remediation state. It is created exactly
          once for a pushed remediation and executed by the internal executor;
          there is no client-supplied target or force option.
        </Alert>
      ) : (
        <>
          <ul className="divide-y border border-gray-200 rounded-lg mb-4">
            {rollbacks.map((r) => (
              <li key={r.id}>
                <button
                  onClick={() => onSelect(r.id)}
                  className={cn(
                    "w-full flex items-center justify-between gap-3 px-3 py-2 text-left hover:bg-gray-50",
                    selected?.id === r.id && "bg-blue-50"
                  )}
                >
                  <span className="font-mono text-xs text-gray-700 break-all">
                    {r.id.slice(0, 8)} · {formatTime(r.created_at)}
                  </span>
                  <Badge tone={toneFor(ROLLBACK_TONE, r.rollback_state)}>
                    {r.rollback_state}
                  </Badge>
                </button>
              </li>
            ))}
          </ul>

          {selected && (
            <>
              <DataList columns={3}>
                <DataRow label="State">
                  <Badge tone={toneFor(ROLLBACK_TONE, selected.rollback_state)}>
                    {selected.rollback_state}
                  </Badge>
                </DataRow>
                <DataRow label="Rollback target" mono>
                  {shortDigest(selected.rollback_target_sha)}
                </DataRow>
                <DataRow label="Expected branch SHA" mono>
                  {shortDigest(selected.expected_branch_sha)}
                </DataRow>
                <DataRow label="Revert branch" mono>
                  {selected.revert_branch}
                </DataRow>
                <DataRow label="Revert SHA" mono>
                  {shortDigest(selected.revert_sha)}
                </DataRow>
                <DataRow label="Revert PR" mono>
                  {selected.revert_pr_number != null ? `#${selected.revert_pr_number}` : "—"}
                </DataRow>
                <DataRow label="Cleanup status" mono>
                  {selected.cleanup_status}
                </DataRow>
                <DataRow label="Finished">{formatTime(selected.finished_at)}</DataRow>
              </DataList>

              {selected.revert_pr_url && (
                <a
                  href={selected.revert_pr_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 mt-3"
                >
                  Open revert PR <ExternalLink className="h-3 w-3" />
                </a>
              )}

              {selected.rollback_state === "CONFLICT" && (
                <Alert tone="warning" className="mt-3" title="CYVRIX stopped to protect newer changes">
                  The branch moved (or the target became stale) before rollback.
                  No unsafe override is available; resolve the repository state
                  and create a new remediation if needed.
                </Alert>
              )}
              {selected.rollback_state === "FAILED" && (
                <Alert tone="danger" className="mt-3" title={`Rollback failed: ${selected.fail_reason_code ?? "unknown"}`}>
                  {selected.fail_detail ?? "No additional detail was recorded."}
                </Alert>
              )}

              <Link
                href={`/rollbacks/${selected.id}`}
                className="text-sm text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 mt-4"
              >
                Open rollback detail
                <ExternalLink className="h-3 w-3" />
              </Link>
            </>
          )}
        </>
      )}
    </Section>
  );
}
