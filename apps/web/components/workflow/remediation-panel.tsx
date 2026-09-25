"use client";

import Link from "next/link";
import {
  ExternalLink,
  GitBranch,
  GitPullRequest,
  Play,
  ShieldCheck,
  Undo2,
} from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataList, DataRow, Section } from "@/components/ui/card";
import { cn } from "@/lib/cn";
import {
  formatTime,
  shortDigest,
  toneFor,
  REMEDIATION_TONE,
} from "@/lib/workflow";
import type { GitRemediation } from "@/lib/types";

/**
 * V3.5/V3.6 remediation stage. Branch names, SHAs, and PR URLs here come
 * from the server record. "Start" actions send an empty body — the
 * server derives branch/ceiling/target and rejects any client authority.
 */
export function RemediationPanel({
  remediations,
  selectedId,
  onSelect,
  canStartRemediation,
  canStartVerification,
  canStartRollback,
  busy,
  error,
  onStartRemediation,
  onStartVerification,
  onStartRollback,
}: {
  remediations: GitRemediation[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  canStartRemediation: boolean;
  canStartVerification: boolean;
  canStartRollback: boolean;
  busy: boolean;
  error: string | null;
  onStartRemediation: () => void;
  onStartVerification: () => void;
  onStartRollback: () => void;
}) {
  const selected = remediations.find((r) => r.id === selectedId) ?? remediations[0];

  return (
    <Section
      title="Git / GitHub remediation"
      icon={<GitBranch className="h-4 w-4" />}
      actions={
        canStartRemediation ? (
          <Button onClick={onStartRemediation} pending={busy}>
            <Play className="h-4 w-4" />
            Start remediation
          </Button>
        ) : undefined
      }
    >
      {remediations.length === 0 ? (
        <Alert tone="info" title="No remediation record">
          Remediation becomes available only for a run the server marked
          RESULT_READY or COMPLETED with host-side scope verification.
        </Alert>
      ) : (
        <>
          <ul className="divide-y border border-gray-200 rounded-lg mb-4">
            {remediations.map((r) => (
              <li key={r.id}>
                <button
                  onClick={() => onSelect(r.id)}
                  className={cn(
                    "w-full flex items-center justify-between gap-3 px-3 py-2 text-left hover:bg-gray-50",
                    selected?.id === r.id && "bg-blue-50"
                  )}
                >
                  <span className="font-mono text-xs text-gray-700 break-all">
                    {r.id.slice(0, 8)} · {r.repo_owner}/{r.repo_name}
                  </span>
                  <Badge tone={toneFor(REMEDIATION_TONE, r.remediation_state)}>
                    {r.remediation_state}
                  </Badge>
                </button>
              </li>
            ))}
          </ul>

          {selected && (
            <>
              <DataList columns={3}>
                <DataRow label="State">
                  <Badge tone={toneFor(REMEDIATION_TONE, selected.remediation_state)}>
                    {selected.remediation_state}
                  </Badge>
                </DataRow>
                <DataRow label="Repository" mono>
                  {selected.repo_owner}/{selected.repo_name}
                </DataRow>
                <DataRow label="Stage ceiling" mono>
                  {selected.stage_ceiling}
                </DataRow>
                <DataRow label="Source branch" mono>
                  {selected.source_branch}
                </DataRow>
                <DataRow label="Target branch" mono>
                  {selected.target_branch}
                </DataRow>
                <DataRow label="Remediation branch" mono>
                  {selected.remediation_branch}
                </DataRow>
                <DataRow label="Base commit" mono>
                  {shortDigest(selected.base_commit_sha)}
                </DataRow>
                <DataRow label="Committed SHA" mono>
                  {shortDigest(selected.committed_sha)}
                </DataRow>
                <DataRow label="Pushed SHA" mono>
                  {shortDigest(selected.pushed_sha)}
                </DataRow>
                <DataRow label="Cleanup status" mono>
                  {selected.cleanup_status}
                </DataRow>
                <DataRow label="Created">{formatTime(selected.created_at)}</DataRow>
                <DataRow label="Finished">{formatTime(selected.finished_at)}</DataRow>
              </DataList>

              {(selected.pr_url || selected.pr_number != null) && (
                <div className="mt-3 flex items-center gap-2 text-sm">
                  <GitPullRequest className="h-4 w-4 text-purple-600" />
                  <span className="text-gray-700">
                    PR #{selected.pr_number ?? "—"} · {selected.pr_state ?? "state unknown"}
                  </span>
                  {selected.pr_url && (
                    <a
                      href={selected.pr_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-blue-600 hover:text-blue-800"
                    >
                      Open <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>
              )}

              {selected.fail_reason_code && (
                <Alert tone="danger" className="mt-3" title={`Remediation failed: ${selected.fail_reason_code}`}>
                  {selected.fail_detail ?? "No additional detail was recorded."}
                </Alert>
              )}
              {(selected.remediation_state === "STALE" ||
                selected.remediation_state === "INCONSISTENT") && (
                <Alert tone="warning" className="mt-3" title="CYVRIX stopped to protect newer changes">
                  The repository or remote state no longer matches the frozen
                  contract. No unsafe override is offered here.
                </Alert>
              )}

              <div className="flex flex-wrap items-center gap-3 mt-4">
                {canStartVerification && (
                  <Button onClick={onStartVerification} pending={busy} disabled={busy}>
                    <ShieldCheck className="h-4 w-4" />
                    Start verification
                  </Button>
                )}
                {canStartRollback && (
                  <Button
                    variant="danger"
                    onClick={onStartRollback}
                    pending={busy}
                    disabled={busy}
                  >
                    <Undo2 className="h-4 w-4" />
                    Start rollback
                  </Button>
                )}
                <Link
                  href={`/remediations/${selected.id}`}
                  className="text-sm text-blue-600 hover:text-blue-800 inline-flex items-center gap-1"
                >
                  Open remediation detail
                  <ExternalLink className="h-3 w-3" />
                </Link>
              </div>
            </>
          )}
        </>
      )}

      {error && (
        <Alert tone="danger" className="mt-3" title="Request rejected by the server">
          {error}
        </Alert>
      )}
    </Section>
  );
}
