"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchRepositoryControl } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toneFor, REPO_CONTROL_TONE } from "@/lib/workflow";

/**
 * One repository's operational containment state, read from the server.
 * The pause action is only a REQUEST; the server enforces capability and
 * tenant ownership (cross-tenant reads are 404).
 */
export function RepoControlRow({
  repositoryId,
  name,
  canControl,
  onRequestPause,
}: {
  repositoryId: string;
  name: string;
  canControl: boolean;
  onRequestPause: (repositoryId: string, repoName: string) => void;
}) {
  const { data, isError } = useQuery({
    queryKey: ["repo-control", repositoryId],
    queryFn: () => fetchRepositoryControl(repositoryId),
  });

  const state = isError ? "UNAVAILABLE" : data?.control_state;

  return (
    <li className="py-2 flex items-center justify-between gap-3">
      <span className="text-sm font-mono text-gray-700 break-all">{name}</span>
      <span className="flex items-center gap-2 shrink-0">
        {state ? (
          <Badge tone={toneFor(REPO_CONTROL_TONE, state)}>{state}</Badge>
        ) : (
          <Badge tone="neutral">…</Badge>
        )}
        {canControl && state === "ENABLED" && (
          <Button
            variant="secondary"
            onClick={() => onRequestPause(repositoryId, name)}
          >
            Pause containment
          </Button>
        )}
      </span>
    </li>
  );
}
