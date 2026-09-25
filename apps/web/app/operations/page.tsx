"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Ban,
  Gauge,
  Play,
  RotateCcw,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import {
  fetchBreakers,
  fetchLastReconciliation,
  fetchOpsCapabilities,
  fetchOpsEvents,
  fetchOpsStatus,
  fetchRepositories,
  resetBreaker,
  runReconciliation,
  setOpsState,
  setRepositoryControl,
} from "@/lib/api";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { RepoControlRow } from "@/components/ops/repo-control-row";
import { formatTime, toneFor, OPS_STATE_TONE, BREAKER_TONE } from "@/lib/workflow";
import type { CircuitBreaker } from "@/lib/types";

type Pending =
  | null
  | { kind: "state"; target: string; title: string; description: string; consequences: string[]; phrase?: string }
  | { kind: "breaker"; breaker: CircuitBreaker }
  | { kind: "repo"; repositoryId: string; repoName: string; controlState: string };

/**
 * V3.7 operations console. Every control here is capability-gated and
 * step-up-gated SERVER-SIDE; the UI only reflects capabilities returned
 * by the server and confirms dangerous actions. No control can approve,
 * authorize, or execute a remediation — operators operate the platform.
 */
export default function OperationsPage() {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const capabilitiesQuery = useQuery({
    queryKey: ["ops-capabilities"],
    queryFn: fetchOpsCapabilities,
  });

  const has = (cap: string) => capabilitiesQuery.data?.capabilities.includes(cap) ?? false;

  const statusQuery = useQuery({
    queryKey: ["ops-status"],
    queryFn: fetchOpsStatus,
    enabled: has("VIEW_OPERATIONS"),
    refetchInterval: 10000,
  });
  const breakersQuery = useQuery({
    queryKey: ["ops-breakers"],
    queryFn: fetchBreakers,
    enabled: has("VIEW_OPERATIONS"),
  });
  const reconciliationQuery = useQuery({
    queryKey: ["ops-reconciliation"],
    queryFn: fetchLastReconciliation,
    enabled: has("VIEW_OPERATIONS"),
  });
  const eventsQuery = useQuery({
    queryKey: ["ops-events"],
    queryFn: () => fetchOpsEvents(50),
    enabled: has("VIEW_DIAGNOSTICS"),
  });
  const repositoriesQuery = useQuery({
    queryKey: ["repositories"],
    queryFn: fetchRepositories,
    enabled: has("VIEW_OPERATIONS"),
  });

  async function execute(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await queryClient.invalidateQueries({ queryKey: ["ops-status"] });
      await queryClient.invalidateQueries({ queryKey: ["ops-breakers"] });
      await queryClient.invalidateQueries({ queryKey: ["ops-reconciliation"] });
      await queryClient.invalidateQueries({ queryKey: ["repo-control"] });
      await queryClient.invalidateQueries({ queryKey: ["ops-events"] });
      setPending(null);
    } catch (e) {
      const reason = (e as { reasonCode?: string }).reasonCode;
      const msg = e instanceof Error ? e.message : "Request failed";
      setActionError(reason ? `${msg} (${reason})` : msg);
    } finally {
      setBusy(false);
    }
  }

  if (capabilitiesQuery.isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-5xl">
        <LoadingBlock />
      </div>
    );
  }

  if (capabilitiesQuery.error) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-5xl">
        <ErrorState
          title="Could not determine operator access"
          error={capabilitiesQuery.error}
          onRetry={() => capabilitiesQuery.refetch()}
        />
      </div>
    );
  }

  const role = capabilitiesQuery.data?.role ?? "USER";
  const canView = has("VIEW_OPERATIONS");

  if (!canView) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-5xl">
        <PageHeader title="Operations" subtitle={`Signed in as ${role}`} />
        <Alert tone="warning" title="Operator access required">
          Your account does not have the VIEW_OPERATIONS capability. This page
          performs no privileged fetch without it; the server enforces the same
          rule independently of what the browser shows.
        </Alert>
      </div>
    );
  }

  const status = statusQuery.data;

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl">
      <PageHeader
        title="Operations"
        subtitle={`Signed in as ${role} · ${capabilitiesQuery.data?.capabilities.length ?? 0} capabilities`}
      />

      {actionError && (
        <Alert tone="danger" className="mb-5" title="Control rejected by the server">
          {actionError}
        </Alert>
      )}

      <Section
        title="System status"
        icon={<Gauge className="h-4 w-4" />}
        actions={
          status ? (
            <Badge tone={toneFor(OPS_STATE_TONE, status.operational_state)}>
              {status.operational_state}
            </Badge>
          ) : undefined
        }
      >
        {statusQuery.isError ? (
          <p className="text-sm text-red-700">Status unavailable.</p>
        ) : !status ? (
          <p className="text-sm text-gray-500">Loading status…</p>
        ) : (
          <>
            <DataList columns={3}>
              <DataRow label="Operational state">{status.operational_state}</DataRow>
              <DataRow label="Kill switch">
                {status.kill_switch_disabled ? "ACTIVE (execution blocked)" : "inactive"}
              </DataRow>
              <DataRow label="Detail">{status.detail ?? "—"}</DataRow>
            </DataList>
            <div className="flex flex-wrap gap-3 mt-4">
              {has("PAUSE_SYSTEM") && (
                <Button
                  variant="secondary"
                  onClick={() =>
                    setPending({
                      kind: "state",
                      target: "PAUSED",
                      title: "Pause the platform?",
                      description: "New executions stop being admitted. In-flight work is not killed.",
                      consequences: [
                        "New execution admissions are blocked (fail closed).",
                        "In-flight sandboxed runs are allowed to finish.",
                        "Nothing is approved, authorized, or rolled back by this action.",
                      ],
                    })
                  }
                >
                  Pause
                </Button>
              )}
              {has("PAUSE_SYSTEM") && (
                <Button
                  variant="secondary"
                  onClick={() =>
                    setPending({
                      kind: "state",
                      target: "DRAINING",
                      title: "Drain the platform?",
                      description: "Admissions stop and the operator lets queued work settle.",
                      consequences: [
                        "New execution admissions are blocked.",
                        "Existing jobs are allowed to complete or expire.",
                      ],
                    })
                  }
                >
                  Drain
                </Button>
              )}
              {has("EMERGENCY_STOP") && (
                <Button
                  variant="danger"
                  onClick={() =>
                    setPending({
                      kind: "state",
                      target: "EMERGENCY_STOP",
                      title: "Emergency stop",
                      description:
                        "Immediately blocks all remediation mutations platform-wide. Requires a fresh step-up authentication.",
                      consequences: [
                        "All execution/remediation/verification/rollback mutations are refused.",
                        "In-flight worker activity is not force-killed by this control.",
                        "Resume requires reconciliation and a pause-first transition.",
                      ],
                      phrase: "EMERGENCY_STOP",
                    })
                  }
                >
                  <ShieldAlert className="h-4 w-4" />
                  Emergency stop
                </Button>
              )}
              {has("RESUME_SYSTEM") && status.operational_state !== "NORMAL" && (
                <Button
                  onClick={() =>
                    setPending({
                      kind: "state",
                      target: "NORMAL",
                      title: "Resume normal operation?",
                      description:
                        "Resume is refused unless a recent clean reconciliation found no unresolved state. Requires step-up.",
                      consequences: [
                        "Requires a COMPLETED reconciliation within 15 minutes with no blocking findings.",
                        "Refused if the platform is in EMERGENCY_STOP (pause first).",
                      ],
                    })
                  }
                >
                  <Play className="h-4 w-4" />
                  Resume
                </Button>
              )}
            </div>
          </>
        )}
      </Section>

      <div className="mt-6">
        <Section
          title="Circuit breakers"
          icon={<Wrench className="h-4 w-4" />}
          actions={
            has("RESET_CIRCUIT") ? (
              <span className="text-xs text-gray-500">Reset requires step-up</span>
            ) : undefined
          }
        >
          {breakersQuery.isError ? (
            <p className="text-sm text-red-700">Breakers unavailable.</p>
          ) : (breakersQuery.data ?? []).length === 0 ? (
            <EmptyState
              icon={<Wrench className="h-8 w-8" />}
              title="No circuit breakers"
              description="Breakers appear when execution failures trip them."
            />
          ) : (
            <ul className="divide-y">
              {(breakersQuery.data ?? []).map((b) => (
                <li key={b.id} className="py-2 flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-mono text-gray-700 break-all">
                      {b.scope} · {b.action_type}
                    </p>
                    <p className="text-xs text-gray-500">
                      {b.consecutive_failures}/{b.max_consecutive_failures} failures
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge tone={toneFor(BREAKER_TONE, b.breaker_state)}>{b.breaker_state}</Badge>
                    {has("RESET_CIRCUIT") && (
                      <Button
                        variant="secondary"
                        onClick={() => setPending({ kind: "breaker", breaker: b })}
                      >
                        Reset
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>

      <div className="mt-6">
        <Section
          title="Reconciliation"
          icon={<RotateCcw className="h-4 w-4" />}
          actions={
            has("RUN_RECONCILIATION") ? (
              <Button
                variant="secondary"
                pending={busy}
                onClick={() => execute(() => runReconciliation())}
              >
                Run reconciliation
              </Button>
            ) : undefined
          }
        >
          {reconciliationQuery.data ? (
            <DataList columns={3}>
              <DataRow label="Status">{reconciliationQuery.data.status}</DataRow>
              <DataRow label="Trigger">{reconciliationQuery.data.trigger}</DataRow>
              <DataRow label="Findings">
                {(reconciliationQuery.data.findings ?? []).length}
              </DataRow>
            </DataList>
          ) : (
            <p className="text-sm text-gray-500">No reconciliation has run yet.</p>
          )}
        </Section>
      </div>

      <div className="mt-6">
        <Section title="Repository controls" icon={<Ban className="h-4 w-4" />}>
          {repositoriesQuery.isError ? (
            <p className="text-sm text-red-700">Repositories unavailable.</p>
          ) : (repositoriesQuery.data ?? []).length === 0 ? (
            <p className="text-sm text-gray-500">No repositories connected.</p>
          ) : (
            <ul className="divide-y">
              {(repositoriesQuery.data ?? []).map((r) => (
                <RepoControlRow
                  key={r.repository.id}
                  repositoryId={r.repository.id}
                  name={`${r.repository.owner}/${r.repository.name}`}
                  canControl={has("SET_REPO_CONTROL")}
                  onRequestPause={(repositoryId, repoName) =>
                    setPending({ kind: "repo", repositoryId, repoName, controlState: "PAUSED" })
                  }
                />
              ))}
            </ul>
          )}
        </Section>
      </div>

      {has("VIEW_DIAGNOSTICS") && (
        <div className="mt-6">
          <Section title="Operational events (diagnostics)" icon={<Activity className="h-4 w-4" />}>
            {(eventsQuery.data ?? []).length === 0 ? (
              <p className="text-sm text-gray-500">No operational events.</p>
            ) : (
              <ul className="divide-y">
                {(eventsQuery.data ?? []).map((e) => (
                  <li key={e.id} className="py-2 flex items-start justify-between gap-3 text-sm">
                    <div className="min-w-0">
                      <p className="font-medium text-gray-800 break-all">{e.event_type}</p>
                      {e.detail && (
                        <p className="text-xs text-gray-500 break-words">{e.detail}</p>
                      )}
                    </div>
                    <span className="text-xs text-gray-500 shrink-0">
                      {formatTime(e.created_at)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </div>
      )}

      <ConfirmDialog
        open={pending !== null}
        danger={
          pending?.kind === "state" &&
          (pending.target === "EMERGENCY_STOP")
        }
        title={
          pending?.kind === "state"
            ? pending.title
            : pending?.kind === "breaker"
            ? "Reset this circuit breaker?"
            : pending?.kind === "repo"
            ? `Pause containment for ${pending.repoName}?`
            : ""
        }
        description={
          pending?.kind === "state"
            ? pending.description
            : pending?.kind === "breaker"
            ? "Resetting closes the breaker and clears its failure counter so execution can be re-admitted. Requires fresh step-up authentication."
            : "Pausing containment stops new remediations for this repository until re-enabled."
        }
        consequences={
          pending?.kind === "state"
            ? pending.consequences
            : pending?.kind === "breaker"
            ? [
                "The breaker returns to CLOSED with zero consecutive failures.",
                "This does not re-run or undo any past execution.",
              ]
            : ["New remediations for this repository are blocked.", "In-flight work is not killed."]
        }
        confirmLabel={
          pending?.kind === "repo" ? "Pause repository" : pending?.kind === "breaker" ? "Reset breaker" : "Confirm"
        }
        confirmPhrase={pending?.kind === "state" ? pending.phrase : undefined}
        pending={busy}
        onConfirm={() => {
          if (pending?.kind === "state") {
            execute(() => setOpsState(pending.target));
          } else if (pending?.kind === "breaker") {
            execute(() => resetBreaker(pending.breaker.id));
          } else if (pending?.kind === "repo") {
            execute(() =>
              setRepositoryControl(pending.repositoryId, { control_state: pending.controlState })
            );
          }
        }}
        onCancel={() => setPending(null)}
      />
    </div>
  );
}
