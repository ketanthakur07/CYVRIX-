"use client";

import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert } from "@/components/ui/alert";
import {
  authorizeAction,
  fetchProposalAuthorizations,
  fetchProposalRuns,
  fetchRemediationRollbacks,
  fetchRemediationVerifications,
  fetchRunRemediations,
  fetchVerificationChecks,
  revokeAuthorization,
  startRemediation,
  startRollback,
  startVerification,
} from "@/lib/api";
import {
  verificationAccepted,
  isTerminalRun,
  isTerminalRemediation,
  isTerminalVerification,
  isTerminalRollback,
} from "@/lib/workflow";
import type { ActionProposal, Approval } from "@/lib/types";
import { AuthorizationPanel } from "./authorization-panel";
import { ExecutionPanel } from "./execution-panel";
import { RemediationPanel } from "./remediation-panel";
import { VerificationPanel } from "./verification-panel";
import { RollbackPanel } from "./rollback-panel";
import { StateTimeline } from "./state-timeline";

/**
 * V3.9 — the full lifecycle for one action, from proposal to rollback.
 *
 * This component only DISPLAYS server records and REQUESTS transitions.
 * Every mutation sends human metadata (or an empty body) and the server
 * re-verifies digest, policy, eligibility, kill switch, and freshness.
 * No client state grants authority; unknown/absent data renders as
 * "—"/"not yet", never as success.
 */
export function ActionLifecycle({
  proposal,
  approval,
}: {
  proposal: ActionProposal;
  approval: Approval | undefined;
}) {
  const queryClient = useQueryClient();
  const proposalId = proposal.id;

  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedRemediationId, setSelectedRemediationId] = useState<string | null>(null);
  const [selectedVerificationId, setSelectedVerificationId] = useState<string | null>(null);
  const [selectedRollbackId, setSelectedRollbackId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const authorizationsQuery = useQuery({
    queryKey: ["authorizations", proposalId],
    queryFn: () => fetchProposalAuthorizations(proposalId),
  });

  const runsQuery = useQuery({
    queryKey: ["runs", proposalId],
    queryFn: () => fetchProposalRuns(proposalId),
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data || data.length === 0) return false;
      return data.some((r) => !isTerminalRun(r.run_state)) ? 5000 : false;
    },
  });

  const runs = useMemo(() => runsQuery.data ?? [], [runsQuery.data]);
  const effectiveRunId = selectedRunId ?? runs[0]?.id ?? null;

  const remediationsQuery = useQuery({
    queryKey: ["remediations", effectiveRunId],
    queryFn: () => fetchRunRemediations(effectiveRunId as string),
    enabled: !!effectiveRunId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data || data.length === 0) return false;
      return data.some((r) => !isTerminalRemediation(r.remediation_state)) ? 5000 : false;
    },
  });

  const remediations = useMemo(() => remediationsQuery.data ?? [], [remediationsQuery.data]);
  const effectiveRemediationId =
    selectedRemediationId ?? remediations[0]?.id ?? null;
  const selectedRemediation = remediations.find((r) => r.id === effectiveRemediationId) ?? null;

  const verificationsQuery = useQuery({
    queryKey: ["verifications", effectiveRemediationId],
    queryFn: () => fetchRemediationVerifications(effectiveRemediationId as string),
    enabled: !!effectiveRemediationId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data || data.length === 0) return false;
      return data.some((v) => !isTerminalVerification(v.verification_state)) ? 5000 : false;
    },
  });

  const verifications = useMemo(() => verificationsQuery.data ?? [], [verificationsQuery.data]);
  const effectiveVerificationId =
    selectedVerificationId ?? verifications[0]?.id ?? null;

  const checksQuery = useQuery({
    queryKey: ["verification-checks", effectiveVerificationId],
    queryFn: () => fetchVerificationChecks(effectiveVerificationId as string),
    enabled: !!effectiveVerificationId,
  });

  const rollbacksQuery = useQuery({
    queryKey: ["rollbacks", effectiveRemediationId],
    queryFn: () => fetchRemediationRollbacks(effectiveRemediationId as string),
    enabled: !!effectiveRemediationId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data || data.length === 0) return false;
      return data.some((r) => !isTerminalRollback(r.rollback_state)) ? 5000 : false;
    },
  });

  const rollbacks = useMemo(() => rollbacksQuery.data ?? [], [rollbacksQuery.data]);

  // When new records appear, default the selection to the newest one.
  useEffect(() => {
    if (!selectedRunId && runs[0]) setSelectedRunId(runs[0].id);
  }, [runs, selectedRunId]);
  useEffect(() => {
    if (!selectedRemediationId && remediations[0]) {
      setSelectedRemediationId(remediations[0].id);
    }
  }, [remediations, selectedRemediationId]);
  useEffect(() => {
    if (!selectedVerificationId && verifications[0]) {
      setSelectedVerificationId(verifications[0].id);
    }
  }, [verifications, selectedVerificationId]);
  useEffect(() => {
    if (!selectedRollbackId && rollbacks[0]) setSelectedRollbackId(rollbacks[0].id);
  }, [rollbacks, selectedRollbackId]);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await queryClient.invalidateQueries({ queryKey: ["authorizations", proposalId] });
      await queryClient.invalidateQueries({ queryKey: ["runs", proposalId] });
      await queryClient.invalidateQueries({ queryKey: ["remediations"] });
      await queryClient.invalidateQueries({ queryKey: ["verifications"] });
      await queryClient.invalidateQueries({ queryKey: ["rollbacks"] });
    } catch (e) {
      const reason = (e as { reasonCode?: string }).reasonCode;
      const msg = e instanceof Error ? e.message : "Request failed";
      setError(reason ? `${msg} (${reason})` : msg);
    } finally {
      setBusy(false);
    }
  }

  const reached = {
    proposed: true,
    approved:
      proposal.status === "APPROVED" ||
      !!approval &&
        (approval.approval_state === "APPROVED" || approval.approval_state === "USED"),
    authorized: authorizationsQuery.data ? authorizationsQuery.data.length > 0 : false,
    executed: runs.some((r) => r.run_state === "COMPLETED" || r.run_state === "RESULT_READY"),
    verified: verifications.some((v) => verificationAccepted(v.result)),
    rolled_back: rollbacks.some((r) => r.rollback_state === "COMPLETED"),
  } as const;

  const activeRun = runs.find((r) => r.id === effectiveRunId) ?? null;
  const canStartRemediation =
    !!activeRun &&
    (activeRun.run_state === "RESULT_READY" || activeRun.run_state === "COMPLETED") &&
    remediations.length === 0;
  const canStartVerification =
    !!selectedRemediation?.committed_sha && verifications.length === 0;
  const canStartRollback =
    !!selectedRemediation?.pushed_sha && rollbacks.length === 0;

  return (
    <div className="space-y-5">
      <StateTimeline reached={reached} />

      <AuthorizationPanel
        proposal={proposal}
        approval={approval}
        authorizations={authorizationsQuery.data ?? []}
        busy={busy}
        error={error}
        onAuthorize={() => run(() => authorizeAction(proposalId, { reason: "" }))}
        onRevoke={(id) => run(() => revokeAuthorization(id, { reason: "" }))}
      />

      <ExecutionPanel
        runs={runs}
        selectedRunId={effectiveRunId}
        onSelect={setSelectedRunId}
      />

      <RemediationPanel
        remediations={remediations}
        selectedId={effectiveRemediationId}
        onSelect={setSelectedRemediationId}
        canStartRemediation={canStartRemediation}
        canStartVerification={canStartVerification}
        canStartRollback={canStartRollback}
        busy={busy}
        error={error}
        onStartRemediation={() =>
          run(() => startRemediation(effectiveRunId as string))
        }
        onStartVerification={() =>
          run(() => startVerification(effectiveRemediationId as string))
        }
        onStartRollback={() =>
          run(() => startRollback(effectiveRemediationId as string))
        }
      />

      <VerificationPanel
        verifications={verifications}
        selectedId={effectiveVerificationId}
        onSelect={setSelectedVerificationId}
        checks={checksQuery.data ?? []}
      />

      <RollbackPanel
        rollbacks={rollbacks}
        selectedId={selectedRollbackId ?? rollbacks[0]?.id ?? null}
        onSelect={setSelectedRollbackId}
      />

      {busy && (
        <Alert tone="info" role="status">
          Requesting a server-side transition…
        </Alert>
      )}
    </div>
  );
}
