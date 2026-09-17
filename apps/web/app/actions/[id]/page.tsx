"use client";

import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  FileEdit,
  GitBranch,
  Lock,
  Scale,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import {
  approveProposal,
  fetchActionApproval,
  fetchActionProposal,
  rejectProposal,
} from "@/lib/api";
import type { ActionProposal, Approval } from "@/lib/types";

/**
 * CYVRIX V3.2 — Human approval screen for one action proposal.
 *
 * Security/UX rules (docs/v3-approval-model.md §8, security-model §9):
 * - Every security-relevant field is visible — never hidden behind collapses.
 * - Only [APPROVE] and [REJECT] exist. No "fix it", no "approve all".
 * - Approval requires an explicit typed confirmation of the action digest.
 * - All proposal content is rendered as plain text — never as HTML.
 * - The browser makes no authorization decisions; the server re-verifies
 *   everything (digest, policy, eligibility, step-up, expiry).
 */

const APPROVAL_STATE_STYLES: Record<string, string> = {
  PENDING: "bg-yellow-100 text-yellow-800 border-yellow-200",
  APPROVED: "bg-green-100 text-green-800 border-green-200",
  REJECTED: "bg-red-100 text-red-800 border-red-200",
  EXPIRED: "bg-gray-100 text-gray-800 border-gray-200",
  REVOKED: "bg-purple-100 text-purple-800 border-purple-200",
  USED: "bg-blue-100 text-blue-800 border-blue-200",
};

const APPROVAL_LEVEL_LABELS: Record<string, string> = {
  LOW: "Self-approval allowed (with step-up)",
  MEDIUM: "Self-approval allowed (with step-up)",
  HIGH: "Second principal required",
  CRITICAL: "Second principal required",
};

function JsonAsText({ value }: { value: unknown }) {
  return (
    <pre className="text-xs bg-gray-50 border border-gray-200 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="border border-gray-200 rounded-lg p-4">
      <h3 className="flex items-center gap-2 font-semibold text-gray-900 mb-3 text-sm">
        {icon}
        {title}
      </h3>
      {children}
    </section>
  );
}

export default function ActionApprovalPage() {
  const params = useParams();
  const id = params.id as string;
  const queryClient = useQueryClient();

  const [confirmText, setConfirmText] = useState("");
  const [reason, setReason] = useState("");
  const [secondApproverId, setSecondApproverId] = useState("");
  const [tokenShown, setTokenShown] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"" | "approve" | "reject">("");

  const { data: proposal, isLoading, error } = useQuery({
    queryKey: ["action-proposal", id],
    queryFn: () => fetchActionProposal(id),
  });

  const { data: approval } = useQuery({
    queryKey: ["action-approval", id],
    queryFn: () => fetchActionApproval(id),
    enabled: !!proposal,
  });

  const needsSecondPrincipal = useMemo(
    () =>
      !!proposal &&
      (proposal.risk_level === "HIGH" || proposal.risk_level === "CRITICAL") &&
      proposal.created_by !== undefined,
    [proposal]
  );

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-4 max-w-4xl mx-auto">
          <div className="h-8 bg-gray-200 rounded w-96" />
          <div className="h-64 bg-gray-200 rounded-lg" />
        </div>
      </div>
    );
  }

  if (error || !proposal) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center max-w-4xl mx-auto">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Action proposal not found</p>
          <p className="text-red-600 text-sm mt-1">
            It may have expired, or you may not have access.
          </p>
        </div>
      </div>
    );
  }

  const terminalStates = ["REJECTED", "EXPIRED", "STALE"];
  const isApproved = proposal.status === "APPROVED";
  const actionClosed = terminalStates.includes(proposal.status) || isApproved;

  async function doApprove() {
    setActionError(null);
    setBusy("approve");
    try {
      const result = await approveProposal(id, {
        reason,
        second_approver_user_id: secondApproverId || undefined,
      });
      if (result.authorization_token) {
        setTokenShown(result.authorization_token);
      }
      await queryClient.invalidateQueries({ queryKey: ["action-proposal", id] });
      await queryClient.invalidateQueries({ queryKey: ["action-approval", id] });
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Approval failed");
    } finally {
      setBusy("");
    }
  }

  async function doReject() {
    setActionError(null);
    setBusy("reject");
    try {
      await rejectProposal(id, { reason });
      await queryClient.invalidateQueries({ queryKey: ["action-proposal", id] });
      await queryClient.invalidateQueries({ queryKey: ["action-approval", id] });
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Rejection failed");
    } finally {
      setBusy("");
    }
  }

  const confirmMatches = confirmText === proposal.action_digest;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <h1 className="text-2xl font-bold text-gray-900 mb-1 flex items-center gap-2">
        <Scale className="h-6 w-6" />
        Action approval
      </h1>
      <p className="text-sm text-gray-500 mb-6">
        Review the exact scope below. Approval binds to this exact action —
        it authorizes nothing else. Approval is NOT execution: no code runs,
        nothing is written to any repository.
      </p>

      {/* State banner — APPROVED is never displayed as EXECUTED */}
      <div
        className={`rounded-lg border p-4 mb-6 ${
          isApproved
            ? "bg-green-50 border-green-200"
            : terminalStates.includes(proposal.status)
            ? "bg-gray-50 border-gray-200"
            : "bg-yellow-50 border-yellow-200"
        }`}
      >
        <div className="flex items-center gap-2">
          {isApproved ? (
            <ShieldCheck className="h-5 w-5 text-green-600" />
          ) : (
            <ShieldAlert className="h-5 w-5 text-yellow-600" />
          )}
          <span className="font-semibold">
            Proposal status: {proposal.status}
          </span>
          {isApproved && (
            <span className="text-sm text-green-700">
              — approval recorded. This action has NOT been executed.
            </span>
          )}
        </div>
        {approval && (
          <p className="text-sm text-gray-600 mt-2">
            Approval state:{" "}
            <span
              className={`px-2 py-0.5 rounded border text-xs font-medium ${
                APPROVAL_STATE_STYLES[approval.approval_state] ??
                "bg-gray-100 text-gray-800 border-gray-200"
              }`}
            >
              {approval.approval_state}
            </span>
            {approval.authorization_used_at && (
              <span className="ml-2 text-xs text-gray-500">
                authorization used at {approval.authorization_used_at}
              </span>
            )}
          </p>
        )}
      </div>

      {/* WHAT / WHERE / WHY */}
      <div className="space-y-4 mb-6">
        <Section title="What will change" icon={<FileEdit className="h-4 w-4" />}>
          <p className="text-sm text-gray-700 whitespace-pre-wrap break-words">
            {proposal.rationale || "No rationale provided."}
          </p>
          <div className="mt-3">
            <p className="text-xs font-medium text-gray-500 mb-1">Expected diff</p>
            <pre className="text-xs bg-gray-900 text-gray-100 rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
              {proposal.expected_diff || "(empty)"}
            </pre>
          </div>
        </Section>

        <Section title="Where it will change" icon={<GitBranch className="h-4 w-4" />}>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
            <div>
              <dt className="text-gray-500">Base commit</dt>
              <dd className="font-mono break-all">{proposal.base_commit_sha}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Target branch</dt>
              <dd className="font-mono break-words">{proposal.target_branch}</dd>
            </div>
          </dl>
          <div className="mt-3">
            <p className="text-xs font-medium text-gray-500 mb-1">
              Files affected ({proposal.files.length})
            </p>
            <ul className="text-sm font-mono space-y-0.5 break-all">
              {proposal.files.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
          </div>
          <div className="mt-3">
            <p className="text-xs font-medium text-gray-500 mb-1">
              Operations ({proposal.operations.length})
            </p>
            <JsonAsText value={proposal.operations} />
          </div>
        </Section>

        <Section title="Risk & trust" icon={<AlertTriangle className="h-4 w-4" />}>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 text-sm">
            <div>
              <dt className="text-gray-500">Risk before</dt>
              <dd className="font-semibold">
                {proposal.risk_level} ({proposal.risk_score})
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">Expected risk after</dt>
              <dd className="font-semibold text-green-700">Reduced</dd>
            </div>
            <div>
              <dt className="text-gray-500">Trust level</dt>
              <dd>{proposal.recommendation_trust ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Validation</dt>
              <dd>{proposal.validation_state ?? "—"}</dd>
            </div>
          </dl>
        </Section>

        <Section title="Policy" icon={<Lock className="h-4 w-4" />}>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-sm">
            <div>
              <dt className="text-gray-500">Policy decision</dt>
              <dd className="font-semibold">{proposal.policy_decision}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Policy version</dt>
              <dd>{proposal.policy_version}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Reason code</dt>
              <dd className="font-mono text-xs break-all">
                {proposal.policy_reason_code}
              </dd>
            </div>
            <div>
              <dt className="text-gray-500">Expires</dt>
              <dd className="text-xs">{proposal.expires_at ?? "—"}</dd>
            </div>
          </dl>
          <div className="mt-3">
            <p className="text-xs font-medium text-gray-500 mb-1">
              Action digest (approval binds to this exact value)
            </p>
            <p className="font-mono text-xs bg-gray-50 border rounded p-2 break-all">
              {proposal.action_digest}
            </p>
          </div>
        </Section>

        <Section title="Evidence" icon={<FileEdit className="h-4 w-4" />}>
          <JsonAsText value={proposal.evidence ?? {}} />
        </Section>
      </div>

      {/* One-time token issuance banner */}
      {tokenShown && (
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <p className="font-medium text-blue-900 text-sm mb-1">
            One-time authorization token (shown only once)
          </p>
          <p className="text-xs text-blue-700 mb-2">
            Store it now — it is never displayed again and only its hash is
            persisted. It is single-use and expires with the approval.
          </p>
          <code className="block font-mono text-xs bg-white border border-blue-200 rounded p-2 break-all select-all">
            {tokenShown}
          </code>
        </div>
      )}

      {/* Approve / reject controls */}
      {actionClosed ? (
        <div className="border border-gray-200 rounded-lg p-4 text-sm text-gray-600">
          This proposal is {proposal.status.toLowerCase()} — the approval
          decision window is closed.
          {isApproved && " The recorded approval is authorization data only; nothing was executed."}
        </div>
      ) : (
        <div className="border border-gray-200 rounded-lg p-4">
          {needsSecondPrincipal && (
            <div className="bg-orange-50 border border-orange-200 rounded p-3 mb-4 text-sm text-orange-800">
              <strong>Second principal required.</strong> This is a{" "}
              {proposal.risk_level}-risk action: the approver must be a
              different user than the proposal creator, and both users need a
              recent step-up authentication.
            </div>
          )}

          <label className="block text-sm font-medium text-gray-700 mb-1">
            Reason (optional, stored as human metadata)
          </label>
          <textarea
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={2000}
            rows={2}
            className="w-full border border-gray-300 rounded p-2 text-sm mb-4"
            placeholder="Why are you approving/rejecting this action?"
          />

          {needsSecondPrincipal && (
            <>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Second approver user ID
              </label>
              <input
                value={secondApproverId}
                onChange={(e) => setSecondApproverId(e.target.value)}
                className="w-full border border-gray-300 rounded p-2 text-sm font-mono mb-4"
                placeholder="UUID of the second principal"
              />
            </>
          )}

          <label className="block text-sm font-medium text-gray-700 mb-1">
            Type the action digest to confirm approval
          </label>
          <input
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            className="w-full border border-gray-300 rounded p-2 text-sm font-mono mb-1"
            placeholder="Paste the full action digest"
          />
          <p className="text-xs text-gray-500 mb-4">
            {APPROVAL_LEVEL_LABELS[proposal.risk_level] ??
              "Approval requirements depend on the policy decision."}
          </p>

          {actionError && (
            <div className="bg-red-50 border border-red-200 text-red-700 text-sm rounded p-3 mb-4">
              {actionError}
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={doApprove}
              disabled={!confirmMatches || busy !== ""}
              className="px-4 py-2 bg-green-600 text-white rounded font-medium text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:bg-green-700"
            >
              {busy === "approve" ? "Approving…" : "APPROVE"}
            </button>
            <button
              onClick={doReject}
              disabled={busy !== ""}
              className="px-4 py-2 bg-red-600 text-white rounded font-medium text-sm disabled:opacity-40 disabled:cursor-not-allowed hover:bg-red-700"
            >
              {busy === "reject" ? "Rejecting…" : "REJECT"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
