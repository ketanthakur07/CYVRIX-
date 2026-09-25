"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { Download, ListChecks, ShieldCheck, ShieldAlert } from "lucide-react";
import {
  auditExportPath,
  fetchAuditCheckpoints,
  fetchAuditEvents,
  verifyAuditChain,
} from "@/lib/api";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { JsonBlock } from "@/components/ui/code-block";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { cn } from "@/lib/cn";
import {
  formatTime,
  shortDigest,
  toneFor,
  AUDIT_VERIFY_TONE,
} from "@/lib/workflow";
import type { AuditEvent, AuditVerifyResult } from "@/lib/types";

const PAGE_SIZE = 100;

/**
 * V3.8 audit chain detail. The timeline and event detail separate TRUSTED
 * envelope fields (server-derived) from the UNTRUSTED payload/evidence,
 * which is rendered as inert text. Integrity verification is requested
 * from the SERVER — the browser never computes the hash chain.
 */
export default function AuditChainPage() {
  const params = useParams();
  const chainId = params.chainId as string;

  const [fromSeq, setFromSeq] = useState(1);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);
  const [verifyResult, setVerifyResult] = useState<AuditVerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const eventsQuery = useQuery({
    queryKey: ["audit-events", chainId, fromSeq],
    queryFn: () => fetchAuditEvents(chainId, { limit: PAGE_SIZE, from_seq: fromSeq }),
  });
  const checkpointsQuery = useQuery({
    queryKey: ["audit-checkpoints", chainId],
    queryFn: () => fetchAuditCheckpoints(chainId),
  });

  async function doVerify() {
    setVerifying(true);
    setVerifyError(null);
    try {
      setVerifyResult(await verifyAuditChain(chainId));
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "Verification request failed");
    } finally {
      setVerifying(false);
    }
  }

  if (eventsQuery.isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-5xl">
        <LoadingBlock />
      </div>
    );
  }

  if (eventsQuery.error) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-5xl">
        <ErrorState
          title="Audit chain not available"
          error={eventsQuery.error}
          onRetry={() => eventsQuery.refetch()}
        />
      </div>
    );
  }

  const events: AuditEvent[] = eventsQuery.data ?? [];
  const selected = events.find((e) => e.seq === selectedSeq) ?? events[0] ?? null;

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl">
      <PageHeader
        title="Audit chain"
        subtitle={<span className="font-mono text-xs break-all">{chainId}</span>}
        backHref="/audit"
        backLabel="Back to audit"
        actions={
          <a
            href={auditExportPath(chainId)}
            className="inline-flex items-center gap-2 px-3 py-2 rounded border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <Download className="h-4 w-4" />
            Export NDJSON
          </a>
        }
      />

      <Section
        title="Integrity verification"
        icon={<ShieldCheck className="h-4 w-4" />}
        actions={
          <Button onClick={doVerify} pending={verifying} pendingLabel="Verifying…">
            Verify chain
          </Button>
        }
      >
        <p className="text-xs text-gray-500 mb-3">
          Verification is computed by the server and returned as a structured
          verdict. The browser never recomputes the chain.
        </p>

        {verifyError && (
          <Alert tone="danger" title="Verification request failed">
            {verifyError}
          </Alert>
        )}

        {verifyResult && (
          <div>
            <div className="flex items-center gap-2">
              {verifyResult.status === "VALID" ? (
                <ShieldCheck className="h-5 w-5 text-green-600" />
              ) : (
                <ShieldAlert className="h-5 w-5 text-red-600" />
              )}
              <Badge tone={toneFor(AUDIT_VERIFY_TONE, verifyResult.status)}>
                {verifyResult.status}
              </Badge>
              <span className="text-xs text-gray-500">
                {verifyResult.checked_events} event(s) checked
              </span>
            </div>
            {verifyResult.issues.length > 0 && (
              <ul className="mt-3 space-y-1 text-sm">
                {verifyResult.issues.map((issue, i) => (
                  <li key={i} className="flex items-start gap-2 text-red-700">
                    <span className="font-mono text-xs shrink-0">{issue.code}</span>
                    <span className="text-gray-600 break-words">
                      {issue.seq != null ? `seq ${issue.seq}: ` : ""}
                      {issue.detail ?? ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Section>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mt-6">
        <Section
          title={`Events (${events.length})`}
          icon={<ListChecks className="h-4 w-4" />}
          actions={
            events.length === PAGE_SIZE ? (
              <button
                onClick={() => {
                  const last = events[events.length - 1];
                  if (last) setFromSeq(last.seq + 1);
                }}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                Next page →
              </button>
            ) : fromSeq > 1 ? (
              <button
                onClick={() => setFromSeq(1)}
                className="text-xs text-blue-600 hover:text-blue-800"
              >
                ← First page
              </button>
            ) : undefined
          }
        >
          {events.length === 0 ? (
            <p className="text-sm text-gray-500">No events on this chain.</p>
          ) : (
            <ul className="max-h-[32rem] overflow-y-auto divide-y">
              {events.map((e) => (
                <li key={e.seq}>
                  <button
                    onClick={() => setSelectedSeq(e.seq)}
                    className={cn(
                      "w-full text-left px-2 py-2 hover:bg-gray-50",
                      selected?.seq === e.seq && "bg-blue-50"
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-gray-500">#{e.seq}</span>
                      <span className="font-medium text-xs text-gray-900 break-all">
                        {e.event_type}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 mt-1 text-[11px] text-gray-500">
                      <span>{e.actor_type}</span>
                      <span>{formatTime(e.recorded_at)}</span>
                    </div>
                    {e.result && (
                      <span className="text-[11px] text-gray-500">result: {e.result}</span>
                    )}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Event detail">
          {!selected ? (
            <p className="text-sm text-gray-500">Select an event.</p>
          ) : (
            <>
              <DataList columns={2}>
                <DataRow label="Sequence" mono>{selected.seq}</DataRow>
                <DataRow label="Event type">{selected.event_type}</DataRow>
                <DataRow label="Event version" mono>{selected.event_version}</DataRow>
                <DataRow label="Actor type">{selected.actor_type}</DataRow>
                <DataRow label="Actor id" mono>{selected.actor_id ?? "—"}</DataRow>
                <DataRow label="Reason code" mono>{selected.reason_code ?? "—"}</DataRow>
                <DataRow label="Result" mono>{selected.result ?? "—"}</DataRow>
                <DataRow label="Occurred">{formatTime(selected.occurred_at)}</DataRow>
                <DataRow label="Recorded">{formatTime(selected.recorded_at)}</DataRow>
                <DataRow label="Repository" mono>{selected.repository_id ?? "—"}</DataRow>
                <DataRow label="Action" mono>{selected.action_id ?? "—"}</DataRow>
                <DataRow label="Authorization" mono>{selected.authorization_id ?? "—"}</DataRow>
                <DataRow label="Execution run" mono>{selected.execution_run_id ?? "—"}</DataRow>
                <DataRow label="Verification" mono>{selected.verification_id ?? "—"}</DataRow>
                <DataRow label="Rollback" mono>{selected.rollback_id ?? "—"}</DataRow>
                <DataRow label="Prev digest" mono>{shortDigest(selected.prev_digest)}</DataRow>
                <DataRow label="Event digest" mono>{shortDigest(selected.event_digest)}</DataRow>
              </DataList>

              <div className="mt-4">
                <p className="text-xs font-medium text-gray-500 mb-1">
                  Untrusted payload (redacted, rendered as inert text)
                </p>
                <JsonBlock value={selected.payload} />
              </div>
            </>
          )}
        </Section>
      </div>

      <div className="mt-6">
        <Section title={`Checkpoints (${checkpointsQuery.data?.length ?? 0})`}>
          {checkpointsQuery.data && checkpointsQuery.data.length > 0 ? (
            <ul className="divide-y">
              {checkpointsQuery.data.map((cp) => (
                <li key={`${cp.chain_id}-${cp.through_sequence}`} className="py-2 text-sm flex items-center justify-between gap-3">
                  <span className="font-mono text-xs text-gray-700">
                    through #{cp.through_sequence} · {cp.event_count} events
                  </span>
                  <span className="text-xs text-gray-500">
                    mac key v{cp.mac_key_version} · {formatTime(cp.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-gray-500">
              No checkpoints recorded (checkpointing may be disabled).
            </p>
          )}
        </Section>
      </div>
    </div>
  );
}
