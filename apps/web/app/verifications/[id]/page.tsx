"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { fetchVerification, fetchVerificationChecks } from "@/lib/api";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, PageHeader, Section } from "@/components/ui/card";
import { JsonBlock } from "@/components/ui/code-block";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import {
  formatTime,
  toneFor,
  VERIFICATION_STATE_TONE,
  VERIFICATION_RESULT_TONE,
} from "@/lib/workflow";

/**
 * V3.6 verification detail. Renders the server's verdict and each
 * deterministic check with bounded evidence. A failed security-finding
 * check is surfaced as a regression — never a green success banner.
 */
export default function VerificationPage() {
  const params = useParams();
  const id = params.id as string;

  const verificationQuery = useQuery({
    queryKey: ["verification", id],
    queryFn: () => fetchVerification(id),
  });
  const checksQuery = useQuery({
    queryKey: ["verification-checks", id],
    queryFn: () => fetchVerificationChecks(id),
  });

  if (verificationQuery.isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <LoadingBlock />
      </div>
    );
  }

  if (verificationQuery.error || !verificationQuery.data) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <ErrorState
          title="Verification not available"
          error={verificationQuery.error}
          onRetry={() => verificationQuery.refetch()}
        />
      </div>
    );
  }

  const v = verificationQuery.data;
  const checks = checksQuery.data ?? [];
  const regression = checks.find(
    (c) => c.check_type === "VERIFY_SECURITY_FINDING" && c.result === "FAIL"
  );

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title="Verification"
        subtitle={<span className="font-mono text-xs">{v.id}</span>}
        backHref={`/remediations/${v.git_remediation_id}`}
        backLabel="Back to remediation"
        actions={
          <span className="flex items-center gap-2">
            <Badge tone={toneFor(VERIFICATION_STATE_TONE, v.verification_state)}>
              {v.verification_state}
            </Badge>
            {v.result && (
              <Badge tone={toneFor(VERIFICATION_RESULT_TONE, v.result)}>{v.result}</Badge>
            )}
          </span>
        }
      />

      {regression && (
        <Alert tone="danger" className="mb-5" title="SECURITY REGRESSION DETECTED">
          The security-finding re-evaluation failed. This verification is not a
          success even if the original finding no longer appears.
        </Alert>
      )}

      <Section title="Verification record" icon={<ShieldCheck className="h-4 w-4" />}>
        <DataList columns={3}>
          <DataRow label="Reason code" mono>{v.reason_code ?? "—"}</DataRow>
          <DataRow label="Detail">{v.detail ?? "—"}</DataRow>
          <DataRow label="Plan version" mono>{v.plan_version}</DataRow>
          <DataRow label="Checks total">{v.checks_total}</DataRow>
          <DataRow label="Checks passed">{v.checks_passed}</DataRow>
          <DataRow label="Checks failed">{v.checks_failed}</DataRow>
          <DataRow label="Other checks">{v.checks_other}</DataRow>
          <DataRow label="Started">{formatTime(v.started_at)}</DataRow>
          <DataRow label="Finished">{formatTime(v.finished_at)}</DataRow>
        </DataList>
      </Section>

      <div className="mt-6">
        <Section title={`Checks (${checks.length})`}>
          {checks.length === 0 ? (
            <p className="text-sm text-gray-500">No checks recorded.</p>
          ) : (
            <div className="space-y-3">
              {checks.map((c, i) => (
                <div key={`${c.check_type}-${i}`} className="border border-gray-200 rounded p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-gray-800 break-all">
                      {c.check_type} · v{c.check_version}
                    </span>
                    <Badge tone={toneFor(VERIFICATION_RESULT_TONE, c.result)}>{c.result}</Badge>
                  </div>
                  <p className="text-xs text-gray-500 mt-1 font-mono break-all">
                    reason: {c.reason_code}
                  </p>
                  <div className="mt-2">
                    <JsonBlock value={c.evidence} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Section>
      </div>

      <div className="mt-5">
        <Section title="Frozen verification plan">
          <JsonBlock value={v.verification_plan} />
        </Section>
      </div>
    </div>
  );
}
