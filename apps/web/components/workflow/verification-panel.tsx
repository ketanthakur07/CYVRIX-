"use client";

import Link from "next/link";
import { ExternalLink, ShieldCheck, ShieldX } from "lucide-react";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { DataList, DataRow, Section } from "@/components/ui/card";
import { JsonBlock } from "@/components/ui/code-block";
import { cn } from "@/lib/cn";
import {
  formatTime,
  toneFor,
  VERIFICATION_STATE_TONE,
  VERIFICATION_RESULT_TONE,
} from "@/lib/workflow";
import type { VerificationCheck, VerificationRun } from "@/lib/types";

/**
 * V3.6 verification stage. Shows the deterministic checks and their
 * bounded evidence. A failed security-finding re-evaluation is surfaced
 * as a REGRESSION, never hidden behind a generic success banner.
 */
export function VerificationPanel({
  verifications,
  selectedId,
  onSelect,
  checks,
}: {
  verifications: VerificationRun[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  checks: VerificationCheck[];
}) {
  const selected = verifications.find((v) => v.id === selectedId) ?? verifications[0];

  const regressionCheck = checks.find(
    (c) => c.check_type === "VERIFY_SECURITY_FINDING" && c.result === "FAIL"
  );

  return (
    <Section
      title="Verification"
      icon={<ShieldCheck className="h-4 w-4" />}
      actions={
        selected ? (
          <Badge tone="neutral">
            {selected.checks_passed}/{selected.checks_total} checks passed
          </Badge>
        ) : undefined
      }
    >
      {verifications.length === 0 ? (
        <Alert tone="info" title="Not verified">
          Verification runs server-side deterministic checks against the
          committed change. It is created explicitly and executed by the
          internal executor — the browser never computes a verdict.
        </Alert>
      ) : (
        <>
          <ul className="divide-y border border-gray-200 rounded-lg mb-4">
            {verifications.map((v) => (
              <li key={v.id}>
                <button
                  onClick={() => onSelect(v.id)}
                  className={cn(
                    "w-full flex items-center justify-between gap-3 px-3 py-2 text-left hover:bg-gray-50",
                    selected?.id === v.id && "bg-blue-50"
                  )}
                >
                  <span className="font-mono text-xs text-gray-700 break-all">
                    {v.id.slice(0, 8)} · {formatTime(v.created_at)}
                  </span>
                  <span className="flex items-center gap-2 shrink-0">
                    <Badge tone={toneFor(VERIFICATION_STATE_TONE, v.verification_state)}>
                      {v.verification_state}
                    </Badge>
                    {v.result && (
                      <Badge tone={toneFor(VERIFICATION_RESULT_TONE, v.result)}>
                        {v.result}
                      </Badge>
                    )}
                  </span>
                </button>
              </li>
            ))}
          </ul>

          {selected && (
            <>
              <DataList columns={3}>
                <DataRow label="State">
                  <Badge tone={toneFor(VERIFICATION_STATE_TONE, selected.verification_state)}>
                    {selected.verification_state}
                  </Badge>
                </DataRow>
                <DataRow label="Result">
                  {selected.result ? (
                    <Badge tone={toneFor(VERIFICATION_RESULT_TONE, selected.result)}>
                      {selected.result}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </DataRow>
                <DataRow label="Reason code" mono>
                  {selected.reason_code ?? "—"}
                </DataRow>
                <DataRow label="Checks passed">{selected.checks_passed}</DataRow>
                <DataRow label="Checks failed">{selected.checks_failed}</DataRow>
                <DataRow label="Other checks">{selected.checks_other}</DataRow>
                <DataRow label="Plan version" mono>
                  {selected.plan_version}
                </DataRow>
                <DataRow label="Plan digest" mono>
                  {selected.plan_digest.slice(0, 16)}…
                </DataRow>
                <DataRow label="Finished">{formatTime(selected.finished_at)}</DataRow>
              </DataList>

              {regressionCheck && (
                <Alert tone="danger" className="mt-3" title="SECURITY REGRESSION DETECTED">
                  The original finding may be resolved, but the security-finding
                  re-evaluation failed. Overall verification is not a success —
                  review the failing check and roll back if needed.
                </Alert>
              )}

              {checks.length > 0 && (
                <div className="mt-4">
                  <p className="text-xs font-medium text-gray-500 mb-2">
                    Checks ({checks.length})
                  </p>
                  <div className="space-y-2">
                    {checks.map((c, i) => (
                      <div key={`${c.check_type}-${i}`} className="border border-gray-200 rounded p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs text-gray-800 break-all">
                            {c.check_type} · v{c.check_version}
                          </span>
                          <Badge tone={toneFor(VERIFICATION_RESULT_TONE, c.result)}>
                            {c.result}
                          </Badge>
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
                </div>
              )}

              <Link
                href={`/verifications/${selected.id}`}
                className="text-sm text-blue-600 hover:text-blue-800 inline-flex items-center gap-1 mt-4"
              >
                Open verification detail
                <ExternalLink className="h-3 w-3" />
              </Link>
            </>
          )}
        </>
      )}

      {selected && selected.result && selected.result !== "PASS" && selected.result !== "SKIPPED" && (
        <div className="mt-3 flex items-center gap-2 text-xs text-red-700">
          <ShieldX className="h-4 w-4" />
          Verification did not pass — CYVRIX does not report this as success.
        </div>
      )}
    </Section>
  );
}
