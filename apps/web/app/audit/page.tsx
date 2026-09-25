"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { Activity, ShieldCheck } from "lucide-react";
import { fetchAuditChains, fetchAuditIntegrityStatus } from "@/lib/api";
import { Alert, EmptyState } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { PageHeader, Section } from "@/components/ui/card";
import { ErrorState, LoadingBlock } from "@/components/ui/query-state";
import { ApiError } from "@/lib/api";

/**
 * V3.8 audit console index. Capability-gated server-side (VIEW_AUDIT —
 * ADMIN only). The UI shows "not authorized" for a 403 but never assumes
 * access; every route re-checks the capability on the server.
 *
 * The integrity status here is a server-computed summary. The browser
 * never recomputes the cryptographic chain.
 */
export default function AuditIndexPage() {
  const chainsQuery = useQuery({
    queryKey: ["audit-chains"],
    queryFn: fetchAuditChains,
  });
  const statusQuery = useQuery({
    queryKey: ["audit-integrity-status"],
    queryFn: fetchAuditIntegrityStatus,
  });

  if (chainsQuery.isLoading) {
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <LoadingBlock />
      </div>
    );
  }

  const err = chainsQuery.error;
  if (err) {
    const forbidden = err instanceof ApiError && err.status === 403;
    return (
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        <ErrorState
          title={forbidden ? "Audit access not granted" : "Audit unavailable"}
          error={err}
          onRetry={() => chainsQuery.refetch()}
        />
      </div>
    );
  }

  const chains = chainsQuery.data ?? [];
  const status = statusQuery.data;

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <PageHeader
        title="Audit integrity"
        subtitle="Tamper-evident security history. Read-only — there is no edit or delete path."
      />

      <Alert tone="info" className="mb-5" title="Tamper-evidence, not physical immutability">
        Every event is hash-chained per tenant. Integrity failures are
        detected by the server verifier; the browser never computes digests.
      </Alert>

      <Section
        title="Integrity status"
        icon={<ShieldCheck className="h-4 w-4" />}
        actions={
          status ? (
            <Badge tone={status.checkpointing_enabled ? "success" : "warning"}>
              {status.checkpointing_enabled ? "checkpointing enabled" : "checkpointing disabled"}
            </Badge>
          ) : undefined
        }
      >
        {statusQuery.isError ? (
          <p className="text-sm text-red-700">Integrity status unavailable.</p>
        ) : !status || status.chains.length === 0 ? (
          <p className="text-sm text-gray-500">No audit chains for this tenant.</p>
        ) : (
          <ul className="divide-y">
            {status.chains.map((c) => (
              <li key={c.chain_id} className="py-2 flex items-center justify-between gap-3 text-sm">
                <span className="font-mono text-xs text-gray-700 break-all">
                  {c.chain_id.slice(0, 12)}…
                </span>
                <span className="flex items-center gap-3 text-xs text-gray-500">
                  <span>last seq {c.last_sequence}</span>
                  <span>{c.event_count} events</span>
                </span>
              </li>
            ))}
          </ul>
        )}
        {!status?.checkpointing_enabled && (
          <Alert tone="warning" className="mt-3">
            Without a checkpoint key, tail-truncation cannot be detected by
            checkpoints alone. This is a documented limitation, not a hidden one.
          </Alert>
        )}
      </Section>

      <div className="mt-6">
        <Section title={`Chains (${chains.length})`} icon={<Activity className="h-4 w-4" />}>
          {chains.length === 0 ? (
            <EmptyState
              icon={<Activity className="h-8 w-8" />}
              title="No audit chains"
              description="Chains are created as lifecycle events are recorded."
            />
          ) : (
            <ul className="divide-y">
              {chains.map((c) => (
                <li key={c.chain_id}>
                  <Link
                    href={`/audit/${c.chain_id}`}
                    className="flex items-center justify-between gap-3 py-2 hover:bg-gray-50 px-1 rounded"
                  >
                    <span className="font-mono text-xs text-gray-700 break-all">
                      {c.chain_id}
                    </span>
                    <span className="text-xs text-gray-500 shrink-0">
                      seq {c.last_sequence} →
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </div>
  );
}
