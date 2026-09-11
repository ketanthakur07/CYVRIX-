"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCw,
  ArrowRight,
  Shield,
} from "lucide-react";
import { fetchScan, fetchScanFindings } from "@/lib/api";
import {
  SEVERITY_COLORS,
  STATUS_COLORS,
  SCAN_STATUS_STEPS,
  isTerminalStatus,
  VERDICT_COLORS,
  SOURCE_TYPE_COLORS,
  SOURCE_TYPE_ICONS,
  TRUST_LEVEL_COLORS,
} from "@/lib/types";
import type { FindingDetail, ScanStatus } from "@/lib/types";

export default function ScanPage() {
  const params = useParams();
  const id = params.id as string;

  const { data: scan, isLoading: scanLoading, error: scanError } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => fetchScan(id),
    refetchInterval: (query) => {
      // Stop polling when scan reaches terminal state
      const status = query.state.data?.status;
      if (status && isTerminalStatus(status as ScanStatus)) {
        return false;
      }
      return 2000;
    },
  });

  const { data: findings, isLoading: findingsLoading } = useQuery({
    queryKey: ["scanFindings", id],
    queryFn: () => fetchScanFindings(id),
    refetchInterval: (query) => {
      const status = scan?.status;
      if (status && isTerminalStatus(status as ScanStatus)) {
        return false;
      }
      return 5000;
    },
    enabled: !!scan,
  });

  const isRunning = scan && !isTerminalStatus(scan.status as ScanStatus);
  const currentStep = scan
    ? SCAN_STATUS_STEPS.indexOf(scan.status as ScanStatus)
    : 0;

  if (scanLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="h-32 bg-gray-200 rounded-lg" />
        </div>
      </div>
    );
  }

  if (scanError || !scan) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Scan not found</p>
          <p className="text-red-600 text-sm mt-1">
            The scan may have been removed or you may not have access.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-2 text-sm text-gray-500 mb-1">
          <Link
            href={`/repositories/${scan.repository_id}`}
            className="hover:text-gray-700"
          >
            Repository
          </Link>
          <span>/</span>
          <span>Scan {id.slice(0, 8)}</span>
        </div>
        <h1 className="text-2xl font-bold">Scan Details</h1>
      </div>

      {/* Status bar */}
      <div className="bg-white border rounded-lg p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            {scan.status === "COMPLETED" ? (
              <CheckCircle className="h-6 w-6 text-green-500" />
            ) : scan.status === "FAILED" ? (
              <XCircle className="h-6 w-6 text-red-500" />
            ) : (
              <RefreshCw className="h-6 w-6 text-blue-500 animate-spin" />
            )}
            <div>
              <p className="font-medium">
                {scan.status.replace(/_/g, " ")}
              </p>
              {scan.error_reason && (
                <p className="text-sm text-red-600 mt-1">
                  {scan.error_reason}
                </p>
              )}
            </div>
          </div>
          {scan.commit_sha && (
            <span className="text-sm font-mono text-gray-500">
              Commit: {scan.commit_sha.slice(0, 8)}
            </span>
          )}
        </div>

        {/* Progress steps */}
        <div className="flex items-center gap-2 flex-wrap">
          {SCAN_STATUS_STEPS.map((step, i) => (
            <div key={step} className="flex items-center">
              <div
                className={`px-3 py-1 rounded text-xs font-medium ${
                  i < currentStep
                    ? "bg-green-100 text-green-800"
                    : i === currentStep
                    ? "bg-blue-100 text-blue-800"
                    : "bg-gray-100 text-gray-500"
                }`}
              >
                {step}
              </div>
              {i < SCAN_STATUS_STEPS.length - 1 && (
                <div className="w-8 h-px bg-gray-200 mx-1" />
              )}
            </div>
          ))}
        </div>

        {/* Failed scan retry hint */}
        {scan.status === "FAILED" && (
          <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-4">
            <p className="text-red-800 text-sm font-medium">Scan Failed</p>
            {scan.error_reason && (
              <p className="text-red-600 text-sm mt-1">
                Reason: {scan.error_reason}
              </p>
            )}
            <Link
              href={`/repositories/${scan.repository_id}`}
              className="inline-flex items-center gap-1 mt-2 text-sm text-blue-600 hover:underline"
            >
              Go to repository to retry
            </Link>
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="bg-white border rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">
          Findings {findings ? `(${findings.length})` : ""}
        </h2>

        {findingsLoading && !findings ? (
          <div className="animate-pulse space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-16 bg-gray-200 rounded" />
            ))}
          </div>
        ) : findings && findings.length === 0 ? (
          <div className="text-center py-8">
            <Shield className="h-8 w-8 text-gray-300 mx-auto mb-2" />
            <p className="text-gray-500">
              {isRunning
                ? "Scan in progress... findings will appear here."
                : scan.status === "COMPLETED"
                ? "No vulnerabilities detected in this scan."
                : "Findings will appear once the scan completes."}
            </p>
          </div>
        ) : findings && findings.length > 0 ? (
          <div className="divide-y">
            {findings.map((finding) => (
              <Link
                key={finding.id}
                href={`/findings/${finding.id}`}
                className="block py-4 hover:bg-gray-50 transition-colors px-2 rounded"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.UNKNOWN}`}
                      >
                        {finding.severity}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-medium border ${SOURCE_TYPE_COLORS[finding.source_type] || SOURCE_TYPE_COLORS.DEPENDENCY}`}
                      >
                        {SOURCE_TYPE_ICONS[finding.source_type] || "📦"} {finding.source_type}
                      </span>
                      {finding.vulnerability_id && (
                        <span className="text-xs font-mono text-gray-500">
                          {finding.vulnerability_id}
                        </span>
                      )}
                      {finding.recommendation?.trust_level && (
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${TRUST_LEVEL_COLORS[finding.recommendation.trust_level] || TRUST_LEVEL_COLORS.UNCERTAIN}`}
                        >
                          {finding.recommendation.trust_level}
                        </span>
                      )}
                    </div>
                    <p className="font-medium">{finding.title}</p>
                    <p className="text-sm text-gray-500 mt-1">
                      {finding.package_name}
                      {finding.package_version
                        ? `@${finding.package_version}`
                        : ""}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 ml-4">
                    {finding.risk_assessment && (
                      <div className="text-right">
                        <p className="text-xs text-gray-500">Risk</p>
                        <p className="font-bold text-lg">
                          {finding.risk_assessment.risk_score}
                        </p>
                      </div>
                    )}
                    {finding.investigation && finding.investigation.verdict && (
                      <span
                        className={`px-2 py-1 rounded text-xs font-medium ${VERDICT_COLORS[finding.investigation.verdict] || "bg-gray-100 text-gray-800"}`}
                      >
                        {finding.investigation.verdict}
                      </span>
                    )}
                    <ArrowRight className="h-4 w-4 text-gray-400" />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
