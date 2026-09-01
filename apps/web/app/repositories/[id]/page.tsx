"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  GitBranch,
  AlertTriangle,
  Scan,
  ArrowRight,
  Clock,
  CheckCircle,
  XCircle,
  RefreshCw,
  FileText,
  AlertCircle,
} from "lucide-react";
import { fetchRepository, fetchRepositoryScans, triggerScan } from "@/lib/api";
import { STATUS_COLORS, SEVERITY_COLORS } from "@/lib/types";
import type { Scan as ScanType } from "@/lib/types";

export default function RepositoryPage() {
  const params = useParams();
  const id = params.id as string;
  const queryClient = useQueryClient();

  const {
    data: repo,
    isLoading: repoLoading,
    error: repoError,
  } = useQuery({
    queryKey: ["repository", id],
    queryFn: () => fetchRepository(id),
  });

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ["scans", id],
    queryFn: () => fetchRepositoryScans(id),
  });

  const scanMutation = useMutation({
    mutationFn: () => triggerScan(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["scans", id] });
      queryClient.invalidateQueries({ queryKey: ["repository", id] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  if (repoLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 bg-gray-200 rounded-lg" />
            ))}
          </div>
          <div className="h-32 bg-gray-200 rounded-lg" />
        </div>
      </div>
    );
  }

  if (repoError || !repo) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Repository not found</p>
          <p className="text-red-600 text-sm mt-1">
            The repository may have been removed or you may not have access.
          </p>
        </div>
      </div>
    );
  }

  const repoData = repo.repository;
  const isActive = repoData.is_active;

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 text-sm text-gray-500 mb-1">
            <Link href="/repositories" className="hover:text-gray-700">
              Repositories
            </Link>
            <span>/</span>
          </div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <GitBranch className="h-6 w-6" />
            {repoData.owner}/{repoData.name}
          </h1>
          <div className="flex items-center gap-3 mt-1">
            <span
              className={`text-xs font-medium px-2 py-0.5 rounded ${isActive ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"}`}
            >
              {isActive ? "Active" : "Inactive"}
            </span>
            <span className="text-xs text-gray-500">
              {repoData.default_branch} branch
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Link
            href={`/repositories/${id}/findings`}
            className="inline-flex items-center gap-2 px-3 py-2 border rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
          >
            <FileText className="h-4 w-4" />
            View Findings
          </Link>
          <button
            onClick={() => scanMutation.mutate()}
            disabled={!isActive || scanMutation.isPending}
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {scanMutation.isPending ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <Scan className="h-4 w-4" />
            )}
            {scanMutation.isPending ? "Starting..." : "Run Scan"}
          </button>
        </div>
      </div>

      {/* Scan error */}
      {scanMutation.isError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6 flex items-start gap-3">
          <AlertCircle className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
          <div>
            <p className="text-red-800 font-medium text-sm">
              Failed to start scan
            </p>
            <p className="text-red-600 text-sm mt-1">
              {scanMutation.error?.message || "An unexpected error occurred."}
            </p>
          </div>
        </div>
      )}

      {/* Inactive notice */}
      {!isActive && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
          <p className="text-yellow-800 text-sm">
            This repository is inactive. Activate it before running a scan.
          </p>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-white border rounded-lg p-4">
          <p className="text-sm text-gray-500">Total Findings</p>
          <p className="text-3xl font-bold">{repo.total_findings}</p>
        </div>
        {repo.findings_by_severity.map((s) => (
          <div key={s.severity} className="bg-white border rounded-lg p-4">
            <p className="text-sm text-gray-500">{s.severity}</p>
            <p
              className={`text-3xl font-bold ${SEVERITY_COLORS[s.severity as keyof typeof SEVERITY_COLORS] ? s.severity.toLowerCase() : ""}`}
            >
              {s.count}
            </p>
          </div>
        ))}
      </div>

      {/* Latest scan info */}
      {repo.latest_scan && (
        <div className="bg-white border rounded-lg p-6 mb-8">
          <h2 className="text-lg font-semibold mb-3">Latest Scan</h2>
          <div className="flex items-center gap-4">
            <span
              className={`px-3 py-1 rounded-full text-sm font-medium ${STATUS_COLORS[repo.latest_scan.status] || STATUS_COLORS.QUEUED}`}
            >
              {repo.latest_scan.status}
            </span>
            <span className="text-sm text-gray-500">
              {new Date(repo.latest_scan.created_at).toLocaleString()}
            </span>
            {repo.latest_scan.commit_sha && (
              <span className="text-sm font-mono text-gray-500">
                {repo.latest_scan.commit_sha.slice(0, 8)}
              </span>
            )}
          </div>
          {repo.latest_scan.error_reason && (
            <p className="text-sm text-red-600 mt-2">
              Error: {repo.latest_scan.error_reason}
            </p>
          )}
        </div>
      )}

      {/* Scan history */}
      <div className="bg-white border rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Scan History</h2>
        {scansLoading ? (
          <div className="animate-pulse space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-14 bg-gray-200 rounded" />
            ))}
          </div>
        ) : !scans || scans.length === 0 ? (
          <div className="text-center py-8">
            <Scan className="h-8 w-8 text-gray-300 mx-auto mb-2" />
            <p className="text-gray-500">
              No scans yet. Run your first scan to see results.
            </p>
          </div>
        ) : (
          <div className="divide-y">
            {scans.map((scan) => (
              <Link
                key={scan.id}
                href={`/scans/${scan.id}`}
                className="flex items-center justify-between py-3 hover:bg-gray-50 transition-colors px-2 rounded"
              >
                <div className="flex items-center gap-3">
                  {scan.status === "COMPLETED" ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : scan.status === "FAILED" ? (
                    <XCircle className="h-5 w-5 text-red-500" />
                  ) : (
                    <Clock className="h-5 w-5 text-yellow-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium">
                      Scan {scan.id.slice(0, 8)}
                    </p>
                    <p className="text-xs text-gray-500">
                      {new Date(scan.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-1 rounded text-xs font-medium ${STATUS_COLORS[scan.status] || STATUS_COLORS.QUEUED}`}
                  >
                    {scan.status}
                  </span>
                  <ArrowRight className="h-4 w-4 text-gray-400" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
