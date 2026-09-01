"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import {
  Shield,
  GitBranch,
  AlertTriangle,
  Scan,
  ArrowRight,
  Clock,
  CheckCircle,
  XCircle,
} from "lucide-react";
import { fetchDashboard } from "@/lib/api";
import { SEVERITY_COLORS, STATUS_COLORS, isTerminalStatus } from "@/lib/types";
import type { Scan as ScanType, SeverityCount } from "@/lib/types";

export default function DashboardPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["dashboard"],
    queryFn: fetchDashboard,
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded-lg" />
            ))}
          </div>
          <div className="h-48 bg-gray-200 rounded-lg" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Failed to load dashboard</p>
          <p className="text-red-600 text-sm mt-1">
            Please check that the API server is running.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-bold mb-6">Security Dashboard</h1>

      {/* Stats cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <div className="bg-white border rounded-lg p-6">
          <div className="flex items-center gap-3">
            <GitBranch className="h-8 w-8 text-blue-500" />
            <div>
              <p className="text-sm text-gray-500">Repositories</p>
              <p className="text-3xl font-bold">{data?.total_repositories ?? 0}</p>
            </div>
          </div>
        </div>
        <div className="bg-white border rounded-lg p-6">
          <div className="flex items-center gap-3">
            <Scan className="h-8 w-8 text-purple-500" />
            <div>
              <p className="text-sm text-gray-500">Scans</p>
              <p className="text-3xl font-bold">{data?.total_scans ?? 0}</p>
            </div>
          </div>
        </div>
        <div className="bg-white border rounded-lg p-6">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-8 w-8 text-orange-500" />
            <div>
              <p className="text-sm text-gray-500">Findings</p>
              <p className="text-3xl font-bold">{data?.total_findings ?? 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Severity breakdown */}
      {data?.findings_by_severity && data.findings_by_severity.length > 0 && (
        <div className="bg-white border rounded-lg p-6 mb-8">
          <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
          <div className="flex flex-wrap gap-3">
            {data.findings_by_severity.map((s) => (
              <div
                key={s.severity}
                className={`px-4 py-2 rounded-lg border ${SEVERITY_COLORS[s.severity as keyof typeof SEVERITY_COLORS] || SEVERITY_COLORS.UNKNOWN}`}
              >
                <span className="font-medium">{s.severity}</span>
                <span className="ml-2 font-bold">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Empty state */}
      {data?.total_repositories === 0 && (
        <div className="bg-white border rounded-lg p-12 text-center">
          <Shield className="h-12 w-12 text-gray-300 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-700 mb-2">
            No repositories connected yet
          </h2>
          <p className="text-gray-500 mb-4">
            Connect your GitHub account to start scanning repositories for
            vulnerabilities.
          </p>
          <a
            href="/api/github/connect"
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 transition-colors"
          >
            <GitBranch className="h-4 w-4" />
            Connect GitHub
          </a>
        </div>
      )}

      {/* Recent scans */}
      {data?.recent_scans && data.recent_scans.length > 0 && (
        <div className="bg-white border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
          <div className="divide-y">
            {data.recent_scans.map((scan) => (
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
        </div>
      )}
    </div>
  );
}
