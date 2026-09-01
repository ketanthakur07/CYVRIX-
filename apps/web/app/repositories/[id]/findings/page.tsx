"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import Link from "next/link";
import { useState } from "react";
import {
  AlertTriangle,
  Shield,
  ArrowRight,
  ArrowLeft,
  Filter,
  Search,
} from "lucide-react";
import {
  fetchRepository,
  fetchRepositoryFindings,
} from "@/lib/api";
import type {
  RepositorySummary,
  Finding,
  Severity,
  FindingStatus,
  SEVERITY_COLORS,
} from "@/lib/types";

const severityOptions: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const statusOptions: FindingStatus[] = ["OPEN", "CONFIRMED", "FALSE_POSITIVE", "RESOLVED"];

const severityBadgeClasses: Record<string, string> = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM: "bg-yellow-100 text-yellow-800 border-yellow-200",
  LOW: "bg-green-100 text-green-800 border-green-200",
  UNKNOWN: "bg-gray-100 text-gray-800 border-gray-200",
};

export default function RepositoryFindingsPage() {
  const params = useParams();
  const id = params.id as string;
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");

  const { data: repo, isLoading: repoLoading } = useQuery({
    queryKey: ["repository", id],
    queryFn: () => fetchRepository(id),
  });

  const { data: findings, isLoading: findingsLoading, error: findingsError } =
    useQuery({
      queryKey: ["repositoryFindings", id, severityFilter, statusFilter],
      queryFn: () =>
        fetchRepositoryFindings(id, {
          severity: severityFilter || undefined,
          status: statusFilter || undefined,
        }),
    });

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back link */}
      <Link
        href={`/repositories/${id}`}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-4"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to repository
      </Link>

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">
            {repo
              ? `${repo.repository.owner}/${repo.repository.name}`
              : "Repository"}
          </h1>
          <p className="text-sm text-gray-500">Findings</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white border rounded-lg p-4 mb-6">
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-400" />
            <span className="text-sm font-medium text-gray-600">Filters:</span>
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-1.5 border rounded-md text-sm bg-white"
            aria-label="Filter by severity"
          >
            <option value="">All Severities</option>
            {severityOptions.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-1.5 border rounded-md text-sm bg-white"
            aria-label="Filter by status"
          >
            <option value="">All Statuses</option>
            {statusOptions.map((s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            ))}
          </select>
          {(severityFilter || statusFilter) && (
            <button
              onClick={() => {
                setSeverityFilter("");
                setStatusFilter("");
              }}
              className="text-sm text-blue-600 hover:underline"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      {/* Loading */}
      {findingsLoading && (
        <div className="space-y-3">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-20 bg-gray-200 rounded-lg animate-pulse" />
          ))}
        </div>
      )}

      {/* Error */}
      {findingsError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Failed to load findings</p>
          <p className="text-red-600 text-sm mt-1">
            Please check that the API server is running.
          </p>
        </div>
      )}

      {/* Empty */}
      {!findingsLoading && !findingsError && findings && findings.length === 0 && (
        <div className="bg-white border rounded-lg p-12 text-center">
          <Shield className="h-12 w-12 text-gray-300 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-700 mb-2">
            No vulnerabilities detected
          </h2>
          <p className="text-gray-500">
            {severityFilter || statusFilter
              ? "No findings match the current filters."
              : "This repository has no known vulnerabilities in the latest scan."}
          </p>
        </div>
      )}

      {/* Findings list */}
      {!findingsLoading && !findingsError && findings && findings.length > 0 && (
        <div className="bg-white border rounded-lg divide-y">
          {findings.map((finding) => (
            <Link
              key={finding.id}
              href={`/findings/${finding.id}`}
              className="block px-6 py-4 hover:bg-gray-50 transition-colors"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-medium border ${severityBadgeClasses[finding.severity] || severityBadgeClasses.UNKNOWN}`}
                    >
                      {finding.severity}
                    </span>
                    <span className="text-xs text-gray-500">
                      {finding.status.replace("_", " ")}
                    </span>
                    {finding.vulnerability_id && (
                      <span className="text-xs font-mono text-gray-400">
                        {finding.vulnerability_id}
                      </span>
                    )}
                  </div>
                  <p className="font-medium text-gray-900 truncate">
                    {finding.title}
                  </p>
                  <p className="text-sm text-gray-500">
                    {finding.package_name}
                    {finding.package_version
                      ? `@${finding.package_version}`
                      : ""}
                  </p>
                </div>
                <ArrowRight className="h-4 w-4 text-gray-400 shrink-0 ml-4" />
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
