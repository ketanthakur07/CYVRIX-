"use client";

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";
import {
  GitBranch,
  AlertTriangle,
  Shield,
  Scan,
  ArrowRight,
  CheckCircle,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { fetchRepositories, activateRepository, deactivateRepository } from "@/lib/api";
import { SEVERITY_TEXT_COLORS } from "@/lib/types";
import type { RepositorySummary } from "@/lib/types";

function RepositoriesContent() {
  const searchParams = useSearchParams();
  const connected = searchParams.get("connected") === "true";
  const error = searchParams.get("error");
  const queryClient = useQueryClient();

  const { data, isLoading, error: fetchError } = useQuery({
    queryKey: ["repositories"],
    queryFn: fetchRepositories,
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, activate }: { id: string; activate: boolean }) =>
      activate ? activateRepository(id) : deactivateRepository(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["repositories"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-48" />
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-gray-200 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  if (fetchError) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Failed to load repositories</p>
          <p className="text-red-600 text-sm mt-1">
            Please check that the API server is running.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Repositories</h1>
        <a
          href="/api/github/connect"
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          <GitBranch className="h-4 w-4" />
          Connect GitHub
        </a>
      </div>

      {/* Connection success banner */}
      {connected && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6 flex items-center gap-2">
          <CheckCircle className="h-5 w-5 text-green-600" />
          <p className="text-green-800 text-sm">
            GitHub connected successfully! Repositories have been imported.
          </p>
        </div>
      )}

      {/* Connection error banner */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="h-5 w-5 text-red-600" />
            <p className="text-red-800 font-medium text-sm">
              {error === "github_unavailable"
                ? "GitHub is temporarily unavailable"
                : error === "auth_failed"
                ? "GitHub authentication failed. The App may need to be reinstalled."
                : error === "no_repositories"
                ? "No repositories found. Make sure the GitHub App has access to at least one repository."
                : "Connection error occurred."}
            </p>
          </div>
          <a
            href="/api/github/connect"
            className="text-sm text-blue-600 hover:underline mt-1 inline-block"
          >
            Try connecting again
          </a>
        </div>
      )}

      {/* Empty state */}
      {!data || data.length === 0 ? (
        <div className="bg-white border rounded-lg p-12 text-center">
          <Shield className="h-12 w-12 text-gray-300 mx-auto mb-4" />
          <h2 className="text-lg font-semibold text-gray-700 mb-2">
            No repositories connected
          </h2>
          <p className="text-gray-500 mb-4">
            Connect your GitHub account to see your repositories here.
          </p>
          <a
            href="/api/github/connect"
            className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md font-medium hover:bg-blue-700 transition-colors"
          >
            <GitBranch className="h-4 w-4" />
            Connect GitHub
          </a>
        </div>
      ) : (
        <div className="space-y-3">
          {data.map((summary) => (
            <div
              key={summary.repository.id}
              className="bg-white border rounded-lg p-4 hover:shadow-md transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  <GitBranch className="h-5 w-5 text-gray-400 shrink-0" />
                  <div className="min-w-0">
                    <Link
                      href={`/repositories/${summary.repository.id}`}
                      className="font-medium hover:text-blue-600 transition-colors"
                    >
                      {summary.repository.owner}/{summary.repository.name}
                    </Link>
                    <p className="text-sm text-gray-500">
                      {summary.repository.default_branch} branch
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {summary.findings_by_severity.length > 0 && (
                    <div className="flex gap-2">
                      {summary.findings_by_severity.map((s) => (
                        <span
                          key={s.severity}
                          className={`text-xs font-medium ${SEVERITY_TEXT_COLORS[s.severity as keyof typeof SEVERITY_TEXT_COLORS] || ""}`}
                        >
                          {s.severity}: {s.count}
                        </span>
                      ))}
                    </div>
                  )}

                  {summary.risk_score !== null && (
                    <div className="text-right">
                      <p className="text-xs text-gray-500">Risk</p>
                      <p className="font-bold text-lg">{summary.risk_score}</p>
                    </div>
                  )}

                  <button
                    onClick={() =>
                      toggleMutation.mutate({
                        id: summary.repository.id,
                        activate: !summary.repository.is_active,
                      })
                    }
                    disabled={toggleMutation.isPending}
                    className={`flex items-center gap-1 px-3 py-1.5 rounded-md text-sm font-medium transition-colors disabled:opacity-50 ${
                      summary.repository.is_active
                        ? "bg-green-50 text-green-700 hover:bg-green-100 border border-green-200"
                        : "bg-gray-50 text-gray-500 hover:bg-gray-100 border border-gray-200"
                    }`}
                    title={
                      summary.repository.is_active
                        ? "Deactivate repository"
                        : "Activate repository"
                    }
                  >
                    {summary.repository.is_active ? (
                      <ToggleRight className="h-4 w-4" />
                    ) : (
                      <ToggleLeft className="h-4 w-4" />
                    )}
                    {summary.repository.is_active ? "Active" : "Inactive"}
                  </button>

                  {summary.repository.is_active && (
                    <Link
                      href={`/repositories/${summary.repository.id}`}
                      className="inline-flex items-center gap-1 px-3 py-1.5 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
                    >
                      <Scan className="h-4 w-4" />
                      Scan
                    </Link>
                  )}

                  <Link
                    href={`/repositories/${summary.repository.id}`}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function RepositoriesPage() {
  return (
    <Suspense
      fallback={
        <div className="container mx-auto px-4 py-8">
          <div className="animate-pulse space-y-4">
            <div className="h-8 bg-gray-200 rounded w-48" />
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 bg-gray-200 rounded-lg" />
            ))}
          </div>
        </div>
      }
    >
      <RepositoriesContent />
    </Suspense>
  );
}
