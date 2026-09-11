"use client";

import { useQuery } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  AlertTriangle,
  Brain,
  BarChart3,
  ArrowLeft,
  FileText,
  Info,
} from "lucide-react";
import { fetchFinding } from "@/lib/api";
import {
  SEVERITY_COLORS,
  RISK_LEVEL_COLORS,
  VERDICT_COLORS,
  SOURCE_TYPE_COLORS,
  SOURCE_TYPE_ICONS,
  TRUST_LEVEL_COLORS,
  VALIDATION_STATE_COLORS,
} from "@/lib/types";

export default function FindingPage() {
  const params = useParams();
  const id = params.id as string;

  const { data: finding, isLoading, error } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => fetchFinding(id),
  });

  if (isLoading) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-4">
              <div className="h-48 bg-gray-200 rounded-lg" />
              <div className="h-64 bg-gray-200 rounded-lg" />
            </div>
            <div className="space-y-4">
              <div className="h-48 bg-gray-200 rounded-lg" />
              <div className="h-32 bg-gray-200 rounded-lg" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error || !finding) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-red-800 font-medium">Finding not found</p>
          <p className="text-red-600 text-sm mt-1">
            The finding may have been removed or you may not have access.
          </p>
        </div>
      </div>
    );
  }

  const inv = finding.investigation;
  const risk = finding.risk_assessment;

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Back link */}
      <Link
        href={`/scans/${finding.scan_id}`}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-4"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to scan
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2 flex-wrap">
            <span
              className={`px-3 py-1 rounded-lg text-sm font-medium border ${SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.UNKNOWN}`}
            >
              {finding.severity}
            </span>
            <span
              className={`px-3 py-1 rounded-lg text-sm font-medium border ${SOURCE_TYPE_COLORS[finding.source_type] || SOURCE_TYPE_COLORS.DEPENDENCY}`}
            >
              {SOURCE_TYPE_ICONS[finding.source_type] || "📦"} {finding.source_type}
            </span>
            {finding.vulnerability_id && (
              <span className="text-sm font-mono text-gray-500">
                {finding.vulnerability_id}
              </span>
            )}
          </div>
          <h1 className="text-2xl font-bold">{finding.title}</h1>
          <p className="text-gray-500 mt-1">
            {finding.package_name}
            {finding.package_version ? `@${finding.package_version}` : ""}
          </p>
        </div>
        {risk && (
          <div className="text-right shrink-0 ml-4">
            <p className="text-sm text-gray-500">Risk Score</p>
            <p
              className={`text-4xl font-bold ${RISK_LEVEL_COLORS[risk.risk_level] || ""}`}
            >
              {risk.risk_score}
            </p>
            <p className="text-sm text-gray-500">{risk.risk_level}</p>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          {finding.description && (
            <div className="bg-white border rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Description
              </h2>
              {/* Repository content is untrusted — rendered as plain text */}
              <p className="text-gray-700 whitespace-pre-wrap break-words">
                {finding.description}
              </p>
            </div>
          )}

          {/* AI Investigation */}
          <div className="bg-white border rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
              <Brain className="h-5 w-5" />
              AI Investigation
            </h2>

            {!inv ? (
              <div className="text-center py-6">
                <Brain className="h-8 w-8 text-gray-300 mx-auto mb-2" />
                <p className="text-gray-500">
                  AI investigation not available for this finding.
                </p>
              </div>
            ) : inv.status === "FAILED" ? (
              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <p className="text-yellow-800 font-medium text-sm">
                  AI Investigation Unavailable
                </p>
                <p className="text-yellow-700 text-sm mt-1">
                  The vulnerability was detected successfully, but contextual AI
                  analysis could not be completed. Risk assessment is based on
                  available deterministic information.
                </p>
              </div>
            ) : inv.status === "PENDING" || inv.status === "RUNNING" ? (
              <div className="text-center py-6">
                <div className="animate-spin h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-2" />
                <p className="text-gray-500">Investigation in progress...</p>
              </div>
            ) : (
              <div className="space-y-4">
                {/* Verdict and metadata */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div className="bg-gray-50 rounded-lg p-3">
                    <p className="text-xs text-gray-500">Verdict</p>
                    <p
                      className={`font-medium ${inv.verdict ? VERDICT_COLORS[inv.verdict] || "" : ""}`}
                    >
                      {inv.verdict || "Unknown"}
                    </p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <p className="text-xs text-gray-500">Exploitability</p>
                    <p className="font-medium">{inv.exploitability || "Unknown"}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <p className="text-xs text-gray-500">Exposure</p>
                    <p className="font-medium">{inv.exposure || "Unknown"}</p>
                  </div>
                  <div className="bg-gray-50 rounded-lg p-3">
                    <p className="text-xs text-gray-500">Confidence</p>
                    <p className="font-medium">
                      {inv.confidence != null
                        ? `${(inv.confidence * 100).toFixed(0)}%`
                        : "N/A"}
                    </p>
                  </div>
                </div>

                {/* Summary */}
                {inv.summary && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">
                      Summary
                    </p>
                    {/* AI output is untrusted — rendered as plain text */}
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {inv.summary}
                    </p>
                  </div>
                )}

                {/* Evidence */}
                {inv.evidence && inv.evidence.length > 0 && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-2">
                      Evidence
                    </p>
                    <div className="space-y-2">
                      {inv.evidence.map((ev, i) => (
                        <div key={i} className="bg-gray-50 rounded-lg p-3 text-sm">
                          <span className="font-mono text-blue-600 break-all">
                            {ev.file}
                          </span>
                          {ev.line > 0 && (
                            <span className="text-gray-500">:{ev.line}</span>
                          )}
                          {/* Evidence reasons are AI-generated — untrusted */}
                          <p className="text-gray-600 mt-1 break-words">
                            {ev.reason}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendation */}
                {inv.recommendation && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">
                      Recommendation
                    </p>
                    {/* AI-generated recommendation — untrusted */}
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {inv.recommendation}
                    </p>
                  </div>
                )}

                {/* Assumptions & Uncertainties */}
                {(inv.assumptions?.length || inv.uncertainties?.length) ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {inv.assumptions && inv.assumptions.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-gray-700 mb-1">
                          Assumptions
                        </p>
                        <ul className="text-sm text-gray-600 list-disc list-inside">
                          {inv.assumptions.map((a, i) => (
                            <li key={i} className="break-words">{a}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {inv.uncertainties && inv.uncertainties.length > 0 && (
                      <div>
                        <p className="text-sm font-medium text-gray-700 mb-1">
                          Uncertainties
                        </p>
                        <ul className="text-sm text-gray-600 list-disc list-inside">
                          {inv.uncertainties.map((u, i) => (
                            <li key={i} className="break-words">{u}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ) : null}

                {/* Evidence validation warning */}
                {inv.status === "COMPLETED" && inv.evidence && inv.evidence.length > 0 && (
                  <div className="flex items-start gap-2 bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-700">
                    <Info className="h-4 w-4 mt-0.5 shrink-0" />
                    <span>
                      Evidence shown above is from the AI investigation and may
                      include model-provided assessments. File references are
                      cross-validated against the repository.
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Recommendation Section */}
          {finding.recommendation && (
            <div className="bg-white border rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Recommendation
              </h2>

              <div className="space-y-4">
                {/* Trust level and validation state */}
                <div className="flex items-center gap-2 flex-wrap">
                  {finding.recommendation.trust_level && (
                    <span
                      className={`px-3 py-1 rounded-lg text-sm font-medium ${TRUST_LEVEL_COLORS[finding.recommendation.trust_level] || TRUST_LEVEL_COLORS.UNCERTAIN}`}
                    >
                      Trust: {finding.recommendation.trust_level}
                    </span>
                  )}
                  {finding.recommendation.validation_state && (
                    <span
                      className={`px-3 py-1 rounded-lg text-sm font-medium ${VALIDATION_STATE_COLORS[finding.recommendation.validation_state] || VALIDATION_STATE_COLORS.UNVERIFIED}`}
                    >
                      {finding.recommendation.validation_state.replace(/_/g, " ")}
                    </span>
                  )}
                </div>

                {/* What */}
                {finding.recommendation.what && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">What</p>
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {finding.recommendation.what}
                    </p>
                  </div>
                )}

                {/* Why */}
                {finding.recommendation.why && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Why</p>
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {finding.recommendation.why}
                    </p>
                  </div>
                )}

                {/* Change */}
                {finding.recommendation.change && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Recommended Change</p>
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {finding.recommendation.change}
                    </p>
                  </div>
                )}

                {/* Risk */}
                {finding.recommendation.risk && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Risk</p>
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {finding.recommendation.risk}
                    </p>
                  </div>
                )}

                {/* Validation */}
                {finding.recommendation.validation && (
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">How to Validate</p>
                    <p className="text-gray-600 whitespace-pre-wrap break-words">
                      {finding.recommendation.validation}
                    </p>
                  </div>
                )}

                {/* Uncertainty */}
                {finding.recommendation.uncertainty && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                    <p className="text-sm font-medium text-yellow-800 mb-1">Uncertainty</p>
                    <p className="text-yellow-700 text-sm whitespace-pre-wrap break-words">
                      {finding.recommendation.uncertainty}
                    </p>
                  </div>
                )}

                {/* Validation details */}
                {finding.recommendation.validation_details && (
                  <div className="bg-gray-50 border rounded-lg p-3">
                    <p className="text-xs text-gray-500 mb-2">Validation Details</p>
                    <p className="text-sm text-gray-600 mb-2">
                      {finding.recommendation.validation_details.summary}
                    </p>
                    <div className="space-y-1">
                      {finding.recommendation.validation_details.checks.map((check, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs">
                          <span>{check.passed ? "✅" : "❌"}</span>
                          <span className="font-medium">{check.check.replace(/_/g, " ")}</span>
                          <span className="text-gray-500">— {check.reason}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Advisory notice */}
                <div className="flex items-start gap-2 bg-blue-50 border border-blue-200 rounded-lg p-3 text-xs text-blue-700">
                  <Info className="h-4 w-4 mt-0.5 shrink-0" />
                  <span>
                    Recommendations are advisory only. CYVRIX does not automatically
                    modify repositories, push code, create PRs, or deploy changes.
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Risk Assessment */}
          {risk ? (
            <div className="bg-white border rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Risk Assessment
              </h2>
              <div className="space-y-3">
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Base Score</span>
                  <span className="font-medium">
                    {risk.factors.base_score}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">
                    Exposure Modifier
                  </span>
                  <span className="font-medium">
                    {risk.factors.exposure_mod > 0 ? "+" : ""}
                    {risk.factors.exposure_mod}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">
                    Exploitability Modifier
                  </span>
                  <span className="font-medium">
                    {risk.factors.exploit_mod > 0 ? "+" : ""}
                    {risk.factors.exploit_mod}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">
                    Confidence Modifier
                  </span>
                  <span className="font-medium">
                    {risk.factors.confidence_mod > 0 ? "+" : ""}
                    {risk.factors.confidence_mod}
                  </span>
                </div>
                <hr />
                <div className="flex justify-between">
                  <span className="text-sm font-medium">Final Score</span>
                  <span
                    className={`text-xl font-bold ${RISK_LEVEL_COLORS[risk.risk_level] || ""}`}
                  >
                    {risk.risk_score}/100
                  </span>
                </div>
                <p className="text-xs text-gray-400">
                  Algorithm: v{risk.risk_version}
                </p>
                {!risk.factors.ai_available && (
                  <div className="bg-yellow-50 border border-yellow-200 rounded p-2 text-xs text-yellow-800">
                    AI investigation unavailable — score is severity-based only
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-white border rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <BarChart3 className="h-5 w-5" />
                Risk Assessment
              </h2>
              <p className="text-sm text-gray-500">
                Risk assessment pending...
              </p>
            </div>
          )}

          {/* Metadata */}
          <div className="bg-white border rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-3">Details</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Status</span>
                <span className="font-medium">{finding.status}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Scanner</span>
                <span className="font-medium">{finding.scanner}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Created</span>
                <span className="font-medium">
                  {new Date(finding.created_at).toLocaleDateString()}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
