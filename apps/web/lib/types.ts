/**
 * CYVRIX V1 — Shared TypeScript types
 * These mirror the backend Pydantic schemas exactly.
 * Never add fields that don't exist in the backend contract.
 */

// ── Enums ──────────────────────────────────────────────────────────

export type ScanStatus =
  | "QUEUED"
  | "CLONING"
  | "SCANNING"
  | "ANALYZING"
  | "COMPLETED"
  | "FAILED";

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

export type SourceType = "DEPENDENCY" | "CONTAINER" | "LOG";

export type FindingStatus =
  | "OPEN"
  | "CONFIRMED"
  | "FALSE_POSITIVE"
  | "RESOLVED";

export type InvestigationStatus =
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED";

export type Verdict =
  | "CONFIRMED"
  | "LIKELY"
  | "UNLIKELY"
  | "FALSE_POSITIVE"
  | "UNKNOWN";

export type Exploitability = "LOW" | "MEDIUM" | "HIGH" | "UNKNOWN";

export type Exposure = "INTERNAL" | "EXTERNAL" | "UNKNOWN";

export type RiskLevel = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

// ── Evidence ───────────────────────────────────────────────────────

export interface EvidenceItem {
  file: string;
  line: number;
  reason: string;
}

// ── Risk ───────────────────────────────────────────────────────────

export interface RiskFactors {
  base_score: number;
  exposure_mod: number;
  exploit_mod: number;
  confidence_mod: number;
  ai_available: boolean;
  degraded: boolean;
}

export interface RiskAssessment {
  id: string;
  finding_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  risk_version: number;
  factors: RiskFactors;
  created_at: string;
}

// ── Investigation ──────────────────────────────────────────────────

export interface Investigation {
  id: string;
  finding_id: string;
  status: InvestigationStatus;
  verdict: Verdict | null;
  exploitability: Exploitability | null;
  exposure: Exposure | null;
  confidence: number | null;
  summary: string | null;
  evidence: EvidenceItem[] | null;
  assumptions: string[] | null;
  uncertainties: string[] | null;
  recommendation: string | null;
  created_at: string;
}

// ── Repository ─────────────────────────────────────────────────────

export interface Repository {
  id: string;
  github_repo_id: number;
  owner: string;
  name: string;
  default_branch: string;
  is_active: boolean;
  created_at: string;
}

// ── Scan ───────────────────────────────────────────────────────────

export interface Scan {
  id: string;
  repository_id: string;
  status: ScanStatus;
  trigger: string;
  error_reason: string | null;
  started_at: string | null;
  completed_at: string | null;
  commit_sha: string | null;
  created_at: string;
}

// ── Finding ────────────────────────────────────────────────────────

export interface Finding {
  id: string;
  scan_id: string;
  repository_id: string;
  fingerprint: string;
  scanner: string;
  source_type: SourceType;
  vulnerability_id: string | null;
  package_name: string | null;
  package_version: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  status: FindingStatus;
  created_at: string;
}

export type TrustLevel = "SUPPORTED" | "LIKELY" | "UNCERTAIN";

export type ValidationState = "VALIDATED" | "PARTIALLY_VALIDATED" | "UNVERIFIED" | "UNSAFE";

export interface Recommendation {
  id: string;
  finding_id: string;
  status: string;
  trust_level: TrustLevel | null;
  title: string;
  description: string | null;
  what: string | null;
  why: string | null;
  change: string | null;
  uncertainty: string | null;
  risk: string | null;
  validation: string | null;
  validation_state: ValidationState | null;
  validation_details: {
    checks: Array<{ check: string; passed: boolean; reason: string }>;
    summary: string;
  } | null;
  validated_at: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  repository_id: string;
  report_type: string;
  format: string;
  content: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  investigation: Investigation | null;
  risk_assessment: RiskAssessment | null;
  recommendation: Recommendation | null;
}

// ── Severity Count ─────────────────────────────────────────────────

export interface SeverityCount {
  severity: string;
  count: number;
}

// ── Dashboard ──────────────────────────────────────────────────────

export interface DashboardSummary {
  total_repositories: number;
  total_scans: number;
  total_findings: number;
  findings_by_severity: SeverityCount[];
  recent_scans: Scan[];
}

// ── Repository Summary ─────────────────────────────────────────────

export interface RepositorySummary {
  repository: Repository;
  total_findings: number;
  findings_by_severity: SeverityCount[];
  latest_scan: Scan | null;
  risk_score: number | null;
}

// ── Display Constants ──────────────────────────────────────────────

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH: "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM: "bg-yellow-100 text-yellow-800 border-yellow-200",
  LOW: "bg-green-100 text-green-800 border-green-200",
  UNKNOWN: "bg-gray-100 text-gray-800 border-gray-200",
};

export const SEVERITY_TEXT_COLORS: Record<Severity, string> = {
  CRITICAL: "text-red-600",
  HIGH: "text-orange-600",
  MEDIUM: "text-yellow-600",
  LOW: "text-green-600",
  UNKNOWN: "text-gray-600",
};

export const RISK_LEVEL_COLORS: Record<RiskLevel, string> = {
  CRITICAL: "text-red-600",
  HIGH: "text-orange-600",
  MEDIUM: "text-yellow-600",
  LOW: "text-green-600",
  INFO: "text-gray-600",
};

export const VERDICT_COLORS: Record<Verdict, string> = {
  CONFIRMED: "bg-red-100 text-red-800",
  LIKELY: "bg-orange-100 text-orange-800",
  UNLIKELY: "bg-green-100 text-green-800",
  FALSE_POSITIVE: "bg-gray-100 text-gray-600",
  UNKNOWN: "bg-gray-100 text-gray-500",
};

export const STATUS_COLORS: Record<ScanStatus, string> = {
  COMPLETED: "bg-green-100 text-green-800",
  FAILED: "bg-red-100 text-red-800",
  QUEUED: "bg-yellow-100 text-yellow-800",
  CLONING: "bg-blue-100 text-blue-800",
  SCANNING: "bg-blue-100 text-blue-800",
  ANALYZING: "bg-blue-100 text-blue-800",
};

export const SCAN_STATUS_STEPS: ScanStatus[] = [
  "QUEUED",
  "CLONING",
  "SCANNING",
  "ANALYZING",
  "COMPLETED",
];

/** Check if a scan status is terminal (no more polling needed) */
export function isTerminalStatus(status: ScanStatus): boolean {
  return status === "COMPLETED" || status === "FAILED";
}

// ── V2 Source Type Colors ─────────────────────────────────────────

export const SOURCE_TYPE_COLORS: Record<SourceType, string> = {
  DEPENDENCY: "bg-blue-100 text-blue-800 border-blue-200",
  CONTAINER: "bg-purple-100 text-purple-800 border-purple-200",
  LOG: "bg-teal-100 text-teal-800 border-teal-200",
};

export const SOURCE_TYPE_ICONS: Record<SourceType, string> = {
  DEPENDENCY: "📦",
  CONTAINER: "🐳",
  LOG: "📋",
};

// ── V3.1/V3.2 Action Proposals & Approvals ─────────────────────────

export type ProposalStatus =
  | "PROPOSED"
  | "POLICY_CHECKED"
  | "REJECTED"
  | "EXPIRED"
  | "STALE"
  | "APPROVED";

export type ApprovalState =
  | "PENDING"
  | "APPROVED"
  | "REJECTED"
  | "EXPIRED"
  | "REVOKED"
  | "USED";

export interface ActionProposal {
  id: string;
  finding_id: string;
  recommendation_id: string;
  repository_id: string;
  created_by?: string;
  action_type: string;
  status: ProposalStatus;
  base_commit_sha: string;
  target_branch: string;
  files: string[];
  operations: Record<string, unknown>[];
  expected_diff: string;
  rationale: string | null;
  evidence: Record<string, unknown> | null;
  risk_score: number;
  risk_level: RiskLevel;
  recommendation_trust: string | null;
  validation_state: ValidationState | null;
  policy_version: string;
  policy_decision: string;
  policy_reason_code: string;
  policy_matched_rule: string;
  policy_explanation: string | null;
  action_digest: string;
  expires_at: string | null;
  created_at: string | null;
}

export interface Approval {
  id: string;
  action_proposal_id: string;
  action_digest: string;
  approver_user_id: string;
  second_approver_user_id: string | null;
  approval_state: ApprovalState;
  approval_reason: string | null;
  policy_version: string;
  policy_decision: string;
  approval_level: string | null;
  approved_at: string | null;
  expires_at: string | null;
  authorization_issued_at: string | null;
  authorization_used_at: string | null;
  created_at: string | null;
}

// ── V2 Trust Level Colors ─────────────────────────────────────────

export const TRUST_LEVEL_COLORS: Record<TrustLevel, string> = {
  SUPPORTED: "bg-green-100 text-green-800",
  LIKELY: "bg-yellow-100 text-yellow-800",
  UNCERTAIN: "bg-gray-100 text-gray-600",
};

// ── V2 Validation State Colors ────────────────────────────────────

export const VALIDATION_STATE_COLORS: Record<ValidationState, string> = {
  VALIDATED: "bg-green-100 text-green-800",
  PARTIALLY_VALIDATED: "bg-yellow-100 text-yellow-800",
  UNVERIFIED: "bg-gray-100 text-gray-600",
  UNSAFE: "bg-red-100 text-red-800",
};

// ── V3.2 Approval State Colors ────────────────────────────────────

export const APPROVAL_STATE_COLORS: Record<ApprovalState, string> = {
  PENDING: "bg-yellow-100 text-yellow-800",
  APPROVED: "bg-green-100 text-green-800",
  REJECTED: "bg-red-100 text-red-800",
  EXPIRED: "bg-gray-100 text-gray-800",
  REVOKED: "bg-purple-100 text-purple-800",
  USED: "bg-blue-100 text-blue-800",
};
