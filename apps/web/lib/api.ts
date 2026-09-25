/**
 * CYVRIX V1 — Shared API client
 *
 * Handles:
 * - Base URL resolution (proxied through Next.js)
 * - Error classification (401, 403, 404, 409, 5xx)
 * - Safe error messages (never leaks internals)
 * - JSON parsing with error handling
 * - Auth redirect on 401
 */

const API_BASE = "/api";

export class ApiError extends Error {
  public status: number;
  public detail?: string;
  /**
   * Machine-readable server reason code (e.g. "STEP_UP_REQUIRED",
   * "KILL_SWITCH_ACTIVE"). Always a server-controlled enum-like token,
   * never reconstructed from free text. Optional.
   */
  public reasonCode?: string;

  constructor(status: number, message: string, detail?: string, reasonCode?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.reasonCode = reasonCode;
  }
}

/** Extract a safe reason code from a backend error body without ever
 * trusting or echoing free-form internals. Only a token matching the
 * server's SCREAMING_SNAKE convention is accepted. */
function extractReasonCode(body: unknown): string | undefined {
  if (!body || typeof body !== "object") return undefined;
  const detail = (body as { detail?: unknown }).detail;
  const candidate =
    typeof detail === "string"
      ? detail
      : detail && typeof detail === "object"
      ? (detail as { reason_code?: unknown }).reason_code
      : undefined;
  if (typeof candidate === "string" && /^[A-Z][A-Z0-9_]{2,63}$/.test(candidate)) {
    return candidate;
  }
  return undefined;
}

function classifyError(status: number): string {
  switch (status) {
    case 401:
      return "Authentication required. Please log in.";
    case 403:
      return "You do not have access to this resource.";
    case 404:
      return "The requested resource was not found.";
    case 409:
      return "A conflicting operation is already in progress.";
    case 422:
      return "The request contains invalid data.";
    case 429:
      return "Too many requests. Please try again later.";
    default:
      if (status >= 500) {
        return "The server encountered an error. Please try again.";
      }
      return `Request failed (HTTP ${status}).`;
  }
}

/**
 * Safe fetch wrapper. Throws ApiError with user-friendly messages.
 * Never exposes internal details, tokens, or stack traces.
 */
export async function apiFetch<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const url = `${API_BASE}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
      credentials: "same-origin", // Include cookies for session auth
    });
  } catch (err) {
    throw new ApiError(
      0,
      "Unable to connect to the server. Please check your network connection."
    );
  }

  // Handle 401 by redirecting to login (unless already on auth endpoints)
  if (response.status === 401 && !path.startsWith("/auth/")) {
    // Don't redirect if we're already checking auth status
    if (path !== "/auth/me") {
      window.location.href = "/api/auth/login";
    }
    throw new ApiError(401, "Session expired. Please log in again.");
  }

  if (!response.ok) {
    let detail: string | undefined;
    let reasonCode: string | undefined;
    try {
      const body = await response.json();
      reasonCode = extractReasonCode(body);
      const rawDetail = (body as { detail?: unknown }).detail;
      if (typeof rawDetail === "string") {
        detail = rawDetail;
      } else if (rawDetail && typeof rawDetail === "object") {
        detail = String(
          (rawDetail as { message?: unknown }).message ?? reasonCode ?? ""
        );
      }
    } catch {
      // Ignore parse errors on error responses
    }

    throw new ApiError(
      response.status,
      classifyError(response.status),
      detail,
      reasonCode
    );
  }

  // 204/205 carry no body; never attempt to parse JSON from nothing.
  if (response.status === 204 || response.status === 205) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

// ── Convenience functions ──────────────────────────────────────────

import type {
  DashboardSummary,
  RepositorySummary,
  Repository,
  Scan,
  FindingDetail,
  Finding,
} from "./types";

export async function fetchDashboard(): Promise<DashboardSummary> {
  return apiFetch<DashboardSummary>("/dashboard");
}

export async function fetchRepositories(): Promise<RepositorySummary[]> {
  return apiFetch<RepositorySummary[]>("/repositories");
}

export async function fetchRepository(id: string): Promise<RepositorySummary> {
  return apiFetch<RepositorySummary>(`/repositories/${id}`);
}

export async function fetchRepositoryFindings(
  id: string,
  params?: { severity?: string; status?: string }
): Promise<Finding[]> {
  const searchParams = new URLSearchParams();
  if (params?.severity) searchParams.set("severity", params.severity);
  if (params?.status) searchParams.set("status", params.status);
  const qs = searchParams.toString();
  return apiFetch<Finding[]>(`/repositories/${id}/findings${qs ? `?${qs}` : ""}`);
}

export async function fetchRepositoryScans(
  id: string
): Promise<Scan[]> {
  return apiFetch<Scan[]>(`/repositories/${id}/scans`);
}

export async function fetchScan(id: string): Promise<Scan> {
  return apiFetch<Scan>(`/scans/${id}`);
}

export async function fetchScanFindings(
  id: string
): Promise<FindingDetail[]> {
  return apiFetch<FindingDetail[]>(`/scans/${id}/findings`);
}

export async function fetchFinding(id: string): Promise<FindingDetail> {
  return apiFetch<FindingDetail>(`/findings/${id}`);
}

export async function triggerScan(
  repositoryId: string
): Promise<{ id: string }> {
  return apiFetch<{ id: string }>("/scans", {
    method: "POST",
    body: JSON.stringify({ repository_id: repositoryId }),
  });
}

export async function activateRepository(
  id: string
): Promise<{ ok: boolean; is_active: boolean }> {
  return apiFetch(`/repositories/${id}/activate`, { method: "POST" });
}

export async function deactivateRepository(
  id: string
): Promise<{ ok: boolean; is_active: boolean }> {
  return apiFetch(`/repositories/${id}/deactivate`, { method: "POST" });
}

// ── V2 API Functions ──────────────────────────────────────────────

import type { Recommendation, Report, SourceType } from "./types";

/** Trigger a container/Dockerfile security scan */
export async function triggerContainerScan(
  repositoryId: string
): Promise<{ id: string }> {
  return apiFetch<{ id: string }>(`/repositories/${repositoryId}/container-scan`, {
    method: "POST",
  });
}

/** Trigger a log/security analysis scan */
export async function triggerLogAnalysis(
  repositoryId: string
): Promise<{ id: string }> {
  return apiFetch<{ id: string }>(`/repositories/${repositoryId}/log-analysis`, {
    method: "POST",
  });
}

/** Get recommendation for a finding (read-only, 404 if not found) */
export async function fetchRecommendation(
  findingId: string
): Promise<Recommendation> {
  return apiFetch<Recommendation>(`/findings/${findingId}/recommendation`);
}

/** Generate or retrieve recommendation for a finding (POST, idempotent) */
export async function generateRecommendation(
  findingId: string
): Promise<Recommendation> {
  return apiFetch<Recommendation>(`/findings/${findingId}/recommendation`, {
    method: "POST",
  });
}

/** Trigger recommendation re-validation */
export async function validateRecommendation(
  findingId: string
): Promise<{
  ok: boolean;
  validation_state: string;
  trust_level: string | null;
  summary: string;
  checks: Array<{ check: string; passed: boolean; reason: string }>;
}> {
  return apiFetch(`/findings/${findingId}/recommendation/validate`, {
    method: "POST",
  });
}

/** Generate a report for a scan */
export async function generateReport(
  scanId: string,
  format: "markdown" | "json" = "markdown"
): Promise<{ id: string }> {
  return apiFetch<{ id: string }>(`/reports/${scanId}`, {
    method: "POST",
    body: JSON.stringify({ format }),
  });
}

/** Get a report by ID */
export async function fetchReport(reportId: string): Promise<Report> {
  return apiFetch<Report>(`/reports/${reportId}`);
}

/** List reports for a scan */
export async function fetchReportsByScan(
  scanId: string
): Promise<Report[]> {
  return apiFetch<Report[]>(`/reports/scan/${scanId}`);
}

// ── V3.1/V3.2 Action Proposals & Approvals ──────────────────────────

import type { ActionProposal, Approval } from "./types";

/** Get one action proposal (read-only; ownership enforced server-side) */
export async function fetchActionProposal(id: string): Promise<ActionProposal> {
  return apiFetch<ActionProposal>(`/actions/${id}`);
}

/** List action proposals, optionally filtered by finding */
export async function fetchActionProposals(
  findingId?: string
): Promise<ActionProposal[]> {
  const qs = findingId ? `?finding_id=${encodeURIComponent(findingId)}` : "";
  return apiFetch<ActionProposal[]>(`/actions${qs}`);
}

/** Get the current approval for a proposal (404 when none exists) */
export async function fetchActionApproval(id: string): Promise<Approval> {
  return apiFetch<Approval>(`/actions/${id}/approval`);
}

/** Begin step-up authentication (fresh GitHub re-auth round-trip) */
export async function beginStepUp(): Promise<{ state: string; redirect: string }> {
  return apiFetch("/actions/step-up", { method: "POST" });
}

/** Check whether the current session has a fresh step-up approval */
export async function fetchStepUpStatus(): Promise<{
  step_up_valid: boolean;
  max_age_minutes?: number;
}> {
  return apiFetch("/actions/step-up/status");
}

/**
 * Approve an action proposal. Authorization data only — the server
 * re-verifies digest, policy, eligibility, and step-up. The one-time
 * authorization token (when a new approval is issued) is returned
 * exactly once and must be stored by the user immediately.
 */
export async function approveProposal(
  proposalId: string,
  body: { reason?: string; second_approver_user_id?: string }
): Promise<Approval & { authorization_token: string }> {
  return apiFetch(`/actions/${proposalId}/approve`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Reject a pending approval request (state transition only) */
export async function rejectProposal(
  proposalId: string,
  body: { reason?: string }
): Promise<Approval> {
  return apiFetch(`/actions/${proposalId}/reject`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Revoke an APPROVED approval (state transition only, no resurrection) */
export async function revokeApproval(
  proposalId: string,
  approvalId: string,
  body: { reason?: string }
): Promise<Approval> {
  return apiFetch(`/actions/${proposalId}/approval/${approvalId}/revoke`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// ══════════════════════════════════════════════════════════════════
// V3.3–V3.8 CLIENTS
//
// Every mutation here sends only human metadata. No client function
// accepts an authority field (approved/authorized/verified/rollback_sha/
// decision/tenant/actor) — those do not exist in the request schemas and
// are enforced server-side. State returned by these calls is display
// data; the server remains the authority for every transition.
// ══════════════════════════════════════════════════════════════════

import type {
  AuditChain,
  AuditCheckpoint,
  AuditEvent,
  AuditIntegrityStatus,
  AuditVerifyResult,
  CircuitBreaker,
  ExecutionAuthorization,
  ExecutionRun,
  GitRemediation,
  OperationalEvent,
  OpsCapabilities,
  OpsState,
  Reconciliation,
  RepositoryControl,
  RollbackRun,
  VerificationCheck,
  VerificationRun,
} from "./types";

// ── V3.3 Execution authorization ──────────────────────────────────────

/** Authorize execution of an APPROVED action (authorization data only;
 * executes nothing). Server re-verifies digest/policy/approval/step-up. */
export async function authorizeAction(
  proposalId: string,
  body: { reason?: string }
): Promise<ExecutionAuthorization> {
  return apiFetch<ExecutionAuthorization>(`/actions/${proposalId}/authorize`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function fetchProposalAuthorizations(
  proposalId: string
): Promise<ExecutionAuthorization[]> {
  return apiFetch<ExecutionAuthorization[]>(
    `/actions/${proposalId}/authorization`
  );
}

export async function fetchAuthorization(
  authorizationId: string
): Promise<ExecutionAuthorization> {
  return apiFetch<ExecutionAuthorization>(
    `/actions/authorization/${authorizationId}`
  );
}

/** Revoke a live authorization (AUTHORIZED → REVOKED; no resurrection). */
export async function revokeAuthorization(
  authorizationId: string,
  body: { reason?: string }
): Promise<ExecutionAuthorization> {
  return apiFetch<ExecutionAuthorization>(
    `/actions/authorization/${authorizationId}/revoke`,
    { method: "POST", body: JSON.stringify(body) }
  );
}

// ── V3.4 Execution runs ───────────────────────────────────────────────

export async function fetchProposalRuns(
  proposalId: string
): Promise<ExecutionRun[]> {
  return apiFetch<ExecutionRun[]>(`/actions/${proposalId}/runs`);
}

export async function fetchExecutionRun(runId: string): Promise<ExecutionRun> {
  return apiFetch<ExecutionRun>(`/executor/runs/user/${runId}`);
}

// ── V3.5 Git/GitHub remediation ───────────────────────────────────────

/** Start remediation for a server-verified run. Body is empty by design
 * (extra="forbid"): no branch, digest, or stage ceiling is accepted. */
export async function startRemediation(
  runId: string
): Promise<GitRemediation> {
  return apiFetch<GitRemediation>(`/actions/runs/${runId}/remediation`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function fetchRunRemediations(
  runId: string
): Promise<GitRemediation[]> {
  return apiFetch<GitRemediation[]>(`/actions/runs/${runId}/remediation`);
}

export async function fetchRemediation(
  remediationId: string
): Promise<GitRemediation> {
  return apiFetch<GitRemediation>(`/remediations/${remediationId}`);
}

// ── V3.6 Verification ─────────────────────────────────────────────────

/** Create the exactly-once verification record (executes nothing). */
export async function startVerification(
  remediationId: string
): Promise<VerificationRun> {
  return apiFetch<VerificationRun>(
    `/remediations/${remediationId}/verification`,
    { method: "POST", body: JSON.stringify({}) }
  );
}

export async function fetchRemediationVerifications(
  remediationId: string
): Promise<VerificationRun[]> {
  return apiFetch<VerificationRun[]>(
    `/remediations/${remediationId}/verification`
  );
}

export async function fetchVerification(
  verificationId: string
): Promise<VerificationRun> {
  return apiFetch<VerificationRun>(`/verifications/${verificationId}`);
}

export async function fetchVerificationChecks(
  verificationId: string
): Promise<VerificationCheck[]> {
  return apiFetch<VerificationCheck[]>(`/verifications/${verificationId}/checks`);
}

// ── V3.6 Rollback ─────────────────────────────────────────────────────

/** Create the exactly-once rollback record. No client SHA exists; the
 * target is server-derived from the frozen contract. Executes nothing. */
export async function startRollback(
  remediationId: string
): Promise<RollbackRun> {
  return apiFetch<RollbackRun>(`/remediations/${remediationId}/rollback`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function fetchRemediationRollbacks(
  remediationId: string
): Promise<RollbackRun[]> {
  return apiFetch<RollbackRun[]>(`/remediations/${remediationId}/rollback`);
}

export async function fetchRollback(rollbackId: string): Promise<RollbackRun> {
  return apiFetch<RollbackRun>(`/rollbacks/${rollbackId}`);
}

// ── V3.7 Operations ───────────────────────────────────────────────────

/** Server-derived role/capabilities. Used ONLY to shape the UI; the
 * server independently authorizes every call. */
export async function fetchOpsCapabilities(): Promise<OpsCapabilities> {
  return apiFetch<OpsCapabilities>("/ops/capabilities");
}

export async function fetchOpsStatus(): Promise<OpsState> {
  return apiFetch<OpsState>("/ops/status");
}

export async function setOpsState(target: string): Promise<OpsState> {
  return apiFetch<OpsState>("/ops/state", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function fetchRepositoryControl(
  repositoryId: string
): Promise<RepositoryControl> {
  return apiFetch<RepositoryControl>(`/ops/repositories/${repositoryId}/control`);
}

export async function setRepositoryControl(
  repositoryId: string,
  body: { control_state: string; reason?: string }
): Promise<RepositoryControl> {
  return apiFetch<RepositoryControl>(`/ops/repositories/${repositoryId}/control`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function fetchBreakers(): Promise<CircuitBreaker[]> {
  return apiFetch<CircuitBreaker[]>("/ops/breakers");
}

export async function resetBreaker(breakerId: string): Promise<CircuitBreaker> {
  return apiFetch<CircuitBreaker>(`/ops/breakers/${breakerId}/reset`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function runReconciliation(): Promise<Reconciliation> {
  return apiFetch<Reconciliation>("/ops/reconciliation/run", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function fetchLastReconciliation(): Promise<Reconciliation | null> {
  return apiFetch<Reconciliation | null>("/ops/reconciliation/last");
}

export async function fetchOpsEvents(limit = 50): Promise<OperationalEvent[]> {
  return apiFetch<OperationalEvent[]>(`/ops/events?limit=${encodeURIComponent(limit)}`);
}

// ── V3.8 Audit ────────────────────────────────────────────────────────

export async function fetchAuditChains(): Promise<AuditChain[]> {
  return apiFetch<AuditChain[]>("/audit/chains");
}

export async function fetchAuditEvents(
  chainId: string,
  params?: { limit?: number; from_seq?: number }
): Promise<AuditEvent[]> {
  const search = new URLSearchParams();
  if (params?.limit != null) search.set("limit", String(params.limit));
  if (params?.from_seq != null) search.set("from_seq", String(params.from_seq));
  const qs = search.toString();
  return apiFetch<AuditEvent[]>(
    `/audit/chains/${chainId}/events${qs ? `?${qs}` : ""}`
  );
}

/** Ask the SERVER to verify a chain. The browser never computes the
 * cryptographic chain itself. */
export async function verifyAuditChain(
  chainId: string
): Promise<AuditVerifyResult> {
  return apiFetch<AuditVerifyResult>(`/audit/chains/${chainId}/verify`);
}

export async function fetchAuditCheckpoints(
  chainId: string
): Promise<AuditCheckpoint[]> {
  return apiFetch<AuditCheckpoint[]>(`/audit/chains/${chainId}/checkpoints`);
}

export async function fetchAuditIntegrityStatus(): Promise<AuditIntegrityStatus> {
  return apiFetch<AuditIntegrityStatus>("/audit/integrity/status");
}

/** Download URL for the deterministic NDJSON export (GET, attachment).
 * Returned as a path the browser navigates to; no client-side build. */
export function auditExportPath(chainId: string): string {
  return `/api/audit/chains/${encodeURIComponent(chainId)}/export`;
}

// ══════════════════════════════════════════════════════════════════
// V4.0 Platform — organizations, members, invitations, API keys
//
// Tenancy rule enforced here in the CLIENT CALL SHAPE: the organization
// always travels in the PATH (a selector the server verifies against the
// caller's membership), never in a body field the server might trust.
// No request body below carries organization_id, role-of-caller, or any
// other authority value.
// ══════════════════════════════════════════════════════════════════

import type {
  Organization,
  OrgMember,
  OrgInvitation,
  OrgInvitationCreated,
  OrgApiKey,
  OrgApiKeyCreated,
  OrgCapabilities,
  OrgPolicy,
} from "./types";

/** Organizations the caller has any recorded membership in. */
export async function fetchOrganizations(): Promise<Organization[]> {
  return apiFetch<Organization[]>("/orgs");
}

export async function createOrganization(name: string): Promise<Organization> {
  return apiFetch<Organization>("/orgs", {
    method: "POST",
    body: JSON.stringify({ name }),
  });
}

export async function fetchOrganization(
  organizationId: string
): Promise<Organization> {
  return apiFetch<Organization>(`/orgs/${organizationId}`);
}

/** Server-derived role + capabilities for the caller in this organization.
 *  Used ONLY to shape the UI; every route re-checks on the server. */
export async function fetchOrgCapabilities(
  organizationId: string
): Promise<OrgCapabilities> {
  return apiFetch<OrgCapabilities>(`/orgs/${organizationId}/capabilities`);
}

export async function fetchOrgMembers(
  organizationId: string
): Promise<OrgMember[]> {
  return apiFetch<OrgMember[]>(`/orgs/${organizationId}/members`);
}

export async function changeMemberRole(
  organizationId: string,
  userId: string,
  role: string
): Promise<OrgMember> {
  return apiFetch<OrgMember>(
    `/orgs/${organizationId}/members/${userId}`,
    { method: "PATCH", body: JSON.stringify({ role }) }
  );
}

export async function changeMemberState(
  organizationId: string,
  userId: string,
  state: string
): Promise<OrgMember> {
  return apiFetch<OrgMember>(
    `/orgs/${organizationId}/members/${userId}/state`,
    { method: "POST", body: JSON.stringify({ state }) }
  );
}

export async function fetchOrgInvitations(
  organizationId: string
): Promise<OrgInvitation[]> {
  return apiFetch<OrgInvitation[]>(`/orgs/${organizationId}/invitations`);
}

/** Returns the plaintext token exactly once — the caller must surface it
 *  and never persist it. The server stores only its hash. */
export async function createOrgInvitation(
  organizationId: string,
  body: { email?: string | null; role?: string }
): Promise<OrgInvitationCreated> {
  return apiFetch<OrgInvitationCreated>(
    `/orgs/${organizationId}/invitations`,
    { method: "POST", body: JSON.stringify(body) }
  );
}

export async function revokeOrgInvitation(
  organizationId: string,
  invitationId: string
): Promise<OrgInvitation> {
  return apiFetch<OrgInvitation>(
    `/orgs/${organizationId}/invitations/${invitationId}/revoke`,
    { method: "POST", body: JSON.stringify({}) }
  );
}

/** Accept a one-time invitation. The token IS the authority here. */
export async function acceptOrgInvitation(token: string): Promise<Organization> {
  return apiFetch<Organization>("/invitations/accept", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}

export async function fetchOrgPolicy(
  organizationId: string
): Promise<OrgPolicy> {
  return apiFetch<OrgPolicy>(`/orgs/${organizationId}/policy`);
}

export async function updateOrgPolicy(
  organizationId: string,
  policy: Record<string, unknown>
): Promise<OrgPolicy> {
  return apiFetch<OrgPolicy>(`/orgs/${organizationId}/policy`, {
    method: "PUT",
    body: JSON.stringify({ policy }),
  });
}

export async function fetchApiKeys(
  organizationId: string
): Promise<OrgApiKey[]> {
  return apiFetch<OrgApiKey[]>(`/orgs/${organizationId}/api-keys`);
}

/** Returns the plaintext secret exactly once — shown, then discarded. */
export async function createApiKey(
  organizationId: string,
  body: { name: string; scopes: string[]; expires_at?: string | null }
): Promise<OrgApiKeyCreated> {
  return apiFetch<OrgApiKeyCreated>(`/orgs/${organizationId}/api-keys`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function revokeApiKey(
  organizationId: string,
  keyId: string
): Promise<OrgApiKey> {
  return apiFetch<OrgApiKey>(
    `/orgs/${organizationId}/api-keys/${keyId}/revoke`,
    { method: "POST", body: JSON.stringify({}) }
  );
}

/** Rotate a key: the old key stops working immediately and the replacement
 *  secret is returned exactly once. Scopes and expiry are preserved. */
export async function rotateApiKey(
  organizationId: string,
  keyId: string
): Promise<OrgApiKeyCreated> {
  return apiFetch<OrgApiKeyCreated>(
    `/orgs/${organizationId}/api-keys/${keyId}/rotate`,
    { method: "POST", body: JSON.stringify({}) }
  );
}
