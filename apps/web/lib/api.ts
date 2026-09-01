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

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
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
    try {
      const body = await response.json();
      detail = body.detail || body.message;
    } catch {
      // Ignore parse errors on error responses
    }

    throw new ApiError(
      response.status,
      classifyError(response.status),
      detail
    );
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
