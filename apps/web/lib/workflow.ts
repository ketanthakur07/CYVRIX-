/**
 * CYVRIX V3.9 — workflow state PRESENTATION helpers.
 *
 * These functions map backend state strings to visual tones and terminal
 * checks. They are DISPLAY ONLY:
 * - They never decide authority (the server re-derives every decision).
 * - They never invent a state; an unrecognised value renders as UNKNOWN.
 * - Terminal checks drive polling only, never success/failure displays.
 *
 * Every string here mirrors `apps/api/app/services/*_model.py` exactly.
 */

export type StateTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "danger"
  | "pending";

export type StateToneMap = Readonly<Record<string, StateTone>>;

/** Rendered when the backend returns a state this build does not know. */
export const UNKNOWN_STATE = "UNKNOWN_STATE";

export function toneFor(map: StateToneMap, state: string | null | undefined): StateTone {
  if (!state) return "neutral";
  return map[state] ?? "neutral";
}

export function isKnownState(map: StateToneMap, state: string | null | undefined): boolean {
  return !!state && state in map;
}

// ── Action proposal (V3.1/V3.2) ─────────────────────────────────────
export const PROPOSAL_STATUS_TONE: StateToneMap = {
  PROPOSED: "pending",
  POLICY_CHECKED: "info",
  APPROVED: "success",
  REJECTED: "danger",
  EXPIRED: "neutral",
  STALE: "warning",
};

// ── Approval (V3.2) ─────────────────────────────────────────────────
export const APPROVAL_TONE: StateToneMap = {
  PENDING: "pending",
  APPROVED: "success",
  REJECTED: "danger",
  EXPIRED: "neutral",
  REVOKED: "danger",
  USED: "info",
};

// ── Authorization (V3.3) ────────────────────────────────────────────
export const AUTHORIZATION_TONE: StateToneMap = {
  AUTHORIZED: "info",
  CONSUMED: "neutral",
  EXPIRED: "neutral",
  REVOKED: "danger",
};

// ── Execution run (V3.4) ────────────────────────────────────────────
export const RUN_TONE: StateToneMap = {
  ADMISSION_PENDING: "pending",
  EXECUTING: "info",
  RESULT_READY: "info",
  COMPLETED: "success",
  FAILED: "danger",
  CLEANUP_FAILED: "warning",
};

export const TERMINAL_RUN_STATES: ReadonlySet<string> = new Set([
  "COMPLETED",
  "FAILED",
  "CLEANUP_FAILED",
]);

export function isTerminalRun(state: string | null | undefined): boolean {
  return !!state && TERMINAL_RUN_STATES.has(state);
}

// ── Git/GitHub remediation (V3.5) ───────────────────────────────────
export const REMEDIATION_TONE: StateToneMap = {
  PENDING: "pending",
  VERIFYING: "info",
  COMMITTING: "info",
  COMMITTED: "info",
  PUSHING: "info",
  PUSHED: "info",
  PR_CREATING: "info",
  PR_CREATED: "success",
  FAILED: "danger",
  STALE: "warning",
  INCONSISTENT: "danger",
};

export const TERMINAL_REMEDIATION_STATES: ReadonlySet<string> = new Set([
  "PR_CREATED",
  "FAILED",
  "STALE",
  "INCONSISTENT",
]);

export function isTerminalRemediation(state: string | null | undefined): boolean {
  return !!state && TERMINAL_REMEDIATION_STATES.has(state);
}

/** A committed remediation is eligible for verification. */
export function isCommitted(remediation: { committed_sha: string | null } | null | undefined): boolean {
  return !!remediation?.committed_sha;
}

/** A pushed remediation is eligible for rollback. */
export function isPushed(remediation: { pushed_sha: string | null } | null | undefined): boolean {
  return !!remediation?.pushed_sha;
}

// ── Verification (V3.6) ─────────────────────────────────────────────
export const VERIFICATION_STATE_TONE: StateToneMap = {
  PENDING: "pending",
  RUNNING: "info",
  COMPLETED: "info", // result carries the verdict, not the state
  FAILED: "danger",
  BLOCKED: "warning",
};

export const VERIFICATION_RESULT_TONE: StateToneMap = {
  PASS: "success",
  FAIL: "danger",
  INCONCLUSIVE: "warning",
  SKIPPED: "neutral",
  BLOCKED: "warning",
};

export const TERMINAL_VERIFICATION_STATES: ReadonlySet<string> = new Set([
  "COMPLETED",
  "FAILED",
  "BLOCKED",
]);

export function isTerminalVerification(state: string | null | undefined): boolean {
  return !!state && TERMINAL_VERIFICATION_STATES.has(state);
}

export function verificationAccepted(result: string | null | undefined): boolean {
  return result === "PASS" || result === "SKIPPED";
}

export function verificationBlocked(result: string | null | undefined): boolean {
  return result === "FAIL" || result === "INCONCLUSIVE" || result === "BLOCKED";
}

// ── Rollback (V3.6) ─────────────────────────────────────────────────
export const ROLLBACK_TONE: StateToneMap = {
  PENDING: "pending",
  PRECHECK: "info",
  ROLLING_BACK: "info",
  VERIFYING: "info",
  COMPLETED: "success",
  FAILED: "danger",
  CONFLICT: "warning",
};

export const TERMINAL_ROLLBACK_STATES: ReadonlySet<string> = new Set([
  "COMPLETED",
  "FAILED",
  "CONFLICT",
]);

export function isTerminalRollback(state: string | null | undefined): boolean {
  return !!state && TERMINAL_ROLLBACK_STATES.has(state);
}

// ── Operations (V3.7) ───────────────────────────────────────────────
export const OPS_STATE_TONE: StateToneMap = {
  NORMAL: "success",
  PAUSED: "warning",
  DRAINING: "info",
  EMERGENCY_STOP: "danger",
};

export const REPO_CONTROL_TONE: StateToneMap = {
  ENABLED: "success",
  PAUSED: "warning",
  DISABLED: "danger",
};

export const BREAKER_TONE: StateToneMap = {
  CLOSED: "success",
  HALF_OPEN: "warning",
  OPEN: "danger",
};

// ── Audit (V3.8) ────────────────────────────────────────────────────
export const AUDIT_VERIFY_TONE: StateToneMap = {
  VALID: "success",
  INVALID: "danger",
  EMPTY: "neutral",
  UNSUPPORTED_VERSION: "warning",
};

// ── V4.0 Organization platform ──────────────────────────────────────

/** Membership states. Only ACTIVE is an authorizing state; the others
 *  render as inert (neutral/pending) so the UI never suggests a
 *  suspended or invited membership can act. */
export const MEMBERSHIP_TONE: StateToneMap = {
  ACTIVE: "success",
  INVITED: "pending",
  SUSPENDED: "warning",
  REMOVED: "neutral",
};

export const ORG_STATE_TONE: StateToneMap = {
  ACTIVE: "success",
  SUSPENDED: "warning",
  DELETED: "danger",
};

/** Organization roles, ordered most- to least-privileged for display. */
export const ORG_ROLE_TONE: StateToneMap = {
  ORG_OWNER: "danger",
  ORG_ADMIN: "warning",
  SECURITY_ENGINEER: "info",
  DEVELOPER: "info",
  AUDITOR: "neutral",
  VIEWER: "neutral",
};

/** Invitation lifecycle. A revoked/accepted invitation is terminal. */
export function invitationTone(invitation: {
  revoked_at?: string | null;
  accepted_at?: string | null;
  expires_at?: string | null;
}): StateTone {
  if (invitation.revoked_at) return "danger";
  if (invitation.accepted_at) return "success";
  if (invitation.expires_at) {
    const at = new Date(invitation.expires_at).getTime();
    if (!Number.isNaN(at) && at < Date.now()) return "neutral";
  }
  return "pending";
}

export function invitationStatusLabel(invitation: {
  revoked_at?: string | null;
  accepted_at?: string | null;
  expires_at?: string | null;
}): string {
  if (invitation.revoked_at) return "revoked";
  if (invitation.accepted_at) return "accepted";
  if (invitation.expires_at) {
    const at = new Date(invitation.expires_at).getTime();
    if (!Number.isNaN(at) && at < Date.now()) return "expired";
  }
  return "pending";
}

/** API key lifecycle. Revoked/expired keys are shown but never usable. */
export function apiKeyTone(key: {
  revoked_at?: string | null;
  expires_at?: string | null;
}): StateTone {
  if (key.revoked_at) return "danger";
  if (key.expires_at) {
    const at = new Date(key.expires_at).getTime();
    if (!Number.isNaN(at) && at < Date.now()) return "neutral";
  }
  return "success";
}

export function apiKeyStatus(key: {
  revoked_at?: string | null;
  expires_at?: string | null;
}): string {
  if (key.revoked_at) return "revoked";
  if (key.expires_at) {
    const at = new Date(key.expires_at).getTime();
    if (!Number.isNaN(at) && at < Date.now()) return "expired";
  }
  return "active";
}

// ── Lifecycle stage model (action hub) ──────────────────────────────
//
// Ordered presentation of the remediation lifecycle. This is a display
// model only: it never asserts that a later stage has occurred.

export type LifecycleStageId =
  | "proposed"
  | "approved"
  | "authorized"
  | "executed"
  | "verified"
  | "rolled_back";

export const LIFECYCLE_ORDER: readonly LifecycleStageId[] = [
  "proposed",
  "approved",
  "authorized",
  "executed",
  "verified",
  "rolled_back",
];

export const LIFECYCLE_LABELS: Record<LifecycleStageId, string> = {
  proposed: "Proposed",
  approved: "Approved",
  authorized: "Authorized",
  executed: "Executed",
  verified: "Verified",
  rolled_back: "Rolled back",
};

/** Format an ISO timestamp for display; returns "—" for null/invalid. */
export function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

/** Shorten a digest for display. Never used as authority. */
export function shortDigest(value: string | null | undefined): string {
  if (!value) return "—";
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}
