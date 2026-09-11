"""CYVRIX V3.1 — Deterministic policy engine.

Implements docs/v3-action-policy.md §1 as executable code.

Design (docs/v3-architecture.md §6, ADR-004):
- PURE FUNCTION: no DB, no network, no filesystem, no clock, no randomness.
  `now` is an explicit parameter so expiry is testable and deterministic.
- DEFAULT DENY: unknown action types, roles, environments, trust levels,
  validation states, operations, and file classes never become allowed.
- DENY PRECEDENCE: all rules are evaluated; DENY overrides
  REQUIRE_APPROVAL overrides ALLOW. Among equal-severity matches the
  lowest rule identifier wins (deterministic tie-break).
- VERSIONED: every decision carries POLICY_VERSION. Rule changes without
  a version bump are a policy violation.
- AI output never reaches this engine as authority: the context contains
  only server-derived security data and pre-validated proposal content.

Decision model (docs/v3-action-policy.md §1.1): exactly
ALLOW | REQUIRE_APPROVAL | DENY — never a bare boolean.

V3.1 note: no rule emits ALLOW. Every valid action requires approval;
ALLOW is reserved for future low-risk classes (V3.2+ policy decision).
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from app.services.action_model import (
    MAX_DIFF_LINES,
    MAX_FILES_PER_PROPOSAL,
    MAX_OPERATIONS_PER_PROPOSAL,
    ActionType,
    OperationType,
    is_major_version_change,
    is_protected_path,
)

POLICY_VERSION = "3.1"

# Decisions (exact three — docs/v3-action-policy.md §1.1)
DECISION_ALLOW = "ALLOW"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
DECISION_DENY = "DENY"

_APPROVAL_SEVERITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_DECISION_SEVERITY = {DECISION_ALLOW: 0, DECISION_REQUIRE_APPROVAL: 1, DECISION_DENY: 2}

SUPPORTED_ENVIRONMENTS = {"development", "staging", "production"}
SUPPORTED_ROLES = {"owner", "approver"}  # V3.1: every authenticated user is 'owner'
SUPPORTED_TRUST_LEVELS = {"SUPPORTED", "LIKELY", "UNCERTAIN"}
SUPPORTED_VALIDATION_STATES = {"VALIDATED", "PARTIALLY_VALIDATED", "UNVERIFIED", "UNSAFE"}
ACTIONABLE_FINDING_STATUSES = {"OPEN", "CONFIRMED"}


@dataclass(frozen=True)
class PolicyContext:
    """Inputs to one policy evaluation.

    Trust classification of inputs (docs/v3-action-policy.md §1.1):
    - TRUSTED server-derived: repository_active, environment, actor_role,
      validation_state, trust_level, risk_level, risk_score,
      finding_status, kill_switch
    - PRE-VALIDATED proposal content (strictly schema-checked upstream,
      but still untrusted in origin): files, operations, target_branch,
      base_commit_sha, counts, protected-path hits, path validity
    """

    action_type: Optional[str] = None
    repository_active: bool = False
    environment: str = ""
    actor_role: str = "owner"
    validation_state: Optional[str] = None
    trust_level: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[int] = None
    finding_status: str = ""
    kill_switch: bool = False

    files: tuple = ()
    operations: tuple = ()
    target_branch: str = ""
    base_commit_sha: str = ""
    paths_valid: bool = False
    files_match_type: bool = False
    operations_valid: bool = False
    protected_path_categories: tuple = ()
    diff_lines: int = 0
    expires_at: Optional[datetime] = None


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    decision: str
    reason_code: str
    explanation: str
    approval_level: Optional[str] = None


@dataclass(frozen=True)
class PolicyDecision:
    decision: str
    policy_version: str
    reason_code: str
    explanation: str
    matched_rule: str
    approval_level: Optional[str]
    risk_level: Optional[str]
    action_type: Optional[str]
    evaluated_at: datetime


def _rule_unknown_action_type(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.action_type is None or ctx.action_type not in ActionType.__members__:
        return RuleHit("POL-001", DECISION_DENY, "UNKNOWN_ACTION_TYPE",
                       f"action_type {ctx.action_type!r} is not allowlisted")
    return None


def _rule_repository_inactive(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.repository_active:
        return RuleHit("POL-002", DECISION_DENY, "REPOSITORY_INACTIVE",
                       "repository is inactive")
    return None


def _rule_unsafe_recommendation(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.validation_state == "UNSAFE":
        return RuleHit("POL-003", DECISION_DENY, "UNSAFE_RECOMMENDATION",
                       "recommendation validation state is UNSAFE")
    return None


def _rule_unvalidated_recommendation(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.validation_state == "UNVERIFIED":
        return RuleHit("POL-004", DECISION_DENY, "UNVALIDATED_RECOMMENDATION",
                       "recommendation has not been re-validated")
    return None


def _rule_missing_validation_state(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.validation_state is None or ctx.validation_state not in SUPPORTED_VALIDATION_STATES:
        return RuleHit("POL-005", DECISION_DENY, "MISSING_VALIDATION_STATE",
                       f"validation_state {ctx.validation_state!r} is missing or unknown")
    return None


def _rule_expired(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.expires_at is None:
        return RuleHit("POL-006", DECISION_DENY, "EXPIRED_PROPOSAL",
                       "proposal has no expiry — refusing unbounded lifetime")
    expires = ctx.expires_at if ctx.expires_at.tzinfo else ctx.expires_at.replace(tzinfo=now.tzinfo)
    if now >= expires:
        return RuleHit("POL-006", DECISION_DENY, "EXPIRED_PROPOSAL",
                       "proposal expired")
    return None


def _rule_kill_switch(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.kill_switch:
        return RuleHit("POL-007", DECISION_DENY, "EXECUTION_DISABLED",
                       "autonomous execution is disabled by kill switch")
    return None


def _rule_invalid_commit(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.base_commit_sha:
        return RuleHit("POL-008", DECISION_DENY, "INVALID_COMMIT",
                       "proposal is not bound to a base commit")
    return None


def _rule_invalid_branch(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.target_branch:
        return RuleHit("POL-009", DECISION_DENY, "INVALID_BRANCH",
                       "proposal is not bound to a target branch")
    return None


def _rule_invalid_paths(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.files:
        return RuleHit("POL-010", DECISION_DENY, "INVALID_PATH",
                       "proposal declares no files")
    if not ctx.paths_valid:
        return RuleHit("POL-010", DECISION_DENY, "INVALID_PATH",
                       "one or more declared paths are unsafe or ambiguous")
    return None


def _rule_protected_path(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.protected_path_categories:
        cats = ", ".join(sorted(set(ctx.protected_path_categories)))
        return RuleHit("POL-011", DECISION_DENY, "PROTECTED_PATH",
                       f"proposal targets protected path categories: {cats}")
    return None


def _rule_out_of_scope_file(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.files_match_type:
        return RuleHit("POL-012", DECISION_DENY, "OUT_OF_SCOPE_FILE",
                       "declared files are outside the action type allowlist")
    return None


def _rule_invalid_operations(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if not ctx.operations:
        return RuleHit("POL-013", DECISION_DENY, "INVALID_OPERATION",
                       "proposal declares no operations")
    if not ctx.operations_valid:
        return RuleHit("POL-013", DECISION_DENY, "INVALID_OPERATION",
                       "one or more operations fail their type schema")
    return None


def _rule_excessive_files(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if len(ctx.files) > MAX_FILES_PER_PROPOSAL:
        return RuleHit("POL-014", DECISION_DENY, "EXCESSIVE_FILE_COUNT",
                       f"file count {len(ctx.files)} exceeds cap {MAX_FILES_PER_PROPOSAL}")
    return None


def _rule_excessive_operations(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if len(ctx.operations) > MAX_OPERATIONS_PER_PROPOSAL:
        return RuleHit("POL-015", DECISION_DENY, "EXCESSIVE_OPERATION_COUNT",
                       f"operation count {len(ctx.operations)} exceeds cap {MAX_OPERATIONS_PER_PROPOSAL}")
    return None


def _rule_excessive_diff(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.diff_lines < 0:
        return RuleHit("POL-016", DECISION_DENY, "EXCESSIVE_DIFF_SIZE",
                       "diff size is malformed (negative)")
    if ctx.diff_lines > MAX_DIFF_LINES:
        return RuleHit("POL-016", DECISION_DENY, "EXCESSIVE_DIFF_SIZE",
                       f"diff size {ctx.diff_lines} lines exceeds cap {MAX_DIFF_LINES}")
    return None


def _rule_missing_risk(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.risk_level is None or ctx.risk_score is None:
        return RuleHit("POL-017", DECISION_DENY, "MISSING_RISK_ASSESSMENT",
                       "no risk assessment available — refusing ambiguity")
    return None


def _rule_malformed_risk(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    score = ctx.risk_score
    if score is not None and (
        isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100
    ):
        return RuleHit("POL-018", DECISION_DENY, "MALFORMED_RISK",
                       "risk_score is malformed")
    if ctx.risk_level is not None and ctx.risk_level not in {
        "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL",
    }:
        return RuleHit("POL-018", DECISION_DENY, "MALFORMED_RISK",
                       "risk_level is malformed")
    return None


def _rule_finding_not_actionable(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.finding_status not in ACTIONABLE_FINDING_STATUSES:
        return RuleHit("POL-019", DECISION_DENY, "FINDING_NOT_ACTIONABLE",
                       f"finding status {ctx.finding_status!r} is not actionable")
    return None


def _rule_unknown_environment(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.environment not in SUPPORTED_ENVIRONMENTS:
        return RuleHit("POL-020", DECISION_DENY, "UNKNOWN_ENVIRONMENT",
                       f"environment {ctx.environment!r} is unknown")
    return None


def _rule_unknown_role(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.actor_role not in SUPPORTED_ROLES:
        return RuleHit("POL-021", DECISION_DENY, "UNKNOWN_ROLE",
                       f"actor role {ctx.actor_role!r} is unknown")
    return None


def _rule_unknown_trust_level(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.trust_level is not None and ctx.trust_level not in SUPPORTED_TRUST_LEVELS:
        return RuleHit("POL-022", DECISION_DENY, "UNKNOWN_TRUST_LEVEL",
                       f"trust level {ctx.trust_level!r} is unknown")
    return None


def _rule_critical_risk(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.risk_level == "CRITICAL":
        return RuleHit("POL-023", DECISION_REQUIRE_APPROVAL, "CRITICAL_RISK_REQUIRES_APPROVAL",
                       "critical-risk action requires approver sign-off",
                       approval_level="CRITICAL")
    return None


def _rule_high_risk(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.risk_level == "HIGH":
        return RuleHit("POL-024", DECISION_REQUIRE_APPROVAL, "HIGH_RISK_REQUIRES_APPROVAL",
                       "high-risk action requires approval",
                       approval_level="HIGH")
    return None


def _rule_major_version_bump(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.action_type != ActionType.DEPENDENCY_UPGRADE.value:
        return None
    for op in ctx.operations:
        if (
            isinstance(op, dict)
            and op.get("type") == OperationType.UPDATE_DEPENDENCY_VERSION.value
            and isinstance(op.get("from_version"), str)
            and isinstance(op.get("to_version"), str)
            and is_major_version_change(op["from_version"], op["to_version"])
        ):
            return RuleHit("POL-025", DECISION_REQUIRE_APPROVAL,
                           "MAJOR_VERSION_REQUIRES_APPROVAL",
                           "dependency upgrade crosses a major version boundary — "
                           "explicit justification required",
                           approval_level="MEDIUM")
    return None


def _rule_documented_security_fix(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.action_type == ActionType.DOCUMENTED_SECURITY_FIX.value:
        return RuleHit("POL-026", DECISION_REQUIRE_APPROVAL, "LOW_RISK_REQUIRES_APPROVAL",
                       "documentation-only fix requires approval (self-approval "
                       "with step-up allowed from V3.2)",
                       approval_level="LOW")
    return None


def _rule_standard_action(ctx: PolicyContext, now: datetime) -> Optional[RuleHit]:
    if ctx.action_type in (
        ActionType.DEPENDENCY_UPGRADE.value,
        ActionType.DOCKERFILE_UPDATE.value,
        ActionType.CONFIGURATION_UPDATE.value,
    ):
        return RuleHit("POL-027", DECISION_REQUIRE_APPROVAL, "MEDIUM_RISK_REQUIRES_APPROVAL",
                       "standard remediation action requires approval",
                       approval_level="MEDIUM")
    return None


# Rule registry — order matters only for equal-severity tie-breaking.
RULES = (
    _rule_unknown_action_type,      # POL-001
    _rule_repository_inactive,      # POL-002
    _rule_unsafe_recommendation,    # POL-003
    _rule_unvalidated_recommendation,  # POL-004
    _rule_missing_validation_state, # POL-005
    _rule_expired,                  # POL-006
    _rule_kill_switch,              # POL-007
    _rule_invalid_commit,           # POL-008
    _rule_invalid_branch,           # POL-009
    _rule_invalid_paths,            # POL-010
    _rule_protected_path,           # POL-011
    _rule_out_of_scope_file,        # POL-012
    _rule_invalid_operations,       # POL-013
    _rule_excessive_files,          # POL-014
    _rule_excessive_operations,     # POL-015
    _rule_excessive_diff,           # POL-016
    _rule_missing_risk,             # POL-017
    _rule_malformed_risk,           # POL-018
    _rule_finding_not_actionable,   # POL-019
    _rule_unknown_environment,      # POL-020
    _rule_unknown_role,             # POL-021
    _rule_unknown_trust_level,      # POL-022
    _rule_critical_risk,            # POL-023
    _rule_high_risk,                # POL-024
    _rule_major_version_bump,       # POL-025
    _rule_documented_security_fix,  # POL-026
    _rule_standard_action,          # POL-027
)

DEFAULT_DENY_RULE_ID = "POL-028"  # fallthrough: no rule matched


def evaluate(ctx: PolicyContext, now: datetime) -> PolicyDecision:
    """Evaluate all rules and resolve by deny precedence. Pure function.

    Same (ctx, now) → same decision, always.
    """
    hits = [hit for rule in RULES if (hit := rule(ctx, now)) is not None]

    if not hits:
        chosen = RuleHit(
            DEFAULT_DENY_RULE_ID, DECISION_DENY, "NO_MATCHING_RULE",
            "no policy rule matched — default deny",
        )
    else:
        # DENY > REQUIRE_APPROVAL > ALLOW; deterministic tie-breaks.
        chosen = min(
            hits,
            key=lambda h: (
                -_DECISION_SEVERITY[h.decision],
                -(_APPROVAL_SEVERITY.get(h.approval_level, -1) if h.decision == DECISION_REQUIRE_APPROVAL else 0),
                h.rule_id,
            ),
        )

    return PolicyDecision(
        decision=chosen.decision,
        policy_version=POLICY_VERSION,
        reason_code=chosen.reason_code,
        explanation=chosen.explanation,
        matched_rule=chosen.rule_id,
        approval_level=chosen.approval_level,
        risk_level=ctx.risk_level,
        action_type=ctx.action_type,
        evaluated_at=now,
    )
