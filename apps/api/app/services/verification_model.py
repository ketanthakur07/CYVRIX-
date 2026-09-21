"""CYVRIX V3.6 — Verification + rollback domain model.

Pure, side-effect-free primitives for the V3.6 verification and
controlled-rollback engines:
- Verification results: PASS | FAIL | INCONCLUSIVE | SKIPPED | BLOCKED
- Closed-world verification operation types (unknown → FAIL CLOSED)
- Verification lifecycle states and the canonical state machine
- Rollback lifecycle states and the canonical state machine
- The frozen, digestable VerificationPlan + its canonical digest
- Bounded, structured check evidence (repository output is UNTRUSTED DATA)

Security properties (docs/v3-verification-rollback.md):
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Unknown check types / states always fail closed
- A verification result can NEVER be produced from client input
- The plan is FROZEN and digestable; it binds the verification to the
  exact remediation contract (repo, base SHA, branches, file scope,
  committed SHA, run id, action digest)
- Evidence is bounded and scrubbed: no secrets, no control characters,
  no unbounded repository text
- This module must NEVER import services that perform side effects
"""
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

from app.services.action_digest import generic_canonical_bytes

# ── Versions ─────────────────────────────────────────────────────────

VERIFICATION_PLAN_VERSION = "1"
VERIFICATION_ENGINE_VERSION = "1"

# ── Reason codes (stable, machine-readable) ──────────────────────────

RC_OK = "OK"
RC_VERIFICATION_NOT_FOUND = "VERIFICATION_NOT_FOUND"
RC_VERIFICATION_NOT_POSSIBLE = "VERIFICATION_NOT_POSSIBLE"
RC_VERIFICATION_REPLAY = "VERIFICATION_REPLAY"
RC_VERIFICATION_IN_PROGRESS = "VERIFICATION_IN_PROGRESS"
RC_VERIFICATION_STATE_INVALID = "VERIFICATION_STATE_INVALID"
RC_UNKNOWN_CHECK_TYPE = "UNKNOWN_CHECK_TYPE"
RC_PLAN_DIGEST_MISMATCH = "PLAN_DIGEST_MISMATCH"
RC_PLAN_INVALID = "PLAN_INVALID"
RC_EVIDENCE_UNBOUNDED = "EVIDENCE_UNBOUNDED"
RC_CHECK_FAILED = "CHECK_FAILED"
RC_CHECK_INCONCLUSIVE = "CHECK_INCONCLUSIVE"
RC_CHECK_SKIPPED = "CHECK_SKIPPED"
RC_CHECK_BLOCKED = "CHECK_BLOCKED"
RC_INTENT_MISMATCH = "INTENT_MISMATCH"
RC_ACTUAL_CHANGE_MISMATCH = "ACTUAL_CHANGE_MISMATCH"
RC_FINDING_STILL_PRESENT = "FINDING_STILL_PRESENT"
RC_SECURITY_REGRESSION = "SECURITY_REGRESSION"
RC_RISK_DRIFT = "RISK_DRIFT"
RC_SECRET_DETECTED = "SECRET_DETECTED"
RC_EXPECTED_CONDITION_UNMET = "EXPECTED_CONDITION_UNMET"
RC_SCOPE_MISMATCH = "SCOPE_MISMATCH"
RC_KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
RC_ACTION_DIGEST_MISMATCH = "ACTION_DIGEST_MISMATCH"
RC_AUTHORIZATION_INVALID = "AUTHORIZATION_INVALID"
RC_ROLLBACK_NOT_ALLOWED = "ROLLBACK_NOT_ALLOWED"
RC_ROLLBACK_NOT_FOUND = "ROLLBACK_NOT_FOUND"
RC_ROLLBACK_REPLAY = "ROLLBACK_REPLAY"
RC_ROLLBACK_IN_PROGRESS = "ROLLBACK_IN_PROGRESS"
RC_ROLLBACK_STATE_INVALID = "ROLLBACK_STATE_INVALID"
RC_ROLLBACK_TARGET_INVALID = "ROLLBACK_TARGET_INVALID"
RC_ROLLBACK_STATE_MISMATCH = "ROLLBACK_STATE_MISMATCH"
RC_ROLLBACK_FAILED = "ROLLBACK_FAILED"
RC_ROLLBACK_VERIFY_FAILED = "ROLLBACK_VERIFY_FAILED"
RC_ROLLBACK_CONFLICT = "ROLLBACK_CONFLICT"
RC_ROLLBACK_NOT_NEEDED = "ROLLBACK_NOT_NEEDED"
RC_VERIFICATION_CHECK_FAILED = "VERIFICATION_CHECK_FAILED"
RC_VERIFICATION_FAILED = "VERIFICATION_FAILED"
RC_REMOTE_STATE_MISMATCH = "REMOTE_STATE_MISMATCH"
RC_GITHUB_STATE_MISMATCH = "GITHUB_STATE_MISMATCH"
RC_BASE_COMMIT_MISMATCH = "BASE_COMMIT_MISMATCH"
RC_BRANCH_INVALID = "BRANCH_INVALID"
RC_GIT_UNAVAILABLE = "GIT_UNAVAILABLE"
RC_GIT_OPERATION_FAILED = "GIT_OPERATION_FAILED"
RC_PR_FAILED = "PR_FAILED"
RC_CREDENTIAL_DENIED = "CREDENTIAL_DENIED"
RC_CLEANUP_FAILED = "CLEANUP_FAILED"
RC_FORCED = "FORCED"

# ── Verification results ─────────────────────────────────────────────


class VerificationResult:
    """Outcomes of a verification run. Values persist verbatim.

    FAIL ≠ INCONCLUSIVE ≠ BLOCKED:
    - FAIL: deterministic evidence proves the security objective unmet
    - INCONCLUSIVE: evidence is ambiguous/missing; acceptance refused
    - BLOCKED: verification could not run at all (kill switch, infra)
    - SKIPPED: check not applicable to this plan (explicitly planned)
    """

    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"


ALL_VERIFICATION_RESULTS = frozenset({
    "PASS", "FAIL", "INCONCLUSIVE", "SKIPPED", "BLOCKED",
})

# Results that are acceptable for the OVERALL verification verdict.
ACCEPTABLE_RESULTS = frozenset({"PASS", "SKIPPED"})


# ── Closed-world verification check types ────────────────────────────


class VerificationCheckType:
    """The ONLY check types that exist. Unknown → fail closed.

    Deterministic, bounded, server-side checks. There is deliberately no
    RUN_ARBITRARY_COMMAND and no RUN_PROJECT_TESTS type: repository
    scripts are untrusted input and never become verification logic.
    """

    VERIFY_DIFF = "VERIFY_DIFF"                       # committed diff ⊆ authorized scope
    VERIFY_FILE_STATE = "VERIFY_FILE_STATE"           # committed content == run AFTER hashes
    VERIFY_SECURITY_FINDING = "VERIFY_SECURITY_FINDING"  # original finding re-evaluation
    VERIFY_DEPENDENCY_STATE = "VERIFY_DEPENDENCY_STATE"  # dependency pin/lock consistency
    VERIFY_CONFIGURATION = "VERIFY_CONFIGURATION"     # parsed config matches expected value
    VERIFY_GIT_STATE = "VERIFY_GIT_STATE"             # branch tip == committed SHA; base intact
    VERIFY_GITHUB_STATE = "VERIFY_GITHUB_STATE"       # remote branch/PR readback
    VERIFY_POLICY_INVARIANT = "VERIFY_POLICY_INVARIANT"  # dangerous-directive regression scan


ALL_CHECK_TYPES = frozenset({
    "VERIFY_DIFF", "VERIFY_FILE_STATE", "VERIFY_SECURITY_FINDING",
    "VERIFY_DEPENDENCY_STATE", "VERIFY_CONFIGURATION", "VERIFY_GIT_STATE",
    "VERIFY_GITHUB_STATE", "VERIFY_POLICY_INVARIANT",
})


# ── Verification states (lifecycle of one verification run) ─────────


class VerificationState:
    """Explicit verification states. Values persist verbatim.

    Lifecycle:
        PENDING → RUNNING → COMPLETED | FAILED | BLOCKED
        COMPLETED is terminal; the RESULT (PASS/FAIL/...) is a column,
        not a state, so evidence stays queryable without resurrection.
        Terminal states never transition again.
    """

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


ALL_VERIFICATION_STATES = frozenset({
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "BLOCKED",
})

VERIFICATION_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"RUNNING", "FAILED", "BLOCKED"}),
    "RUNNING": frozenset({"COMPLETED", "FAILED", "BLOCKED"}),
    "COMPLETED": frozenset(),
    "FAILED": frozenset(),
    "BLOCKED": frozenset(),
}


class VerificationStateError(ValueError):
    pass


def can_transition_verification(current: str, new: str) -> bool:
    if current not in ALL_VERIFICATION_STATES or new not in ALL_VERIFICATION_STATES:
        return False
    return new in VERIFICATION_TRANSITIONS.get(current, frozenset())


def assert_transition_verification(current: str, new: str) -> None:
    if not can_transition_verification(current, new):
        raise VerificationStateError(
            f"verification state transition {current} -> {new} is not permitted")


def is_terminal_verification(state: str) -> bool:
    if state not in ALL_VERIFICATION_STATES:
        return True  # unknown → fail closed
    return len(VERIFICATION_TRANSITIONS[state]) == 0


# ── Rollback states ──────────────────────────────────────────────────


class RollbackState:
    """Explicit rollback states. Values persist verbatim.

    Lifecycle (deterministic, no shortcuts):
        PENDING → PRECHECK → ROLLING_BACK → VERIFYING → COMPLETED
        Any live state → FAILED (terminal; requires human/operator)
        PENDING/PRECHECK → CONFLICT (terminal; remote moved / stale target)

    COMPLETED is recorded ONLY after the post-rollback verification
    proved the restored state. No success-before-proof, ever.
    """

    PENDING = "PENDING"
    PRECHECK = "PRECHECK"
    ROLLING_BACK = "ROLLING_BACK"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CONFLICT = "CONFLICT"


ALL_ROLLBACK_STATES = frozenset({
    "PENDING", "PRECHECK", "ROLLING_BACK", "VERIFYING",
    "COMPLETED", "FAILED", "CONFLICT",
})

ROLLBACK_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"PRECHECK", "FAILED", "CONFLICT"}),
    "PRECHECK": frozenset({"ROLLING_BACK", "FAILED", "CONFLICT"}),
    "ROLLING_BACK": frozenset({"VERIFYING", "FAILED"}),
    "VERIFYING": frozenset({"COMPLETED", "FAILED"}),
    "COMPLETED": frozenset(),
    "FAILED": frozenset(),
    "CONFLICT": frozenset(),
}


class RollbackStateError(ValueError):
    pass


def can_transition_rollback(current: str, new: str) -> bool:
    if current not in ALL_ROLLBACK_STATES or new not in ALL_ROLLBACK_STATES:
        return False
    return new in ROLLBACK_TRANSITIONS.get(current, frozenset())


def assert_transition_rollback(current: str, new: str) -> None:
    if not can_transition_rollback(current, new):
        raise RollbackStateError(
            f"rollback state transition {current} -> {new} is not permitted")


def is_terminal_rollback(state: str) -> bool:
    if state not in ALL_ROLLBACK_STATES:
        return True  # unknown → fail closed
    return len(ROLLBACK_TRANSITIONS[state]) == 0


# ── Regression classification (fix-one-break-three gate) ─────────────


class FindingOutcome:
    FIXED = "FIXED"
    UNCHANGED = "UNCHANGED"
    NEW = "NEW"
    REGRESSED = "REGRESSED"
    INCONCLUSIVE = "INCONCLUSIVE"


ALL_FINDING_OUTCOMES = frozenset({
    "FIXED", "UNCHANGED", "NEW", "REGRESSED", "INCONCLUSIVE",
})

# New findings at/above this severity block acceptance (Phase 34/35).
REGRESSION_BLOCK_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_at_least(severity: object, floor: str) -> bool:
    return _SEVERITY_ORDER.get(str(severity or "").upper(), -1) >= \
        _SEVERITY_ORDER.get(floor, 99)


# ── Deterministic security regression scanner (static, bounded) ──────
# Policy-invariant checks over COMMITTED CONTENT (trusted host-side read
# of git objects), never over repository claims. Mirrors the intent of
# the V3.1 curl-pipe-shell guard and the V3.5 secret scanner.

_DANGEROUS_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("curl_pipe_shell", re.compile(r"curl[^\n|]*\|\s*(ba)?sh", re.IGNORECASE)),
    ("wget_pipe_shell", re.compile(r"wget[^\n|]*\|\s*(ba)?sh", re.IGNORECASE)),
    ("eval_exec", re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE)),
    ("chmod_777", re.compile(r"chmod\s+(-R\s+)?777\b")),
    ("world_writable_root", re.compile(r"chmod\s+(-R\s+)?[67]66\b")),
    ("privileged_docker", re.compile(r"(?im)^\s*--privileged\b")),
    ("docker_sock_mount", re.compile(r"/var/run/docker\.sock")),
    ("disable_ssl_verify", re.compile(
        r"(?i)(verify\s*=\s*False|CERT_NONE|GIT_SSL_NO_VERIFY\s*=\s*true"
        r"|curl\s+[^|]*-k(ernless)?\s)")),
    ("setuid_root", re.compile(r"(?im)^\s*USER\s+root\s*$")),
    ("disable_firewall", re.compile(
        r"(?i)(ufw\s+disable|iptables\s+-F|firewall.*disable)")),
)


def scan_text_for_dangerous_directives(text: str) -> list[str]:
    """Return the NAMES of dangerous patterns found (never the matches)."""
    if not text:
        return []
    found = []
    for name, pattern in _DANGEROUS_PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


# ── Frozen verification plan (digestable, non-executable) ────────────

PLAN_FIELDS = (
    "plan_version",
    "verification_engine_version",
    "git_remediation_id",
    "execution_run_id",
    "execution_authorization_id",
    "action_digest",
    "repository_id",
    "repo_owner",
    "repo_name",
    "base_commit_sha",
    "target_branch",
    "remediation_branch",
    "committed_sha",
    "authorized_files",
    "operations",
    "check_types",
    "regression_block_severities",
)


@dataclass(frozen=True)
class VerificationPlan:
    """Immutable, typed, bounded, deterministic, digestable.

    Derives the check list from the frozen remediation contract + the
    approved operations. Contains no commands, no URLs, no credentials,
    no repository text.
    """

    plan_version: str
    verification_engine_version: str
    git_remediation_id: str
    execution_run_id: str
    execution_authorization_id: str
    action_digest: str
    repository_id: str
    repo_owner: str
    repo_name: str
    base_commit_sha: str
    target_branch: str
    remediation_branch: str
    committed_sha: str
    authorized_files: tuple = field(default=())
    operations: tuple = field(default=())
    check_types: tuple = field(default=())
    regression_block_severities: tuple = field(default=("HIGH", "CRITICAL"))

    def to_dict(self) -> dict:
        return {
            "plan_version": self.plan_version,
            "verification_engine_version": self.verification_engine_version,
            "git_remediation_id": self.git_remediation_id,
            "execution_run_id": self.execution_run_id,
            "execution_authorization_id": self.execution_authorization_id,
            "action_digest": self.action_digest,
            "repository_id": self.repository_id,
            "repo_owner": self.repo_owner,
            "repo_name": self.repo_name,
            "base_commit_sha": self.base_commit_sha,
            "target_branch": self.target_branch,
            "remediation_branch": self.remediation_branch,
            "committed_sha": self.committed_sha,
            "authorized_files": sorted(self.authorized_files),
            "operations": [
                {k: v for k, v in sorted(op.items())}
                for op in self.operations
            ],
            "check_types": sorted(self.check_types),
            "regression_block_severities": sorted(
                self.regression_block_severities),
        }


def derive_check_types(action_type: str, pushed: bool) -> tuple:
    """Server-derived check plan per action type (Phase 5).

    The original-finding check is ALWAYS present (Phase 7). Git/GitHub
    readback is present only when the remediation actually pushed.
    Unknown action type → no checks → the plan build fails closed.
    """
    if action_type == "DEPENDENCY_UPGRADE":
        checks = [
            VerificationCheckType.VERIFY_DIFF,
            VerificationCheckType.VERIFY_FILE_STATE,
            VerificationCheckType.VERIFY_DEPENDENCY_STATE,
            VerificationCheckType.VERIFY_SECURITY_FINDING,
            VerificationCheckType.VERIFY_POLICY_INVARIANT,
        ]
    elif action_type in ("DOCKERFILE_UPDATE", "CONFIGURATION_UPDATE"):
        checks = [
            VerificationCheckType.VERIFY_DIFF,
            VerificationCheckType.VERIFY_FILE_STATE,
            VerificationCheckType.VERIFY_CONFIGURATION,
            VerificationCheckType.VERIFY_SECURITY_FINDING,
            VerificationCheckType.VERIFY_POLICY_INVARIANT,
        ]
    elif action_type == "DOCUMENTED_SECURITY_FIX":
        checks = [
            VerificationCheckType.VERIFY_DIFF,
            VerificationCheckType.VERIFY_FILE_STATE,
            VerificationCheckType.VERIFY_SECURITY_FINDING,
            VerificationCheckType.VERIFY_POLICY_INVARIANT,
        ]
    else:
        return ()  # unknown action type → fail closed upstream
    if pushed:
        checks.extend([
            VerificationCheckType.VERIFY_GIT_STATE,
            VerificationCheckType.VERIFY_GITHUB_STATE,
        ])
    return tuple(checks)


def compute_plan_digest(plan: VerificationPlan) -> str:
    return hashlib.sha256(generic_canonical_bytes(plan.to_dict())).hexdigest()


def verify_plan_digest(plan: VerificationPlan, expected: str) -> bool:
    if not expected:
        return False
    return compute_plan_digest(plan) == expected


# ── Bounded evidence (repository output is UNTRUSTED DATA) ───────────

MAX_EVIDENCE_TEXT = 2000
MAX_EVIDENCE_ITEMS = 64
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def scrub_evidence_text(text: object, limit: int = MAX_EVIDENCE_TEXT) -> str:
    """Scrub + bound any text that becomes evidence.

    Repository-derived strings are hostile: control characters (ANSI
    escapes, terminal injection) are removed, length is capped, and the
    result is plain data — never rendered as HTML anywhere.
    """
    if not isinstance(text, str):
        text = str(text or "")
    return _CONTROL_CHARS_RE.sub("", text)[:limit]


def build_evidence(
    *, check_type: str, check_version: str, expected: object, observed: object,
    result: str, reason_code: str, extra: Optional[dict] = None,
) -> dict:
    """Structured, bounded evidence for one check (Phase 11).

    expected/observed are serialized to bounded strings; no raw command
    output, no diff dumps, no secret-shaped material is stored verbatim.
    """
    if check_type not in ALL_CHECK_TYPES:
        raise ValueError(f"unknown check type: {check_type!r}")
    if result not in ALL_VERIFICATION_RESULTS:
        raise ValueError(f"unknown verification result: {result!r}")
    evidence = {
        "check_type": check_type,
        "check_version": check_version,
        "expected": scrub_evidence_text(expected),
        "observed": scrub_evidence_text(observed),
        "result": result,
        "reason_code": reason_code,
    }
    if extra:
        bounded = {}
        for k, v in sorted(extra.items())[:MAX_EVIDENCE_ITEMS]:
            bounded[str(k)[:100]] = (
                v if isinstance(v, (int, float, bool)) or v is None
                else scrub_evidence_text(v, 500)
            )
        evidence["extra"] = bounded
    return evidence
