"""CYVRIX V3.5 — Git/GitHub remediation domain model.

Pure, side-effect-free primitives for the controlled Git/GitHub
remediation pipeline:
- Remediation states and the canonical state machine
- Stage ceiling semantics (LOCAL_ONLY < COMMIT_ALLOWED < PUSH_ALLOWED <
  PR_ALLOWED) — the authorization's maximum Git/GitHub effect
- The immutable GitRemediationContract + its canonical digest
- Server-derived remediation branch generation + strict branch validation
- Structured, bounded commit message and PR body construction from
  TRUSTED server-side data only
- Secret scanning over content about to be committed/pushed

Security properties (docs/v3-github-remediation.md):
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Unknown states / stages / branches always fail closed
- Branch namespace is server-controlled (cyvrix/remediation/<run-id>);
  clients can never choose a remediation branch
- The contract is FROZEN and digestable; any change to repo identity,
  base SHA, branches, scope, or stage ceiling changes the digest
- Commit/PR text is derived from structured trusted data, bounded, and
  scrubbed of control characters and credential-shaped content
- This module must NEVER import services that perform side effects
"""
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.services.action_digest import generic_canonical_bytes

# ── Contract version ─────────────────────────────────────────────────

CONTRACT_VERSION = "1"

# ── Reason codes (stable, machine-readable) ──────────────────────────

RC_RUN_NOT_FOUND = "RUN_NOT_FOUND"
RC_RUN_NOT_VERIFIED = "RUN_NOT_VERIFIED"
RC_SCOPE_NOT_VERIFIED = "SCOPE_NOT_VERIFIED"
RC_ACTION_DIGEST_MISMATCH = "ACTION_DIGEST_MISMATCH"
RC_CONTRACT_INVALID = "CONTRACT_INVALID"
RC_CONTRACT_DIGEST_MISMATCH = "CONTRACT_DIGEST_MISMATCH"
RC_BASE_COMMIT_MISMATCH = "BASE_COMMIT_MISMATCH"
RC_BRANCH_EXISTS_MISMATCH = "BRANCH_EXISTS_MISMATCH"
RC_BRANCH_INVALID = "BRANCH_INVALID"
RC_REMOTE_MISMATCH = "REMOTE_MISMATCH"
RC_REMOTE_STATE_MISMATCH = "REMOTE_STATE_MISMATCH"
RC_SCOPE_VIOLATION = "ACTION_SCOPE_VIOLATION"
RC_UNEXPECTED_FILE_CHANGE = "UNEXPECTED_FILE_CHANGE"
RC_UNEXPECTED_BINARY = "UNEXPECTED_BINARY"
RC_UNEXPECTED_SYMLINK = "UNEXPECTED_SYMLINK"
RC_UNEXPECTED_PERMISSION = "UNEXPECTED_PERMISSION"
RC_SECRET_DETECTED = "SECRET_DETECTED"
RC_STAGE_EXCEEDED = "STAGE_EXCEEDED"
RC_CREDENTIAL_DENIED = "CREDENTIAL_DENIED"
RC_CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
RC_PUSH_DENIED = "PUSH_DENIED"
RC_PUSH_FAILED = "PUSH_FAILED"
RC_FORCE_PUSH_PROHIBITED = "FORCE_PUSH_PROHIBITED"
RC_DEFAULT_BRANCH_PROHIBITED = "DEFAULT_BRANCH_PROHIBITED"
RC_GIT_UNAVAILABLE = "GIT_UNAVAILABLE"
RC_GIT_OPERATION_FAILED = "GIT_OPERATION_FAILED"
RC_PR_DENIED = "PR_DENIED"
RC_PR_FAILED = "PR_FAILED"
RC_GITHUB_STATE_MISMATCH = "GITHUB_STATE_MISMATCH"
RC_GITHUB_INCONSISTENT = "GITHUB_INCONSISTENT"
RC_KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
RC_AUTHORIZATION_INVALID = "AUTHORIZATION_INVALID"
RC_AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
RC_AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
RC_AUTHORIZATION_CONSUMED = "AUTHORIZATION_CONSUMED"
RC_REMEDIATION_EXISTS = "REMEDIATION_EXISTS"
RC_REPLAY = "REMEDIATION_REPLAY"
RC_REMEDIATION_IN_PROGRESS = "REMEDIATION_IN_PROGRESS"
RC_DIFF_TOO_LARGE = "DIFF_TOO_LARGE"
RC_COMMIT_TOO_LARGE = "COMMIT_TOO_LARGE"
RC_CLEANUP_FAILED = "CLEANUP_FAILED"
RC_OK = "OK"

# ── States ───────────────────────────────────────────────────────────


class GitRemediationState:
    """Explicit remediation states. Values are persisted verbatim.

    Lifecycle:
        PENDING → VERIFYING → COMMITTING → COMMITTED
                → PUSHING → PUSHED → PR_CREATING → PR_CREATED
        Any live state → FAILED (terminal) or STALE (terminal)
        COMMITTED may → INCONSISTENT (push attempted, remote unreadable)
        Terminal states never transition again (no resurrection).

    LOCAL_ONLY ceilings terminate at COMMITTED (commit stays local to the
    ephemeral workspace, which is then destroyed).
    """

    PENDING = "PENDING"
    VERIFYING = "VERIFYING"
    COMMITTING = "COMMITTING"
    COMMITTED = "COMMITTED"
    PUSHING = "PUSHING"
    PUSHED = "PUSHED"
    PR_CREATING = "PR_CREATING"
    PR_CREATED = "PR_CREATED"
    FAILED = "FAILED"
    STALE = "STALE"
    INCONSISTENT = "INCONSISTENT"

ALL_REMEDIATION_STATES = frozenset({
    "PENDING", "VERIFYING", "COMMITTING", "COMMITTED", "PUSHING", "PUSHED",
    "PR_CREATING", "PR_CREATED", "FAILED", "STALE", "INCONSISTENT",
})

# Live states are the ones a unique index must guard (see migration 008)
LIVE_STATES = frozenset({
    "PENDING", "VERIFYING", "COMMITTING", "COMMITTED", "PUSHING", "PUSHED",
    "PR_CREATING",
})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING": frozenset({"VERIFYING", "FAILED", "STALE"}),
    "VERIFYING": frozenset({"COMMITTING", "FAILED", "STALE", "INCONSISTENT"}),
    "COMMITTING": frozenset({"COMMITTED", "FAILED", "STALE", "INCONSISTENT"}),
    "COMMITTED": frozenset({"PUSHING", "FAILED", "INCONSISTENT"}),
    "PUSHING": frozenset({"PUSHED", "FAILED", "INCONSISTENT"}),
    "PUSHED": frozenset({"PR_CREATING", "FAILED"}),
    "PR_CREATING": frozenset({"PR_CREATED", "FAILED", "INCONSISTENT"}),
    "PR_CREATED": frozenset(),
    "FAILED": frozenset(),
    "STALE": frozenset(),
    "INCONSISTENT": frozenset(),
}


class RemediationStateError(ValueError):
    pass


def can_transition(current: str, new: str) -> bool:
    if current not in ALL_REMEDIATION_STATES or new not in ALL_REMEDIATION_STATES:
        return False
    return new in ALLOWED_TRANSITIONS.get(current, frozenset())


def assert_transition(current: str, new: str) -> None:
    if not can_transition(current, new):
        raise RemediationStateError(
            f"remediation state transition {current} -> {new} is not permitted"
        )


def is_terminal(state: str) -> bool:
    if state not in ALL_REMEDIATION_STATES:
        return True  # unknown → fail closed
    return len(ALLOWED_TRANSITIONS[state]) == 0


# ── Stage ceilings (Phase 17: LOCAL ≠ COMMIT ≠ PUSH ≠ PR) ────────────

STAGE_LOCAL_ONLY = "LOCAL_ONLY"
STAGE_COMMIT_ALLOWED = "COMMIT_ALLOWED"
STAGE_PUSH_ALLOWED = "PUSH_ALLOWED"
STAGE_PR_ALLOWED = "PR_ALLOWED"

STAGE_ORDER = {
    STAGE_LOCAL_ONLY: 0,
    STAGE_COMMIT_ALLOWED: 1,
    STAGE_PUSH_ALLOWED: 2,
    STAGE_PR_ALLOWED: 3,
}

ALL_STAGES = frozenset(STAGE_ORDER)


def stage_at_least(ceiling: str, required: str) -> bool:
    """True when the ceiling permits the required stage. Unknown → False."""
    c, r = STAGE_ORDER.get(ceiling), STAGE_ORDER.get(required)
    if c is None or r is None:
        return False
    return c >= r


# ── Remediation contract (frozen, digestable, non-executable) ────────

CONTRACT_FIELDS = (
    "contract_version",
    "git_remediation_id",
    "execution_run_id",
    "execution_authorization_id",
    "action_digest",
    "repository_id",
    "repo_owner",
    "repo_name",
    "installation_id",
    "base_commit_sha",
    "source_branch",
    "target_branch",
    "remediation_branch",
    "authorized_files",
    "stage_ceiling",
)


@dataclass(frozen=True)
class GitRemediationContract:
    """Immutable, typed, bounded, deterministic, digestable.

    Binds the Git/GitHub effect to exactly: this repository identity
    (canonical owner/name + installation), this base SHA, these branches,
    this file scope, this stage ceiling. Contains no commands, no URLs,
    no credentials.
    """

    contract_version: str
    git_remediation_id: str
    execution_run_id: str
    execution_authorization_id: str
    action_digest: str
    repository_id: str
    repo_owner: str
    repo_name: str
    installation_id: int
    base_commit_sha: str
    source_branch: str
    target_branch: str
    remediation_branch: str
    authorized_files: tuple = field(default=())
    stage_ceiling: str = STAGE_COMMIT_ALLOWED

    def to_dict(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "git_remediation_id": self.git_remediation_id,
            "execution_run_id": self.execution_run_id,
            "execution_authorization_id": self.execution_authorization_id,
            "action_digest": self.action_digest,
            "repository_id": self.repository_id,
            "repo_owner": self.repo_owner,
            "repo_name": self.repo_name,
            "installation_id": self.installation_id,
            "base_commit_sha": self.base_commit_sha,
            "source_branch": self.source_branch,
            "target_branch": self.target_branch,
            "remediation_branch": self.remediation_branch,
            "authorized_files": sorted(self.authorized_files),
            "stage_ceiling": self.stage_ceiling,
        }


def compute_contract_digest(contract: GitRemediationContract) -> str:
    return hashlib.sha256(generic_canonical_bytes(contract.to_dict())).hexdigest()


def verify_contract_digest(contract: GitRemediationContract, expected: str) -> bool:
    if not expected:
        return False
    return compute_contract_digest(contract) == expected


# ── Branch validation + server-side generation ───────────────────────

# refs/heads hierarchy we may ever create
_ALLOWED_BRANCH_PREFIX = "cyvrix/remediation/"
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_BRANCH_LEN = 200


def validate_repo_branch_name(raw: object) -> str:
    """Validate a repository branch/ref name (source/target branches).

    Strict ref-format rules (Phase 4). Unknown/ambiguous → deny. The
    REMEDIATION branch is separately generated server-side; this validates
    the proposal's source/target branch names for Git usage.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError("branch must be a non-empty string")
    if len(raw) > _MAX_BRANCH_LEN:
        raise ValueError("branch too long")
    if _CONTROL_CHARS_RE.search(raw) or "\x00" in raw:
        raise ValueError("branch contains control characters")
    # git check-ref-format rules (subset, strict):
    if raw.startswith("/") or raw.endswith("/") or raw.endswith("."):
        raise ValueError("invalid branch boundary")
    if ".." in raw or "@{" in raw or "\\\\" in raw or raw.startswith("-"):
        raise ValueError("invalid branch sequence")
    if any(seg in ("", ".", "..") for seg in raw.split("/")):
        raise ValueError("invalid branch segment")
    for ch in (" ", "~", "^", ":", "?", "*", "[", "<", ">", "|", "\t"):
        if ch in raw:
            raise ValueError(f"branch contains forbidden character {ch!r}")
    if raw.lower() in ("head", "fetch_head", "orig_head", "all"):
        raise ValueError("branch is a reserved ref name")
    # Ref-hierarchy traversal is never a branch: 'refs/...', 'x/refs/y',
    # and any '.git' component (config/hooks theft, ref smuggling) deny.
    segments = raw.split("/")
    if raw.startswith("refs/") or "refs" in segments or raw.endswith("/refs"):
        raise ValueError("branch may not traverse the refs hierarchy")
    for seg in segments:
        if seg.lower().startswith(".git"):
            raise ValueError("branch contains a .git component")
    return raw


def generate_remediation_branch(execution_run_id: str) -> str:
    """Server-derived deterministic remediation branch (Phase 12).

    Namespace is fixed; the run UUID is the only variable part. Clients
    can never choose this branch. The input MUST be a canonical UUID —
    no stripping/sanitizing of arbitrary strings (a non-UUID input is a
    caller bug and fails closed).
    """
    try:
        safe_id = str(uuid.UUID(str(execution_run_id))).replace("-", "")
    except (ValueError, AttributeError, TypeError):
        raise ValueError("cannot derive remediation branch: run id is not a UUID")
    return f"{_ALLOWED_BRANCH_PREFIX}{safe_id}"


def is_remediation_branch(name: str) -> bool:
    return isinstance(name, str) and name.startswith(_ALLOWED_BRANCH_PREFIX)


# ── Commit message (Phase 13: structured, bounded, trusted data) ─────

_MAX_COMMIT_SUBJECT = 100
_MAX_COMMIT_BODY = 1000


def _scrub(text: str) -> str:
    """Remove control characters (commit/PR injection defense)."""
    return _CONTROL_CHARS_RE.sub("", text or "")


def build_commit_message(
    *,
    repo_name: str,
    action_digest: str,
    base_commit_sha: str,
    execution_run_id: str,
    git_remediation_id: str,
    finding_title: str,
) -> str:
    """Deterministic commit message from trusted server-side data only.

    No repository-derived text, no AI text, no client text. Traceable to
    the action/authorization/run. Bounded.
    """
    subject = f"CYVRIX remediation: {(_scrub(finding_title) or 'security fix')[:_MAX_COMMIT_SUBJECT]}"
    body = (
        f"Applied by CYVRIX controlled remediation (V3.5).\n\n"
        f"Repository: {(_scrub(repo_name) or 'unknown')[:100]}\n"
        f"Base commit: {base_commit_sha}\n"
        f"Action digest: {action_digest}\n"
        f"Execution run: {execution_run_id}\n"
        f"Remediation id: {git_remediation_id}\n\n"
        f"This change was proposed by deterministic analysis, approved by a "
        f"human principal, executed in an isolated sandbox, and verified "
        f"against the authorized scope before this commit was created."
    )
    return f"{subject}\n\n{_scrub(body)[:_MAX_COMMIT_BODY + 500]}\n"


# ── PR title/body (Phase 19: trusted data, no repo text, no secrets) ─

_MAX_PR_BODY = 4000


def build_pr_title_and_body(
    *,
    finding_title: str,
    severity: str,
    repo_name: str,
    base_commit_sha: str,
    remediation_branch: str,
    authorized_files: tuple,
    action_digest: str,
    git_remediation_id: str,
    execution_run_id: str,
) -> tuple[str, str]:
    """Deterministic PR title/body from trusted structured data only."""
    title = f"CYVRIX remediation: {(_scrub(finding_title) or 'security fix')[:80]}"
    files = "\n".join(f"- `{f}`" for f in sorted(authorized_files)[:10]) or "- (none)"
    body = (
        f"## Automated security remediation\n\n"
        f"**Finding:** {(_scrub(finding_title) or 'security fix')[:200]}\n"
        f"**Severity:** {(_scrub(severity) or 'UNKNOWN')[:20]}\n\n"
        f"### What changed\n{files}\n\n"
        f"### Provenance\n"
        f"- Proposed from finding analysis; approved by a human principal\n"
        f"- Executed in an isolated sandbox; actual changes verified against "
        f"the authorized scope before commit\n"
        f"- Repository: {(_scrub(repo_name) or 'unknown')[:100]}\n"
        f"- Base commit: `{base_commit_sha}`\n"
        f"- Source branch: `{remediation_branch}`\n"
        f"- Action digest: `{action_digest}`\n"
        f"- Remediation id: `{git_remediation_id}`\n"
        f"- Execution run: `{execution_run_id}`\n\n"
        f"---\n"
        f"Generated by CYVRIX V3.5 controlled remediation. The changed "
        f"files above were the complete authorized scope; the push was "
        f"verified against the authorized base commit."
    )
    return title, _scrub(body)[:_MAX_PR_BODY]


# ── Secret scanning (Phase 16 — prevent obvious credential exposure) ─

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}")),
    ("github_oauth", re.compile(r"gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,}|ghs_[A-Za-z0-9]{36,}")),
    ("github_finegrained", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret", re.compile(r"(?i)aws(.{0,20})?(secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("generic_api_key", re.compile(
        r"(?i)(api[_-]?key|secret|password|passwd|token|credential)"
        r"['\"]?\s*[:=]\s*['\"][^'\"]{16,}['\"]")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("cyvrix_token", re.compile(r"\bcyv1_[A-Za-z0-9_-]{20,}\b")),
)

SECRET_SCAN_MAX_FILE_BYTES = 2 * 1024 * 1024  # mirror workspace per-file cap


def scan_text_for_secrets(text: str) -> list[str]:
    """Return the NAMES of secret patterns found (never the matches)."""
    if not text:
        return []
    found = []
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            found.append(name)
    return found


# ── Time helpers ─────────────────────────────────────────────────────


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
