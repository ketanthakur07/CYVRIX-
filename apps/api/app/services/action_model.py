"""CYVRIX V3.1 — Action domain model.

Pure, side-effect-free primitives for ActionProposal construction:
- Action type / operation type / status allowlists
- Path normalization and validation (traversal, absolute, UNC, Unicode)
- Protected-path denylist
- Per-action-type file and operation allowlists
- Scope caps

Security properties:
- No I/O of any kind: no DB, no network, no filesystem, no subprocess
- Unknown action types / operation types are always invalid (default deny)
- Path validation is strict: any ambiguity is rejected, not "fixed"
- This module must NEVER import app services that perform side effects

This module implements the V3.1 scope of docs/v3-action-model.md.
Execution capability is intentionally absent (V3.4+).
"""
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from fnmatch import fnmatch
from typing import Optional

# ── Scope caps (explicit constants — docs/v3-action-policy.md §3, §8) ──

MAX_FILES_PER_PROPOSAL = 10
MAX_OPERATIONS_PER_PROPOSAL = 50
MAX_DIFF_LINES = 500
MAX_DIFF_CHARS = 50_000
MAX_PATH_LENGTH = 1000
MAX_TEXT_LENGTH = 5000
MAX_KEY_LENGTH = 500
MAX_NAME_LENGTH = 200
MAX_VERSION_LENGTH = 100
MAX_RATIONALE_LENGTH = 2000
MAX_BRANCH_LENGTH = 255
DEFAULT_PROPOSAL_TTL_HOURS = 24

# ── Allowlists ────────────────────────────────────────────────────────


class ActionType(str, Enum):
    """Allowlisted action types. Unknown values are always invalid."""

    DEPENDENCY_UPGRADE = "DEPENDENCY_UPGRADE"
    DOCKERFILE_UPDATE = "DOCKERFILE_UPDATE"
    CONFIGURATION_UPDATE = "CONFIGURATION_UPDATE"
    DOCUMENTED_SECURITY_FIX = "DOCUMENTED_SECURITY_FIX"


class OperationType(str, Enum):
    """Allowlisted structured operation types. No command/script types exist."""

    UPDATE_DEPENDENCY_VERSION = "UPDATE_DEPENDENCY_VERSION"
    UPDATE_DOCKERFILE_INSTRUCTION = "UPDATE_DOCKERFILE_INSTRUCTION"
    APPEND_DOCKERFILE_INSTRUCTION = "APPEND_DOCKERFILE_INSTRUCTION"
    REMOVE_DOCKERFILE_INSTRUCTION = "REMOVE_DOCKERFILE_INSTRUCTION"
    UPDATE_CONFIGURATION_VALUE = "UPDATE_CONFIGURATION_VALUE"
    REPLACE_TEXT = "REPLACE_TEXT"


class ProposalStatus(str, Enum):
    """V3.1 statuses. APPROVED/AUTHORIZED/EXECUTING/... arrive in V3.2+."""

    PROPOSED = "PROPOSED"
    POLICY_CHECKED = "POLICY_CHECKED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    STALE = "STALE"


# Operations allowed per action type
OPERATIONS_FOR_ACTION_TYPE: dict[str, set[str]] = {
    ActionType.DEPENDENCY_UPGRADE.value: {
        OperationType.UPDATE_DEPENDENCY_VERSION.value,
    },
    ActionType.DOCKERFILE_UPDATE.value: {
        OperationType.UPDATE_DOCKERFILE_INSTRUCTION.value,
        OperationType.APPEND_DOCKERFILE_INSTRUCTION.value,
        OperationType.REMOVE_DOCKERFILE_INSTRUCTION.value,
    },
    ActionType.CONFIGURATION_UPDATE.value: {
        OperationType.UPDATE_CONFIGURATION_VALUE.value,
    },
    ActionType.DOCUMENTED_SECURITY_FIX.value: {
        OperationType.REPLACE_TEXT.value,
    },
}

# Per-type file basenames (additional evidence-based narrowing may apply)
FILE_BASENAMES_FOR_ACTION_TYPE: dict[str, set[str]] = {
    ActionType.DEPENDENCY_UPGRADE.value: {
        "package.json", "package-lock.json",
        "requirements.txt", "poetry.lock", "pyproject.toml",
    },
    ActionType.DOCKERFILE_UPDATE.value: set(),  # handled by Dockerfile-name rule
    ActionType.CONFIGURATION_UPDATE.value: set(),  # empty by design → all denied
    ActionType.DOCUMENTED_SECURITY_FIX.value: set(),  # handled by .md extension rule
}

# Evidence keys whose values may carry a file path (see docs/v3-action-model.md)
EVIDENCE_PATH_KEYS = {"dockerfile", "file", "manifest_path", "path", "files"}

# ── Errors ────────────────────────────────────────────────────────────


class PathValidationError(ValueError):
    """A proposed file path is unsafe or ambiguous."""


class ProposalValidationError(ValueError):
    """A proposal payload failed schema/scope validation. Carries all errors."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors[:10]))


# ── Path security ─────────────────────────────────────────────────────

_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_VALID_PATH_RE = re.compile(r"^[A-Za-z0-9._/@+\- ]+$")
_GIT_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/\-]+$")
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-+]*$")
_PACKAGE_NAME_RE = re.compile(r"^(@[A-Za-z0-9._\-]+/)?[A-Za-z0-9._\-]+$")


def normalize_and_validate_path(raw: object) -> str:
    """Normalize a repository-relative path and reject anything unsafe.

    Rules (docs/v3-action-policy.md §4):
    - Must be a non-empty string within the length cap
    - NFC Unicode normalization applied; lookalike/mixed forms rejected
    - Absolute POSIX paths, Windows drives, UNC paths rejected
    - Backslash separators rejected (Windows ambiguity)
    - Any ".." segment, "~" prefix, or empty segment rejected
    - Percent-encoding rejected (encoded-traversal ambiguity)
    - Control characters, NUL, and characters outside a conservative
      allowlist rejected
    - The result is a canonical relative POSIX path (no trailing slash,
      no "." components)
    """
    if not isinstance(raw, str) or not raw:
        raise PathValidationError("path must be a non-empty string")

    if len(raw) > MAX_PATH_LENGTH:
        raise PathValidationError("path exceeds maximum length")

    if "\x00" in raw or _CONTROL_CHARS_RE.search(raw):
        raise PathValidationError("path contains control characters")

    # Reject backslashes entirely: avoids Windows separator ambiguity
    if "\\" in raw:
        raise PathValidationError("backslash separators are not allowed")

    if raw.startswith("/") or raw.startswith("//"):
        raise PathValidationError("absolute paths are not allowed")

    if _WINDOWS_DRIVE_RE.match(raw) or raw.startswith("\\\\"):
        raise PathValidationError("windows/UNC paths are not allowed")

    if raw.startswith("~"):
        raise PathValidationError("home-relative paths are not allowed")

    if "%" in raw:
        raise PathValidationError("percent-encoded paths are not allowed")

    # NFC normalize, then reject mixed forms (homoglyph tricks)
    normalized = unicodedata.normalize("NFC", raw)
    if normalized != raw and not normalized.isascii():
        # Non-ASCII path that changed under normalization: ambiguous → reject
        raise PathValidationError("path requires unicode normalization: ambiguous")

    segments = [seg for seg in normalized.split("/")]
    if any(seg == "" for seg in segments[:-1]) or segments[-1] == "":
        raise PathValidationError("empty path segment")

    for seg in segments:
        if seg in (".", ".."):
            raise PathValidationError("path traversal segment")
        if not _VALID_PATH_RE.match(seg):
            raise PathValidationError("path contains disallowed characters")

    return "/".join(segments)


def is_protected_path(path: str) -> Optional[str]:
    """Return the protected-path category if the path matches the denylist.

    Limitation (documented in docs/v3-action-policy.md §4): this is a
    declared-path classifier. Filename matching alone cannot prove what a
    path will resolve to at execution time; the executor (V3.4+) must
    re-resolve real paths inside the sandbox. Policy is authoritative:
    protected paths are denied for every action type.

    Unknown/sensitive-looking paths are handled by per-type allowlists,
    which default to deny (e.g. CONFIGURATION_UPDATE has an empty allowlist).
    """
    protected_rules: list[tuple[str, str]] = [
        # (pattern, category)
        (".github/workflows/*", "CI_WORKFLOWS"),
        (".github/workflows/**", "CI_WORKFLOWS"),
        ("**/Jenkinsfile*", "CI_WORKFLOWS"),
        ("**/.gitlab-ci*", "CI_WORKFLOWS"),
        ("**/.circleci/*", "CI_WORKFLOWS"),
        ("**/auth/**", "AUTHENTICATION"),
        ("**/auth.py", "AUTHENTICATION"),
        ("**/authentication/**", "AUTHENTICATION"),
        ("**/login/**", "AUTHENTICATION"),
        ("**/oauth*", "AUTHENTICATION"),
        ("**/jwt*", "AUTHENTICATION"),
        ("**/session*security*", "AUTHENTICATION"),
        ("**/permissions*", "AUTHORIZATION"),
        ("**/acl*", "AUTHORIZATION"),
        ("**/rbac*", "AUTHORIZATION"),
        ("**/middleware/**", "SECURITY_MIDDLEWARE"),
        ("**/middlewares/**", "SECURITY_MIDDLEWARE"),
        (".env*", "SECRETS_CONFIG"),
        ("**/.env*", "SECRETS_CONFIG"),
        ("**/*.pem", "SECRETS_CONFIG"),
        ("**/*.key", "SECRETS_CONFIG"),
        ("**/*.p12", "SECRETS_CONFIG"),
        ("**/*.pfx", "SECRETS_CONFIG"),
        ("**/secrets*", "SECRETS_CONFIG"),
        ("**/credentials*", "SECRETS_CONFIG"),
        ("**/.npmrc", "SECRETS_CONFIG"),
        ("**/.netrc", "SECRETS_CONFIG"),
        ("**/deploy*", "DEPLOYMENT_CONFIG"),
        ("**/docker-compose*", "DEPLOYMENT_CONFIG"),
        ("**/k8s/**", "DEPLOYMENT_CONFIG"),
        ("**/kubernetes/**", "DEPLOYMENT_CONFIG"),
        ("**/terraform/**", "DEPLOYMENT_CONFIG"),
        ("**/*.tf", "DEPLOYMENT_CONFIG"),
        ("**/.ssh/**", "INFRA_CREDENTIALS"),
        ("**/id_rsa*", "INFRA_CREDENTIALS"),
        ("**/.aws/**", "INFRA_CREDENTIALS"),
        ("**/kube/config*", "INFRA_CREDENTIALS"),
        ("**/policy/**", "POLICY_DEFINITIONS"),
        ("**/policies/**", "POLICY_DEFINITIONS"),
        ("**/audit*", "AUDIT_INTEGRITY"),
        # Executables / binaries / bytecode
        ("**/*.so", "BINARY"),
        ("**/*.dylib", "BINARY"),
        ("**/*.dll", "BINARY"),
        ("**/*.exe", "BINARY"),
        ("**/*.bin", "BINARY"),
        ("**/*.pyc", "BINARY"),
        ("**/*.jar", "BINARY"),
    ]
    # Probe a slash-prefixed variant so top-level protected directories
    # (deploy/, audit/, policy/, .github/, .ssh/, .env*) match **/ patterns.
    probe = "/" + path
    for pattern, category in protected_rules:
        if fnmatch(path, pattern) or fnmatch(probe, pattern):
            return category
    return None


# ── Evidence-based narrowing ──────────────────────────────────────────


def evidence_allowed_paths(evidence: object) -> Optional[set[str]]:
    """Extract validated file paths from finding evidence, if present.

    Returns None when evidence carries no usable path information, in
    which case per-type basename rules apply. When paths ARE present the
    proposal's declared files must be a subset of them (stricter rule).
    """
    if not isinstance(evidence, dict):
        return None

    found: set[str] = set()
    for key in EVIDENCE_PATH_KEYS:
        value = evidence.get(key)
        candidates: list[object] = []
        if isinstance(value, str):
            candidates = [value]
        elif isinstance(value, list):
            candidates = [v for v in value if isinstance(v, str)]

        for raw in candidates:
            try:
                found.add(normalize_and_validate_path(raw))
            except PathValidationError:
                # Evidence paths are advisory narrowing data; a malformed
                # evidence path does not widen the scope — it just
                # contributes nothing.
                continue

    return found or None


def _allowed_by_type_rules(action_type: str, path: str) -> bool:
    """Per-type file rules when evidence narrowing is unavailable."""
    basename = path.rsplit("/", 1)[-1].lower()
    if action_type == ActionType.DOCKERFILE_UPDATE.value:
        return basename == "dockerfile" or basename.endswith(".dockerfile")
    if action_type == ActionType.DOCUMENTED_SECURITY_FIX.value:
        return basename.endswith(".md")
    basenames = FILE_BASENAMES_FOR_ACTION_TYPE.get(action_type, set())
    return basename in basenames


def validate_files_for_action_type(
    action_type: str,
    files: list[str],
    evidence: object,
) -> list[str]:
    """Validate the declared file scope against allowlists + evidence.

    Returns the canonical file list. Raises ProposalValidationError.
    """
    errors: list[str] = []
    if not files:
        errors.append("at least one file is required")
        raise ProposalValidationError(errors)
    if len(files) > MAX_FILES_PER_PROPOSAL:
        raise ProposalValidationError(
            [f"file count {len(files)} exceeds cap {MAX_FILES_PER_PROPOSAL}"]
        )

    canonical: list[str] = []
    for raw in files:
        try:
            canonical.append(normalize_and_validate_path(raw))
        except PathValidationError as e:
            errors.append(f"invalid path {raw!r}: {e}")
    if errors:
        raise ProposalValidationError(errors)

    if len(set(canonical)) != len(canonical):
        raise ProposalValidationError(["duplicate file entries"])

    evidence_paths = evidence_allowed_paths(evidence)
    for path in canonical:
        if is_protected_path(path):
            continue  # protected-path classification is reported separately
        if evidence_paths is not None:
            if path not in evidence_paths:
                errors.append(f"file {path!r} is outside finding evidence scope")
        elif not _allowed_by_type_rules(action_type, path):
            errors.append(f"file {path!r} is not allowed for {action_type}")
    if errors:
        raise ProposalValidationError(errors)

    return canonical


# ── Operation validation ──────────────────────────────────────────────


def _validate_string_field(op: dict, key: str, max_len: int, errors: list[str],
                           required: bool = True, pattern: Optional[re.Pattern] = None,
                           pattern_desc: str = "") -> None:
    value = op.get(key)
    if value is None or value == "":
        if required:
            errors.append(f"{op.get('type', '?')}: missing '{key}'")
        return
    if not isinstance(value, str):
        errors.append(f"{op.get('type', '?')}: '{key}' must be a string")
        return
    if "\x00" in value or _CONTROL_CHARS_RE.search(value):
        errors.append(f"{op.get('type', '?')}: '{key}' contains control characters")
        return
    if len(value) > max_len:
        errors.append(f"{op.get('type', '?')}: '{key}' exceeds {max_len} chars")
        return
    if pattern is not None and not pattern.match(value):
        errors.append(f"{op.get('type', '?')}: '{key}' {pattern_desc or 'has invalid format'}")


def _validate_int_field(op: dict, key: str, minimum: int, maximum: int,
                        errors: list[str]) -> None:
    value = op.get(key)
    if value is None:
        errors.append(f"{op.get('type', '?')}: missing '{key}'")
        return
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{op.get('type', '?')}: '{key}' must be an integer")
        return
    if value < minimum or value > maximum:
        errors.append(f"{op.get('type', '?')}: '{key}' out of range [{minimum}, {maximum}]")


def validate_operation(
    op: object,
    action_type: str,
    canonical_files: list[str],
) -> dict:
    """Validate one structured operation against its type schema.

    Returns the validated operation dict (exact keys only).
    Raises ProposalValidationError on any deviation.
    """
    errors: list[str] = []

    if not isinstance(op, dict):
        raise ProposalValidationError(["operation must be an object"])

    op_type = op.get("type")
    if not isinstance(op_type, str) or op_type not in OperationType.__members__:
        raise ProposalValidationError([f"unknown operation type: {op_type!r}"])

    allowed_ops = OPERATIONS_FOR_ACTION_TYPE.get(action_type, set())
    if op_type not in allowed_ops:
        raise ProposalValidationError(
            [f"operation {op_type} is not allowed for action type {action_type}"]
        )

    # Exact-key enforcement: no arbitrary fields, no command/script bodies
    expected_keys: dict[str, set[str]] = {
        OperationType.UPDATE_DEPENDENCY_VERSION.value: {
            "type", "file", "name", "ecosystem", "from_version", "to_version"},
        OperationType.UPDATE_DOCKERFILE_INSTRUCTION.value: {
            "type", "file", "line_no", "old_text", "new_text"},
        OperationType.APPEND_DOCKERFILE_INSTRUCTION.value: {
            "type", "file", "after_line", "instruction"},
        OperationType.REMOVE_DOCKERFILE_INSTRUCTION.value: {
            "type", "file", "line_no"},
        OperationType.UPDATE_CONFIGURATION_VALUE.value: {
            "type", "file", "key", "value"},
        OperationType.REPLACE_TEXT.value: {
            "type", "file", "old_text", "new_text"},
    }
    actual_keys = set(op.keys())
    if actual_keys != expected_keys[op_type]:
        unknown = actual_keys - expected_keys[op_type]
        missing = expected_keys[op_type] - actual_keys
        if unknown:
            errors.append(f"{op_type}: unknown fields {sorted(unknown)}")
        if missing:
            errors.append(f"{op_type}: missing fields {sorted(missing)}")
        raise ProposalValidationError(errors)

    # file must reference the declared scope
    try:
        file_path = normalize_and_validate_path(op.get("file"))
    except PathValidationError as e:
        raise ProposalValidationError([f"{op_type}: invalid 'file': {e}"])
    if file_path not in canonical_files:
        errors.append(f"{op_type}: 'file' {file_path!r} is not in the declared file scope")
        raise ProposalValidationError(errors)

    if op_type == OperationType.UPDATE_DEPENDENCY_VERSION.value:
        _validate_string_field(op, "name", MAX_NAME_LENGTH, errors,
                               pattern=_PACKAGE_NAME_RE, pattern_desc="is not a valid package name")
        _validate_string_field(op, "ecosystem", 20, errors,
                               pattern=re.compile(r"^(npm|pypi)$"), pattern_desc="must be npm or pypi")
        _validate_string_field(op, "from_version", MAX_VERSION_LENGTH, errors,
                               pattern=_VERSION_RE, pattern_desc="is not a valid version")
        _validate_string_field(op, "to_version", MAX_VERSION_LENGTH, errors,
                               pattern=_VERSION_RE, pattern_desc="is not a valid version")
        if (
            not errors
            and isinstance(op.get("from_version"), str)
            and isinstance(op.get("to_version"), str)
            and op["from_version"] == op["to_version"]
        ):
            errors.append(f"{op_type}: from_version equals to_version")
        # No range specifiers: exact pins only
        for vkey in ("from_version", "to_version"):
            v = op.get(vkey)
            if isinstance(v, str) and any(c in v for c in ("^", "~", "*", ">", "<", "|")):
                errors.append(f"{op_type}: '{vkey}' must be an exact version")

    elif op_type == OperationType.UPDATE_DOCKERFILE_INSTRUCTION.value:
        _validate_int_field(op, "line_no", 1, 100_000, errors)
        _validate_string_field(op, "old_text", MAX_TEXT_LENGTH, errors)
        _validate_string_field(op, "new_text", MAX_TEXT_LENGTH, errors, required=False)
        if isinstance(op.get("new_text"), str):
            lowered = op["new_text"].lower()
            if "curl" in lowered and ("| sh" in lowered or "|sh" in lowered or "| bash" in lowered):
                errors.append(f"{op_type}: new_text contains a curl-pipe-shell pattern")

    elif op_type == OperationType.APPEND_DOCKERFILE_INSTRUCTION.value:
        _validate_int_field(op, "after_line", 0, 100_000, errors)
        _validate_string_field(op, "instruction", MAX_TEXT_LENGTH, errors)
        lowered = str(op.get("instruction", "")).lower()
        if "curl" in lowered and ("| sh" in lowered or "|sh" in lowered or "| bash" in lowered):
            errors.append(f"{op_type}: instruction contains a curl-pipe-shell pattern")

    elif op_type == OperationType.REMOVE_DOCKERFILE_INSTRUCTION.value:
        _validate_int_field(op, "line_no", 1, 100_000, errors)

    elif op_type == OperationType.UPDATE_CONFIGURATION_VALUE.value:
        _validate_string_field(op, "key", MAX_KEY_LENGTH, errors)
        _validate_string_field(op, "value", MAX_TEXT_LENGTH, errors)

    elif op_type == OperationType.REPLACE_TEXT.value:
        _validate_string_field(op, "old_text", MAX_TEXT_LENGTH, errors)
        _validate_string_field(op, "new_text", MAX_TEXT_LENGTH, errors, required=False)

    if errors:
        raise ProposalValidationError(errors)

    return dict(op)


def files_match_action_type(action_type: str, files: list[str], evidence: object) -> bool:
    """Boolean form of validate_files_for_action_type for policy contexts."""
    try:
        validate_files_for_action_type(action_type, files, evidence)
        return True
    except ProposalValidationError:
        return False


def validate_operations(
    operations: object,
    action_type: str,
    canonical_files: list[str],
) -> list[dict]:
    """Validate the full operation list: caps, duplicates, per-op schemas."""
    if not isinstance(operations, list) or not operations:
        raise ProposalValidationError(["at least one operation is required"])
    if len(operations) > MAX_OPERATIONS_PER_PROPOSAL:
        raise ProposalValidationError(
            [f"operation count {len(operations)} exceeds cap {MAX_OPERATIONS_PER_PROPOSAL}"]
        )

    validated: list[dict] = []
    seen: list[str] = []
    for op in operations:
        validated_op = validate_operation(op, action_type, canonical_files)
        # Canonical duplicate detection: identical type+file+semantics
        fingerprint = repr(sorted(validated_op.items(), key=lambda kv: kv[0]))
        if fingerprint in seen:
            raise ProposalValidationError(["duplicate operation"])
        seen.append(fingerprint)
        validated.append(validated_op)

    return validated


# ── Binding / expiry helpers ──────────────────────────────────────────


def validate_base_commit_sha(raw: object) -> str:
    """Require a full lowercase 40-hex git commit SHA (binding to state)."""
    if not isinstance(raw, str) or not _COMMIT_SHA_RE.match(raw):
        raise ProposalValidationError(
            ["base_commit_sha must be a full 40-character lowercase hex SHA"]
        )
    return raw


def validate_target_branch(raw: object) -> str:
    """Validate the target branch name conservatively."""
    if not isinstance(raw, str) or not raw:
        raise ProposalValidationError(["target_branch is required"])
    if len(raw) > MAX_BRANCH_LENGTH:
        raise ProposalValidationError(["target_branch exceeds maximum length"])
    if ".." in raw or raw.startswith("/") or raw.endswith("/") or raw.startswith("-"):
        raise ProposalValidationError(["target_branch has an invalid shape"])
    if not _GIT_BRANCH_RE.match(raw):
        raise ProposalValidationError(["target_branch contains invalid characters"])
    return raw


def validate_rationale(raw: object) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str):
        raise ProposalValidationError(["rationale must be a string"])
    if len(raw) > MAX_RATIONALE_LENGTH:
        raise ProposalValidationError(["rationale exceeds maximum length"])
    if _CONTROL_CHARS_RE.search(raw):
        raise ProposalValidationError(["rationale contains control characters"])
    return raw


def validate_expected_diff(raw: object) -> str:
    if not isinstance(raw, str):
        raise ProposalValidationError(["expected_diff must be a string"])
    if len(raw) > MAX_DIFF_CHARS:
        raise ProposalValidationError(["expected_diff exceeds maximum size"])
    if raw.count("\n") + (1 if raw else 0) > MAX_DIFF_LINES:
        raise ProposalValidationError(["expected_diff exceeds line cap"])
    if "\x00" in raw:
        raise ProposalValidationError(["expected_diff contains NUL characters"])
    return raw


def proposal_expiry(created_at: datetime) -> datetime:
    """Server-derived expiry. Clients cannot set or extend expirations."""
    created = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
    return created + timedelta(hours=DEFAULT_PROPOSAL_TTL_HOURS)


# ── Version semantics ─────────────────────────────────────────────────


def is_major_version_change(from_version: str, to_version: str) -> bool:
    """Best-effort semver-ish comparison. Unknown → True (conservative).

    Used by the policy engine to escalate DEPENDENCY_UPGRADE approval
    requirements for major bumps.
    """
    def leading_numeric(v: str) -> Optional[int]:
        head = re.match(r"^(\d+)", v)
        return int(head.group(1)) if head else None

    a, b = leading_numeric(from_version), leading_numeric(to_version)
    if a is None or b is None:
        return True  # unparseable → treat as major (stricter approval)
    return a != b


# ── Whole-proposal validation ─────────────────────────────────────────


@dataclass
class ValidatedProposalContent:
    """Validated, security-relevant proposal content (pre-persistence)."""

    action_type: str
    files: list[str] = field(default_factory=list)
    operations: list[dict] = field(default_factory=list)
    expected_diff: str = ""
    target_branch: str = ""
    base_commit_sha: str = ""
    rationale: str = ""


def validate_proposal_content(payload: dict) -> ValidatedProposalContent:
    """Validate a full proposal payload. Raises ProposalValidationError.

    Accepts only exact top-level keys; everything is bounded; paths are
    canonicalized; operations are schema-checked. No side effects.
    """
    if not isinstance(payload, dict):
        raise ProposalValidationError(["payload must be an object"])

    allowed_keys = {
        "action_type", "files", "operations", "expected_diff",
        "target_branch", "base_commit_sha", "rationale",
    }
    unknown = set(payload.keys()) - allowed_keys
    if unknown:
        raise ProposalValidationError([f"unknown fields: {sorted(unknown)}"])

    errors: list[str] = []

    action_type = payload.get("action_type")
    if not isinstance(action_type, str) or action_type not in ActionType.__members__:
        raise ProposalValidationError([f"unknown action_type: {action_type!r}"])

    files = payload.get("files")
    if not isinstance(files, list):
        raise ProposalValidationError(["files must be a list"])

    operations = payload.get("operations")
    if not isinstance(operations, list):
        raise ProposalValidationError(["operations must be a list"])

    try:
        base_commit_sha = validate_base_commit_sha(payload.get("base_commit_sha"))
    except ProposalValidationError as e:
        errors.extend(e.errors)
        base_commit_sha = ""

    try:
        target_branch = validate_target_branch(payload.get("target_branch"))
    except ProposalValidationError as e:
        errors.extend(e.errors)
        target_branch = ""

    try:
        rationale = validate_rationale(payload.get("rationale"))
    except ProposalValidationError as e:
        errors.extend(e.errors)
        rationale = ""

    try:
        expected_diff = validate_expected_diff(payload.get("expected_diff"))
    except ProposalValidationError as e:
        errors.extend(e.errors)
        expected_diff = ""

    if errors:
        raise ProposalValidationError(errors)

    canonical_files = validate_files_for_action_type(action_type, files, None)
    validated_ops = validate_operations(operations, action_type, canonical_files)

    return ValidatedProposalContent(
        action_type=action_type,
        files=canonical_files,
        operations=validated_ops,
        expected_diff=expected_diff,
        target_branch=target_branch,
        base_commit_sha=base_commit_sha,
        rationale=rationale,
    )
