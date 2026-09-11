"""CYVRIX V3.1 — Action canonicalization and digest.

Implements docs/v3-execution-model.md §3:
- Canonical serialization of the security-relevant action content
- SHA-256 digest binding (approval binding target in V3.2+)

Canonicalization rules:
- UTF-8 JSON, object keys recursively sorted, compact separators
- Strings NFC-normalized
- Files sorted (order is semantically irrelevant)
- Operations keep their order (order affects semantics)
- UUIDs lowercase; enums as their canonical string values
- Timestamps, ids, created_by, status, policy fields are EXCLUDED:
  the digest represents the executable semantics of the action only

Pure module: no I/O, no clock access, no randomness.
"""
import hashlib
import json
import unicodedata
from typing import Any

from app.services.action_model import normalize_and_validate_path

# Fields that constitute the complete executable semantics of an action.
DIGEST_FIELDS = (
    "action_type",
    "repository_id",
    "base_commit_sha",
    "target_branch",
    "files",          # sorted
    "operations",     # order preserved
    "expected_diff",  # content-sensitive: whitespace is significant
)


class DigestError(ValueError):
    """The content cannot be canonicalized into a digest."""


def _canonicalize(value: Any) -> Any:
    """Recursively canonicalize a JSON-like structure."""
    if isinstance(value, dict):
        return {
            _canonicalize_key(str(k)): _canonicalize(v)
            for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        # Floats are not allowed in canonical content: ambiguous
        # serialization. Use strings or ints.
        raise DigestError("float values are not canonicalizable")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    raise DigestError(f"value of type {type(value).__name__} is not canonicalizable")


def _canonicalize_key(key: str) -> str:
    return unicodedata.normalize("NFC", key)


def extract_digest_content(content: dict) -> dict:
    """Extract only the digest-relevant fields from proposal content.

    Raises DigestError when required fields are missing.
    """
    if not isinstance(content, dict):
        raise DigestError("content must be a dict")

    extracted: dict[str, Any] = {}
    for field_name in DIGEST_FIELDS:
        if field_name not in content:
            raise DigestError(f"missing digest field: {field_name}")
        extracted[field_name] = content[field_name]

    extracted["files"] = sorted(extracted["files"])

    for path_field in ("base_commit_sha", "target_branch"):
        # Binding fields are canonical strings, not paths; validate shape
        # conservatively without rejecting valid branch names.
        value = extracted[path_field]
        if not isinstance(value, str) or not value:
            raise DigestError(f"{path_field} must be a non-empty string")

    if extracted["repository_id"] is not None:
        rid = str(extracted["repository_id"]).strip().lower()
        extracted["repository_id"] = rid

    return extracted


def canonical_json_bytes(content: dict) -> bytes:
    """Deterministic serialization of digest-relevant content."""
    extracted = extract_digest_content(content)
    canonical = _canonicalize(extracted)
    return json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_action_digest(content: dict) -> str:
    """SHA-256 hex digest over the canonical action representation.

    Same semantic action → same digest.
    Two materially different actions → different digests.
    """
    return hashlib.sha256(canonical_json_bytes(content)).hexdigest()
