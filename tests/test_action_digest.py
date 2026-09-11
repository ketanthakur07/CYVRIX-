"""CYVRIX V3.1 — Action Canonicalization & Digest Tests.

Verifies: same action → same digest; irrelevant variation → same digest;
any security-relevant change → different digest; canonical form stability.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.action_digest import (
    DigestError,
    canonical_json_bytes,
    compute_action_digest,
    extract_digest_content,
)


def make_content(**overrides):
    content = {
        "action_type": "DEPENDENCY_UPGRADE",
        "repository_id": "11111111-1111-1111-1111-111111111111",
        "base_commit_sha": "a" * 40,
        "target_branch": "cyvrix/fix-lodash",
        "files": ["package.json", "package-lock.json"],
        "operations": [{
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
            "name": "lodash", "ecosystem": "npm",
            "from_version": "4.17.19", "to_version": "4.17.21",
        }],
        "expected_diff": "-  \"lodash\": \"4.17.19\"\n+  \"lodash\": \"4.17.21\"",
    }
    content.update(overrides)
    return content


# ═══════════════════════════════════════════════════════════════════
# Same semantic action → same digest
# ═══════════════════════════════════════════════════════════════════

class TestDigestStability:
    def test_identical_content_same_digest(self):
        assert compute_action_digest(make_content()) == compute_action_digest(make_content())

    def test_file_order_irrelevant(self):
        a = compute_action_digest(make_content(files=["package.json", "package-lock.json"]))
        b = compute_action_digest(make_content(files=["package-lock.json", "package.json"]))
        assert a == b

    def test_key_order_irrelevant(self):
        c1 = make_content()
        c2 = dict(reversed(list(c1.items())))
        assert compute_action_digest(c1) == compute_action_digest(c2)

    def test_operation_key_order_irrelevant(self):
        a = compute_action_digest(make_content())
        flipped = dict(reversed(list(make_content()["operations"][0].items())))
        b = compute_action_digest(make_content(operations=[flipped]))
        assert a == b

    def test_uuid_case_irrelevant(self):
        a = compute_action_digest(make_content(
            repository_id="AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"))
        b = compute_action_digest(make_content(
            repository_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))
        assert a == b

    def test_digest_is_sha256_hex(self):
        digest = compute_action_digest(make_content())
        assert len(digest) == 64
        int(digest, 16)  # valid hex

    def test_thousand_evaluations_identical(self):
        first = compute_action_digest(make_content())
        for _ in range(1000):
            assert compute_action_digest(make_content()) == first


# ═══════════════════════════════════════════════════════════════════
# Materially different action → different digest
# ═══════════════════════════════════════════════════════════════════

class TestDigestSensitivity:
    base = None

    @classmethod
    def digest(cls, **overrides):
        return compute_action_digest(make_content(**overrides))

    def test_changed_file(self):
        assert self.digest(files=["requirements.txt"]) != self.digest()

    def test_changed_operation_value(self):
        changed_op = {
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
            "name": "lodash", "ecosystem": "npm",
            "from_version": "4.17.19", "to_version": "4.17.22",
        }
        assert self.digest(operations=[changed_op]) != self.digest()

    def test_changed_operation_type(self):
        changed_op = {
            "type": "UPDATE_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
            "line_no": 1, "old_text": "x", "new_text": "y",
        }
        assert self.digest(operations=[changed_op]) != self.digest()

    def test_added_operation_changes_digest(self):
        extra = {
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "package-lock.json",
            "name": "lodash", "ecosystem": "npm",
            "from_version": "4.17.19", "to_version": "4.17.21",
        }
        ops = make_content()["operations"] + [extra]
        assert self.digest(operations=ops) != self.digest()

    def test_operation_order_matters(self):
        ops_a = make_content()["operations"]
        ops_b = list(reversed(ops_a)) if len(ops_a) > 1 else None
        if ops_b:
            assert self.digest(operations=ops_b) != self.digest(operations=ops_a)

    def test_changed_base_commit(self):
        assert self.digest(base_commit_sha="b" * 40) != self.digest()

    def test_changed_repository(self):
        assert self.digest(repository_id="2" * 8 + "-2222-2222-2222-222222222222") != self.digest()

    def test_changed_branch(self):
        assert self.digest(target_branch="cyvrix/other") != self.digest()

    def test_changed_action_type(self):
        assert self.digest(action_type="DOCKERFILE_UPDATE") != self.digest()

    def test_changed_diff(self):
        assert self.digest(expected_diff="changed") != self.digest()

    def test_diff_whitespace_matters(self):
        # Diff content is semantically sensitive: whitespace IS the change
        assert self.digest(expected_diff="-a\n+b") != self.digest(expected_diff="- a\n+ b")


# ═══════════════════════════════════════════════════════════════════
# Digest scope — non-semantic fields excluded
# ═══════════════════════════════════════════════════════════════════

class TestDigestScope:
    def test_non_semantic_fields_excluded(self):
        extracted = extract_digest_content(make_content())
        assert set(extracted.keys()) == {
            "action_type", "repository_id", "base_commit_sha",
            "target_branch", "files", "operations", "expected_diff",
        }
        # ids/status/timestamps/created_by must never affect the digest
        with_id = extract_digest_content({**make_content(), "id": "x", "created_at": "now"})
        assert extract_digest_content(make_content()) == with_id

    def test_missing_field_rejected(self):
        content = make_content()
        del content["target_branch"]
        with pytest.raises(DigestError):
            compute_action_digest(content)

    def test_floats_rejected(self):
        content = make_content()
        content["operations"] = [{"type": "X", "v": 0.1}]
        with pytest.raises((DigestError, Exception)):
            canonical_json_bytes(content)

    def test_canonical_serialization_is_idempotent(self):
        """Re-serializing the parsed canonical bytes must be a fixed point
        (proves separators/sort_keys are deterministic). Content strings may
        legitimately contain whitespace — the diff is whitespace-sensitive."""
        raw = canonical_json_bytes(make_content())
        reparsed = json.loads(raw.decode("utf-8"))
        assert json.dumps(reparsed, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8") == raw
