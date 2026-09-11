"""CYVRIX V3.1 — Policy Engine Tests.

Covers: the executable decision table (POL-001..POL-028), deny
precedence, default deny, determinism, expiry, purity, and property
tests proving unsafe inputs can never produce ALLOW.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services import policy_engine as pe
from app.services.action_model import (
    MAX_DIFF_LINES,
    MAX_FILES_PER_PROPOSAL,
    MAX_OPERATIONS_PER_PROPOSAL,
)
from app.services.policy_engine import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    POLICY_VERSION,
    PolicyContext,
    evaluate,
)

NOW = datetime(2026, 9, 7, 12, 0, 0, tzinfo=timezone.utc)
EXPIRES = NOW + timedelta(hours=24)

VALID_OP = {
    "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
    "name": "lodash", "ecosystem": "npm",
    "from_version": "4.17.19", "to_version": "4.17.21",
}


def make_context(**overrides):
    ctx = PolicyContext(
        action_type="DEPENDENCY_UPGRADE",
        repository_active=True,
        environment="production",
        actor_role="owner",
        validation_state="VALIDATED",
        trust_level="SUPPORTED",
        risk_level="MEDIUM",
        risk_score=45,
        finding_status="OPEN",
        kill_switch=False,
        files=("package.json",),
        operations=(VALID_OP,),
        target_branch="cyvrix/fix-lodash",
        base_commit_sha="a" * 40,
        paths_valid=True,
        files_match_type=True,
        operations_valid=True,
        protected_path_categories=(),
        diff_lines=2,
        expires_at=EXPIRES,
    )
    for key, value in overrides.items():
        object.__setattr__(ctx, key, value)
    return ctx


# ═══════════════════════════════════════════════════════════════════
# Decision table
# ═══════════════════════════════════════════════════════════════════

class TestDecisionTable:
    def test_valid_action_requires_approval_medium(self):
        d = evaluate(make_context(), NOW)
        assert d.decision == DECISION_REQUIRE_APPROVAL
        assert d.approval_level == "MEDIUM"
        assert d.policy_version == POLICY_VERSION == "3.1"
        assert d.reason_code == "MEDIUM_RISK_REQUIRES_APPROVAL"
        assert d.matched_rule == "POL-027"
        assert d.action_type == "DEPENDENCY_UPGRADE"
        assert d.risk_level == "MEDIUM"
        assert d.evaluated_at == NOW

    def test_rule_table_covers_every_allowlisted_action_type(self):
        """Completeness: every allowlisted type is covered by a rule, so the
        POL-028 default-deny fallthrough is pure defense in depth."""
        from app.services.action_model import ActionType
        covered = {"DEPENDENCY_UPGRADE", "DOCKERFILE_UPDATE", "CONFIGURATION_UPDATE"}
        # POL-027 standard rule + POL-026 documented fix + POL-001 unknown
        ctx = make_context(action_type="DOCUMENTED_SECURITY_FIX", files=("SECURITY.md",),
                           operations=({"type": "REPLACE_TEXT", "file": "SECURITY.md",
                                        "old_text": "a", "new_text": "b"},))
        assert evaluate(ctx, NOW).matched_rule == "POL-026"
        for at in covered:
            assert evaluate(make_context(action_type=at), NOW).matched_rule == "POL-027"
        assert set(ActionType.__members__) == covered | {"DOCUMENTED_SECURITY_FIX"}

    def test_structurally_valid_context_never_defaults(self):
        d = evaluate(make_context(), NOW)
        assert d.matched_rule != "POL-028"

    @pytest.mark.parametrize("action_type", [None, "", "SHELL_COMMAND", "FILE_EDIT", "run_script"])
    def test_unknown_action_type_denied(self, action_type):
        d = evaluate(make_context(action_type=action_type), NOW)
        assert d.decision == DECISION_DENY
        assert d.reason_code == "UNKNOWN_ACTION_TYPE"
        assert d.matched_rule == "POL-001"

    def test_repository_inactive_denied(self):
        d = evaluate(make_context(repository_active=False), NOW)
        assert (d.decision, d.reason_code, d.matched_rule) == (
            DECISION_DENY, "REPOSITORY_INACTIVE", "POL-002")

    def test_unsafe_recommendation_denied(self):
        d = evaluate(make_context(validation_state="UNSAFE"), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "UNSAFE_RECOMMENDATION")

    def test_unvalidated_recommendation_denied(self):
        d = evaluate(make_context(validation_state="UNVERIFIED"), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "UNVALIDATED_RECOMMENDATION")

    @pytest.mark.parametrize("state", [None, "", "GARBAGE", "validated"])
    def test_missing_or_unknown_validation_state_denied(self, state):
        d = evaluate(make_context(validation_state=state), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "MISSING_VALIDATION_STATE")

    def test_expired_proposal_denied(self):
        d = evaluate(make_context(expires_at=NOW - timedelta(seconds=1)), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXPIRED_PROPOSAL")

    def test_missing_expiry_denied(self):
        d = evaluate(make_context(expires_at=None), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXPIRED_PROPOSAL")

    def test_boundary_exactly_at_expiry_denied(self):
        d = evaluate(make_context(expires_at=NOW), NOW)
        assert d.decision == DECISION_DENY

    def test_kill_switch_denied(self):
        d = evaluate(make_context(kill_switch=True), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXECUTION_DISABLED")

    def test_invalid_commit_denied(self):
        d = evaluate(make_context(base_commit_sha=""), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "INVALID_COMMIT")

    def test_invalid_branch_denied(self):
        d = evaluate(make_context(target_branch=""), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "INVALID_BRANCH")

    def test_invalid_paths_denied(self):
        d = evaluate(make_context(paths_valid=False), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "INVALID_PATH")

    @pytest.mark.parametrize("cats", [("CI_WORKFLOWS",), ("SECRETS_CONFIG", "CI_WORKFLOWS")])
    def test_protected_path_denied(self, cats):
        d = evaluate(make_context(protected_path_categories=cats), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "PROTECTED_PATH")

    def test_out_of_scope_file_denied(self):
        d = evaluate(make_context(files_match_type=False), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "OUT_OF_SCOPE_FILE")

    def test_invalid_operations_denied(self):
        d = evaluate(make_context(operations_valid=False), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "INVALID_OPERATION")

    def test_no_operations_denied(self):
        d = evaluate(make_context(operations=()), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "INVALID_OPERATION")

    def test_excessive_files_denied(self):
        files = tuple(f"docs/{i}.md" for i in range(MAX_FILES_PER_PROPOSAL + 1))
        d = evaluate(make_context(files=files), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXCESSIVE_FILE_COUNT")

    def test_excessive_operations_denied(self):
        ops = tuple({"type": "UPDATE_DOCKERFILE_INSTRUCTION", "file": "Dockerfile",
                     "line_no": i, "old_text": "x", "new_text": "y"}
                    for i in range(MAX_OPERATIONS_PER_PROPOSAL + 1))
        d = evaluate(make_context(operations=ops), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXCESSIVE_OPERATION_COUNT")

    def test_excessive_diff_denied(self):
        d = evaluate(make_context(diff_lines=MAX_DIFF_LINES + 1), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "EXCESSIVE_DIFF_SIZE")

    def test_missing_risk_denied(self):
        d = evaluate(make_context(risk_level=None, risk_score=None), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "MISSING_RISK_ASSESSMENT")

    @pytest.mark.parametrize("score,level", [(-1, "MEDIUM"), (101, "MEDIUM"), (50, "GARBAGE")])
    def test_malformed_risk_denied(self, score, level):
        d = evaluate(make_context(risk_score=score, risk_level=level), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "MALFORMED_RISK")

    @pytest.mark.parametrize("status", ["RESOLVED", "FALSE_POSITIVE", "", "UNKNOWN"])
    def test_finding_not_actionable_denied(self, status):
        d = evaluate(make_context(finding_status=status), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "FINDING_NOT_ACTIONABLE")

    def test_unknown_environment_denied(self):
        d = evaluate(make_context(environment="dev-prod"), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "UNKNOWN_ENVIRONMENT")

    def test_unknown_role_denied(self):
        d = evaluate(make_context(actor_role="superadmin"), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "UNKNOWN_ROLE")

    def test_unknown_trust_level_denied(self):
        d = evaluate(make_context(trust_level="ABSOLUTELY"), NOW)
        assert (d.decision, d.reason_code) == (DECISION_DENY, "UNKNOWN_TRUST_LEVEL")

    def test_critical_risk_requires_critical_approval(self):
        d = evaluate(make_context(risk_level="CRITICAL", risk_score=95), NOW)
        assert d.decision == DECISION_REQUIRE_APPROVAL
        assert d.approval_level == "CRITICAL"
        assert d.reason_code == "CRITICAL_RISK_REQUIRES_APPROVAL"

    def test_high_risk_requires_high_approval(self):
        d = evaluate(make_context(risk_level="HIGH", risk_score=75), NOW)
        assert d.decision == DECISION_REQUIRE_APPROVAL
        assert d.approval_level == "HIGH"

    def test_major_version_bump_escalates(self):
        op = {**VALID_OP, "from_version": "4.17.19", "to_version": "5.0.0"}
        d = evaluate(make_context(operations=(op,)), NOW)
        assert d.decision == DECISION_REQUIRE_APPROVAL
        assert d.reason_code == "MAJOR_VERSION_REQUIRES_APPROVAL"

    def test_documented_fix_is_low(self):
        d = evaluate(make_context(
            action_type="DOCUMENTED_SECURITY_FIX",
            files=("SECURITY.md",),
            operations=({"type": "REPLACE_TEXT", "file": "SECURITY.md",
                         "old_text": "old", "new_text": "new"},),
            trust_level="UNCERTAIN",
        ), NOW)
        assert d.decision == DECISION_REQUIRE_APPROVAL
        assert d.approval_level == "LOW"


# ═══════════════════════════════════════════════════════════════════
# Deny precedence & determinism
# ═══════════════════════════════════════════════════════════════════

class TestPrecedenceAndDeterminism:
    def test_deny_overrides_require_approval(self):
        # CRITICAL risk (REQUIRE_APPROVAL CRITICAL) + protected path (DENY)
        d = evaluate(make_context(risk_level="CRITICAL", risk_score=95,
                                  protected_path_categories=("CI_WORKFLOWS",)), NOW)
        assert d.decision == DECISION_DENY
        assert d.reason_code == "PROTECTED_PATH"

    def test_deny_tie_break_is_deterministic_lowest_rule(self):
        # POL-002 (inactive) and POL-003 (unsafe) both deny → lowest id wins
        d = evaluate(make_context(repository_active=False, validation_state="UNSAFE"), NOW)
        assert d.matched_rule == "POL-002"

    def test_require_approval_picks_highest_level(self):
        # HIGH risk + major bump → HIGH beats MEDIUM
        op = {**VALID_OP, "to_version": "5.0.0"}
        d = evaluate(make_context(risk_level="HIGH", risk_score=80, operations=(op,)), NOW)
        assert d.approval_level == "HIGH"
        assert d.reason_code == "HIGH_RISK_REQUIRES_APPROVAL"

    def test_determinism_100_evaluations(self):
        decisions = [evaluate(make_context(), NOW) for _ in range(100)]
        assert all(d == decisions[0] for d in decisions)
        # Different clock readings must not change the decision
        d2 = evaluate(make_context(), NOW + timedelta(minutes=5))
        d1 = decisions[0]
        assert (d1.decision, d1.reason_code, d1.matched_rule, d1.policy_version) == \
               (d2.decision, d2.reason_code, d2.matched_rule, d2.policy_version)

    def test_performance_1000_evaluations(self):
        import time
        start = time.perf_counter()
        for _ in range(1000):
            evaluate(make_context(), NOW)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"policy evaluation too slow: {elapsed:.2f}s"


# ═══════════════════════════════════════════════════════════════════
# Property tests: unsafe inputs never become ALLOW
# ═══════════════════════════════════════════════════════════════════

class TestNeverAllowProperties:
    @pytest.mark.parametrize("action_type", [
        "SHELL_COMMAND", "ARBITRARY_FILE_EDIT", "EXECUTE_SCRIPT",
        "RUN_BINARY", "REMOTE_SCRIPT", "GARBAGE", None,
    ])
    def test_unknown_action_types_never_allowed(self, action_type):
        d = evaluate(make_context(action_type=action_type), NOW)
        assert d.decision != DECISION_ALLOW

    @pytest.mark.parametrize("cats", [
        ("CI_WORKFLOWS",), ("AUTHENTICATION",), ("SECRETS_CONFIG",),
        ("POLICY_DEFINITIONS",), ("AUDIT_INTEGRITY",), ("BINARY",),
    ])
    def test_protected_paths_never_allowed(self, cats):
        d = evaluate(make_context(protected_path_categories=cats), NOW)
        assert d.decision == DECISION_DENY

    @pytest.mark.parametrize("state", ["UNSAFE", "UNVERIFIED", None, "GARBAGE"])
    def test_unsafe_or_unvalidated_never_allowed(self, state):
        d = evaluate(make_context(validation_state=state), NOW)
        assert d.decision == DECISION_DENY

    def test_excessive_scope_never_allowed(self):
        files = tuple(f"d/{i}.md" for i in range(MAX_FILES_PER_PROPOSAL + 1))
        d = evaluate(make_context(files=files), NOW)
        assert d.decision == DECISION_DENY

    @pytest.mark.parametrize("field,value", [
        ("risk_score", -5), ("risk_score", 10**9), ("risk_score", True),
        ("diff_lines", -1),
    ])
    def test_garbage_numbers_fail_safe(self, field, value):
        d = evaluate(make_context(**{field: value}), NOW)
        assert d.decision == DECISION_DENY

    def test_v31_never_emits_allow(self):
        """No V3.1 rule may produce ALLOW — approval is always required."""
        contexts = [
            make_context(),
            make_context(action_type="DOCUMENTED_SECURITY_FIX", files=("SECURITY.md",),
                         operations=({"type": "REPLACE_TEXT", "file": "SECURITY.md",
                                      "old_text": "a", "new_text": "b"},)),
            make_context(risk_level="INFO", risk_score=5),
            make_context(risk_level="LOW", risk_score=10),
        ]
        for ctx in contexts:
            assert evaluate(ctx, NOW).decision == DECISION_REQUIRE_APPROVAL


# ═══════════════════════════════════════════════════════════════════
# Purity — policy engine must have zero side-effect capability
# ═══════════════════════════════════════════════════════════════════

class TestPurity:
    FORBIDDEN_MODULES = {
        "subprocess", "socket", "httpx", "requests", "urllib", "redis",
        "sqlalchemy", "asyncpg", "ctypes", "multiprocessing",
    }
    FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "system", "popen", "random"}

    def test_no_side_effect_imports_or_calls(self):
        """AST-level purity: no forbidden imports, no dangerous builtins,
        no clock access, no randomness. Docstrings are irrelevant."""
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(pe))
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
                name = getattr(func, "id", None) or getattr(func, "attr", None)
                assert name not in self.FORBIDDEN_CALLS, name
            if isinstance(node, ast.Attribute) and node.attr in {"now", "utcnow", "random"}:
                owner = getattr(node.value, "id", None)
                assert owner not in {"datetime", "random"}, "clock/random access in policy engine"

    def test_evaluate_has_no_io_side_effects(self):
        import os
        before = set(os.listdir(".")) if os.path.isdir(".") else set()
        for _ in range(10):
            evaluate(make_context(), NOW)
        after = set(os.listdir(".")) if os.path.isdir(".") else set()
        assert before == after
