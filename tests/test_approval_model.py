"""CYVRIX V3.2 — Approval domain model unit tests.

Pure-function tests: state machine, eligibility, tokens, expiry, reasons.
No DB, no network, no clock dependence (explicit `now` everywhere).
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services import approval_model
from app.services.approval_model import (
    APPROVAL_TTL_MINUTES,
    ApprovalState,
    ApprovalStateError,
    MAX_REASON_LENGTH,
    approval_expiry,
    assert_transition,
    can_transition,
    check_approver_eligibility,
    generate_token,
    hash_token,
    is_approval_expired,
    is_step_up_fresh,
    is_terminal,
    validate_reason,
    verify_token_hash,
)

NOW = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)


# ── State machine ────────────────────────────────────────────────────


class TestStateMachine:
    @pytest.mark.parametrize("current,new", [
        ("PENDING", "APPROVED"),
        ("PENDING", "REJECTED"),
        ("APPROVED", "REVOKED"),
        ("APPROVED", "EXPIRED"),
    ])
    def test_allowed_transitions(self, current, new):
        assert can_transition(current, new) is True
        assert_transition(current, new)  # must not raise

    @pytest.mark.parametrize("current,new", [
        ("USED", "APPROVED"),
        ("REJECTED", "APPROVED"),
        ("EXPIRED", "APPROVED"),
        ("REVOKED", "APPROVED"),
        ("APPROVED", "APPROVED"),
        ("APPROVED", "USED"),
        ("PENDING", "USED"),
        ("PENDING", "PENDING"),
        ("REJECTED", "REVOKED"),
        ("REVOKED", "USED"),
        ("EXPIRED", "REVOKED"),
    ])
    def test_forbidden_transitions(self, current, new):
        assert can_transition(current, new) is False
        with pytest.raises(ApprovalStateError):
            assert_transition(current, new)

    def test_unknown_states_fail_closed(self):
        assert can_transition("BOGUS", "APPROVED") is False
        assert can_transition("PENDING", "BOGUS") is False
        assert can_transition("", "") is False
        with pytest.raises(ApprovalStateError):
            assert_transition("BOGUS", "APPROVED")

    def test_terminal_states(self):
        assert is_terminal("USED")
        assert is_terminal("REJECTED")
        assert is_terminal("REVOKED")
        assert is_terminal("EXPIRED")
        assert not is_terminal("PENDING")
        assert not is_terminal("APPROVED")
        # Unknown state treated as terminal (fail closed)
        assert is_terminal("NOT_A_STATE")

    def test_no_path_back_to_approval_from_terminal(self):
        """The defining property: terminal states are dead ends."""
        for terminal in ("USED", "REJECTED", "REVOKED", "EXPIRED"):
            for target in ApprovalState.__dict__.values():
                if isinstance(target, str):
                    assert can_transition(terminal, target) is False


# ── Expiry ───────────────────────────────────────────────────────────


class TestExpiry:
    def test_approval_ttl_is_one_hour(self):
        assert APPROVAL_TTL_MINUTES == 60

    def test_expiry_is_bounded(self):
        exp = approval_expiry(NOW)
        assert exp == NOW + timedelta(minutes=60)

    def test_not_expired_before(self):
        exp = approval_expiry(NOW)
        assert is_approval_expired(exp, NOW) is False
        assert is_approval_expired(exp, NOW + timedelta(minutes=59)) is False

    def test_expired_at_boundary(self):
        exp = approval_expiry(NOW)
        assert is_approval_expired(exp, exp) is True
        assert is_approval_expired(exp, exp + timedelta(seconds=1)) is True

    def test_never_infinite(self):
        exp = approval_expiry(NOW)
        assert exp is not None
        assert exp < NOW + timedelta(days=1)

    def test_naive_datetimes_normalized_to_utc(self):
        naive = datetime(2026, 9, 12, 12, 0, 0)  # no tzinfo
        exp = approval_expiry(naive)
        assert exp.tzinfo is not None

    def test_naive_comparison_safe(self):
        exp_naive = datetime(2026, 9, 12, 13, 0, 0)
        assert is_approval_expired(exp_naive, NOW + timedelta(minutes=61)) is True
        assert is_approval_expired(exp_naive, NOW) is False


# ── Step-up freshness ────────────────────────────────────────────────


class TestStepUpFreshness:
    def test_none_is_never_fresh(self):
        assert is_step_up_fresh(None, NOW) is False

    def test_fresh_within_window(self):
        assert is_step_up_fresh(NOW - timedelta(minutes=5), NOW) is True
        assert is_step_up_fresh(NOW, NOW) is True

    def test_stale_after_window(self):
        stale = NOW - timedelta(minutes=16)
        assert is_step_up_fresh(stale, NOW) is False

    def test_future_timestamp_not_fresh(self):
        """Clock-skewed future marker must not count (negative age)."""
        assert is_step_up_fresh(NOW + timedelta(minutes=5), NOW) is False

    def test_naive_marker_normalized(self):
        naive = datetime(2026, 9, 12, 11, 55, 0)
        assert is_step_up_fresh(naive, NOW) is True


# ── Approver eligibility ─────────────────────────────────────────────


def _elig(**overrides):
    args = dict(
        risk_level="MEDIUM",
        approver_id="user-a",
        proposer_id="user-a",
        second_approver_user_id=None,
        step_up_at=NOW,
        now=NOW,
    )
    args.update(overrides)
    return check_approver_eligibility(**args)


class TestApproverEligibility:
    def test_medium_self_approval_with_step_up(self):
        ok, rc = _elig(risk_level="MEDIUM")
        assert ok is True and rc == "OK"

    def test_low_self_approval_with_step_up(self):
        ok, rc = _elig(risk_level="LOW")
        assert ok is True and rc == "OK"

    def test_no_step_up_denies_low_and_medium(self):
        for rl in ("LOW", "MEDIUM"):
            ok, rc = _elig(risk_level=rl, step_up_at=None)
            assert ok is False and rc == "STEP_UP_REQUIRED"

    def test_stale_step_up_denies(self):
        ok, rc = _elig(risk_level="LOW", step_up_at=NOW - timedelta(minutes=20))
        assert ok is False and rc == "STEP_UP_REQUIRED"

    @pytest.mark.parametrize("rl", ["HIGH", "CRITICAL"])
    def test_second_principal_required_for_high_risk(self, rl):
        ok, rc = _elig(risk_level=rl)  # approver == proposer
        assert ok is False and rc == "SECOND_APPROVER_REQUIRED"

    @pytest.mark.parametrize("rl", ["HIGH", "CRITICAL"])
    def test_second_principal_with_fresh_step_up(self, rl):
        ok, rc = _elig(
            risk_level=rl,
            approver_id="user-b",
            proposer_id="user-a",
            step_up_at=NOW,
            second_step_up_at=NOW,
        )
        assert ok is True and rc == "OK"

    @pytest.mark.parametrize("rl", ["HIGH", "CRITICAL"])
    def test_second_principal_without_own_step_up_denied(self, rl):
        ok, rc = _elig(
            risk_level=rl,
            approver_id="user-b",
            proposer_id="user-a",
            step_up_at=NOW,
            second_step_up_at=None,
        )
        assert ok is False and rc == "STEP_UP_REQUIRED"

    def test_unknown_risk_level_fails_closed(self):
        ok, rc = _elig(risk_level="CATASTROPHIC")
        assert ok is False and rc == "UNKNOWN_RISK_LEVEL"

    def test_none_risk_level_fails_closed(self):
        ok, rc = _elig(risk_level=None)
        assert ok is False and rc == "UNKNOWN_RISK_LEVEL"

    def test_lowercase_risk_normalized(self):
        ok, rc = _elig(risk_level="medium")
        assert ok is True and rc == "OK"


# ── Tokens ───────────────────────────────────────────────────────────


class TestTokens:
    def test_generated_token_has_prefix_and_entropy(self):
        t = generate_token()
        assert t.startswith("cyv1_")
        # 32 bytes urlsafe → 43 chars + prefix
        assert len(t) >= 40

    def test_tokens_are_unique(self):
        tokens = {generate_token() for _ in range(200)}
        assert len(tokens) == 200

    def test_hash_is_stable(self):
        t = generate_token()
        assert hash_token(t) == hash_token(t)

    def test_different_tokens_different_hashes(self):
        h1, h2 = hash_token(generate_token()), hash_token(generate_token())
        assert h1 != h2

    def test_hash_is_hex_sha256_length(self):
        assert len(hash_token(generate_token())) == 64

    def test_verify_roundtrip(self):
        t = generate_token()
        h = hash_token(t)
        assert verify_token_hash(t, h) is True

    def test_verify_rejects_wrong_token(self):
        h = hash_token(generate_token())
        assert verify_token_hash("cyv1_forged", h) is False

    def test_verify_rejects_empty(self):
        h = hash_token(generate_token())
        assert verify_token_hash("", h) is False
        assert verify_token_hash("cyv1_x", "") is False

    def test_plaintext_never_equals_hash(self):
        t = generate_token()
        h = hash_token(t)
        assert t not in h and h not in t

    def test_hash_is_keyed_not_bare_sha256(self):
        """A bare SHA-256 would allow rainbow attacks on a stolen DB dump."""
        import hashlib

        t = generate_token()
        assert hash_token(t) != hashlib.sha256(t.encode()).hexdigest()


# ── Reasons ──────────────────────────────────────────────────────────


class TestReasons:
    def test_none_becomes_empty(self):
        assert validate_reason(None) == ""

    def test_passthrough(self):
        assert validate_reason("looks good to me") == "looks good to me"

    def test_length_bound(self):
        with pytest.raises(ApprovalStateError):
            validate_reason("x" * (MAX_REASON_LENGTH + 1))

    def test_max_length_accepted(self):
        assert validate_reason("x" * MAX_REASON_LENGTH) == "x" * MAX_REASON_LENGTH

    def test_control_characters_rejected(self):
        with pytest.raises(ApprovalStateError):
            validate_reason("ok\x00thanks")
        with pytest.raises(ApprovalStateError):
            validate_reason("line\x01break")

    def test_non_string_rejected(self):
        with pytest.raises(ApprovalStateError):
            validate_reason(42)
        with pytest.raises(ApprovalStateError):
            validate_reason(["why"])

    def test_whitespace_and_unicode_allowed(self):
        assert validate_reason("approved — LGTM 👍") == "approved — LGTM 👍"


# ── Step-up marker validation ────────────────────────────────────────


class TestStepUpMarker:
    def test_valid_epoch_string(self):
        assert approval_model.validate_step_up_marker(str(int(NOW.timestamp())))

    def test_rejects_non_numeric(self):
        assert not approval_model.validate_step_up_marker("yesterday")
        assert not approval_model.validate_step_up_marker("")

    def test_rejects_non_string(self):
        assert not approval_model.validate_step_up_marker(12345)
        assert not approval_model.validate_step_up_marker(None)

    def test_rejects_absurd_values(self):
        assert not approval_model.validate_step_up_marker("0")
        assert not approval_model.validate_step_up_marker("99999999999999")
