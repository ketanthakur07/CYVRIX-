"""CYVRIX V3.3 — Execution authorization unit tests (pure domain + service).

Covers: state machine (no resurrection, unknown states fail closed),
contract immutability + digest sensitivity (action/repository/branch/
commit/scope/policy/expiry changes all change the digest), reason-code
taxonomy, kill-switch fail-closed read semantics, and the pure time
boundary semantics.

The golden path, attack scenarios, API security, and audit durability are
covered in test_execution_authorization_api.py; genuine concurrency in
test_execution_authorization_races.py.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services import execution_authorization_model as eam  # noqa: E402

NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=timezone.utc)


# ── State machine ────────────────────────────────────────────────────


class TestAuthorizationStateMachine:
    def test_allowed_transitions_from_authorized(self):
        assert eam.can_transition("AUTHORIZED", "CONSUMED")
        assert eam.can_transition("AUTHORIZED", "EXPIRED")
        assert eam.can_transition("AUTHORIZED", "REVOKED")

    @pytest.mark.parametrize("terminal", ["CONSUMED", "EXPIRED", "REVOKED"])
    def test_terminal_states_have_no_outgoing(self, terminal):
        for target in ("AUTHORIZED", "CONSUMED", "EXPIRED", "REVOKED"):
            assert not eam.can_transition(terminal, target), f"{terminal} -> {target}"

    @pytest.mark.parametrize(
        "current,new",
        [
            ("CONSUMED", "AUTHORIZED"),
            ("EXPIRED", "AUTHORIZED"),
            ("REVOKED", "AUTHORIZED"),
            ("AUTHORIZED", "AUTHORIZED"),
            ("AUTHORIZED", "PENDING"),
            ("PENDING", "AUTHORIZED"),
            ("UNKNOWN", "AUTHORIZED"),
            ("AUTHORIZED", "UNKNOWN"),
            ("", "AUTHORIZED"),
        ],
    )
    def test_forbidden_transitions_fail_closed(self, current, new):
        assert not eam.can_transition(current, new)
        with pytest.raises(eam.AuthorizationStateError):
            eam.assert_transition(current, new)

    def test_unknown_state_is_terminal(self):
        assert eam.is_terminal("SOMETHING_ELSE")
        assert eam.is_terminal("CONSUMED")
        assert not eam.is_terminal("AUTHORIZED")

    def test_denied_is_not_a_state(self):
        # Denial creates no record; it is an outcome, never a state.
        assert "DENIED" not in eam.ALL_AUTHORIZATION_STATES


# ── Contract digest sensitivity (§28) ────────────────────────────────


def _contract(**overrides) -> eam.ExecutionAuthorizationContract:
    base = dict(
        contract_version="1",
        authorization_id="11111111-1111-1111-1111-111111111111",
        action_proposal_id="22222222-2222-2222-2222-222222222222",
        approval_id="33333333-3333-3333-3333-333333333333",
        action_digest="a" * 64,
        repository_id="44444444-4444-4444-4444-444444444444",
        base_commit_sha="a" * 40,
        target_branch="cyvrix/fix",
        policy_version="3.1",
        policy_decision="REQUIRE_APPROVAL",
        allowed_files=("package.json",),
        allowed_operations=("UPDATE_DEPENDENCY_VERSION",),
        authorized_at="2026-09-14T12:00:00+00:00",
        expires_at="2026-09-14T13:00:00+00:00",
    )
    base.update(overrides)
    return eam.ExecutionAuthorizationContract(**base)


class TestContractDigest:
    def test_deterministic(self):
        assert eam.compute_contract_digest(_contract()) == \
            eam.compute_contract_digest(_contract())

    def test_file_order_is_irrelevant(self):
        # Files are a set semantically: sorted before serialization.
        a = eam.compute_contract_digest(_contract(allowed_files=("a.json", "b.json")))
        b = eam.compute_contract_digest(_contract(allowed_files=("b.json", "a.json")))
        assert a == b

    def test_operation_order_is_significant(self):
        a = eam.compute_contract_digest(_contract(allowed_operations=("op1", "op2")))
        b = eam.compute_contract_digest(_contract(allowed_operations=("op2", "op1")))
        assert a != b

    @pytest.mark.parametrize(
        "override",
        [
            {"action_digest": "b" * 64},                       # action changed
            {"repository_id": "55555555-5555-5555-5555-555555555555"},  # repo changed
            {"base_commit_sha": "b" * 40},                     # commit changed
            {"target_branch": "cyvrix/other"},                 # branch changed
            {"allowed_files": ("other.json",)},                # scope changed
            {"allowed_files": ("package.json", "extra.json")},  # scope expanded
            {"policy_version": "3.2"},                         # policy changed
            {"policy_decision": "ALLOW"},                      # policy decision changed
            {"expires_at": "2026-09-14T13:00:01+00:00"},       # expiry changed
            {"approval_id": "66666666-6666-6666-6666-666666666666"},  # approval changed
            {"authorization_id": "77777777-7777-7777-7777-777777777777"},
            {"contract_version": "2"},
            {"authorized_at": "2026-09-14T12:00:01+00:00"},
        ],
    )
    def test_any_material_change_changes_digest(self, override):
        assert eam.compute_contract_digest(_contract(**override)) != \
            eam.compute_contract_digest(_contract())

    def test_verify_detects_mismatch(self):
        digest = eam.compute_contract_digest(_contract())
        assert eam.verify_contract_digest(_contract(), digest)
        assert not eam.verify_contract_digest(
            _contract(action_digest="b" * 64), digest
        )
        assert not eam.verify_contract_digest(_contract(), "")
        assert not eam.verify_contract_digest(_contract(), None)

    def test_contract_is_frozen(self):
        c = _contract()
        with pytest.raises(Exception):
            c.action_digest = "b" * 64

    def test_to_dict_roundtrip_keeps_digest(self):
        c = _contract()
        d = c.to_dict()
        rebuilt = eam.ExecutionAuthorizationContract(
            contract_version=d["contract_version"],
            authorization_id=d["authorization_id"],
            action_proposal_id=d["action_proposal_id"],
            approval_id=d["approval_id"],
            action_digest=d["action_digest"],
            repository_id=d["repository_id"],
            base_commit_sha=d["base_commit_sha"],
            target_branch=d["target_branch"],
            policy_version=d["policy_version"],
            policy_decision=d["policy_decision"],
            allowed_files=tuple(d["allowed_files"]),
            allowed_operations=tuple(d["allowed_operations"]),
            authorized_at=d["authorized_at"],
            expires_at=d["expires_at"],
        )
        assert eam.compute_contract_digest(rebuilt) == eam.compute_contract_digest(c)


# ── Reason codes (stable taxonomy, §32) ──────────────────────────────


class TestReasonCodes:
    def test_required_codes_exist_and_are_distinct(self):
        codes = [
            eam.RC_AUTHORIZATION_NOT_FOUND, eam.RC_ACTION_NOT_FOUND,
            eam.RC_APPROVAL_NOT_FOUND, eam.RC_APPROVAL_INVALID,
            eam.RC_APPROVAL_EXPIRED, eam.RC_APPROVAL_REVOKED,
            eam.RC_APPROVAL_CONSUMED, eam.RC_ACTION_EXPIRED, eam.RC_ACTION_STALE,
            eam.RC_ACTION_DIGEST_MISMATCH, eam.RC_APPROVAL_DIGEST_MISMATCH,
            eam.RC_POLICY_DENIED, eam.RC_POLICY_VERSION_STALE,
            eam.RC_RISK_CHANGED, eam.RC_RECOMMENDATION_CHANGED,
            eam.RC_AUTHORIZATION_REPLAY, eam.RC_KILL_SWITCH_ACTIVE,
            eam.RC_UNAUTHORIZED_CONSUMER, eam.RC_CONTRACT_INVALID,
            eam.RC_CONTRACT_DIGEST_MISMATCH, eam.RC_NOT_AUTHORIZED,
            eam.RC_TOKEN_INVALID, eam.RC_TOKEN_REPLAY,
        ]
        assert len(codes) == len(set(codes))
        assert all(isinstance(c, str) and c for c in codes)


# ── Time security (§41/§42) ──────────────────────────────────────────


class TestTimeSemantics:
    def test_naive_timestamps_treated_as_utc(self):
        naive = datetime(2026, 9, 14, 13, 0, 0)  # no tzinfo
        now = datetime(2026, 9, 14, 12, 59, 59, tzinfo=timezone.utc)
        assert not eam.is_expired(naive, now)
        assert eam.is_expired(naive, now + timedelta(seconds=2))

    def test_expiry_boundary_is_inclusive(self):
        exp = NOW + timedelta(hours=1)
        # Exactly at expiry: expired (now >= expires_at)
        assert eam.is_expired(exp, exp)
        # One second before: not expired
        assert not eam.is_expired(exp, exp - timedelta(seconds=1))

    def test_missing_expiry_fails_closed(self):
        assert eam.is_expired(None, NOW)

    def test_authorization_window_is_the_approval_window(self):
        # No independent TTL: same predicate, same boundary.
        exp = NOW + timedelta(minutes=42)
        assert eam.authorization_window_expired(exp, NOW) is False
        assert eam.authorization_window_expired(exp, exp) is True
        assert eam.authorization_window_expired(None, NOW) is True


# ── Kill-switch read semantics (§22, fail closed) ────────────────────


class TestKillSwitchRead:
    @pytest.mark.asyncio
    async def test_missing_row_fails_closed(self, session_factory):
        from app.services import execution_authorization_service as svc

        async with session_factory() as db:
            disabled, reason = await svc.read_kill_switch(db)
        assert disabled is True
        assert reason == "KILL_SWITCH_UNPROVISIONED"

    @pytest.mark.asyncio
    async def test_false_means_enabled(self, session_factory):
        from app.models import SystemControl
        from app.services import execution_authorization_service as svc

        async with session_factory() as session:
            session.add(SystemControl(key="execution_disabled", value="false"))
            await session.commit()

        async with session_factory() as db:
            disabled, reason = await svc.read_kill_switch(db)
        assert disabled is False
        assert reason is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "", "off", " false"])
    async def test_any_non_false_value_is_disabled(self, session_factory, value):
        from app.models import SystemControl
        from app.services import execution_authorization_service as svc

        async with session_factory() as session:
            session.add(SystemControl(key="execution_disabled", value=value))
            await session.commit()

        async with session_factory() as db:
            disabled, reason = await svc.read_kill_switch(db)
        assert disabled is True

    @pytest.mark.asyncio
    async def test_read_error_fails_closed(self, session_factory, monkeypatch):
        from app.services import execution_authorization_service as svc

        class ExplodingSession:
            async def execute(self, *_a, **_k):
                raise RuntimeError("db down")

        disabled, reason = await svc.read_kill_switch(ExplodingSession())
        assert disabled is True
        assert reason and reason.startswith("KILL_SWITCH_READ_FAILED")
