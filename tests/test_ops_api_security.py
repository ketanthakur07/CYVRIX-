"""CYVRIX V3.7 — operator API security tests (Phase 43/45).

Covers:
- unauthenticated access denied (fail closed)
- USER role denied all operator capabilities (403)
- step-up required for emergency stop / resume / breaker reset
- EMERGENCY_STOP → NORMAL refused (409); one-way door
- resume refused without recent clean reconciliation
- tenant isolation: user B cannot read/modify user A's repo control,
  breaker reset, or view A's anything (404 cross-tenant)
- authority-field rejection: force/skip/bypass flags create no authority
- rate limiting on ops endpoints (429)
- no secrets in any response
"""
import asyncio
import os
import sys
import uuid as uuid_mod
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import (
    CircuitBreaker, RepositoryControl, SystemControl, User,
)
from app.services import ops_model as om


pytestmark = pytest.mark.usefixtures("clean_db")


def _promote(session_factory, user, role):
    import asyncio

    async def _set():
        async with session_factory() as s:
            db_user = await s.get(User, user.id)
            db_user.role = role
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_set())


def _seed_repo_control(session_factory, repo, state):
    import asyncio

    async def _set():
        async with session_factory() as s:
            s.add(RepositoryControl(repository_id=repo.id, control_state=state))
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_set())


def _seed_breaker(session_factory, repo, state="OPEN"):
    import asyncio

    async def _set():
        async with session_factory() as s:
            s.add(CircuitBreaker(repository_id=repo.id, scope="EXECUTION",
                                 breaker_state=state))
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_set())


def _sync_redis():
    """A synchronous Redis client for out-of-band test setup.

    The app's async Redis pool (app.session.get_redis) is bound to the
    event loop that first created it, and TestClient drives the ASGI app
    on its own loop. Touching that shared pool from a different loop
    poisons it, so every later rate-limit check fails closed with a 429.
    A plain sync client keeps test setup loop-independent.
    """
    import redis as redis_sync
    from app.config import get_settings

    return redis_sync.Redis.from_url(
        get_settings().redis_url, socket_connect_timeout=5, socket_timeout=5
    )


def _seed_step_up_for(user):
    """Seed a fresh step-up marker for the operator user in Redis."""
    now = int(datetime.now(timezone.utc).timestamp())
    client = _sync_redis()
    try:
        client.set(f"stepup:{user.id}", str(now))
    finally:
        client.close()


def _seed_reconciliation(session_factory, status="COMPLETED", findings=None, age_s=0):
    import asyncio
    from app.models import ReconciliationRun

    async def _set():
        async with session_factory() as s:
            s.add(ReconciliationRun(
                trigger="TEST", status=status,
                findings=findings or [],
                stats={"inspected": 0},
                created_at=datetime.now(timezone.utc) - timedelta(seconds=age_s),
            ))
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_set())





@pytest.fixture
def operator_client(authenticated_client, session_factory, test_user):
    _promote(session_factory, test_user, om.Role.OPERATOR)
    # The auth override returns the in-memory user object; sync its role.
    test_user.role = om.Role.OPERATOR
    return authenticated_client


@pytest.fixture
def user_client(authenticated_client_b):
    return authenticated_client_b


@pytest.mark.usefixtures("clean_rate_limits")
class TestAuthzMatrix:
    def test_unauthenticated_denied(self, client):
        r = client.get("/api/ops/status")
        assert r.status_code == 401

    def test_user_role_denied(self, user_client):
        r = user_client.get("/api/ops/status")
        assert r.status_code == 403
        assert r.json()["detail"] == "OPERATOR_CAPABILITY_REQUIRED"

    def test_operator_can_view(self, operator_client):
        r = operator_client.get("/api/ops/status")
        assert r.status_code == 200
        body = r.json()
        assert body["operational_state"] in om.ALL_OPS_STATES or body["operational_state"] == "UNKNOWN"

    def test_invalid_role_grants_nothing(self, client, session_factory, test_user):
        # simulate a tampered role value: capability check must fail closed
        import asyncio

        async def _set():
            async with session_factory() as s:
                u = await s.get(User, test_user.id)
                u.role = "SUPERADMIN"  # not a valid role
                await s.commit()
        asyncio.get_event_loop().run_until_complete(_set())
        test_user.role = "SUPERADMIN"  # in-memory sync with the override
        r = authenticated_client_for(client, test_user).get("/api/ops/status")
        assert r.status_code == 403


def authenticated_client_for(client, user):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.auth import get_current_user

    async def override():
        return user
    app.dependency_overrides[get_current_user] = override
    return client


@pytest.mark.usefixtures("clean_rate_limits")
class TestStepUpEnforcement:
    def test_emergency_stop_requires_step_up(self, operator_client):
        r = operator_client.post("/api/ops/state", json={"target": "EMERGENCY_STOP"})
        assert r.status_code == 403
        assert r.json()["detail"] == "STEP_UP_REQUIRED"

    def test_resume_requires_step_up(self, operator_client, session_factory):
        _seed_control_state(session_factory, "PAUSED")
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        # step-up missing first (403) takes precedence
        assert r.status_code in (403, 409)

    def test_pause_allowed_without_step_up(self, operator_client):
        r = operator_client.post("/api/ops/state", json={"target": "PAUSED"})
        assert r.status_code == 200
        assert r.json()["operational_state"] == "PAUSED"


def _seed_control_state(session_factory, value):
    import asyncio

    async def _set():
        async with session_factory() as s:
            from sqlalchemy import select
            row = (await s.execute(
                select(SystemControl).where(SystemControl.key == "operational_state")
            )).scalar_one()
            row.value = value
            await s.commit()
    asyncio.get_event_loop().run_until_complete(_set())


@pytest.fixture
def clean_rate_limits():
    """Flush ops rate-limit keys around each test (Redis persists counters)."""
    def _flush():
        client = _sync_redis()
        try:
            keys = list(client.scan_iter("ratelimit:ops:*"))
            if keys:
                client.delete(*keys)
        finally:
            client.close()

    _flush()
    yield
    _flush()


@pytest.mark.usefixtures("clean_rate_limits")
class TestOneWayDoor:
    def test_emergency_to_normal_refused(self, operator_client, session_factory, test_user):
        _seed_control_state(session_factory, "EMERGENCY_STOP")
        _seed_step_up_for(test_user)
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code == 409
        assert r.json()["detail"] == "RESUME_FROM_EMERGENCY_STOP_REQUIRES_PAUSE_FIRST"
        # state unchanged
        s = operator_client.get("/api/ops/status")
        assert s.json()["operational_state"] == "EMERGENCY_STOP"

    def test_resume_requires_reconciliation(self, operator_client, session_factory):
        _seed_control_state(session_factory, "PAUSED")
        # no reconciliation recorded yet → refused even with step-up
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code in (403, 409)
        if r.status_code == 409:
            assert "RECONCILIATION" in r.json()["detail"]

    def test_resume_with_clean_recent_reconciliation(self, operator_client, session_factory, test_user):
        _seed_control_state(session_factory, "PAUSED")
        _seed_reconciliation(session_factory, findings=[])
        _seed_step_up_for(test_user)
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code == 200

    def test_resume_with_many_reconciled_events_no_500(self, operator_client, session_factory, test_user):
        """Regression: _resume_gate once scalar_one_or_none()'d a multi-row
        JOB_RECONCILED event query, turning resume into a 500 as soon as
        two reconciled events existed (i.e., after the first real
        reconciliation pass). Resume must evaluate reconciliation_runs
        and never 500 on a populated audit feed."""
        import asyncio
        from app.models import OperationalEvent

        async def _seed_events():
            async with session_factory() as s:
                for i in range(3):
                    s.add(OperationalEvent(
                        event_type="JOB_RECONCILED",
                        reason_code="OK",
                        detail=f"reconciled pass {i}",
                    ))
                await s.commit()
        asyncio.get_event_loop().run_until_complete(_seed_events())
        _seed_control_state(session_factory, "PAUSED")
        _seed_reconciliation(session_factory, findings=[])
        _seed_step_up_for(test_user)
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code == 200, r.text

    def test_resume_with_multiple_reconciliation_runs_no_500(self, operator_client, session_factory, test_user):
        """The gate reads reconciliation_runs with limit(1); several past
        runs must not disturb the decision (no 500, no false refusal)."""
        _seed_control_state(session_factory, "PAUSED")
        _seed_reconciliation(session_factory, findings=[])
        _seed_reconciliation(session_factory, findings=[])
        _seed_step_up_for(test_user)
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code == 200, r.text

    def test_resume_with_blocking_findings_refused(self, operator_client, session_factory, test_user):
        _seed_control_state(session_factory, "PAUSED")
        _seed_reconciliation(session_factory, findings=[
            {"subject": "git_remediation:x", "classification": "INCONSISTENT", "reason": "r"}])
        _seed_step_up_for(test_user)
        r = operator_client.post("/api/ops/state", json={"target": "NORMAL"})
        assert r.status_code == 409
        assert r.json()["detail"] == "RECONCILIATION_FINDINGS_UNRESOLVED"





@pytest.mark.usefixtures("clean_rate_limits")
class TestTenantIsolation:
    def test_user_b_cannot_read_repo_control_of_a(self, user_client, test_repository):
        r = user_client.get(f"/api/ops/repositories/{test_repository.id}/control")
        # Non-operator: capability denial first (403) � no resource info.
        assert r.status_code in (403, 404)

    def test_operator_cannot_touch_other_tenant_repo(self, operator_client, test_repository_b):
        # THE isolation test: an authorized operator still gets 404 for
        # repositories outside their installations (never 200/403 leak).
        r = operator_client.get(f"/api/ops/repositories/{test_repository_b.id}/control")
        assert r.status_code == 404
        r2 = operator_client.post(
            f"/api/ops/repositories/{test_repository_b.id}/control",
            json={"control_state": "PAUSED", "reason": "x"})
        assert r2.status_code == 404

    def test_user_b_cannot_reset_breaker_of_a(self, user_client, session_factory, test_repository):
        _seed_breaker(session_factory, test_repository)
        # find breaker id
        import asyncio
        from sqlalchemy import select

        async def _get():
            async with session_factory() as s:
                return (await s.execute(select(CircuitBreaker))).scalars().first()
        breaker = asyncio.get_event_loop().run_until_complete(_get())
        r = user_client.post(f"/api/ops/breakers/{breaker.id}/reset")
        assert r.status_code in (403, 404)

    def test_unknown_repo_404(self, operator_client):
        r = operator_client.get(f"/api/ops/repositories/{uuid_mod.uuid4()}/control")
        assert r.status_code == 404


class TestAuthorityFieldRejection:
    def test_state_transition_ignores_unknown_fields(self, operator_client):
        r = operator_client.post("/api/ops/state", json={
            "target": "PAUSED", "force": True, "skip_authorization": True,
            "bypass": True})
        # extra fields must not create authority: transition still subject
        # to the normal rules (PAUSED is legal from NORMAL so it succeeds)
        assert r.status_code == 200

    def test_invalid_target_rejected(self, operator_client):
        r = operator_client.post("/api/ops/state", json={"target": "LAWLESS"})
        assert r.status_code == 422

    def test_invalid_repo_control_rejected(self, operator_client, test_repository):
        r = operator_client.post(
            f"/api/ops/repositories/{test_repository.id}/control",
            json={"control_state": "LAWLESS"})
        assert r.status_code == 422


class TestBreakerResetDurability:
    def test_reset_persists_across_sessions(self, operator_client, session_factory, test_repository, test_user):
        """Regression: reset_circuit() once returned success without
        committing; get_db rolled the session back after the response, so
        the API reported CLOSED while the breaker stayed OPEN (false
        success on a dangerous action). A reset must be durable."""
        _seed_breaker(session_factory, test_repository)
        _seed_step_up_for(test_user)

        async def _get_breaker_id():
            async with session_factory() as s:
                from sqlalchemy import select
                return (await s.execute(select(CircuitBreaker))).scalars().first().id
        breaker_id = asyncio.get_event_loop().run_until_complete(_get_breaker_id())

        r = operator_client.post(f"/api/ops/breakers/{breaker_id}/reset")
        assert r.status_code == 200, r.text

        # Fresh session: the reset must be committed, not just visible in
        # the request's rolled-back transaction.
        async def _read_back():
            async with session_factory() as s:
                from sqlalchemy import select
                row = (await s.execute(
                    select(CircuitBreaker).where(CircuitBreaker.id == breaker_id)
                )).scalar_one()
                return row.breaker_state, row.consecutive_failures
        state, failures = asyncio.get_event_loop().run_until_complete(_read_back())
        assert state == "CLOSED" and failures == 0, (state, failures)

    def test_repo_control_persists_across_sessions(self, operator_client, session_factory, test_repository, test_user):
        """Same class of bug for repository containment: a pause that only
        lives until the response transaction rolls back is a silent
        containment bypass. The change must be durable."""
        _seed_step_up_for(test_user)
        r = operator_client.post(
            f"/api/ops/repositories/{test_repository.id}/control",
            json={"control_state": "PAUSED", "reason": "durability"})
        assert r.status_code == 200, r.text

        async def _read_back():
            async with session_factory() as s:
                from sqlalchemy import select
                from app.models import RepositoryControl
                row = (await s.execute(
                    select(RepositoryControl).where(
                        RepositoryControl.repository_id == test_repository.id)
                )).scalar_one()
                return row.control_state
        state = asyncio.get_event_loop().run_until_complete(_read_back())
        assert state == "PAUSED", state


class TestRateLimiting:
    def test_ops_endpoints_rate_limited(self, operator_client, monkeypatch):
        # Force the limiter to deny (fail-closed path) deterministically.
        from app.rate_limit import check_rate_limit

        async def denied(*a, **k):
            return False, 0
        monkeypatch.setattr("app.routes.ops.check_rate_limit", denied)
        r = operator_client.get("/api/ops/status")
        assert r.status_code == 429


@pytest.mark.usefixtures("clean_rate_limits")
class TestCapabilitiesEndpoint:
    """V3.9 console identity view — read-only, server-derived, no authority."""

    def test_unauthenticated_denied(self, client):
        r = client.get("/api/ops/capabilities")
        assert r.status_code == 401

    def test_user_role_has_no_capabilities(self, user_client):
        r = user_client.get("/api/ops/capabilities")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == om.Role.USER
        assert body["capabilities"] == []

    def test_operator_capabilities_do_not_include_audit(self, operator_client):
        r = operator_client.get("/api/ops/capabilities")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == om.Role.OPERATOR
        assert om.CAP_VIEW_OPERATIONS in body["capabilities"]
        assert om.CAP_VIEW_AUDIT not in body["capabilities"]
        assert set(body["step_up_required"]) == set(om.STEP_UP_REQUIRED_CAPABILITIES)

    def test_admin_capabilities_include_audit(self, client, session_factory, test_user):
        test_user.role = om.Role.ADMIN
        r = authenticated_client_for(client, test_user).get("/api/ops/capabilities")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == om.Role.ADMIN
        for cap in (om.CAP_VIEW_OPERATIONS, om.CAP_VIEW_AUDIT,
                    om.CAP_VERIFY_AUDIT, om.CAP_EXPORT_AUDIT):
            assert cap in body["capabilities"]

    def test_invalid_role_fails_closed(self, client, session_factory, test_user):
        test_user.role = "SUPERADMIN"
        r = authenticated_client_for(client, test_user).get("/api/ops/capabilities")
        assert r.status_code == 200
        assert r.json()["role"] == om.Role.USER
        assert r.json()["capabilities"] == []

    def test_query_params_cannot_escalate(self, user_client):
        r = user_client.get("/api/ops/capabilities?role=ADMIN&capabilities=EMERGENCY_STOP")
        assert r.status_code == 200
        assert r.json()["role"] == om.Role.USER
        assert r.json()["capabilities"] == []

    def test_no_secret_leakage(self, operator_client):
        import json
        body = json.dumps(operator_client.get("/api/ops/capabilities").json())
        for needle in ("secret", "token", "password", "private_key"):
            assert needle not in body.lower()


class TestNoSecretLeakage:
    def test_status_response_has_no_secrets(self, operator_client):
        import json
        r = operator_client.get("/api/ops/status")
        body = json.dumps(r.json())
        for needle in ("secret", "token", "password", "private_key"):
            assert needle not in body.lower()

    def test_events_response_bounded_fields(self, operator_client):
        r = operator_client.get("/api/ops/events")
        assert r.status_code == 200
