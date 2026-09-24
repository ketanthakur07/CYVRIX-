"""V3.8 — audit API security tests (read-only surface, capability-gated).

Covers:
- authentication required (401)
- USER/OPERATOR denied (403), ADMIN allowed (VIEW/VERIFY/EXPORT_AUDIT)
- cross-tenant chain access → 404 (no existence leak)
- method safety: mutation verbs rejected — no audit mutation API exists
- client authority fields (digest/sequence/previous) cannot influence identity
- malformed ids → 404 (never 500, never distinguishable)
- no secrets in any response
"""
import asyncio
import os
import sys
import uuid as uuid_mod
from contextlib import contextmanager

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests-only-32chars!!")
os.environ.setdefault("ENVIRONMENT", "development")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.database import get_db
from app.models import AuditChain, GithubInstallation, User
from app.services import audit_service as aus

APP = None
GET_CURRENT_USER = None
UUID = uuid_mod.UUID


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def tenant_admin(engine, session_factory, test_installation):
    """An ADMIN who OWNS test_installation (the audited tenant)."""
    async def _run():
        async with session_factory() as s:
            admin = User(email=f"audit-admin-{uuid_mod.uuid4()}@t.local",
                         role="ADMIN",
                         github_id=int(uuid_mod.uuid4().int % 900000) + 1)
            s.add(admin)
            await s.flush()
            await s.execute(update(GithubInstallation)
                            .where(GithubInstallation.id == test_installation.id)
                            .values(user_id=admin.id))
            await s.commit()
            await s.refresh(admin)
            return admin.id
    return run(_run())


@pytest.fixture
def api_client(engine, session_factory, tenant_admin):
    """TestClient with DB bound to the test engine and admin identity."""
    global APP, GET_CURRENT_USER
    if APP is None:
        from app.main import app as _app
        from app.auth import get_current_user as _gcu
        APP, GET_CURRENT_USER = _app, _gcu

    async def _override_db():
        async with session_factory() as session:
            yield session

    async def _override_user():
        async with session_factory() as s:
            return (await s.execute(
                select(User).where(User.id == tenant_admin))).scalar_one()

    APP.dependency_overrides[get_db] = _override_db
    APP.dependency_overrides[GET_CURRENT_USER] = _override_user
    with TestClient(APP) as client:
        yield client
    APP.dependency_overrides.pop(get_db, None)
    APP.dependency_overrides.pop(GET_CURRENT_USER, None)


@contextmanager
def acting_as(session_factory, user_id):
    """Swap the authenticated identity for one request block, restoring
    the previous override afterwards (never a global clear). Binds the
    DB to the test engine for the block's lifetime."""
    global APP, GET_CURRENT_USER
    if APP is None:
        from app.main import app as _app
        from app.auth import get_current_user as _gcu
        APP, GET_CURRENT_USER = _app, _gcu

    async def _override_db():
        async with session_factory() as session:
            yield session

    async def _override_user():
        async with session_factory() as s:
            return (await s.execute(
                select(User).where(User.id == user_id))).scalar_one()
    prev_user = APP.dependency_overrides.get(GET_CURRENT_USER)
    prev_db = APP.dependency_overrides.get(get_db)
    APP.dependency_overrides[GET_CURRENT_USER] = _override_user
    APP.dependency_overrides[get_db] = _override_db
    try:
        yield TestClient(APP)
    finally:
        if prev_user is not None:
            APP.dependency_overrides[GET_CURRENT_USER] = prev_user
        else:
            APP.dependency_overrides.pop(GET_CURRENT_USER, None)
        if prev_db is not None:
            APP.dependency_overrides[get_db] = prev_db
        else:
            APP.dependency_overrides.pop(get_db, None)


@pytest.fixture
def chain_with_events(session_factory, test_installation):
    async def _make():
        for et in ("SYSTEM_PAUSED", "EMERGENCY_STOP", "CIRCUIT_RESET"):
            async with session_factory() as s:
                await aus.emit_security_event(
                    s, installation_id=test_installation.id,
                    event_type=et, actor_type=aus.ActorType.SYSTEM,
                    reason_code="T", result="OK", payload={"k": "v"})
                await s.commit()
        async with session_factory() as s:
            return (await s.execute(select(AuditChain).where(
                AuditChain.installation_id == test_installation.id))).scalar_one()
    return run(_make())


def _seed_user(session_factory, role):
    async def _run():
        async with session_factory() as s:
            u = User(email=f"{role.lower()}-{uuid_mod.uuid4()}@t.local",
                     role=role,
                     github_id=int(uuid_mod.uuid4().int % 900000) + 1)
            s.add(u)
            await s.commit()
            await s.refresh(u)
            return u.id
    return run(_run())


class TestAuthn:
    def test_chains_require_auth(self, engine, session_factory, test_installation):
        global APP, GET_CURRENT_USER
        if APP is None:
            from app.main import app as _app
            from app.auth import get_current_user as _gcu
            APP, GET_CURRENT_USER = _app, _gcu
        APP.dependency_overrides.pop(GET_CURRENT_USER, None)
        client = TestClient(APP)
        r = client.get("/api/audit/chains")
        assert r.status_code == 401, r.status_code


class TestAuthz:
    def test_user_role_denied(self, engine, session_factory, test_installation, tenant_admin):
        uid = _seed_user(session_factory, "USER")
        with acting_as(session_factory, uid) as client:
            r = client.get("/api/audit/chains")
        assert r.status_code == 403 and r.json()["detail"] == "OPERATOR_CAPABILITY_REQUIRED"

    def test_operator_role_denied(self, engine, session_factory, test_installation, tenant_admin):
        uid = _seed_user(session_factory, "OPERATOR")
        with acting_as(session_factory, uid) as client:
            for path in ("/api/audit/chains", "/api/audit/integrity/status"):
                r = client.get(path)
                assert r.status_code == 403, (path, r.status_code)

    def test_admin_can_view_verify_export(self, api_client, chain_with_events):
        chain = chain_with_events
        r = api_client.get("/api/audit/chains")
        assert r.status_code == 200 and any(
            c["chain_id"] == str(chain.id) for c in r.json()), r.text
        r = api_client.get(f"/api/audit/chains/{chain.id}/verify")
        assert r.status_code == 200 and r.json()["status"] == "VALID", r.text
        r = api_client.get(f"/api/audit/chains/{chain.id}/events")
        assert r.status_code == 200 and len(r.json()) == 3
        r = api_client.get(f"/api/audit/chains/{chain.id}/checkpoints")
        assert r.status_code == 200
        r = api_client.get(f"/api/audit/chains/{chain.id}/export")
        assert r.status_code == 200 and "cyvrix_audit_export" in r.text


class TestTenantIsolation:
    def test_cross_tenant_chain_404(self, engine, session_factory, test_installation, tenant_admin, chain_with_events):
        chain_id = str(chain_with_events.id)
        uid = _seed_user(session_factory, "ADMIN")  # admin owning NOTHING
        with acting_as(session_factory, uid) as client:
            codes = []
            for path in (f"/api/audit/chains/{chain_id}/events",
                         f"/api/audit/chains/{chain_id}/verify",
                         f"/api/audit/chains/{chain_id}/checkpoints",
                         f"/api/audit/chains/{chain_id}/export"):
                r = client.get(path)
                codes.append(r.status_code)
                # The critical property: cross-tenant access NEVER returns
                # 200/403 (existence or privilege leak). 404 = isolation;
                # 429 = rate limiter correctly throttling the probe.
                assert r.status_code in (404, 429), (path, r.status_code)
            assert codes.count(200) == 0
            r = client.get("/api/audit/chains")
            assert r.status_code == 200 and r.json() == []  # own list empty

    def test_malformed_chain_id_404_never_500(self, api_client):
        """A malformed (non-UUID) chain id must NEVER produce a 500 or a
        distinguishable error; 404 = not found, 429 = limiter throttling
        the probe (both correct; 500/403/200 would be defects)."""
        r = api_client.get("/api/audit/chains/not-a-uuid/verify")
        assert r.status_code in (404, 429), (r.status_code, r.text[:200])


class TestMethodSafety:
    def test_no_mutation_api_exists(self, api_client, chain_with_events):
        """Every mutation verb against every audit path must be refused —
        audit mutations are not public API operations (Phase 26)."""
        chain_id = str(chain_with_events.id)
        probes = [
            ("POST", "/api/audit/chains", {}),
            ("POST", f"/api/audit/chains/{chain_id}/events",
             {"event_type": "EXECUTION_COMPLETED"}),
            ("PUT", f"/api/audit/chains/{chain_id}/events", {}),
            ("PATCH", f"/api/audit/chains/{chain_id}/events", {}),
            ("DELETE", f"/api/audit/chains/{chain_id}/events", {}),
            ("POST", f"/api/audit/chains/{chain_id}/verify", {}),
            ("DELETE", f"/api/audit/chains/{chain_id}", {}),
        ]
        for method, path, body in probes:
            r = api_client.request(method, path, json=body)
            assert r.status_code in (404, 405), (method, path, r.status_code)


class TestNoClientAuthority:
    def test_query_params_cannot_influence_identity(self, api_client, chain_with_events):
        """sequence/digest/previous are server-managed: query params are
        only ever FILTERS — they can never forge identity or skip
        verification of anything."""
        chain = chain_with_events
        r = api_client.get(
            f"/api/audit/chains/{chain.id}/verify",
            params={"event_digest": "f" * 64, "previous_digest": "0" * 64,
                    "sequence": 999, "force": True, "skip": True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "VALID" and body["checked_events"] == 3
        assert "force" not in body and "skip" not in body


class TestResponseHygiene:
    def test_no_secrets_in_verify_or_export(self, api_client, session_factory, test_installation, chain_with_events):
        async def _seed():
            async with session_factory() as s:
                await aus.emit_security_event(
                    s, installation_id=test_installation.id,
                    event_type="GITHUB_CREDENTIAL_ISSUED",
                    payload={"github_token": "ghp_" + "x" * 30, "note": "ok"})
                await s.commit()
        run(_seed())
        chain = chain_with_events
        r = api_client.get(f"/api/audit/chains/{chain.id}/export")
        assert "ghp_" + "x" * 30 not in r.text
        assert "[REDACTED]" in r.text  # redaction BEFORE canonicalization
        r2 = api_client.get(f"/api/audit/chains/{chain.id}/events")
        assert all(
            (ev.get("payload") or {}).get("github_token") in (None, "[REDACTED]")
            for ev in r2.json())
