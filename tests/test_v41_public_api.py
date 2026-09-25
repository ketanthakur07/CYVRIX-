"""CYVRIX V4.1 — public API, scope, idempotency and contract tests.

Covers the invariants this increment is responsible for:

  - the scope registry is a CLOSED WORLD and grants nothing by itself
  - API keys rotate deterministically; the old key dies immediately
  - idempotency: same key + same request replays, same key + different
    request conflicts, a different key is a new operation, and the record
    is tenant-scoped so it cannot be used to cross organizations
  - the public error envelope is stable and echoes no submitted value
  - collections are bounded and cursor-pageable, filters are allowlisted
  - the public API is tenant-isolated and exposes exactly one mutation
  - rate-limit headers describe only the caller's own organization
"""
import sys
import os
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import GithubInstallation, Repository, Scan
from app.services import api_key_service, v4_rbac as rbac
from app.services import idempotency_service as idem
from app.services import organization_service as org_svc


pytestmark = pytest.mark.usefixtures("clean_db")

READ_SCOPES = ["repositories:read", "findings:read", "scans:read", "actions:read"]


async def _seed(session_factory, owner, *, name="Org", scopes=None, repo_name="repo",
                is_active=True):
    """Create org + installation + repository + one API key. Returns a dict."""
    async with session_factory() as s:
        org = await org_svc.create_organization(s, name=name, creator_user_id=owner.id)
        await s.flush()
        inst = GithubInstallation(
            user_id=owner.id,
            installation_id=uuid4().int % 900000 + 1,
            account_login=f"acct-{repo_name}",
            account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id,
            github_repo_id=uuid4().int % 900000 + 1,
            owner="acme",
            name=repo_name,
            default_branch="main",
            is_active=is_active,
        )
        s.add(repo)
        await s.flush()
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        row, secret = await api_key_service.create_api_key(
            s,
            org_id=org.id,
            actor_membership=actor,
            actor_user_id=owner.id,
            name="ci",
            scopes=scopes if scopes is not None else list(READ_SCOPES),
        )
        await s.commit()
        return {
            "org_id": org.id,
            "repo_id": repo.id,
            "prefix": row.prefix,
            "secret": secret,
        }


def _auth(secret):
    return {"Authorization": f"Bearer {secret}"}


# ── Phase 5/6: scope registry ────────────────────────────────────────


class TestScopeRegistry:
    def test_no_administrative_wildcard_exists(self):
        for scope in rbac.API_SCOPES:
            assert not scope.startswith("admin")
            assert "*" not in scope

    def test_no_scope_can_manage_the_organization(self):
        for scope in rbac.API_SCOPES:
            assert not scope.startswith(("members:", "policy:", "orgs:"))

    def test_every_high_impact_scope_is_a_real_scope(self):
        assert rbac.HIGH_IMPACT_API_SCOPES <= rbac.API_SCOPES

    def test_every_read_scope_is_a_real_scope(self):
        assert rbac.READ_API_SCOPES <= rbac.API_SCOPES

    def test_planned_scopes_are_not_issuable(self):
        """A designed-but-unbacked scope must be REFUSED, not accepted."""
        assert rbac.PLANNED_API_SCOPES
        assert rbac.PLANNED_API_SCOPES.isdisjoint(rbac.API_SCOPES)
        for scope in rbac.PLANNED_API_SCOPES:
            assert rbac.is_valid_api_scope(scope) is False

    def test_unknown_scope_names_are_invalid(self):
        for bogus in ("", "admin:*", "SUPERUSER", "findings:read:all", "read"):
            assert rbac.is_valid_api_scope(bogus) is False

    def test_execution_scopes_are_not_yet_issuable(self):
        # Phase 38/51 endpoints do not exist; issuing their scope would
        # advertise a control that is not enforced.
        assert "executions:create" not in rbac.API_SCOPES
        assert "executions:create" in rbac.PLANNED_API_SCOPES

    def test_read_only_classification_fails_closed(self):
        assert rbac.key_is_read_only(list(READ_SCOPES)) is True
        assert rbac.key_is_read_only(["scans:create"]) is False
        assert rbac.key_is_read_only([]) is False
        assert rbac.key_is_read_only(None) is False
        # An unrecognised scope must not be mistaken for a safe one.
        assert rbac.key_is_read_only(["not:a:scope"]) is False


# ── Phase 5/6: issuance rules ────────────────────────────────────────


class TestScopeIssuance:
    async def test_unknown_scope_is_refused_at_issuance(self, session_factory, test_user):
        async with session_factory() as s:
            org = await org_svc.create_organization(s, name="O", creator_user_id=test_user.id)
            await s.flush()
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            with pytest.raises(Exception) as ei:
                await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=actor,
                    actor_user_id=test_user.id, name="k",
                    scopes=["admin:everything"],
                )
            assert "INVALID_API_KEY_SCOPES" in str(ei.value)

    async def test_only_key_managers_can_issue_any_key(
        self, session_factory, test_user, test_user_b
    ):
        """A security engineer cannot mint a key at all — the capability
        gate fires before any scope reasoning."""
        from app.models import OrganizationMembership

        async with session_factory() as s:
            org = await org_svc.create_organization(s, name="O", creator_user_id=test_user.id)
            await s.flush()
            s.add(OrganizationMembership(
                organization_id=org.id, user_id=test_user_b.id,
                role=rbac.OrgRole.SECURITY_ENGINEER, state="ACTIVE",
            ))
            await s.commit()
            engineer = await org_svc.get_membership(
                s, org_id=org.id, user_id=test_user_b.id)
            with pytest.raises(Exception) as ei:
                await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=engineer,
                    actor_user_id=test_user_b.id, name="k", scopes=["scans:create"],
                )
            assert "API_KEY_MANAGEMENT_NOT_PERMITTED" in str(ei.value)

    def test_high_impact_issuance_requires_admin_standing_by_construction(self):
        """FINDING (V4.1): the `HIGH_IMPACT_SCOPE_REQUIRES_ADMIN` guard in
        create_api_key is currently UNREACHABLE, because every role that
        holds CAP_MANAGE_API_KEYS also holds CAP_MANAGE_MEMBERS.

        That is not a hole — it means high-impact scope issuance already
        requires ORG_ADMIN/OWNER standing, which is the intended property.
        The guard is retained as defence in depth in case the role ladder
        changes (e.g. a future role able to issue keys but not administer
        members). This test pins the property that makes it unreachable, so
        relaxing the role ladder fails loudly instead of silently opening a
        hole.
        """
        for role in rbac.ALL_ROLES:
            if rbac.role_has_capability(role, rbac.CAP_MANAGE_API_KEYS):
                assert rbac.membership_manageable_by(role), (
                    f"{role} can issue API keys but cannot manage members: "
                    "the high-impact scope guard is now load-bearing and "
                    "must be tested directly"
                )


# ── Phase 9: rotation ────────────────────────────────────────────────


class TestKeyRotation:
    def test_rotation_issues_a_new_secret_and_kills_the_old_key(
        self, authenticated_client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, scopes=["repositories:read"])
        )
        old = seed["secret"]
        assert authenticated_client.get(
            "/api/v1/repositories", headers=_auth(old)).status_code == 200

        keys = authenticated_client.get(f"/api/orgs/{seed['org_id']}/api-keys").json()
        old_id = keys[0]["id"]
        r = authenticated_client.post(
            f"/api/orgs/{seed['org_id']}/api-keys/{old_id}/rotate")
        assert r.status_code == 201, r.text
        new = r.json()["secret"]
        assert new != old
        # scopes preserved, not widened
        assert r.json()["scopes"] == ["repositories:read"]

        # Old key is dead IMMEDIATELY; new key works.
        assert authenticated_client.get(
            "/api/v1/repositories", headers=_auth(old)).status_code == 401
        assert authenticated_client.get(
            "/api/v1/repositories", headers=_auth(new)).status_code == 200

    def test_rotating_a_revoked_key_is_a_conflict(
        self, authenticated_client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, scopes=["repositories:read"])
        )
        keys = authenticated_client.get(f"/api/orgs/{seed['org_id']}/api-keys").json()
        key_id = keys[0]["id"]
        base = f"/api/orgs/{seed['org_id']}/api-keys/{key_id}"
        assert authenticated_client.post(f"{base}/revoke").status_code == 200
        # A second rotation must not mint a live successor.
        r = authenticated_client.post(f"{base}/rotate")
        assert r.status_code == 409, r.text
        # Console API error shape: detail is a structured object.
        assert r.json()["detail"]["reason_code"] == "API_KEY_ALREADY_REVOKED"

    def test_rotation_cannot_reach_another_organization(
        self, authenticated_client, session_factory, test_user, test_user_b
    ):
        import asyncio

        loop = asyncio.get_event_loop()
        mine = loop.run_until_complete(
            _seed(session_factory, test_user, name="Mine", repo_name="mine"))
        theirs = loop.run_until_complete(
            _seed(session_factory, test_user_b, name="Theirs", repo_name="theirs",
                  scopes=["repositories:read"]))
        their_keys = authenticated_client.get(
            f"/api/orgs/{theirs['org_id']}/api-keys")
        # The caller is not a member of that organization: existence is
        # never confirmed.
        assert their_keys.status_code in (403, 404)

    def test_rotation_preserves_expiry_and_never_extends_it(
        self, session_factory, test_user
    ):
        import asyncio
        from datetime import datetime, timedelta, timezone

        async def _setup():
            async with session_factory() as s:
                org = await org_svc.create_organization(
                    s, name="Exp", creator_user_id=test_user.id)
                await s.flush()
                actor = await org_svc.get_membership(
                    s, org_id=org.id, user_id=test_user.id)
                soon = datetime.now(timezone.utc) + timedelta(hours=3)
                row, _ = await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=actor,
                    actor_user_id=test_user.id, name="k",
                    scopes=["repositories:read"], expires_at=soon)
                await s.commit()
                return org.id, actor, row, soon

        org_id, actor, row, soon = asyncio.get_event_loop().run_until_complete(_setup())

        async def _rotate():
            async with session_factory() as s:
                successor, _ = await api_key_service.rotate_api_key(
                    s, org_id=org_id, actor_membership=actor,
                    actor_user_id=test_user.id, key_id=row.id)
                await s.commit()
                return successor.expires_at

        new_expiry = asyncio.get_event_loop().run_until_complete(_rotate())
        assert new_expiry is not None
        # SQLite hands back naive datetimes; normalise before comparing.
        if new_expiry.tzinfo is None:
            new_expiry = new_expiry.replace(tzinfo=timezone.utc)
        # Not later than the original — rotation must not extend authority.
        assert new_expiry <= soon + timedelta(seconds=1)


# ── Phase 11/12: idempotency semantics ───────────────────────────────


class TestIdempotencyPrimitive:
    def test_digest_is_order_insensitive_but_content_sensitive(self):
        a = idem.canonical_request_digest({"b": 1, "a": 2})
        b = idem.canonical_request_digest({"a": 2, "b": 1})
        c = idem.canonical_request_digest({"a": 3, "b": 1})
        assert a == b
        assert a != c

    def test_client_key_validation(self):
        assert idem.validate_client_key(None) is None
        assert idem.validate_client_key("   ") is None
        assert idem.validate_client_key("abc-123-XYZ_9") == "abc-123-XYZ_9"
        for bad in ("short", "x" * 300, "has spaces", "semi;colon", "quote'\""):
            with pytest.raises(idem.IdempotencyError) as ei:
                idem.validate_client_key(bad)
            assert ei.value.reason_code == "IDEMPOTENCY_KEY_INVALID"

    async def test_same_key_same_request_replays_instead_of_recreating(
        self, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user, name="Idem", repo_name="idem")
        digest = idem.canonical_request_digest({"repository_id": str(seed["repo_id"])})

        async with session_factory() as s:
            first = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="retry-key-0001", request_digest=digest)
            assert first.outcome == idem.OUTCOME_ACQUIRED
            await idem.complete(s, first, status_code=202, body={"scan_id": "s1"})
            await s.commit()

        async with session_factory() as s:
            second = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="retry-key-0001", request_digest=digest)
            assert second.outcome == idem.OUTCOME_REPLAY
            assert second.status_code == 202
            assert second.body == {"scan_id": "s1"}

    async def test_same_key_different_request_is_a_conflict(self, session_factory, test_user):
        seed = await _seed(session_factory, test_user, name="Idem2", repo_name="idem2")

        async with session_factory() as s:
            first = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="retry-key-0002",
                request_digest=idem.canonical_request_digest({"repository_id": "A"}))
            await idem.complete(s, first, status_code=202, body={"scan_id": "s1"})
            await s.commit()

        async with session_factory() as s:
            second = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="retry-key-0002",
                request_digest=idem.canonical_request_digest({"repository_id": "B"}))
            # Must NOT be answered with the other request's result.
            assert second.outcome == idem.OUTCOME_CONFLICT

    async def test_different_scope_same_key_is_a_distinct_operation(
        self, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user, name="Idem3", repo_name="idem3")
        digest = idem.canonical_request_digest({"x": 1})
        async with session_factory() as s:
            r1 = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="shared-key-0001", request_digest=digest)
            await idem.complete(s, r1, status_code=202, body={"a": 1})
            await s.commit()
        async with session_factory() as s:
            r2 = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/other",
                key_value="shared-key-0001", request_digest=digest)
            assert r2.outcome == idem.OUTCOME_ACQUIRED

    async def test_records_are_tenant_scoped(self, session_factory, test_user, test_user_b):
        mine = await _seed(session_factory, test_user, name="T1", repo_name="t1")
        theirs = await _seed(session_factory, test_user_b, name="T2", repo_name="t2")
        digest = idem.canonical_request_digest({"x": 1})

        async with session_factory() as s:
            r = await idem.reserve(
                s, organization_id=mine["org_id"], scope="POST /api/v1/scans",
                key_value="tenant-shared-0001", request_digest=digest)
            await idem.complete(s, r, status_code=202, body={"scan_id": "mine"})
            await s.commit()

        async with session_factory() as s:
            other = await idem.reserve(
                s, organization_id=theirs["org_id"], scope="POST /api/v1/scans",
                key_value="tenant-shared-0001", request_digest=digest)
            # Same key VALUE, different tenant → a new operation, not a
            # replay of another organization's outcome.
            assert other.outcome == idem.OUTCOME_ACQUIRED

    async def test_expired_record_can_be_reclaimed(self, session_factory, test_user):
        from datetime import datetime, timedelta, timezone

        seed = await _seed(session_factory, test_user, name="Idem4", repo_name="idem4")
        digest = idem.canonical_request_digest({"x": 1})
        async with session_factory() as s:
            r = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="expiring-key-0001", request_digest=digest, ttl_hours=0)
            await idem.complete(s, r, status_code=202, body={"scan_id": "old"})
            await s.commit()

        async with session_factory() as s:
            again = await idem.reserve(
                s, organization_id=seed["org_id"], scope="POST /api/v1/scans",
                key_value="expiring-key-0001",
                request_digest=idem.canonical_request_digest({"x": 2}))
            assert again.outcome == idem.OUTCOME_ACQUIRED


class TestIdempotencyEndpoint:
    def _monkeypatch_enqueue(self, monkeypatch):
        import app.worker as worker

        calls = []

        def _fake(scan_id):
            calls.append(scan_id)

        monkeypatch.setattr(worker, "enqueue_scan", _fake)
        return calls

    def test_retry_replays_and_creates_exactly_one_scan(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio

        calls = self._monkeypatch_enqueue(monkeypatch)
        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="Scan", repo_name="scanrepo",
                  scopes=["scans:read", "scans:create"]))
        headers = {**_auth(seed["secret"]), "Idempotency-Key": "ci-run-123456"}
        body = {"repository_id": str(seed["repo_id"])}

        first = client.post("/api/v1/scans", json=body, headers=headers)
        assert first.status_code == 202, first.text
        second = client.post("/api/v1/scans", json=body, headers=headers)
        assert second.status_code == 202
        # Identical outcome, and the side effect happened ONCE.
        assert second.json() == first.json()
        assert len(calls) == 1

    def test_same_key_different_body_is_rejected(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio

        self._monkeypatch_enqueue(monkeypatch)
        loop = asyncio.get_event_loop()
        one = loop.run_until_complete(
            _seed(session_factory, test_user, name="S1", repo_name="s1",
                  scopes=["scans:create"]))
        two = loop.run_until_complete(
            _seed(session_factory, test_user, name="S2", repo_name="s2",
                  scopes=["scans:create"]))
        headers = {**_auth(one["secret"]), "Idempotency-Key": "dup-key-123456"}

        assert client.post(
            "/api/v1/scans", json={"repository_id": str(one["repo_id"])},
            headers=headers).status_code == 202
        conflict = client.post(
            "/api/v1/scans", json={"repository_id": str(two["repo_id"])},
            headers=headers)
        assert conflict.status_code == 409
        assert conflict.json()["code"] == "IDEMPOTENCY_KEY_REUSED"

    def test_malformed_idempotency_key_is_refused_not_ignored(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio

        self._monkeypatch_enqueue(monkeypatch)
        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="Bad", repo_name="bad",
                  scopes=["scans:create"]))
        r = client.post(
            "/api/v1/scans", json={"repository_id": str(seed["repo_id"])},
            headers={**_auth(seed["secret"]), "Idempotency-Key": "no"})
        assert r.status_code == 400
        assert r.json()["code"] == "IDEMPOTENCY_KEY_INVALID"

    def test_enqueue_failure_is_visible_and_leaves_no_hung_scan(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio
        import app.worker as worker

        def _boom(scan_id):
            raise RuntimeError("redis down")

        monkeypatch.setattr(worker, "enqueue_scan", _boom)
        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="Boom", repo_name="boom",
                  scopes=["scans:create"]))

        r = client.post(
            "/api/v1/scans", json={"repository_id": str(seed["repo_id"])},
            headers=_auth(seed["secret"]))
        assert r.status_code == 503
        assert r.json()["code"] == "ANALYSIS_UNAVAILABLE"

        async def _scan_states():
            async with session_factory() as s:
                from sqlalchemy import select
                rows = (await s.execute(
                    select(Scan).where(Scan.repository_id == seed["repo_id"])
                )).scalars().all()
                return [(x.status, x.error_reason) for x in rows]

        states = asyncio.get_event_loop().run_until_complete(_scan_states())
        assert states == [("FAILED", "ENQUEUE_FAILED")]


# ── Phase 13: public error contract ──────────────────────────────────


class TestErrorContract:
    def _assert_envelope(self, r):
        body = r.json()
        for field in ("detail", "code", "message", "request_id"):
            assert field in body, f"missing {field} in {body}"
        assert body["code"] == body["detail"]
        assert isinstance(body["message"], str) and body["message"]
        # Never an internal detail.
        text = r.text.lower()
        for banned in ("traceback", "sqlalchemy", "postgresql://", "c:\\", "/app/app/"):
            assert banned not in text

    def test_missing_key_is_401_envelope(self, client):
        r = client.get("/api/v1/repositories")
        assert r.status_code == 401
        assert r.json()["code"] == "API_KEY_REQUIRED"
        self._assert_envelope(r)

    def test_invalid_key_is_401_envelope(self, client):
        r = client.get("/api/v1/repositories",
                       headers={"Authorization": "Bearer cyv_deadbeef_nope"})
        assert r.status_code == 401
        assert r.json()["code"] == "API_KEY_INVALID"
        self._assert_envelope(r)

    def test_missing_scope_is_403_envelope(self, client, session_factory, test_user):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="E1", repo_name="e1",
                  scopes=["repositories:read"]))
        r = client.get("/api/v1/findings", headers=_auth(seed["secret"]))
        assert r.status_code == 403
        assert r.json()["code"] == "API_SCOPE_REQUIRED"
        self._assert_envelope(r)

    def test_validation_error_does_not_echo_submitted_values(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="E2", repo_name="e2",
                  scopes=["scans:create"]))
        secret_marker = "SUPERSECRETVALUE1234567890"
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": secret_marker, "unexpected": "x"},
            headers=_auth(seed["secret"]))
        assert r.status_code == 422
        assert r.json()["code"] == "VALIDATION_ERROR"
        # Only field path + rule name are exposed.
        assert secret_marker not in r.text
        for entry in r.json()["details"]["errors"]:
            assert set(entry) == {"field", "type"}

    def test_internal_routes_keep_their_existing_error_shape(self, client):
        """The public envelope must not leak into the console API."""
        r = client.get("/api/scans/00000000-0000-0000-0000-000000000000")
        assert r.status_code in (401, 404)
        # Internal shape carries `detail`; it must not gain `code`.
        assert "detail" in r.json()
        assert "code" not in r.json()


# ── Phase 15/16: pagination and filters ──────────────────────────────


class TestPaginationAndFilters:
    def test_collection_is_a_bounded_envelope(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="P1", repo_name="p1"))
        r = client.get("/api/v1/repositories", headers=_auth(seed["secret"]))
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"items", "next_cursor", "has_more"}
        assert body["has_more"] is False
        assert body["next_cursor"] is None

    def test_page_size_is_bounded_by_the_server(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="P2", repo_name="p2"))
        too_big = client.get("/api/v1/repositories?limit=100000",
                             headers=_auth(seed["secret"]))
        assert too_big.status_code == 422
        assert client.get("/api/v1/repositories?limit=0",
                          headers=_auth(seed["secret"])).status_code == 422

    def test_cursor_paginates_without_overlap(
        self, client, session_factory, test_user
    ):
        import asyncio

        async def _seed_many():
            async with session_factory() as s:
                org = await org_svc.create_organization(
                    s, name="Many", creator_user_id=test_user.id)
                await s.flush()
                inst = GithubInstallation(
                    user_id=test_user.id, installation_id=uuid4().int % 900000 + 7,
                    account_login="many", account_type="Organization",
                    organization_id=org.id)
                s.add(inst)
                await s.flush()
                for i in range(5):
                    s.add(Repository(
                        installation_id=inst.id, github_repo_id=1000 + i,
                        owner="o", name=f"r{i}", default_branch="main",
                        is_active=True))
                await s.flush()
                actor = await org_svc.get_membership(
                    s, org_id=org.id, user_id=test_user.id)
                _, secret = await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=actor,
                    actor_user_id=test_user.id, name="k",
                    scopes=["repositories:read"])
                await s.commit()
                return secret

        secret = asyncio.get_event_loop().run_until_complete(_seed_many())

        page1 = client.get("/api/v1/repositories?limit=2", headers=_auth(secret)).json()
        assert len(page1["items"]) == 2 and page1["has_more"] is True
        page2 = client.get(
            f"/api/v1/repositories?limit=2&cursor={page1['next_cursor']}",
            headers=_auth(secret)).json()
        ids1 = {i["id"] for i in page1["items"]}
        ids2 = {i["id"] for i in page2["items"]}
        assert ids1.isdisjoint(ids2), "cursor pages must not overlap"

    def test_malformed_cursor_is_refused_not_ignored(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="P3", repo_name="p3"))
        r = client.get("/api/v1/repositories?cursor=!!!not-base64!!!",
                       headers=_auth(seed["secret"]))
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_CURSOR"

    def test_unknown_filter_value_is_refused(self, client, session_factory, test_user):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="P4", repo_name="p4"))
        r = client.get("/api/v1/findings?severity=APOCALYPTIC",
                       headers=_auth(seed["secret"]))
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_FILTER"

    def test_known_filter_value_is_accepted(self, client, session_factory, test_user):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="P5", repo_name="p5"))
        r = client.get("/api/v1/findings?severity=critical",
                       headers=_auth(seed["secret"]))
        assert r.status_code == 200


# ── Phase 36/37/69: tenant isolation and no chain bypass ─────────────


class TestTenantIsolation:
    def test_cannot_scan_another_organizations_repository(
        self, client, session_factory, test_user, test_user_b, monkeypatch
    ):
        import asyncio
        import app.worker as worker

        monkeypatch.setattr(worker, "enqueue_scan", lambda scan_id: None)
        loop = asyncio.get_event_loop()
        mine = loop.run_until_complete(
            _seed(session_factory, test_user, name="A", repo_name="a",
                  scopes=["scans:create"]))
        theirs = loop.run_until_complete(
            _seed(session_factory, test_user_b, name="B", repo_name="b",
                  scopes=["scans:create"]))

        r = client.post(
            "/api/v1/scans", json={"repository_id": str(theirs["repo_id"])},
            headers=_auth(mine["secret"]))
        # 404, not 403: existence is never confirmed.
        assert r.status_code == 404
        assert r.json()["code"] == "REPOSITORY_NOT_FOUND"

    def test_cannot_read_another_organizations_scan(
        self, client, session_factory, test_user, test_user_b
    ):
        import asyncio
        from sqlalchemy import select

        loop = asyncio.get_event_loop()
        theirs = loop.run_until_complete(
            _seed(session_factory, test_user_b, name="B2", repo_name="b2",
                  scopes=["scans:read"]))

        async def _make_scan():
            async with session_factory() as s:
                scan = Scan(repository_id=theirs["repo_id"], status="COMPLETED",
                            trigger="manual")
                s.add(scan)
                await s.commit()
                return scan.id

        scan_id = loop.run_until_complete(_make_scan())

        # My own org's key must not see their scan.
        mine = loop.run_until_complete(
            _seed(session_factory, test_user, name="A2", repo_name="a2",
                  scopes=["scans:read"]))
        r = client.get(f"/api/v1/scans/{scan_id}", headers=_auth(mine["secret"]))
        assert r.status_code == 404

    def test_no_organization_identifier_is_accepted(
        self, client, session_factory, test_user
    ):
        """A body trying to name a tenant must be rejected, not ignored."""
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="A3", repo_name="a3",
                  scopes=["scans:create"]))
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": str(seed["repo_id"]),
                  "organization_id": str(seed["org_id"])},
            headers=_auth(seed["secret"]))
        assert r.status_code == 422  # extra="forbid"


class TestNoChainBypass:
    def _public_mutations(self):
        from app.main import app

        schema = app.openapi()
        mutations = []
        for path, ops in schema["paths"].items():
            if not path.startswith("/api/v1"):
                continue
            for method, op in ops.items():
                if method.lower() in ("post", "put", "patch", "delete"):
                    mutations.append((method.upper(), path))
        return sorted(mutations)

    def test_the_only_public_mutation_is_an_analysis_request(self):
        assert self._public_mutations() == [("POST", "/api/v1/scans")]

    def test_public_api_exposes_no_approval_or_execution_mutation(self):
        for method, path in self._public_mutations():
            assert "approve" not in path and "authorize" not in path
            assert "execute" not in path and "rollback" not in path

    def test_public_api_does_not_re_export_internal_mutations(self):
        from app.main import app

        schema = app.openapi()
        public = {p for p in schema["paths"] if p.startswith("/api/v1/")}
        # Internal mutation surfaces must not appear under /api/v1.
        for internal in ("/api/actions", "/api/approvals", "/api/executions",
                         "/api/ops", "/api/orgs"):
            assert not any(p.startswith(internal) for p in public)


# ── Phase 19/20: rate-limit classes and headers ──────────────────────


class TestRateLimitHeaders:
    def test_headers_describe_the_callers_own_budget(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="R1", repo_name="r1"))
        r = client.get("/api/v1/repositories", headers=_auth(seed["secret"]))
        assert r.status_code == 200
        assert r.headers["x-ratelimit-limit"] == "600"
        assert int(r.headers["x-ratelimit-remaining"]) >= 0
        assert int(r.headers["x-ratelimit-reset"]) > 0
        assert r.headers["x-ratelimit-class"] == "v1-read"

    def test_writes_use_a_separate_class_from_reads(
        self, client, session_factory, test_user
    ):
        import asyncio

        seed = asyncio.get_event_loop().run_until_complete(
            _seed(session_factory, test_user, name="R2", repo_name="r2",
                  scopes=["scans:read", "scans:create"]))

        def _boom(scan_id):
            raise RuntimeError("no worker in this test")

        import app.worker as worker
        original = worker.enqueue_scan
        worker.enqueue_scan = _boom
        try:
            r = client.post(
                "/api/v1/scans", json={"repository_id": str(seed["repo_id"])},
                headers=_auth(seed["secret"]))
        finally:
            worker.enqueue_scan = original
        # The write class is its own budget, far below the read budget.
        assert r.headers.get("x-ratelimit-class") == "v1-write"
        assert r.headers.get("x-ratelimit-limit") == "60"


# ── Phase 18/63: OpenAPI fidelity ────────────────────────────────────


class TestOpenApiContract:
    def test_public_operations_declare_bearer_authentication(self):
        from app.main import app

        schema = app.openapi()
        assert "securitySchemes" in schema["components"]
        assert "ApiKeyBearer" in schema["components"]["securitySchemes"]
        for path, ops in schema["paths"].items():
            if not path.startswith("/api/v1"):
                continue
            for method, op in ops.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                assert op.get("security") == [{"ApiKeyBearer": []}], (method, path)

    def test_internal_operations_are_not_declared_as_api_key_protected(self):
        from app.main import app

        schema = app.openapi()
        op = schema["paths"]["/api/scans"]["post"]
        assert op.get("security") is None

    def test_reported_version_matches_the_release(self):
        from app.main import app

        assert app.version == "4.1.0"
        assert app.openapi()["info"]["version"] == "4.1.0"
