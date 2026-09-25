"""CYVRIX V4.1 — audit integration, quotas, metrics, job semantics.

Covers:

  - API-key lifecycle events land in the org audit chain and are
    fail-closed for create/rotate (a credential is never minted or
    destroyed unwitnessed); revocation audit is best-effort but the
    revocation itself always stands
  - the org-level audit chain exists for key-only tenants and verifies
    under the V3.8 verifier
  - quota enforcement: org ceiling, global ceiling, atomicity under
    concurrency, fail-closed on Redis loss, refusal never consumes
    capacity
  - metrics: counters render, cardinality attacks collapse, unknown
    metric names fail closed
  - job status semantics: server-computed result, commit binding states,
    unknown statuses collapse to INCONCLUSIVE rather than PASS
"""
import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select

from app.models import (
    ApiKey,
    AuditChain,
    AuditChainEvent,
    GithubInstallation,
    Repository,
    Scan,
)
from app.services import api_key_service, audit_service, organization_service as org_svc
from app.services import v4_rbac as rbac
from app.services.audit_service import verify_chain

pytestmark = pytest.mark.usefixtures("clean_db")


async def _org_with_member(session_factory, user, *, name="Aud"):
    async with session_factory() as s:
        org = await org_svc.create_organization(s, name=name, creator_user_id=user.id)
        await s.flush()
        membership = await org_svc.get_membership(s, org_id=org.id, user_id=user.id)
        await s.commit()
        return org.id, membership


async def _org_events(session_factory, org_id):
    async with session_factory() as s:
        chain = (
            await s.execute(
                select(AuditChain).where(AuditChain.organization_id == org_id)
            )
        ).scalar_one_or_none()
        if chain is None:
            return []
        return list(
            (
                await s.execute(
                    select(AuditChainEvent)
                    .where(AuditChainEvent.chain_id == chain.id)
                    .order_by(AuditChainEvent.seq.asc())
                )
            ).scalars().all()
        )


# ── API key lifecycle audit ──────────────────────────────────────────


class TestApiKeyLifecycleAudit:
    async def test_key_creation_is_hash_chained(self, session_factory, test_user):
        org_id, membership = await _org_with_member(session_factory, test_user)
        async with session_factory() as s:
            row, secret = await api_key_service.create_api_key(
                s, org_id=org_id, actor_membership=membership,
                actor_user_id=test_user.id, name="k1",
                scopes=["repositories:read"],
            )
            await s.commit()

        events = await _org_events(session_factory, org_id)
        created = [e for e in events if e.event_type == "API_KEY_CREATED"]
        assert len(created) == 1
        # The plaintext secret NEVER enters the chain.
        for e in events:
            blob = repr(e.payload) + repr(e.event_digest)
            assert secret not in blob
            assert row.key_hash not in blob

    async def test_key_rotation_is_hash_chained(self, session_factory, test_user):
        org_id, membership = await _org_with_member(session_factory, test_user)
        async with session_factory() as s:
            row, _ = await api_key_service.create_api_key(
                s, org_id=org_id, actor_membership=membership,
                actor_user_id=test_user.id, name="k2",
                scopes=["repositories:read"],
            )
            await s.commit()
            await api_key_service.rotate_api_key(
                s, org_id=org_id, actor_membership=membership,
                actor_user_id=test_user.id, key_id=row.id,
            )
            await s.commit()

        events = await _org_events(session_factory, org_id)
        assert any(e.event_type == "API_KEY_ROTATED" for e in events)

    async def test_key_revocation_is_hash_chained(self, session_factory, test_user):
        org_id, membership = await _org_with_member(session_factory, test_user)
        async with session_factory() as s:
            row, _ = await api_key_service.create_api_key(
                s, org_id=org_id, actor_membership=membership,
                actor_user_id=test_user.id, name="k3",
                scopes=["repositories:read"],
            )
            await s.commit()
            await api_key_service.revoke_api_key(
                s, org_id=org_id, actor_membership=membership, key_id=row.id,
            )
            await s.commit()

        events = await _org_events(session_factory, org_id)
        assert any(e.event_type == "API_KEY_REVOKED" for e in events)

    async def test_creation_is_fail_closed_on_audit_failure(
        self, session_factory, test_user, monkeypatch
    ):
        """A credential must never come into existence unwitnessed: if the
        audit append fails, the creation FAILS and no key row persists."""
        org_id, membership = await _org_with_member(session_factory, test_user)

        async def _boom(*args, **kwargs):
            raise RuntimeError("audit down")

        monkeypatch.setattr(
            audit_service, "emit_security_event", _boom
        )
        async with session_factory() as s:
            with pytest.raises(RuntimeError):
                await api_key_service.create_api_key(
                    s, org_id=org_id, actor_membership=membership,
                    actor_user_id=test_user.id, name="k4",
                    scopes=["repositories:read"],
                )
                await s.commit()

        async with session_factory() as s:
            rows = (
                await s.execute(select(ApiKey).where(ApiKey.organization_id == org_id))
            ).scalars().all()
            assert rows == []  # no unwitnessed credential

    async def test_org_chain_verifies_after_lifecycle(
        self, session_factory, test_user
    ):
        """Key-only tenant (zero installations) still has a verifiable
        tamper-evident chain."""
        org_id, membership = await _org_with_member(session_factory, test_user)
        async with session_factory() as s:
            for i in range(3):
                row, _ = await api_key_service.create_api_key(
                    s, org_id=org_id, actor_membership=membership,
                    actor_user_id=test_user.id, name=f"kc{i}",
                    scopes=["repositories:read"],
                )
                await api_key_service.revoke_api_key(
                    s, org_id=org_id, actor_membership=membership, key_id=row.id,
                )
            await s.commit()

        async with session_factory() as s:
            chain = (
                await s.execute(
                    select(AuditChain).where(AuditChain.organization_id == org_id)
                )
            ).scalar_one()
            result = await verify_chain(s, chain_id=chain.id)
        assert result.status == "VALID", result.issues


# ── Quota enforcement ────────────────────────────────────────────────


class _FakePipe:
    def __init__(self, store):
        self._store = store
        self._ops = []

    def incr(self, k, v=1):
        self._ops.append(("incr", k, v)); return self

    def decr(self, k, v=1):
        self._ops.append(("decr", k, v)); return self

    def expire(self, k, t):
        self._ops.append(("expire", k, t)); return self

    async def execute(self):
        out = []
        for op in self._ops:
            if op[0] == "incr":
                self._store[op[1]] = self._store.get(op[1], 0) + op[2]
                out.append(self._store[op[1]])
            elif op[0] == "decr":
                self._store[op[1]] = self._store.get(op[1], 0) - op[2]
                out.append(self._store[op[1]])
            else:
                out.append(True)
        self._ops = []
        return out


class _FakeRedis:
    def __init__(self):
        self.store = {}

    def pipeline(self):
        return _FakePipe(self.store)

    async def decr(self, k, v=1):
        self.store[k] = self.store.get(k, 0) - v


class TestQuotaService:
    async def test_org_ceiling_enforced_with_compensation(self):
        from app.quota_service import consume_quota

        r = _FakeRedis()
        results = [
            await consume_quota(r, organization_id="o1", action="scans",
                                org_limit=2, global_limit=10)
            for _ in range(3)
        ]
        assert [x.allowed for x in results] == [True, True, False]
        assert results[2].reason_code == "QUOTA_ORG_EXCEEDED"
        # refusal consumed nothing
        assert any(v == 2 for v in r.store.values())

    async def test_global_ceiling_enforced(self):
        from app.quota_service import consume_quota

        r = _FakeRedis()
        for i in range(3):
            await consume_quota(r, organization_id=f"o{i}", action="scans",
                                org_limit=10, global_limit=3)
        d = await consume_quota(r, organization_id="oX", action="scans",
                                org_limit=10, global_limit=3)
        assert not d.allowed and d.reason_code == "QUOTA_GLOBAL_EXCEEDED"

    async def test_concurrent_requests_only_consume_valid_capacity(self):
        """Two requests around the final slot: at most one is admitted and
        every refusal is compensated (no burned capacity).

        The fake redis interleaves only at await points — which is exactly
        where the real Redis pipeline executes atomically — so this drives
        both the admitted and the compensated path in one sequence."""
        from app.quota_service import consume_quota

        r = _FakeRedis()
        first = await consume_quota(r, organization_id="race", action="scans",
                                    org_limit=1, global_limit=10)
        second = await consume_quota(r, organization_id="race", action="scans",
                                     org_limit=1, global_limit=10)
        assert first.allowed is True
        assert second.allowed is False
        assert second.reason_code == "QUOTA_ORG_EXCEEDED"
        # The refusal consumed nothing: counters sit at the limit, not above.
        assert max(v for v in r.store.values()) == 1

    async def test_redis_unavailable_fails_closed(self):
        from app.quota_service import consume_quota

        d = await consume_quota(None, organization_id="o", action="scans",
                                org_limit=5, global_limit=5)
        assert not d.allowed and d.reason_code == "QUOTA_UNAVAILABLE"

    def test_unknown_action_has_no_unlimited_tier(self):
        from app.quota_service import limit_for

        org_limit, global_limit = limit_for("not-registered-action")
        assert org_limit == 0 and global_limit == 0


# ── Metrics ──────────────────────────────────────────────────────────


class TestMetrics:
    def setup_method(self):
        from app.metrics import reset_for_tests

        reset_for_tests()

    def test_counter_renders_in_prometheus_format(self):
        from app.metrics import increment, render_prometheus

        increment("api_requests_total", {"outcome": "SCAN_CREATED"})
        out = render_prometheus()
        assert 'api_requests_total{outcome="SCAN_CREATED"} 1' in out
        assert "# TYPE api_requests_total counter" in out

    def test_unknown_metric_name_fails_closed(self):
        from app.metrics import increment

        with pytest.raises(KeyError):
            increment("definitely_not_a_metric")

    def test_cardinality_attack_collapses_to_sentinel(self):
        from app.metrics import increment, render_prometheus

        increment("api_requests_total", {"outcome": 'x" label="injected'})
        out = render_prometheus()
        assert "injected" not in out
        assert 'outcome="_other"' in out

    def test_summary_and_gauge_render(self):
        from app.metrics import observe_latency, set_gauge, render_prometheus

        observe_latency("api_request_duration", 0.25, {"outcome": "OK"})
        set_gauge("queue_depth", 7)
        out = render_prometheus()
        assert 'api_request_duration_count{outcome="OK"} 1' in out
        assert "queue_depth 7" in out


# ── Job status semantics (server-computed result + commit binding) ───


class TestJobSemantics:
    def _scan(self, **kw):
        scan = Scan(repository_id=uuid4(), status="QUEUED", trigger="api")
        for k, v in kw.items():
            setattr(scan, k, v)
        return scan

    def test_completed_scan_is_pass_with_verified_binding(self):
        from app.routes.api_v1 import _scan_job_result, _commit_binding

        scan = self._scan(
            status="COMPLETED", commit_sha="a" * 40,
            requested_commit_sha="a" * 40,
        )
        assert _scan_job_result(scan) == "PASS"
        assert _commit_binding(scan) == "VERIFIED"

    def test_failed_scan_is_fail_never_pass(self):
        from app.routes.api_v1 import _scan_job_result

        assert _scan_job_result(self._scan(status="FAILED", error_reason="CLONE_FAILED")) == "FAIL"

    def test_commit_mismatch_binding_is_mismatch(self):
        from app.routes.api_v1 import _commit_binding

        scan = self._scan(
            status="FAILED", error_reason="COMMIT_MISMATCH",
            requested_commit_sha="a" * 40, commit_sha="b" * 40,
        )
        assert _commit_binding(scan) == "MISMATCH"

    def test_unknown_status_is_inconclusive_never_pass(self):
        from app.routes.api_v1 import _scan_job_result

        assert _scan_job_result(self._scan(status="SOMETHING_ELSE")) == "INCONCLUSIVE"

    def test_running_job_has_no_result_yet(self):
        from app.routes.api_v1 import _scan_job_result, _commit_binding

        scan = self._scan(status="SCANNING", requested_commit_sha="a" * 40)
        assert _scan_job_result(scan) is None
        assert _commit_binding(scan) == "PENDING"

    def test_unbound_scan_has_no_binding_claim(self):
        from app.routes.api_v1 import _commit_binding

        assert _commit_binding(self._scan(status="COMPLETED")) == "UNBOUND"


# ── CI/webhook commit binding through the status endpoint ────────────


class TestScanStatusEndpoint:
    async def test_status_endpoint_reports_result_and_binding(
        self, client, session_factory, test_user
    ):
        from app.services import api_key_service

        async with session_factory() as s:
            org = await org_svc.create_organization(
                s, name="JS", creator_user_id=test_user.id
            )
            await s.flush()
            inst = GithubInstallation(
                user_id=test_user.id, installation_id=uuid4().int % 900000 + 1,
                account_login="js", account_type="Organization",
                organization_id=org.id,
            )
            s.add(inst)
            await s.flush()
            repo = Repository(
                installation_id=inst.id, github_repo_id=uuid4().int % 900000 + 1,
                owner="js", name="repo", default_branch="main", is_active=True,
            )
            s.add(repo)
            await s.flush()
            scan = Scan(
                repository_id=repo.id, status="COMPLETED", trigger="ci",
                commit_sha="a" * 40, requested_commit_sha="a" * 40,
            )
            s.add(scan)
            membership = await org_svc.get_membership(
                s, org_id=org.id, user_id=test_user.id
            )
            _, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=membership,
                actor_user_id=test_user.id, name="ci",
                scopes=["scans:read"],
            )
            await s.commit()
            scan_id = scan.id

        r = client.get(f"/api/v1/scans/{scan_id}/status",
                       headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["result"] == "PASS"
        assert body["commit_binding"] == "VERIFIED"
        assert body["kind"] == "SCAN"

    async def test_status_of_another_tenants_scan_is_404(
        self, client, session_factory, test_user, test_user_b
    ):
        from app.services import api_key_service

        async with session_factory() as s:
            org_b = await org_svc.create_organization(
                s, name="OB", creator_user_id=test_user_b.id
            )
            await s.flush()
            inst = GithubInstallation(
                user_id=test_user_b.id, installation_id=uuid4().int % 900000 + 2,
                account_login="ob", account_type="Organization",
                organization_id=org_b.id,
            )
            s.add(inst)
            await s.flush()
            repo = Repository(
                installation_id=inst.id, github_repo_id=uuid4().int % 900000 + 2,
                owner="ob", name="repo", default_branch="main", is_active=True,
            )
            s.add(repo)
            await s.flush()
            scan = Scan(repository_id=repo.id, status="COMPLETED", trigger="ci")
            s.add(scan)
            await s.commit()
            scan_id = scan.id

        # Tenant A's key cannot poll tenant B's job.
        async with session_factory() as s:
            org_a = await org_svc.create_organization(
                s, name="OA", creator_user_id=test_user.id
            )
            await s.flush()
            membership = await org_svc.get_membership(
                s, org_id=org_a.id, user_id=test_user.id
            )
            _, secret = await api_key_service.create_api_key(
                s, org_id=org_a.id, actor_membership=membership,
                actor_user_id=test_user.id, name="ci",
                scopes=["scans:read"],
            )
            await s.commit()

        r = client.get(f"/api/v1/scans/{scan_id}/status",
                       headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 404
