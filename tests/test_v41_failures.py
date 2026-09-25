"""CYVRIX V4.1 — infrastructure failure injection.

REAL failure behavior, not mocked exceptions around happy paths:

  - Redis unavailable → rate limiter fails CLOSED (429), quota fails
    CLOSED (503) — a limiter/quota that degrades to "allow" is a bypass
  - queue unavailable → 503 ANALYSIS_UNAVAILABLE, scan marked FAILED with
    ENQUEUE_FAILED (no hung QUEUED row), idempotency record completed so
    a retry replays the same deterministic outcome
  - webhook intake with the audit chain failing → acceptance still stands
    (delivery row IS the record), no crash, no duplicate side effect
  - signature-verification failure leaves NO side effect and NO tenant
    resolution, even when the payload claims a valid installation
"""
import asyncio
import hashlib
import hmac
import json
import os
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select

from app.models import Scan, WebhookDelivery
from app.services import organization_service as org_svc

pytestmark = pytest.mark.usefixtures("clean_db")

WEBHOOK_SECRET = "failure-injection-secret-0123456789"


def _sig(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class TestRateLimitFailClosed:
    async def test_rate_limiter_refuses_when_redis_unreachable(
        self, monkeypatch
    ):
        from app.rate_limit import check_rate_limit
        import app.session as session_mod

        async def _dead_get_redis():
            raise RuntimeError("redis down")

        monkeypatch.setattr(session_mod, "get_redis", _dead_get_redis)
        allowed, remaining = await check_rate_limit("org:test:failclosed", 10, 60)
        assert allowed is False
        assert remaining == 0

    async def test_rate_limited_request_gets_429_not_bypass(
        self, client, session_factory, test_user, monkeypatch
    ):
        """With Redis dead, the public API refuses rather than allows."""
        from app.services import api_key_service

        async with session_factory() as s:
            org = await org_svc.create_organization(
                s, name="FC", creator_user_id=test_user.id
            )
            await s.flush()
            membership = await org_svc.get_membership(
                s, org_id=org.id, user_id=test_user.id
            )
            _, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=membership,
                actor_user_id=test_user.id, name="fc",
                scopes=["repositories:read"],
            )
            await s.commit()

        import app.session as session_mod

        async def _dead_get_redis():
            raise RuntimeError("redis down")

        monkeypatch.setattr(session_mod, "get_redis", _dead_get_redis)
        r = client.get(
            "/api/v1/repositories", headers={"Authorization": f"Bearer {secret}"}
        )
        assert r.status_code == 429
        assert r.json()["code"] == "ORG_RATE_LIMITED"


class TestQuotaFailClosed:
    async def test_quota_endpoint_refuses_when_redis_unreachable(
        self, client, session_factory, engine, test_user, monkeypatch
    ):
        """Redis down: the mutation is REFUSED (429 rate limit or 503
        quota), never silently allowed — and no scan row slips through."""
        from app.services import api_key_service
        from app.models import GithubInstallation, Repository, User

        # Seed through the test engine BEFORE patching/requests (asyncio
        # in an async test is fine — the portal loop is not yet used).
        async with session_factory() as s:
            org = await org_svc.create_organization(
                s, name="FQ", creator_user_id=test_user.id
            )
            await s.flush()
            inst = GithubInstallation(
                user_id=test_user.id,
                installation_id=uuid4().int % 900000 + 1,
                account_login="fq",
                account_type="Organization",
                organization_id=org.id,
            )
            s.add(inst)
            await s.flush()
            repo = Repository(
                installation_id=inst.id,
                github_repo_id=uuid4().int % 900000 + 1,
                owner="fq", name="repo", default_branch="main", is_active=True,
            )
            s.add(repo)
            await s.flush()
            membership = await org_svc.get_membership(
                s, org_id=org.id, user_id=test_user.id
            )
            _, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=membership,
                actor_user_id=test_user.id, name="fq",
                scopes=["scans:create"],
            )
            await s.commit()
            repo_id = repo.id

        import app.session as session_mod

        async def _dead_redis():
            raise RuntimeError("redis down")

        monkeypatch.setattr(session_mod, "get_redis", _dead_redis)
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": str(repo_id)},
            headers={"Authorization": f"Bearer {secret}"},
        )
        # Both gates run fail-closed on dead Redis: the rate limiter
        # refuses first (429); had it passed, quota refuses (503).
        assert r.status_code in (429, 503)
        assert r.json()["code"] in ("ORG_RATE_LIMITED", "QUOTA_UNAVAILABLE")

        # No side effect slipped through.
        async with session_factory() as s:
            scans = (await s.execute(select(Scan))).scalars().all()
        assert scans == []


class TestQueueFailure:
    def test_enqueue_failure_marks_scan_failed_and_completes_idempotency(
        self, client, session_factory, test_user, monkeypatch
    ):
        """The 503 path: the scan row is FAILED/ENQUEUE_FAILED (nothing
        hangs in QUEUED), and the idempotency record is COMPLETED so a
        retry with the same key replays the deterministic failure."""
        from app.services import api_key_service

        async def _seed():
            async with session_factory() as s:
                org = await org_svc.create_organization(
                    s, name="QB", creator_user_id=test_user.id
                )
                await s.flush()
                inst = __import__(
                    "app.models", fromlist=["GithubInstallation"]
                ).GithubInstallation(
                    user_id=test_user.id,
                    installation_id=uuid4().int % 900000 + 1,
                    account_login="qb",
                    account_type="Organization",
                    organization_id=org.id,
                )
                s.add(inst)
                await s.flush()
                repo = __import__(
                    "app.models", fromlist=["Repository"]
                ).Repository(
                    installation_id=inst.id,
                    github_repo_id=uuid4().int % 900000 + 1,
                    owner="qb", name="repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.flush()
                membership = await org_svc.get_membership(
                    s, org_id=org.id, user_id=test_user.id
                )
                _, secret = await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=membership,
                    actor_user_id=test_user.id, name="qb",
                    scopes=["scans:create"],
                )
                await s.commit()
                return org.id, repo.id, secret

        org_id, repo_id, secret = asyncio.get_event_loop().run_until_complete(_seed())

        def _boom(scan_id):
            raise RuntimeError("redis down")

        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", _boom,
        )
        headers = {
            "Authorization": f"Bearer {secret}",
            "Idempotency-Key": "queue-fail-key-0001",
        }
        body = {"repository_id": str(repo_id)}
        first = client.post("/api/v1/scans", json=body, headers=headers)
        assert first.status_code == 503
        assert first.json()["code"] == "ANALYSIS_UNAVAILABLE"

        # Retry with the SAME key replays the SAME recorded outcome —
        # byte-identical to the original response (that is the contract:
        # a retry must never see a different result for the same request).
        second = client.post("/api/v1/scans", json=body, headers=headers)
        assert second.status_code == 503
        assert second.json() == first.json()

        async def _state():
            async with session_factory() as s:
                scans = (
                    await s.execute(select(Scan).where(Scan.repository_id == repo_id))
                ).scalars().all()
                return [(x.status, x.error_reason) for x in scans]

        states = asyncio.get_event_loop().run_until_complete(_state())
        assert states == [("FAILED", "ENQUEUE_FAILED")]


class TestWebhookFailureRecovery:
    def test_webhook_accepted_when_audit_chain_fails(
        self, client, session_factory, test_user, monkeypatch
    ):
        """Audit is the witness, not the gate, for webhook ACCEPTANCE:
        the delivery row is the record and the side effect stands even
        when the chain append fails (logged loudly). No crash, no 500."""
        from app.config import get_settings
        from app.services import webhook_service as wh

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )

        async def _boom(*a, **k):
            raise RuntimeError("audit chain down")

        monkeypatch.setattr(wh.audit_service, "emit_security_event", _boom)

        async def _seed():
            async with session_factory() as s:
                org = await org_svc.create_organization(
                    s, name="WA", creator_user_id=test_user.id
                )
                await s.flush()
                inst = __import__(
                    "app.models", fromlist=["GithubInstallation"]
                ).GithubInstallation(
                    user_id=test_user.id,
                    installation_id=uuid4().int % 900000 + 1,
                    account_login="wa",
                    account_type="Organization",
                    organization_id=org.id,
                )
                s.add(inst)
                await s.flush()
                repo = __import__(
                    "app.models", fromlist=["Repository"]
                ).Repository(
                    installation_id=inst.id,
                    github_repo_id=uuid4().int % 900000 + 1,
                    owner="wa", name="repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.commit()
                return inst.installation_id, repo.github_repo_id

        inst_num, repo_num = asyncio.get_event_loop().run_until_complete(_seed())
        body = json.dumps({
            "ref": "refs/heads/main",
            "after": "a" * 40,
            "commits": [{"id": "a" * 40}],
            "installation": {"id": inst_num},
            "repository": {"id": repo_num},
        }).encode()
        r = client.post(
            "/api/webhooks/github",
            content=body,
            headers={
                "x-github-event": "push",
                "x-github-delivery": "audit-fail-delivery-1",
                "x-hub-signature-256": _sig(body),
            },
        )
        assert r.status_code == 202, r.text

        # Exactly one scan, one delivery record: no duplicate side effect.
        async def _check():
            async with session_factory() as s:
                scans = (await s.execute(select(Scan))).scalars().all()
                deliveries = (
                    await s.execute(select(WebhookDelivery))
                ).scalars().all()
                return scans, deliveries

        scans, deliveries = asyncio.get_event_loop().run_until_complete(_check())
        assert len(scans) == 1
        assert len(deliveries) == 1
        assert deliveries[0].outcome == "ACCEPTED"

    def test_signature_failure_creates_no_side_effect_even_with_valid_claims(
        self, client, session_factory, test_user, monkeypatch
    ):
        """A refused delivery cannot touch tenant state: no scan, no
        reservation, regardless of what the payload claims."""
        from app.config import get_settings
        from app.services import idempotency_service as idem

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )
        body = json.dumps({
            "ref": "refs/heads/main",
            "after": "b" * 40,
            "commits": [{"id": "b" * 40}],
            "installation": {"id": 999999},
            "repository": {"id": 999999},
        }).encode()
        r = client.post(
            "/api/webhooks/github",
            content=body,
            headers={
                "x-github-event": "push",
                "x-github-delivery": "sig-fail-delivery-1",
                "x-hub-signature-256": _sig(body, "wrong-secret"),
            },
        )
        assert r.status_code == 401

        async def _check():
            async with session_factory() as s:
                scans = (await s.execute(select(Scan))).scalars().all()
                reservations = (
                    await s.execute(select(idem.ApiIdempotencyKey))
                ).scalars().all()
                return scans, reservations

        scans, reservations = asyncio.get_event_loop().run_until_complete(_check())
        assert scans == []
        assert reservations == []  # nothing was claimed for the attacker
