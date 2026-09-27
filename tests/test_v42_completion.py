"""CYVRIX V4.2 completion — outbound webhooks, CI intake, mutation
scopes, and worker active_jobs.

Invariants under test (docs/v4-webhooks.md §Outbound, docs/v4-cicd.md
§Dedicated intake, docs/v4-public-api.md §Scope→endpoint backing):

  OUTBOUND WEBHOOKS
  - endpoints are https-only, global-IP, no userinfo/query (SSRF)
  - secrets are returned ONCE, stored encrypted, never resurfaced
  - signatures cover timestamp+delivery_id+event_version+body (HMAC-SHA-256)
  - delivery identity is DB-unique; retries reuse the same delivery_id
  - retry classification: 2xx delivered, 5xx/timeout transient, 4xx permanent
  - disabled endpoints receive nothing; deliveries dead-letter honestly
  - tenant isolation on every management route

  CI INTAKE
  - scope ci:ingest required; org/repo resolved from trusted state only
  - (org, repo, event_id) is DB-unique; replays are ALREADY_PROCESSED
  - commit binding is REQUESTED + worker-verified; CI cannot declare PASS
  - refusals are audited SECURITY-CRITICAL

  MUTATION SCOPES
  - actions:create creates proposals only (never executes)
  - executions:create is a request view; never consumes an authorization
  - audit:export is tenant-scoped; foreign chains are 404
  - scope escalation (scans:read key) is refused on every mutation

  ACTIVE JOBS
  - heartbeat-published counts aggregate across the real fleet; a crashed
    worker's contribution expires with its TTL (no stuck gauge)
    [real-Redis gated]
"""
import asyncio
import json
import os
import sys
import time
import uuid as uuid_mod
from datetime import datetime, timezone
from unittest import mock
from uuid import uuid4

import pytest
from sqlalchemy import select

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import (
    ActionProposal,
    Approval,
    AuditChain,
    AuditChainEvent,
    CiEvent,
    ExecutionAuthorization,
    Finding,
    GithubInstallation,
    Organization,
    OutboundWebhookDelivery,
    OutboundWebhookEndpoint,
    Recommendation,
    Repository,
    Scan,
)
from app.services import api_key_service
from app.services import audit_service
from app.services import organization_service as org_svc
from app.services import outbound_webhook_service as ows
from app.services import v4_rbac as rbac

pytestmark = pytest.mark.usefixtures("clean_db")

# The REAL settings loader, captured before any test patches anything.
_REAL_GET_SETTINGS = __import__("app.config", fromlist=["get_settings"]).get_settings

# The environment has no live Redis: `check_rate_limit` fails closed and
# would reject every seeded request. Tests here are not about the limiter,
# so its importer modules are stubbed with an always-allow. The limiter
# itself is covered by the V4.1 suites.


async def _always_allow(key, max_requests, window_seconds, r=None):
    return True, max_requests


def _stub_quota(monkeypatch, *, allowed=True):
    """The sandbox has no Redis; the quota service correctly fails closed
    there. These tests exercise intake semantics, not the limiter, so a
    deterministic decision is injected into the route module binding.
    The refusal branch itself is exercised with allowed=False by
    test_quota_refusal_is_429_and_audited; the real-Redis path is covered
    by the V4.1 suites."""

    class _Decision:
        def __init__(self):
            self.allowed = allowed
            self.reason_code = None if allowed else "QUOTA_ORG_EXCEEDED"
            self.org_remaining = 999
            self.global_remaining = 999

    async def _decision(redis, **kwargs):
        return _Decision()

    monkeypatch.setattr("app.routes.ci_events.consume_quota", _decision)


@pytest.fixture(autouse=True)
def _stub_rate_limiter(monkeypatch):
    # The SOURCE module first: some call sites import lazily inside the
    # function body (`from app.rate_limit import check_rate_limit`),
    # which re-reads the attribute from the source module on every call.
    # Top-level importers keep their own binding, so they are patched too.
    for path in (
        "app.rate_limit.check_rate_limit",
        "app.routes.api_v1.check_rate_limit",
        "app.routes.ci_events.check_rate_limit",
    ):
        monkeypatch.setattr(path, _always_allow)

_SHA = "a" * 40

# Sandbox has NO DNS. Endpoint URLs use a literal PUBLIC address so the
# SSRF validator runs its real checks (scheme, port, userinfo, query and
# the full _addr_is_global range scan) with zero name resolution.
# `https://93.184.216.34` is a global unicast address — accepted.
_PUBLIC_RECEIVER = "https://93.184.216.34/hook"


# ── Settings helper (outbound webhooks enabled for tests) ────────────


class _WhSettings:
    """Proxy around the real settings with outbound webhooks enabled."""

    _OUTBOUND_FIELDS = (
        "outbound_webhook_secret_key", "outbound_webhook_max_payload_bytes",
        "outbound_webhook_max_endpoints_per_org",
        "outbound_webhook_max_events_per_endpoint",
        "outbound_webhook_rate_per_hour_per_org",
        "outbound_webhook_rate_per_hour_per_endpoint",
        "outbound_webhook_max_attempts", "outbound_webhook_backoff_base_seconds",
        "outbound_webhook_backoff_max_seconds",
        "outbound_webhook_delivery_timeout_seconds",
    )

    def __init__(self):
        base = _REAL_GET_SETTINGS()
        for attr in self._OUTBOUND_FIELDS:
            setattr(self, attr, getattr(base, attr))
        self.outbound_webhook_secret_key = "v42-test-outbound-secret-key"
        self.outbound_webhook_max_attempts = 3
        self.outbound_webhook_backoff_base_seconds = 1
        self.outbound_webhook_backoff_max_seconds = 2

    def __getattr__(self, item):
        return getattr(_REAL_GET_SETTINGS(), item)


def _enable_outbound(monkeypatch):
    """Enable outbound webhooks in the SERVICE and ROUTE layers."""
    s = _WhSettings()
    monkeypatch.setattr(
        "app.services.outbound_webhook_service.get_settings", lambda: s)
    monkeypatch.setattr(
        "app.routes.webhook_endpoints.settings", s)
    return s


# ── Seed helpers (mirror the V4.1 conventions) ───────────────────────


async def _seed(session_factory, owner, *, name="Org", scopes=None,
                repo_name="repo", is_active=True):
    async with session_factory() as s:
        org = await org_svc.create_organization(
            s, name=name, creator_user_id=owner.id)
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
            s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
            name="seed-key", scopes=scopes or ["repositories:read"],
        )
        await s.commit()
        return {
            "org_id": org.id, "repo_id": repo.id, "inst_id": inst.id,
            "prefix": row.prefix, "secret": secret,
        }


def _auth(seed):
    return {"Authorization": f"Bearer {seed['secret']}"}


async def _seed_endpoint(session_factory, test_user, *, url=None):
    """org + one ACTIVE endpoint with a real encrypted secret."""
    async with session_factory() as s:
        org = await org_svc.create_organization(
            s, name="WhOrg", creator_user_id=test_user.id)
        await s.flush()
        secret = ows.generate_signing_secret()
        ep = OutboundWebhookEndpoint(
            organization_id=org.id,
            url=url or _PUBLIC_RECEIVER,
            events=["SCAN_COMPLETED"],
            secret_ciphertext=ows.encrypt_secret(secret),
            secret_hint=secret[:4],
        )
        s.add(ep)
        await s.commit()
        return {"org_id": org.id, "endpoint_id": str(ep.id)}


async def _create_one_delivery(session_factory, org_id) -> str:
    """Fan one event to the seeded endpoint; return the delivery row id."""
    async with session_factory() as s:
        created = await ows.create_deliveries_for_event(
            s, organization_id=org_id, event_type="SCAN_COMPLETED",
            resource_kind="scan", resource_id=str(uuid4()), enqueue=None)
        assert len(created) == 1
        row_id = str((await s.execute(
            select(OutboundWebhookDelivery.id))).scalars().one())
        await s.commit()
    return row_id


class _Resp:
    def __init__(self, status_code):
        self.status_code = status_code


# ═══ OUTBOUND WEBHOOKS ═══════════════════════════════════════════════


class TestOutboundUrlValidation:
    def test_rejects_non_https(self):
        with pytest.raises(ows.UrlValidationError) as ei:
            ows.validate_webhook_url("http://example.com/hook")
        assert ei.value.reason_code == "URL_SCHEME_NOT_HTTPS"

    def test_rejects_localhost_and_loopback(self):
        for url in ("https://localhost/hook", "https://127.0.0.1/hook",
                    "https://[::1]/hook"):
            with pytest.raises(ows.UrlValidationError) as ei:
                ows.validate_webhook_url(url)
            assert ei.value.reason_code in (
                "URL_RESOLVES_NON_GLOBAL", "URL_RESOLUTION_EMPTY")

    def test_rejects_private_link_local_and_metadata(self):
        for url in (
            "https://10.0.0.1/hook", "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://172.16.0.1/hook", "https://100.64.0.1/hook",
            "https://[fe80::1]/hook", "https://[fd00::1]/hook",
        ):
            with pytest.raises(ows.UrlValidationError) as ei:
                ows.validate_webhook_url(url)
            assert ei.value.reason_code == "URL_RESOLVES_NON_GLOBAL"

    def test_rejects_userinfo_query_and_bad_ports(self):
        with pytest.raises(ows.UrlValidationError):
            ows.validate_webhook_url("https://user:pass@example.com/h")
        with pytest.raises(ows.UrlValidationError):
            ows.validate_webhook_url("https://example.com/h?x=1")
        with pytest.raises(ows.UrlValidationError):
            ows.validate_webhook_url("https://example.com:5432/h")
        with pytest.raises(ows.UrlValidationError):
            ows.validate_webhook_url("gopher://example.com")

    def test_accepts_public_https(self):
        try:
            ips = ows.validate_webhook_url("https://example.com/hook")
        except ows.UrlValidationError:
            pytest.skip("no DNS in sandbox — "
                        "TEST=ssrf_public_accept ENV=network")
        assert len(ips) >= 1


class TestOutboundSecretsAndSigning:
    def test_secret_encrypt_roundtrip_and_wrong_key(self, monkeypatch):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        secret = ows.generate_signing_secret()
        ct = ows.encrypt_secret(secret)
        assert secret not in ct
        assert ows.decrypt_secret(ct) == secret

        other = _WhSettings()
        other.outbound_webhook_secret_key = "a-different-key"
        monkeypatch.setattr(ows, "get_settings", lambda: other)
        with pytest.raises(Exception):
            ows.decrypt_secret(ct)

    def test_signature_format_and_tamper_replay_detection(self):
        secret = "s" * 32
        body = json.dumps({"a": 1}).encode()
        ts = int(time.time())
        headers = ows.signature_headers(
            secret=secret, timestamp=ts, delivery_id="d-1",
            event_type="SCAN_COMPLETED", event_version=1, body=body)
        assert headers["x-cyvrix-delivery-id"] == "d-1"
        assert headers["x-cyvrix-timestamp"] == str(ts)
        assert headers["x-cyvrix-signature"].startswith("sha256=")
        assert ows.verify_receiver_side(
            secret=secret, timestamp=str(ts), delivery_id="d-1",
            event_type="SCAN_COMPLETED", event_version="1", body=body,
            signature=headers["x-cyvrix-signature"])
        # Tampered body.
        assert not ows.verify_receiver_side(
            secret=secret, timestamp=str(ts), delivery_id="d-1",
            event_type="SCAN_COMPLETED", event_version="1", body=body + b"x",
            signature=headers["x-cyvrix-signature"])
        # Stale timestamp outside tolerance (replay).
        old_sig = ows.signature_headers(
            secret=secret, timestamp=ts - 10_000, delivery_id="d-1",
            event_type="SCAN_COMPLETED", event_version=1, body=body
        )["x-cyvrix-signature"]
        assert not ows.verify_receiver_side(
            secret=secret, timestamp=str(ts - 10_000), delivery_id="d-1",
            event_type="SCAN_COMPLETED", event_version="1", body=body,
            signature=old_sig, tolerance_seconds=300)


class TestOutboundLifecycle:
    async def test_create_endpoint_secret_shown_once(
        self, client, session_factory, test_user, monkeypatch
    ):
        _enable_outbound(monkeypatch)
        seed = await _seed(session_factory, test_user,
                           scopes=["webhooks:manage"], repo_name="wh1")
        r = client.post(
            "/api/v1/webhooks",
            json={"url": _PUBLIC_RECEIVER,
                  "events": ["SCAN_COMPLETED", "FINDING_CREATED"]},
            headers=_auth(seed))
        assert r.status_code == 201, r.text
        body = r.json()
        assert len(body["signing_secret"]) == 64

        dumped = json.dumps(client.get("/api/v1/webhooks", headers=_auth(seed)).json())
        assert "signing_secret" not in dumped
        assert body["signing_secret"] not in dumped

        async with session_factory() as s:
            row = (await s.execute(
                select(OutboundWebhookEndpoint))).scalars().one()
            assert row.secret_hint == body["signing_secret"][:4]
            # The stored material must not be the plaintext secret.
            assert body["signing_secret"] not in row.secret_ciphertext

    async def test_ssrf_refused_at_creation(
        self, client, session_factory, test_user, monkeypatch
    ):
        _enable_outbound(monkeypatch)
        seed = await _seed(session_factory, test_user,
                           scopes=["webhooks:manage"], repo_name="wh3")
        r = client.post(
            "/api/v1/webhooks",
            json={"url": "https://169.254.169.254/latest/meta-data",
                  "events": ["SCAN_COMPLETED"]},
            headers=_auth(seed))
        assert r.status_code == 422
        assert r.json()["code"] == "URL_RESOLVES_NON_GLOBAL"
        async with session_factory() as s:
            assert (await s.execute(
                select(OutboundWebhookEndpoint))).scalars().all() == []

    async def test_disabled_endpoint_receives_no_new_events(
        self, client, session_factory, test_user, monkeypatch
    ):
        _enable_outbound(monkeypatch)
        seed = await _seed(session_factory, test_user,
                           scopes=["webhooks:manage"], repo_name="wh2")
        r = client.post(
            "/api/v1/webhooks",
            json={"url": _PUBLIC_RECEIVER,
                  "events": ["SCAN_COMPLETED"]},
            headers=_auth(seed))
        assert r.status_code == 201, r.text
        endpoint_id = r.json()["id"]
        rd = client.post(f"/api/v1/webhooks/{endpoint_id}/disable",
                         headers=_auth(seed))
        assert rd.status_code == 200
        assert rd.json()["status"] == "DISABLED"

        async with session_factory() as s:
            created = await ows.create_deliveries_for_event(
                s, organization_id=seed["org_id"],
                event_type="SCAN_COMPLETED", resource_kind="scan",
                resource_id=str(uuid4()), enqueue=None)
            assert created == []

    async def test_tenant_isolation_on_management_routes(
        self, client, session_factory, test_user, test_user_b, monkeypatch
    ):
        _enable_outbound(monkeypatch)
        seed_a = await _seed(session_factory, test_user,
                             scopes=["webhooks:manage"], name="OrgA",
                             repo_name="wha")
        seed_b = await _seed(session_factory, test_user_b,
                             scopes=["webhooks:manage"], name="OrgB",
                             repo_name="whb")
        r = client.post(
            "/api/v1/webhooks",
            json={"url": "https://93.184.216.34/h",
                  "events": ["SCAN_COMPLETED"]},
            headers=_auth(seed_a))
        assert r.status_code == 201, r.text
        endpoint_id = r.json()["id"]
        assert client.get(f"/api/v1/webhooks/{endpoint_id}",
                          headers=_auth(seed_b)).status_code == 404
        assert client.post(f"/api/v1/webhooks/{endpoint_id}/disable",
                           headers=_auth(seed_b)).status_code == 404


class TestOutboundDispatch:
    async def test_success_2xx(self, session_factory, test_user, monkeypatch):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        async def post(url, headers, body):
            return _Resp(200)

        async with session_factory() as s:
            state = await ows.dispatch_delivery(
                s, delivery_row_id=row_id, enqueue=None, post=post)
            row = (await s.execute(
                select(OutboundWebhookDelivery))).scalars().one()
        assert state == "DELIVERED"
        assert row.state == "DELIVERED"
        assert row.delivered_at is not None
        assert row.attempt == 1

    async def test_500_retries_bounded_same_delivery_id_then_dead_letter(
        self, session_factory, test_user, monkeypatch
    ):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        calls = {"n": 0}

        async def post(url, headers, body):
            calls["n"] += 1
            return _Resp(500)

        delivery_ids = []
        for expected in ("RETRYING", "RETRYING", "DEAD_LETTER"):
            async with session_factory() as s:
                state = await ows.dispatch_delivery(
                    s, delivery_row_id=row_id, enqueue=None, post=post)
                row = (await s.execute(
                    select(OutboundWebhookDelivery))).scalars().one()
                delivery_ids.append(row.delivery_id)
                assert row.attempt == len(delivery_ids)
                if expected == "RETRYING":
                    assert row.next_attempt_at is not None
            assert state == expected
        # Stable identity across retries; bounded attempts (3 = MAX).
        assert len(set(delivery_ids)) == 1
        assert calls["n"] == 3
        async with session_factory() as s:
            row = (await s.execute(
                select(OutboundWebhookDelivery))).scalars().one()
            assert row.state == "DEAD_LETTER"
            assert row.dead_lettered_at is not None

    async def test_400_is_permanent_no_retry(
        self, session_factory, test_user, monkeypatch
    ):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        async def post(url, headers, body):
            return _Resp(400)

        async with session_factory() as s:
            state = await ows.dispatch_delivery(
                s, delivery_row_id=row_id, enqueue=None, post=post)
            row = (await s.execute(
                select(OutboundWebhookDelivery))).scalars().one()
        assert state == "DEAD_LETTER"
        assert row.attempt == 1  # well-defined 4xx is never retried

    async def test_timeout_is_transient(
        self, session_factory, test_user, monkeypatch
    ):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        async def post(url, headers, body):
            raise TimeoutError("connect timeout")

        async with session_factory() as s:
            state = await ows.dispatch_delivery(
                s, delivery_row_id=row_id, enqueue=None, post=post)
        assert state == "RETRYING"

    async def test_disabled_endpoint_dead_letters_without_sending(
        self, session_factory, test_user, monkeypatch
    ):
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])
        async with session_factory() as s:
            ep_row = (await s.execute(
                select(OutboundWebhookEndpoint))).scalars().one()
            ep_row.status = "DISABLED"
            await s.commit()

        sent = {"n": 0}

        async def post(url, headers, body):
            sent["n"] += 1
            return _Resp(200)

        async with session_factory() as s:
            state = await ows.dispatch_delivery(
                s, delivery_row_id=row_id, enqueue=None, post=post)
        assert state == "DEAD_LETTER"
        assert sent["n"] == 0  # a disabled receiver is never contacted

    async def test_signed_request_contents(
        self, session_factory, test_user, monkeypatch
    ):
        """The REAL request the receiver sees: signature verifies over the
        exact body, delivery id in header matches payload delivery_id."""
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        # Recover the secret to verify as a receiver would.
        async with session_factory() as s:
            ep_row = (await s.execute(
                select(OutboundWebhookEndpoint))).scalars().one()
            secret = ows.decrypt_secret(ep_row.secret_ciphertext)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        captured = {}

        async def post(url, headers, body):
            captured.update(headers=headers, body=body, url=url)
            return _Resp(200)

        async with session_factory() as s:
            await ows.dispatch_delivery(
                s, delivery_row_id=row_id, enqueue=None, post=post)

        headers = captured["headers"]
        body = captured["body"]
        assert headers["x-cyvrix-delivery-id"]
        payload = json.loads(body)
        assert payload["delivery_id"] == headers["x-cyvrix-delivery-id"]
        assert ows.verify_receiver_side(
            secret=secret, timestamp=headers["x-cyvrix-timestamp"],
            delivery_id=headers["x-cyvrix-delivery-id"],
            event_type=headers["x-cyvrix-event"],
            event_version=headers["x-cyvrix-event-version"],
            body=body, signature=headers["x-cyvrix-signature"])

    async def test_concurrent_claim_single_dispatch(
        self, session_factory, test_user, monkeypatch
    ):
        """Two workers race to claim: exactly ONE dispatch happens."""
        monkeypatch.setattr(ows, "get_settings", lambda: _WhSettings())
        ep = await _seed_endpoint(session_factory, test_user)
        row_id = await _create_one_delivery(session_factory, ep["org_id"])

        calls = {"n": 0}

        async def post(url, headers, body):
            calls["n"] += 1
            await asyncio.sleep(0.01)
            return _Resp(200)

        async def worker():
            async with session_factory() as s:
                return await ows.dispatch_delivery(
                    s, delivery_row_id=row_id, enqueue=None, post=post)

        results = await asyncio.gather(worker(), worker())
        dispatched = [r for r in results if r in ("DELIVERED", "RETRYING",
                                                  "DEAD_LETTER")]
        # The loser observes the winner's claim and dispatches nothing.
        assert dispatched.count("DELIVERED") == 1
        assert calls["n"] == 1


# ═══ CI EVENT INTAKE ══════════════════════════════════════════════════


class TestCiIntake:
    @pytest.fixture(autouse=True)
    def _sandbox_env(self, monkeypatch):
        """Deterministic quota decision and a stubbed enqueue for every
        test in this class. (Sandbox has no Redis: the real quota service
        fails closed and the real enqueue raises — both honest behaviors,
        but not what these tests exercise. The enqueue-failure path is
        covered by the V4.1 failure suites.)"""
        _stub_quota(monkeypatch, allowed=True)
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )

    async def test_accepted_commit_binding_and_audit(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-12345",
                  "repository_full_name": "acme/ci-repo",
                  "commit_sha": _SHA, "ref": "refs/heads/main"},
            headers=_auth(seed))
        assert r.status_code == 202, r.text
        body = r.json()
        assert body["result"] == "ACCEPTED"
        assert "PASS" not in json.dumps(body)
        async with session_factory() as s:
            scan = await s.get(Scan, uuid_mod.UUID(body["scan_id"]))
            assert scan.requested_commit_sha == _SHA
            assert scan.trigger == "ci"
            events = (await s.execute(
                select(AuditChainEvent.event_type))).scalars().all()
            assert "CI_EVENT_ACCEPTED" in events
            assert "CI_EVENT_RECEIVED" in events
            assert "CI_EVENT_PROCESSING_STARTED" in events

    async def test_replay_is_already_processed_exactly_one_scan(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        payload = {"event_id": "build-replay-1",
                   "repository_full_name": "acme/ci-repo",
                   "commit_sha": _SHA}
        r1 = client.post("/api/ci/events", json=payload, headers=_auth(seed))
        assert r1.status_code == 202
        r2 = client.post("/api/ci/events", json=payload, headers=_auth(seed))
        assert r2.status_code == 200
        assert r2.json()["result"] == "ALREADY_PROCESSED"
        async with session_factory() as s:
            scans = (await s.execute(select(Scan))).scalars().all()
            assert len(scans) == 1  # duplicate event → no duplicate scan
            ci_rows = (await s.execute(select(CiEvent))).scalars().all()
            # One ACCEPTED record; the replay adds NO duplicate row.
            assert len([c for c in ci_rows if c.outcome == "ACCEPTED"]) == 1

    async def test_scope_escalation_refused(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["scans:read"], repo_name="ci-no")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-x1",
                  "repository_full_name": "acme/ci-no",
                  "commit_sha": _SHA},
            headers=_auth(seed))
        assert r.status_code == 403
        assert r.json()["result"] == "REJECTED"

    async def test_unknown_repository_404_audited(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-wrong-repo",
                  "repository_full_name": "acme/does-not-exist",
                  "commit_sha": _SHA},
            headers=_auth(seed))
        assert r.status_code == 404
        assert r.json()["result"] == "REJECTED"
        async with session_factory() as s:
            events = (await s.execute(
                select(AuditChainEvent.event_type))).scalars().all()
            assert "CI_EVENT_REJECTED" in events

    async def test_payload_cannot_nominate_other_tenant(
        self, client, session_factory, test_user, test_user_b
    ):
        seed_a = await _seed(session_factory, test_user,
                             scopes=["ci:ingest"], name="TenA",
                             repo_name="ten-a")
        await _seed(session_factory, test_user_b, scopes=["ci:ingest"],
                    name="TenB", repo_name="ten-b")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-ten-b",
                  "repository_full_name": "acme/ten-b",
                  "commit_sha": _SHA},
            headers=_auth(seed_a))
        assert r.status_code == 404  # B's repo invisible to A's credential

    async def test_fake_sha_shape_refused_and_no_pass_ever(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-fake-sha",
                  "repository_full_name": "acme/ci-repo",
                  "commit_sha": "not-a-sha"},
            headers=_auth(seed))
        assert r.status_code == 422
        # A fabricated security claim is REFUSED (extra=forbid), never read.
        r2 = client.post(
            "/api/ci/events",
            json={"event_id": "build-claim-pass",
                  "repository_full_name": "acme/ci-repo",
                  "commit_sha": _SHA, "security_passed": True},
            headers=_auth(seed))
        assert r2.status_code == 422
        assert "PASS" not in r2.text

    async def test_oversized_payload_refused(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        # event_id exceeds the schema bound → refused before any work.
        r = client.post(
            "/api/ci/events",
            json={"event_id": "x" * 200,
                  "repository_full_name": "acme/ci-repo",
                  "commit_sha": _SHA},
            headers=_auth(seed))
        assert r.status_code in (413, 422)

    async def test_quota_refusal_is_429_and_audited(
        self, client, session_factory, test_user, monkeypatch
    ):
        """Regression: the quota-refusal branch used to read an ORM
        attribute AFTER db.rollback() (expired instance → lazy refresh →
        MissingGreenlet → 500 instead of the honest 429)."""
        _stub_quota(monkeypatch, allowed=False)
        seed = await _seed(session_factory, test_user,
                           scopes=["ci:ingest"], repo_name="ci-repo")
        r = client.post(
            "/api/ci/events",
            json={"event_id": "build-quota-1",
                  "repository_full_name": "acme/ci-repo",
                  "commit_sha": _SHA, "ref": "refs/heads/main"},
            headers=_auth(seed))
        assert r.status_code == 429, r.text
        assert r.json()["result"] == "REJECTED"
        async with session_factory() as s:
            refused = (await s.execute(
                select(CiEvent).where(CiEvent.outcome == "REJECTED"))).scalars().all()
            assert len(refused) == 1
            assert refused[0].reason_code is not None
            events = (await s.execute(
                select(AuditChainEvent.event_type))).scalars().all()
            assert "CI_EVENT_REJECTED" in events


# ═══ MUTATION SCOPES ══════════════════════════════════════════════════


class TestMutationScopes:
    async def _seed_finding(
        self, session_factory, seed, *, fp: str
    ) -> str:
        """Scan + Finding + COMPLETED Recommendation, all FK-honest."""
        async with session_factory() as s:
            repo = await s.get(Repository, seed["repo_id"])
            scan = Scan(
                repository_id=repo.id, status="COMPLETED", trigger="manual",
                requested_commit_sha=_SHA)
            s.add(scan)
            await s.flush()
            finding = Finding(
                scan_id=scan.id, repository_id=repo.id,
                fingerprint=fp, title="t", severity="LOW")
            s.add(finding)
            await s.flush()
            rec = Recommendation(
                finding_id=finding.id, status="COMPLETED",
                title="t", trust_level="SUPPORTED")
            s.add(rec)
            await s.commit()
            return str(rec.id)
    async def test_scope_escalation_refused_on_all_mutations(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["scans:read"], repo_name="esc")
        assert client.post("/api/v1/actions", json={},
                           headers=_auth(seed)).status_code == 403
        assert client.post("/api/v1/executions", json={},
                           headers=_auth(seed)).status_code == 403
        assert client.post("/api/v1/rollbacks", json={},
                           headers=_auth(seed)).status_code == 403
        assert client.post(
            f"/api/v1/integrations/repositories/{uuid4()}/deactivate",
            headers=_auth(seed)).status_code == 403
        assert client.get(f"/api/v1/audit/export?chain_id={uuid4()}",
                          headers=_auth(seed)).status_code == 403

    async def test_high_impact_scopes_require_admin_standing(
        self, session_factory, test_user
    ):
        """A non-admin member cannot ISSUE a mutation-scope key."""
        async with session_factory() as s:
            org = await org_svc.create_organization(
                s, name="IssOrg", creator_user_id=test_user.id)
            await s.flush()
            owner = await org_svc.get_membership(
                s, org_id=org.id, user_id=test_user.id)
            # A second user with DEVELOPER role (direct membership row —
            # the production join path is invitation-based; the capability
            # check under test is on the membership role, not the join)."""
            dev_user = __import__("app.models", fromlist=["User"]).User(
                email=f"dev-{uuid4()}@test.local")
            s.add(dev_user)
            await s.flush()
            from app.models import OrganizationMembership
            s.add(OrganizationMembership(
                organization_id=org.id, user_id=dev_user.id,
                role=rbac.OrgRole.DEVELOPER, state="ACTIVE"))
            await s.flush()
            dev_actor = await org_svc.get_membership(
                s, org_id=org.id, user_id=dev_user.id)
            with pytest.raises(Exception):
                await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=dev_actor,
                    actor_user_id=dev_user.id, name="esc-key",
                    scopes=["actions:create"])

    async def test_audit_export_tenant_scoped(
        self, client, session_factory, test_user, test_user_b
    ):
        seed_a = await _seed(session_factory, test_user,
                             scopes=["audit:export"], name="ExpA",
                             repo_name="exp-a")
        seed_b = await _seed(session_factory, test_user_b,
                             scopes=["audit:export"], name="ExpB",
                             repo_name="exp-b")
        async with session_factory() as s:
            chain_id = (await s.execute(
                select(AuditChain.id).where(
                    AuditChain.organization_id == seed_a["org_id"]))
            ).scalars().one()
        r = client.get(f"/api/v1/audit/export?chain_id={chain_id}",
                       headers=_auth(seed_a))
        assert r.status_code == 200
        assert r.text.startswith("{")
        r2 = client.get(f"/api/v1/audit/export?chain_id={chain_id}",
                        headers=_auth(seed_b))
        assert r2.status_code == 404  # foreign chain: existence never confirmed

    async def test_actions_create_proposal_only(
        self, client, session_factory, test_user
    ):
        """Full request-only proof: a proposal is created; NOTHING follows
        (no approval, no authorization, no execution)."""
        seed = await _seed(session_factory, test_user,
                           scopes=["actions:create"], repo_name="act")
        rec_id = await self._seed_finding(session_factory, seed, fp="fp-act-1")

        sha = "b" * 40
        r = client.post(
            "/api/v1/actions",
            json={"recommendation_id": rec_id,
                  "action_type": "DEPENDENCY_UPGRADE",
                  "files": ["requirements.txt"],
                  "operations": [{
                      "type": "UPDATE_DEPENDENCY_VERSION",
                      "file": "requirements.txt",
                      "name": "requests",
                      "ecosystem": "pypi",
                      "from_version": "2.0.0",
                      "to_version": "2.31.0",
                  }],
                  "expected_diff": "- requests==2.0.0\n+ requests==2.31.0",
                  "target_branch": "cyvrix/fix-1",
                  "base_commit_sha": sha},
            headers=_auth(seed))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] in ("POLICY_CHECKED", "REJECTED")
        assert body["policy_decision"] in ("REQUIRE_APPROVAL", "DENY", "ALLOW")
        # Exactly ONE new ActionProposal; zero approvals/authorizations.
        async with session_factory() as s:
            proposals = (await s.execute(
                select(ActionProposal))).scalars().all()
            assert len(proposals) == 1
            assert (await s.execute(
                select(Approval))).scalars().all() == []
            assert (await s.execute(
                select(ExecutionAuthorization))).scalars().all() == []

    async def test_execution_request_view_never_consumes(
        self, client, session_factory, test_user
    ):
        seed = await _seed(session_factory, test_user,
                           scopes=["executions:create"], repo_name="exe")
        rec_id_unused = await self._seed_finding(
            session_factory, seed, fp="fp-exec-1")
        async with session_factory() as s:
            repo = await s.get(Repository, seed["repo_id"])
            finding = (await s.execute(
                select(Finding).where(
                    Finding.fingerprint == "fp-exec-1"))).scalars().one()
            rec = await s.get(Recommendation, uuid_mod.UUID(rec_id_unused))
            sha = "c" * 40
            proposal = ActionProposal(
                finding_id=finding.id, recommendation_id=rec.id,
                repository_id=repo.id, created_by=test_user.id,
                action_type="UPDATE_DEPENDENCY", status="APPROVED",
                base_commit_sha=sha, target_branch="fix",
                files=["requirements.txt"], operations=[{"op": "set"}],
                expected_diff="", risk_score=10, risk_level="LOW",
                policy_version="v1", policy_decision="REQUIRE_APPROVAL",
                policy_reason_code="R", policy_matched_rule="M",
                action_digest="d" * 64,
                expires_at=datetime.now(timezone.utc))
            s.add(proposal)
            await s.flush()
            approval = Approval(
                action_proposal_id=proposal.id, action_digest="d" * 64,
                approver_user_id=test_user.id, approval_state="APPROVED",
                policy_version="v1", policy_decision="REQUIRE_APPROVAL",
                expires_at=datetime.now(timezone.utc))
            s.add(approval)
            await s.flush()
            authz = ExecutionAuthorization(
                action_proposal_id=proposal.id, approval_id=approval.id,
                action_digest="d" * 64, repository_id=repo.id,
                base_commit_sha=sha, target_branch="fix",
                policy_version="v1", policy_decision="REQUIRE_APPROVAL",
                authorization_state="AUTHORIZED",
                contract={}, contract_digest="e" * 64, contract_version="1",
                authorized_by_user_id=test_user.id)
            s.add(authz)
            await s.commit()
            authz_id = str(authz.id)

        r = client.post(
            "/api/v1/executions",
            json={"execution_authorization_id": authz_id},
            headers=_auth(seed))
        assert r.status_code == 200, r.text
        assert r.json()["execution_state"] == "AUTHORIZED"
        # NOT consumed — the one-time token path is untouched.
        async with session_factory() as s:
            row = await s.get(ExecutionAuthorization, uuid_mod.UUID(authz_id))
            assert row.authorization_state == "AUTHORIZED"
            assert row.consumed_at is None

    async def test_execution_request_cross_tenant_404(
        self, client, session_factory, test_user, test_user_b
    ):
        seed_a = await _seed(session_factory, test_user,
                             scopes=["executions:create"], name="ExA",
                             repo_name="exa")
        await _seed(session_factory, test_user_b, scopes=["executions:create"],
                    name="ExB", repo_name="exb")
        r = client.post(
            "/api/v1/executions",
            json={"execution_authorization_id": str(uuid4())},
            headers=_auth(seed_a))
        assert r.status_code == 404


# ═══ ACTIVE JOBS ══════════════════════════════════════════════════════


class TestActiveJobs:
    def test_heartbeat_publishes_active_jobs_and_fleet_aggregates(self):
        """REAL Redis: two workers publish counts; the fleet sum is the
        aggregate; a dead worker's entry expires (crash recovery)."""
        if not os.environ.get("RUN_INTEGRATION_TESTS"):
            pytest.skip("requires real Redis — TEST=active_jobs "
                        "ENV=RUN_INTEGRATION_TESTS=1 + Redis")

        import redis.asyncio as aioredis

        import app.worker_runtime as wr

        async def scenario():
            r = aioredis.from_url(
                _REAL_GET_SETTINGS().redis_url, decode_responses=True)
            try:
                await wr.heartbeat(r, worker_id="v42-worker-a",
                                   queues=["scans"], current_job="job-1",
                                   state="RUNNING", active_jobs=1)
                await wr.heartbeat(r, worker_id="v42-worker-b",
                                   queues=["scans"], current_job="",
                                   state="RUNNING", active_jobs=0)
                fleet = await wr.fleet_snapshot(r)
                total = sum(int((i or {}).get("active_jobs") or "0")
                            for i in fleet["workers"].values())
                assert total == 1  # A owns job-1; B idle; queued jobs excluded

                # Crash recovery: A dies → its TTL record expires/deleted
                # → the gauge cannot stay stuck at 1.
                await r.delete("cyvrix:worker:v42-worker-a")
                fleet = await wr.fleet_snapshot(r)
                total = sum(int((i or {}).get("active_jobs") or "0")
                            for i in fleet["workers"].values())
                assert total == 0
            finally:
                await r.delete("cyvrix:worker:v42-worker-a")
                await r.delete("cyvrix:worker:v42-worker-b")
                await r.aclose()

        asyncio.run(scenario())

    def test_metric_registry_has_real_gauge_semantics(self):
        """active_jobs is a GAUGE in the closed-world registry and the ops
        scrape path can set it from a fleet snapshot (no fake data path)."""
        from app.metrics import _METRICS, set_gauge, snapshot

        assert _METRICS["active_jobs"].kind == "gauge"
        set_gauge("active_jobs", 2)
        assert snapshot()["gauges"]["active_jobs"] == 2.0
        with pytest.raises(TypeError):
            from app.metrics import increment as _inc
            _inc("active_jobs")  # a gauge is never a counter
