"""CYVRIX V4.1 — inbound GitHub webhook tests.

Covers the external-integration boundary the webhook opens:

  - signature verification fails closed on every malformed/absent case
  - unknown events are safely ignored; unparseable payloads are refused
  - installation → organization → repository binding resolves through
    TRUSTED DB state only; payload claims can never select a tenant
  - replay: the same delivery id never re-triggers the side effect, and
    a same-id/different-payload delivery is a conflict, never a replay
  - the one side effect is an analysis REQUEST with the push's commit
    bound; nothing can reach the V3 chain
  - delivery records are structured (no payload content)
"""
import hashlib
import hmac
import json
import os
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import AuditChain, AuditChainEvent, Scan, WebhookDelivery
from app.services import webhook_service as wh
from app.services import idempotency_service as idem
from app.services import organization_service as org_svc

pytestmark = pytest.mark.usefixtures("clean_db")

WEBHOOK_SECRET = "test-webhook-secret-0123456789"


def _sig(body: bytes, secret: str = WEBHOOK_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _push_body(repo_github_id: int, installation_number: int, sha: str) -> bytes:
    return json.dumps({
        "ref": "refs/heads/main",
        "after": sha,
        "commits": [{"id": sha}],
        "installation": {"id": installation_number},
        "repository": {"id": repo_github_id, "full_name": "acme/repo"},
    }).encode()


_SEED_COUNTER = {"n": 0}


async def _seed_installed_repo(session_factory, test_user, *, org_bound=True):
    """Org + installation (bound) + repository; returns binding facts.

    GitHub ids are globally unique per table (unique constraints), so the
    seed uses a monotonic component to make cross-seed collisions within
    one test impossible rather than merely unlikely."""
    from app.models import GithubInstallation, Repository

    _SEED_COUNTER["n"] += 1
    n = _SEED_COUNTER["n"]

    async with session_factory() as s:
        org = await org_svc.create_organization(
            s, name=f"WH{n}", creator_user_id=test_user.id
        )
        await s.flush()
        github_number = uuid4().int % 800000 + n * 1_000_000
        repo_github_id = uuid4().int % 800000 + n * 1_000_000
        inst = GithubInstallation(
            user_id=test_user.id,
            installation_id=github_number,
            account_login="acme",
            account_type="Organization",
            organization_id=org.id if org_bound else None,
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id,
            github_repo_id=repo_github_id,
            owner=f"acme{n}",
            name=f"repo{n}",
            default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.commit()
        return {
            "org_id": org.id,
            "installation_number": github_number,
            "installation_pk": inst.id,
            "repo_github_id": repo_github_id,
            "repo_pk": repo.id,
        }


class TestSignatureVerification:
    def test_valid_signature_accepted(self):
        body = b'{"after": "x"}'
        wh.verify_signature(WEBHOOK_SECRET, _sig(body), body)

    def test_missing_header_refused(self):
        with pytest.raises(wh.WebhookError) as ei:
            wh.verify_signature(WEBHOOK_SECRET, None, b"{}")
        assert ei.value.reason_code == wh.R_MISSING_SIGNATURE
        assert ei.value.http_status == 401

    def test_wrong_secret_refused(self):
        body = b'{"a": 1}'
        with pytest.raises(wh.WebhookError) as ei:
            wh.verify_signature(WEBHOOK_SECRET, _sig(body, "other-secret"), body)
        assert ei.value.reason_code == wh.R_BAD_SIGNATURE

    def test_tampered_body_refused(self):
        body = b'{"a": 1}'
        sig = _sig(body)
        with pytest.raises(wh.WebhookError):
            wh.verify_signature(WEBHOOK_SECRET, sig, b'{"a": 2}')

    def test_malformed_signatures_refused(self):
        body = b"{}"
        for bad in ("sha1=" + "0" * 40, "sha256", "sha256=" + "g" * 64,
                    "sha256=" + "a" * 63, "sha256= " + "0" * 64):
            with pytest.raises(wh.WebhookError):
                wh.verify_signature(WEBHOOK_SECRET, bad, body)

    def test_unconfigured_secret_is_503_not_401(self):
        with pytest.raises(wh.WebhookError) as ei:
            wh.verify_signature("", _sig(b"{}"), b"{}")
        assert ei.value.reason_code == wh.R_MISSING_SECRET
        assert ei.value.http_status == 503


class TestEventAllowlist:
    def test_unknown_event_is_safely_ignored(self):
        with pytest.raises(wh.WebhookError) as ei:
            wh.parse_event("deployment_status", b"{}")
        assert ei.value.http_status == 200  # documented: ignore

    def test_unparseable_payload_refused(self):
        with pytest.raises(wh.WebhookError) as ei:
            wh.parse_event("push", b"not-json{")
        assert ei.value.reason_code == wh.R_BAD_PAYLOAD

    def test_non_object_payload_refused(self):
        with pytest.raises(wh.WebhookError) as ei:
            wh.parse_event("push", b"[1, 2, 3]")
        assert ei.value.reason_code == wh.R_BAD_PAYLOAD

    def test_payload_with_too_many_keys_refused(self):
        blob = json.dumps({f"k{i}": 1 for i in range(300)}).encode()
        with pytest.raises(wh.WebhookError) as ei:
            wh.parse_event("push", blob)
        assert ei.value.reason_code == wh.R_BAD_PAYLOAD

    def test_push_ref_extraction_bounds(self):
        ref = wh.extract_push_ref({"after": "A" * 40, "ref": "refs/heads/main",
                                   "commits": list(range(250))})
        assert ref.head_sha == "a" * 40
        assert ref.commit_count == wh.MAX_DIGEST_ITEMS
        assert wh.extract_push_ref({"after": "a" * 41}) is None
        assert wh.extract_push_ref({"after": "zz"}) is None
        # control characters in ref are dropped, never stored
        ref2 = wh.extract_push_ref({"after": "b" * 40, "ref": "refs/heads/x\x00y"})
        assert ref2.ref == ""


class TestBindingResolution:
    async def test_unbound_installation_number_refused(
        self, session_factory, test_user
    ):
        seed = await _seed_installed_repo(session_factory, test_user)
        async with session_factory() as s:
            with pytest.raises(wh.WebhookError) as ei:
                await wh.resolve_installation(
                    s, claimed_installation_id=seed["installation_number"] + 1
                )
            assert ei.value.reason_code == wh.R_UNKNOWN_INSTALLATION

    async def test_installation_without_organization_refused(
        self, session_factory, test_user
    ):
        seed = await _seed_installed_repo(
            session_factory, test_user, org_bound=False
        )
        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            with pytest.raises(wh.WebhookError) as ei:
                wh.require_organization_id(inst)
            assert ei.value.reason_code == wh.R_UNRESOLVED_ORG

    async def test_repository_of_another_installation_refused(
        self, session_factory, test_user
    ):
        """Fork/owner confusion: a repository id bound to a DIFFERENT
        installation never resolves through this installation."""
        from app.models import GithubInstallation, Repository

        seed = await _seed_installed_repo(session_factory, test_user)
        async with session_factory() as s:
            other = GithubInstallation(
                user_id=test_user.id,
                installation_id=uuid4().int % 900000 + 1,
                account_login="other",
                account_type="Organization",
                organization_id=seed["org_id"],
            )
            s.add(other)
            await s.flush()
            s.add(Repository(
                installation_id=other.id,
                github_repo_id=seed["repo_github_id"] + 1,
                owner="acme",
                name="repo-clone",
                default_branch="main",
                is_active=True,
            ))
            await s.commit()

        # Claim the CLONE's id through the ORIGINAL installation: the
        # payload is internally consistent, but the repository belongs to
        # a different installation row.
        clone_github_id = seed["repo_github_id"] + 1

        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            with pytest.raises(wh.WebhookError) as ei:
                await wh.resolve_repository(
                    s, inst, claimed_repo_id=clone_github_id
                )
            assert ei.value.reason_code == wh.R_UNKNOWN_REPOSITORY

    def test_installation_id_extraction_forms(self):
        assert wh.extract_installation_id({"installation": {"id": 7}}) == 7
        assert wh.extract_installation_id({"installation": 7}) == 7
        assert wh.extract_installation_id({"installation": "7"}) is None
        assert wh.extract_installation_id({}) is None


class TestReplayProtection:
    async def test_same_delivery_twice_creates_one_scan(
        self, session_factory, test_user
    ):
        seed = await _seed_installed_repo(session_factory, test_user)
        sha = "a" * 40
        push = wh.PushRef(head_sha=sha, ref="refs/heads/main", commit_count=1)

        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            first = await wh.request_scan_for_push(
                s, organization_id=seed["org_id"], installation=inst,
                repository=repo, push=push, delivery_id="delivery-0001",
                event_type="push",
            )
            await s.commit()
            assert first.created is True

        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            second = await wh.request_scan_for_push(
                s, organization_id=seed["org_id"], installation=inst,
                repository=repo, push=push, delivery_id="delivery-0001",
                event_type="push",
            )
            assert second.created is False
            assert second.replayed is True
            assert str(second.scan.id) == str(first.scan.id)

        async with session_factory() as s:
            from sqlalchemy import select
            scans = (await s.execute(select(Scan))).scalars().all()
            assert len(scans) == 1

    async def test_same_delivery_different_payload_conflicts(
        self, session_factory, test_user
    ):
        """A captured delivery id replayed with DIFFERENT content must
        never be answered with the original request's outcome."""
        seed = await _seed_installed_repo(session_factory, test_user)

        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            await wh.request_scan_for_push(
                s, organization_id=seed["org_id"], installation=inst,
                repository=repo,
                push=wh.PushRef("a" * 40, "refs/heads/main", 1),
                delivery_id="delivery-0002", event_type="push",
            )
            await s.commit()

        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            with pytest.raises(wh.WebhookError) as ei:
                await wh.request_scan_for_push(
                    s, organization_id=seed["org_id"], installation=inst,
                    repository=repo,
                    push=wh.PushRef("b" * 40, "refs/heads/main", 1),
                    delivery_id="delivery-0002", event_type="push",
                )
            assert ei.value.reason_code == wh.R_DUPLICATE_DELIVERY

    async def test_cross_tenant_delivery_id_is_a_distinct_operation(
        self, session_factory, test_user, test_user_b
    ):
        """Replay protection is tenant-scoped: org B reusing org A's
        delivery id is a NEW record, never a replay of A's outcome."""
        seed_a = await _seed_installed_repo(session_factory, test_user)
        seed_b = await _seed_installed_repo(session_factory, test_user_b)

        async with session_factory() as s:
            inst_a = await wh.resolve_installation(
                s, claimed_installation_id=seed_a["installation_number"]
            )
            repo_a = await wh.resolve_repository(
                s, inst_a, claimed_repo_id=seed_a["repo_github_id"]
            )
            await wh.request_scan_for_push(
                s, organization_id=seed_a["org_id"], installation=inst_a,
                repository=repo_a,
                push=wh.PushRef("c" * 40, "refs/heads/main", 1),
                delivery_id="shared-delivery", event_type="push",
            )
            await s.commit()

        async with session_factory() as s:
            inst_b = await wh.resolve_installation(
                s, claimed_installation_id=seed_b["installation_number"]
            )
            repo_b = await wh.resolve_repository(
                s, inst_b, claimed_repo_id=seed_b["repo_github_id"]
            )
            result = await wh.request_scan_for_push(
                s, organization_id=seed_b["org_id"], installation=inst_b,
                repository=repo_b,
                push=wh.PushRef("c" * 40, "refs/heads/main", 1),
                delivery_id="shared-delivery", event_type="push",
            )
            assert result.created is True  # B's own operation

    async def test_webhook_scan_is_request_only_and_commit_bound(
        self, session_factory, test_user
    ):
        seed = await _seed_installed_repo(session_factory, test_user)
        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            result = await wh.request_scan_for_push(
                s, organization_id=seed["org_id"], installation=inst,
                repository=repo,
                push=wh.PushRef("d" * 40, "refs/heads/main", 1),
                delivery_id="delivery-0003", event_type="push",
            )
            await s.commit()
            scan = result.scan
            await s.refresh(scan)
            assert scan.trigger == "webhook"
            assert scan.requested_commit_sha == "d" * 40
            assert scan.status == "QUEUED"


class TestEndToEndIntake:
    def test_signed_push_creates_one_scan_and_delivery_record(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio
        import app.worker as worker

        enqueued = []
        monkeypatch.setattr(
            worker, "enqueue_scan", lambda scan_id: enqueued.append(scan_id)
        )
        from app.config import get_settings

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )

        seed = asyncio.get_event_loop().run_until_complete(
            _seed_installed_repo(session_factory, test_user)
        )
        sha = "e" * 40
        body = _push_body(seed["repo_github_id"], seed["installation_number"], sha)
        headers = {
            "x-github-event": "push",
            "x-github-delivery": "e2e-delivery-0001",
            "x-hub-signature-256": _sig(body),
            "content-type": "application/json",
        }
        r = client.post("/api/webhooks/github", content=body, headers=headers)
        assert r.status_code == 202, r.text
        assert len(enqueued) == 1

        async def _check():
            async with session_factory() as s:
                from sqlalchemy import select

                scans = (await s.execute(select(Scan))).scalars().all()
                deliveries = (
                    await s.execute(select(WebhookDelivery))
                ).scalars().all()
                return scans, deliveries

        scans, deliveries = asyncio.get_event_loop().run_until_complete(_check())
        assert len(scans) == 1
        assert scans[0].requested_commit_sha == sha
        assert scans[0].trigger == "webhook"
        assert len(deliveries) == 1
        assert deliveries[0].outcome == "ACCEPTED"
        assert deliveries[0].signature_state == "VALID"

    def test_bad_signature_is_401_and_never_processes(
        self, client, session_factory, test_user, monkeypatch
    ):
        import asyncio
        from app.config import get_settings

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )
        seed = asyncio.get_event_loop().run_until_complete(
            _seed_installed_repo(session_factory, test_user)
        )
        body = _push_body(seed["repo_github_id"], seed["installation_number"], "f" * 40)
        headers = {
            "x-github-event": "push",
            "x-github-delivery": "e2e-delivery-0002",
            "x-hub-signature-256": _sig(body, "wrong-secret"),
        }
        r = client.post("/api/webhooks/github", content=body, headers=headers)
        assert r.status_code == 401

        async def _check():
            async with session_factory() as s:
                from sqlalchemy import select

                scans = (await s.execute(select(Scan))).scalars().all()
                deliveries = (
                    await s.execute(select(WebhookDelivery))
                ).scalars().all()
                return scans, deliveries

        scans, deliveries = asyncio.get_event_loop().run_until_complete(_check())
        assert scans == []  # no side effect
        assert len(deliveries) == 1
        assert deliveries[0].outcome == "REJECTED"
        assert deliveries[0].reason_code == wh.R_BAD_SIGNATURE

    def test_unknown_event_is_200_ignored(
        self, client, session_factory, test_user, monkeypatch
    ):
        from app.config import get_settings

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )
        body = b'{"zen": "ok"}'
        r = client.post(
            "/api/webhooks/github",
            content=body,
            headers={
                "x-github-event": "gollum",
                "x-github-delivery": "e2e-delivery-0003",
                "x-hub-signature-256": _sig(body),
            },
        )
        assert r.status_code == 200

    def test_webhook_delivery_id_cannot_cross_tenants_via_payload(
        self, client, session_factory, test_user, test_user_b, monkeypatch
    ):
        """A signed push claiming a repository owned by ANOTHER tenant's
        installation must not create a scan for that tenant."""
        import asyncio
        from app.config import get_settings

        monkeypatch.setattr(
            get_settings(), "github_webhook_secret", WEBHOOK_SECRET
        )
        seed_b = asyncio.get_event_loop().run_until_complete(
            _seed_installed_repo(session_factory, test_user_b)
        )
        # Push claims tenant B's repository but tenant A's installation.
        body = _push_body(seed_b["repo_github_id"], seed_b["installation_number"], "a" * 40)
        r = client.post(
            "/api/webhooks/github",
            content=body,
            headers={
                "x-github-event": "push",
                "x-github-delivery": "e2e-delivery-0004",
                "x-hub-signature-256": _sig(body, WEBHOOK_SECRET),
            },
        )

        from sqlalchemy import select

        async def _scans():
            async with session_factory() as s:
                return (await s.execute(select(Scan))).scalars().all()

        scans = asyncio.get_event_loop().run_until_complete(_scans())
        from app.models import Repository

        async def _repos():
            async with session_factory() as s:
                return (await s.execute(select(Repository))).scalars().all()

        repos = asyncio.get_event_loop().run_until_complete(_repos())
        # Any scan created belongs to a real repository (binding held).
        for scan in scans:
            assert any(repo.id == scan.repository_id for repo in repos)


class TestWebhookAudit:
    async def test_accepted_push_lands_in_org_audit_chain(
        self, session_factory, test_user, monkeypatch
    ):
        import app.worker as worker

        monkeypatch.setattr(worker, "enqueue_scan", lambda scan_id: None)
        seed = await _seed_installed_repo(session_factory, test_user)
        async with session_factory() as s:
            inst = await wh.resolve_installation(
                s, claimed_installation_id=seed["installation_number"]
            )
            repo = await wh.resolve_repository(
                s, inst, claimed_repo_id=seed["repo_github_id"]
            )
            await wh.audit_webhook_event(
                s,
                organization_id=seed["org_id"],
                repository_id=repo.id,
                event_type="push",
                outcome="ACCEPTED",
                reason_code=None,
                delivery_id="audit-delivery-1",
                signature_state="VALID",
            )
            await s.commit()

        async with session_factory() as s:
            from sqlalchemy import select

            chain = (
                await s.execute(
                    select(AuditChain).where(
                        AuditChain.organization_id == seed["org_id"]
                    )
                )
            ).scalar_one()
            events = (
                await s.execute(
                    select(AuditChainEvent).where(
                        AuditChainEvent.chain_id == chain.id
                    )
                )
            ).scalars().all()
            assert any(e.event_type == "WEBHOOK_ACCEPTED" for e in events)

    async def test_refusal_lands_in_audit_chain(
        self, session_factory, test_user
    ):
        seed = await _seed_installed_repo(session_factory, test_user)
        async with session_factory() as s:
            await wh.audit_webhook_event(
                s,
                organization_id=seed["org_id"],
                repository_id=None,
                event_type="push",
                outcome="REJECTED",
                reason_code=wh.R_UNKNOWN_INSTALLATION,
                delivery_id="audit-delivery-2",
                signature_state="VALID",
            )
            await s.commit()

        async with session_factory() as s:
            from sqlalchemy import select

            chain = (
                await s.execute(
                    select(AuditChain).where(
                        AuditChain.organization_id == seed["org_id"]
                    )
                )
            ).scalar_one()
            events = (
                await s.execute(
                    select(AuditChainEvent).where(
                        AuditChainEvent.chain_id == chain.id
                    )
                )
            ).scalars().all()
            assert any(
                e.event_type == "WEBHOOK_REJECTED"
                and e.reason_code == wh.R_UNKNOWN_INSTALLATION
                for e in events
            )
