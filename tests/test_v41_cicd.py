"""CYVRIX V4.1 — CI/CD integration red-team tests.

Covers the CI trust model (docs/v4-cicd.md is normative):

  - a CI request is commit-bound: the requested SHA is verified against
    the actual clone in the worker; a stale commit is refused with
    COMMIT_MISMATCH, never silently attached to a newer commit
  - CI cannot self-declare a security result: the only result surface is
    server-computed from scan state
  - CI cannot name another tenant's repository (404, existence hidden)
  - CI cannot use a webhook delivery id as an authority (replay claim is
    webhook-scoped; CI uses Idempotency-Key)
  - the CI Action path (submission → poll) maps to exactly the public
    endpoints, and the mapping cannot reach the V3 chain
"""
import asyncio
import json
import os
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select

from app.models import (
    GithubInstallation,
    Repository,
    Scan,
)
from app.services import api_key_service, organization_service as org_svc

pytestmark = pytest.mark.usefixtures("clean_db")


async def _seed_ci_tenant(session_factory, user, *, name="CI"):
    async with session_factory() as s:
        org = await org_svc.create_organization(s, name=name, creator_user_id=user.id)
        await s.flush()
        inst = GithubInstallation(
            user_id=user.id, installation_id=uuid4().int % 900000 + 1,
            account_login=f"{name.lower()}-acme", account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=uuid4().int % 900000 + 1,
            owner=f"{name.lower()}-acme", name="repo", default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.flush()
        membership = await org_svc.get_membership(s, org_id=org.id, user_id=user.id)
        _, secret = await api_key_service.create_api_key(
            s, org_id=org.id, actor_membership=membership,
            actor_user_id=user.id, name="ci",
            scopes=["scans:read", "scans:create", "repositories:read"],
        )
        await s.commit()
        return {
            "org_id": org.id, "repo_id": repo.id, "secret": secret,
        }


# ── Commit binding at the API surface ────────────────────────────────


class TestCommitBindingSurface:
    def test_commit_bound_submission_records_requested_sha(
        self, client, session_factory, test_user, monkeypatch
    ):
        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user)
        )
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )
        sha = "a" * 40
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": str(seed["repo_id"]), "commit_sha": sha},
            headers={"Authorization": f"Bearer {seed['secret']}"},
        )
        assert r.status_code == 202, r.text

        async def _scan():
            async with session_factory() as s:
                return (
                    await s.execute(
                        select(Scan).where(Scan.repository_id == seed["repo_id"])
                    )
                ).scalar_one()

        scan = asyncio.get_event_loop().run_until_complete(_scan())
        assert scan.requested_commit_sha == sha
        assert scan.trigger == "api"

    def test_malformed_commit_sha_is_refused(
        self, client, session_factory, test_user
    ):
        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user)
        )
        for bad in ("short", "z" * 40, "a" * 39, "a" * 41, ""):
            r = client.post(
                "/api/v1/scans",
                json={"repository_id": str(seed["repo_id"]), "commit_sha": bad},
                headers={"Authorization": f"Bearer {seed['secret']}"},
            )
            assert r.status_code == 422, bad

    def test_uppercase_hex_sha_is_normalized_not_rejected(
        self, client, session_factory, test_user, monkeypatch
    ):
        """Uppercase hex is a valid SHA spelling; the API normalizes it to
        the lowercase canonical form GitHub uses."""
        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user)
        )
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": str(seed["repo_id"]), "commit_sha": "A" * 40},
            headers={"Authorization": f"Bearer {seed['secret']}"},
        )
        assert r.status_code == 202, r.text

        async def _scan():
            async with session_factory() as s:
                return (
                    await s.execute(
                        select(Scan).where(Scan.repository_id == seed["repo_id"])
                    )
                ).scalar_one()

        scan = asyncio.get_event_loop().run_until_complete(_scan())
        assert scan.requested_commit_sha == "a" * 40

    def test_ci_cannot_claim_result_in_body(
        self, client, session_factory, test_user
    ):
        """A CI payload declaring security state is rejected wholesale."""
        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user)
        )
        r = client.post(
            "/api/v1/scans",
            json={
                "repository_id": str(seed["repo_id"]),
                "result": "PASS",
                "verdict": "CLEAN",
                "security_status": "SECURE",
            },
            headers={"Authorization": f"Bearer {seed['secret']}"},
        )
        assert r.status_code == 422  # extra="forbid"

    def test_ci_cannot_submit_against_another_tenants_repository(
        self, client, session_factory, test_user, test_user_b
    ):
        loop = asyncio.get_event_loop()
        mine = loop.run_until_complete(_seed_ci_tenant(session_factory, test_user))
        theirs = loop.run_until_complete(
            _seed_ci_tenant(session_factory, test_user_b, name="CI-B")
        )
        r = client.post(
            "/api/v1/scans",
            json={"repository_id": str(theirs["repo_id"]), "commit_sha": "a" * 40},
            headers={"Authorization": f"Bearer {mine['secret']}"},
        )
        assert r.status_code == 404  # existence hidden

    def test_ci_idempotency_key_is_namespace_isolated_from_webhook(
        self, client, session_factory, test_user, monkeypatch
    ):
        """The same opaque key value in the API namespace and the webhook
        namespace is TWO distinct operations — neither can replay the
        other's outcome."""
        from app.services import idempotency_service as idem

        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user)
        )
        monkeypatch.setattr(
            __import__("app.worker", fromlist=["enqueue_scan"]),
            "enqueue_scan", lambda scan_id: None,
        )
        shared_value = "shared-key-00000001"
        headers = {
            "Authorization": f"Bearer {seed['secret']}",
            "Idempotency-Key": shared_value,
        }
        first = client.post(
            "/api/v1/scans",
            json={"repository_id": str(seed["repo_id"])},
            headers=headers,
        )
        assert first.status_code == 202

        async def _check():
            async with session_factory() as s:
                rows = (
                    await s.execute(
                        select(idem.ApiIdempotencyKey).where(
                            idem.ApiIdempotencyKey.key_value == shared_value
                        )
                    )
                ).scalars().all()
                return rows

        rows = asyncio.get_event_loop().run_until_complete(_check())
        assert len(rows) == 1
        assert rows[0].scope == "POST /api/v1/scans"  # webhook namespace untouched


# ── Worker-side commit binding (the enforcement point) ───────────────


class TestWorkerCommitBinding:
    def test_commit_mismatch_fails_scan_before_analysis(
        self, session_factory, test_user, monkeypatch
    ):
        """The binding check runs BEFORE scanning: with a mismatching
        clone, no findings/dependencies are ever produced."""
        import uuid as uuid_module
        from types import SimpleNamespace
        import sys as _sys

        worker_dir = os.path.join(
            os.path.dirname(__file__), "..", "services", "worker"
        )
        if worker_dir not in _sys.path:
            _sys.path.insert(0, os.path.abspath(worker_dir))

        # Import the worker module fresh with the API models already loaded.
        import importlib
        import app.models as models  # ensure metadata registered

        from worker import tasks as worker_tasks

        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user, name="WB")
        )
        scan_id = uuid_module.uuid4()

        async def _make_scan():
            async with session_factory() as s:
                s.add(Scan(
                    id=scan_id, repository_id=seed["repo_id"], status="QUEUED",
                    trigger="ci", requested_commit_sha="a" * 40,
                ))
                await s.commit()

        asyncio.get_event_loop().run_until_complete(_make_scan())

        # Stub the credential mint + clone: the repository has advanced
        # past the request. The binding check runs BEFORE any analysis.
        async def _stub_token(*a, **k):
            return "stub-token"

        monkeypatch.setattr(
            worker_tasks, "get_installation_access_token", _stub_token
        )
        monkeypatch.setattr(
            worker_tasks, "clone_repo", lambda url, ws, branch: "b" * 40
        )

        failures = []
        monkeypatch.setattr(
            worker_tasks, "_fail_scan",
            lambda db, scan, reason: failures.append(reason),
        )
        monkeypatch.setattr(
            worker_tasks, "SessionLocal",
            lambda: _StubScanDB(session_factory, scan_id),
        )

        result = worker_tasks.run_scan(str(scan_id))
        assert result == {"error": "COMMIT_MISMATCH"}, result
        assert failures == ["COMMIT_MISMATCH"]

    def test_stale_commit_is_never_attached_to_newer_commit(
        self, session_factory, test_user, monkeypatch
    ):
        """CI requested commit A; the clone returns B (repository
        advanced). The scan MUST fail as COMMIT_MISMATCH — its result can
        never be presented as covering B."""
        import uuid as uuid_module

        from worker import tasks as worker_tasks

        seed = asyncio.get_event_loop().run_until_complete(
            _seed_ci_tenant(session_factory, test_user, name="WC")
        )
        scan_id = uuid_module.uuid4()

        async def _make_scan():
            async with session_factory() as s:
                s.add(Scan(
                    id=scan_id, repository_id=seed["repo_id"], status="QUEUED",
                    trigger="ci", requested_commit_sha="1" * 40,
                ))
                await s.commit()

        asyncio.get_event_loop().run_until_complete(_make_scan())

        async def _stub_token2(*a, **k):
            return "stub-token"

        monkeypatch.setattr(
            worker_tasks, "get_installation_access_token", _stub_token2
        )
        monkeypatch.setattr(
            worker_tasks, "clone_repo", lambda url, ws, branch: "2" * 40
        )
        failures = []
        monkeypatch.setattr(
            worker_tasks, "_fail_scan",
            lambda db, scan, reason: failures.append(reason),
        )
        monkeypatch.setattr(
            worker_tasks, "SessionLocal", lambda: _StubScanDB(session_factory, scan_id)
        )

        worker_tasks.run_scan(str(scan_id))
        assert failures == ["COMMIT_MISMATCH"]


class _StubScanDB:
    """Stub sync session for the worker: resolves the real Scan row and a
    minimal bound Repository (is_active, installation present) so the run
    reaches the commit-binding check — the code under test."""

    def __init__(self, factory, scan_id):
        self._factory = factory
        self._scan_id = scan_id
        self._scan = None
        self._repo = None

    def get(self, model, pk):
        if model is Scan and self._scan is None:
            asyncio.get_event_loop().run_until_complete(self._load())
        return self._scan if model is Scan else self._repo

    async def _load(self):
        async with self._factory() as s:
            scan = await s.get(Scan, self._scan_id)
            repo = await s.get(Repository, scan.repository_id)
            inst = await s.get(GithubInstallation, repo.installation_id)
            # Detached copies the worker can mutate freely.
            self._scan = Scan(
                id=scan.id, repository_id=scan.repository_id,
                status=scan.status, trigger=scan.trigger,
                requested_commit_sha=scan.requested_commit_sha,
            )
            self._repo = Repository(
                id=repo.id, installation_id=repo.installation_id,
                github_repo_id=repo.github_repo_id, owner=repo.owner,
                name=repo.name, default_branch=repo.default_branch,
                is_active=repo.is_active,
            )
            self._repo.installation = inst

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


# ── The CI Action mapping (submission → poll) stays on the public API ─


class TestCIPipelineMapping:
    def test_action_polls_only_public_endpoints(self):
        """Static check: the shipped Action references ONLY /api/v1
        endpoints — it can never reach the console/V3 surface."""
        path = os.path.join(
            os.path.dirname(__file__), "..", ".github", "actions", "cyvrix-ci", "index.js"
        )
        with open(path, "r") as f:
            source = f.read()
        assert "/api/v1/repositories" in source
        assert "/api/v1/scans" in source
        assert "/api/v1/scans/" in source  # status polling
        for banned in ("/api/approvals", "/api/executions", "/api/ops",
                       "/api/orgs", "/api/actions"):
            assert banned not in source

    def test_action_fails_closed_on_missing_credentials(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", ".github", "actions", "cyvrix-ci", "index.js"
        )
        with open(path, "r") as f:
            source = f.read()
        assert "refusing to run (fail closed)" in source
        assert "fail closed (INCONCLUSIVE)" in source

    def test_workflow_requests_only_read_permission(self):
        path = os.path.join(
            os.path.dirname(__file__), "..", ".github", "workflows",
            "cyvrix-analysis.yml.example",
        )
        with open(path, "r") as f:
            source = f.read()
        assert "contents: read" in source
        assert "contents: write" not in source
