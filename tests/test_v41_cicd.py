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

from sqlalchemy import select, delete as sa_delete

from app.models import (
    Finding,
    GithubInstallation,
    Investigation,
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


# ── Worker rescan durability (V4.1 release-certification regression) ──


def _run(coro):
    """Run a coroutine on a dedicated fresh event loop.

    The worker pipeline calls asyncio.run() internally, which UNSETS the
    thread's current event loop on exit — a subsequent
    asyncio.get_event_loop() would raise on Python 3.12. A dedicated
    loop per call makes the stub independent of that global state."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class _ExecResult:
    """Minimal result facade for the worker's ``db.execute(select(...))``
    call sites (scalar_one_or_none / scalars().all)."""

    def __init__(self, rows):
        self._rows = rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _RescanSessionStub:
    """Sync-session facade over the async test DB for the worker's
    run_scan pipeline (same spirit as _StubScanDB above, but able to run
    the full persist/investigate/risk flow in-process).

    - get() returns cached detached copies the worker can mutate
    - add()/flush() insert genuinely new rows (Findings, Investigations,
      RiskAssessments, Recommendations, AuditEvents) into the real DB
    - commit() syncs worker-side Scan mutations (status/timestamps/errors)
    - execute() translates the pipeline's simple select(...) filters into
      real queries so fingerprint dedup and investigation reuse hit the
      actual database constraint semantics
    """

    def __init__(self, factory, scan_id, *, poison_commits=False):
        self._factory = factory
        self._scan_id = scan_id
        self._objects = {}  # (model, str(pk)) -> detached object
        self._pending = []
        self._poison_commits = poison_commits
        self._poisoned = poison_commits

    def get(self, model, pk):
        return _run(self._load(model, pk))

    async def _load(self, model, pk):
        key = (model, str(pk))
        if key in self._objects:
            return self._objects[key]
        async with self._factory() as s:
            row = await s.get(model, pk)
            if row is None:
                return None
            if model is Repository:
                inst = await s.get(GithubInstallation, row.installation_id)
                s.expunge(inst)
            s.expunge(row)
        if model is Repository:
            obj = Repository(
                id=row.id, installation_id=row.installation_id,
                github_repo_id=row.github_repo_id, owner=row.owner,
                name=row.name, default_branch=row.default_branch,
                is_active=row.is_active,
            )
            obj.installation = inst
        else:
            obj = row
        self._objects[key] = obj
        return obj

    def add(self, obj):
        self._pending.append(obj)

    def flush(self):
        self._sync()

    def commit(self):
        if self._poisoned:
            from sqlalchemy.exc import PendingRollbackError
            raise PendingRollbackError("simulated poisoned session (failed flush)")
        self._sync()

    def rollback(self):
        # Mirrors real session semantics: rollback recovers a session
        # whose flush failed.
        self._poisoned = False

    def close(self):
        pass

    def execute(self, stmt, **kwargs):
        return _run(self._execute(stmt))

    async def _execute(self, stmt):
        # V4.2: the pipeline may issue a bulk DELETE (redelivery
        # convergence for scan-scoped dependency rows). Honor it against
        # the real database, then drop the stale copies from the stub's
        # detached-object cache so subsequent selects see the truth.
        if getattr(stmt, "is_delete", False):
            table = stmt.table
            criteria = stmt._where_criteria or ()
            wc = criteria[0] if criteria else None
            async with self._factory() as s:
                delete_stmt = sa_delete(table)
                if wc is not None:
                    delete_stmt = delete_stmt.where(wc)
                await s.execute(delete_stmt)
                await s.commit()
            self._objects = {
                k: v for k, v in self._objects.items()
                if getattr(k[0], "__tablename__", None) != table.name
            }
            return _ExecResult([])
        entity = stmt.column_descriptions[0]["entity"]
        wc = stmt.whereclause
        clauses = list(wc.clauses) if hasattr(wc, "clauses") else ([] if wc is None else [wc])
        filters = {crit.left.key: crit.right.value for crit in clauses}
        async with self._factory() as s:
            rows = (await s.execute(select(entity).filter_by(**filters))).scalars().all()
            for r in rows:
                s.expunge(r)
                # Register so later worker-side mutations are persisted
                # by commit(), exactly like an attached session object.
                self._objects[(type(r), str(r.id))] = r
        return _ExecResult(rows)

    def _sync(self):
        _run(self._sync_async())

    async def _sync_async(self):
        # Mirror real session semantics: commit() persists BOTH pending
        # inserts and attribute mutations on already-tracked (attached)
        # objects. merge() copies the detached object's current column
        # values into the managed row. Only models the pipeline actually
        # mutates are merged back — Repository/Installation are read-only
        # here (and Repository is a reconstructed subset view).
        mutable = (Scan, Finding, Investigation)
        async with self._factory() as s:
            if self._pending:
                for obj in self._pending:
                    s.add(obj)
                await s.flush()
                for obj in self._pending:
                    s.expunge(obj)
                    self._objects[(type(obj), str(obj.id))] = obj
                self._pending.clear()
            for (model, _pk), obj in list(self._objects.items()):
                if model in mutable:
                    await s.merge(obj)
            await s.commit()


async def _seed_rescan_tenant(session_factory, user):
    async with session_factory() as s:
        inst = GithubInstallation(
            user_id=user.id, installation_id=uuid4().int % 900000 + 1,
            account_login="rescan-acme", account_type="Organization",
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id, github_repo_id=uuid4().int % 900000 + 1,
            owner=f"rescan-acme-{uuid4().hex[:8]}", name="repo", default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.flush()
        scan = Scan(
            repository_id=repo.id, status="QUEUED", trigger="manual",
            requested_commit_sha="a" * 40,
        )
        s.add(scan)
        await s.commit()
        return {"repo_id": repo.id, "scan_id": scan.id}


async def _seed_rescan_scan(session_factory, repo_id):
    """A second scan of the SAME repository (the re-scan scenario)."""
    async with session_factory() as s:
        scan = Scan(
            repository_id=repo_id, status="QUEUED", trigger="manual",
            requested_commit_sha="a" * 40,
        )
        s.add(scan)
        await s.commit()
        return {"scan_id": scan.id}


class TestWorkerRescanDurability:
    """Re-scanning a repository must reuse findings (fingerprint dedup)
    without colliding with the 1:1 investigations constraint, and a
    mid-pipeline crash must still leave terminal scan state.

    Regression: the second scan of a repository crashed with
    UniqueViolation(investigations_finding_id_key) because the worker
    re-inserted an Investigation row for a finding carried over from the
    previous scan; the poisoned session then made _fail_scan itself raise
    PendingRollbackError, RQ dead-lettered the job, and the scan was
    stuck non-terminal forever (golden-path E2E TIMEOUT on rerun).
    """

    @pytest.fixture(autouse=True)
    def _import_worker(self):
        worker_dir = os.path.join(
            os.path.dirname(__file__), "..", "services", "worker"
        )
        if worker_dir not in sys.path:
            sys.path.insert(0, os.path.abspath(worker_dir))
        import app.models as models  # noqa: F401 — register metadata
        from worker import tasks as worker_tasks
        self.worker_tasks = worker_tasks

    def _stub_pipeline(self, monkeypatch, session_factory, scan_id, *, poison=False):
        wt = self.worker_tasks

        async def _stub_token(*a, **k):
            return "stub-token"

        async def _stub_llm(*a, **k):
            from app.schemas import InvestigationResult
            return InvestigationResult(
                verdict="LIKELY", exploitability="HIGH", exposure="EXTERNAL",
                confidence=0.7, summary="stubbed investigation",
                recommendation="upgrade the dependency",
            )

        monkeypatch.setattr(wt, "get_installation_access_token", _stub_token)
        monkeypatch.setattr(wt, "clone_repo", lambda url, ws, branch: "a" * 40)
        monkeypatch.setattr(wt, "_run_investigation_with_context", _stub_llm)

        async def _stub_scan_repository(workspace, repo_id, scan_id_):
            return {
                "dependencies": [],
                "findings": [{
                    "fingerprint": self.fingerprint,
                    "scanner": "dependency",
                    "source_type": "DEPENDENCY",
                    "vulnerability_id": "CVE-2026-0001",
                    "package_name": "lodash",
                    "package_version": "4.17.19",
                    "title": "Prototype Pollution in lodash",
                    "description": "Versions before 4.17.21 are vulnerable.",
                    "severity": "HIGH",
                    "evidence": {"manifest_path": "package.json"},
                }],
                "manifests_found": 1,
                "total_deps": 0,
                "parse_errors": [],
            }

        monkeypatch.setattr(wt, "scan_repository", _stub_scan_repository)
        stub = _RescanSessionStub(session_factory, scan_id, poison_commits=poison)
        monkeypatch.setattr(wt, "SessionLocal", lambda: stub)
        return stub

    def test_second_scan_reuses_investigation_row_and_completes(
        self, session_factory, test_user, monkeypatch
    ):
        seed = _run(_seed_rescan_tenant(session_factory, test_user))
        self.fingerprint = f"fp-rescan-{uuid4().hex[:12]}"

        # Scan 1: creates the finding + its investigation.
        self._stub_pipeline(monkeypatch, session_factory, seed["scan_id"])
        result1 = self.worker_tasks.run_scan(str(seed["scan_id"]))
        assert result1 == {"ok": True, "findings": 1}, result1

        # Scan 2 of the SAME repository: fingerprint dedup carries the
        # finding over; the investigation row must be reused, not re-inserted.
        scan2 = _run(
            _seed_rescan_scan(session_factory, seed["repo_id"])
        )
        self._stub_pipeline(monkeypatch, session_factory, scan2["scan_id"])
        result2 = self.worker_tasks.run_scan(str(scan2["scan_id"]))
        assert result2 == {"ok": True, "findings": 1}, result2

        async def _assert_db():
            from sqlalchemy import func
            from app.models import Investigation as Inv, RiskAssessment as Risk
            async with session_factory() as s:
                scan_row = await s.get(Scan, scan2["scan_id"])
                inv_count = (await s.execute(
                    select(func.count()).select_from(Inv)
                )).scalar_one()
                risk_count = (await s.execute(
                    select(func.count()).select_from(Risk)
                )).scalar_one()
            return scan_row.status, inv_count, risk_count

        status, inv_count, risk_count = _run(_assert_db())
        # Terminal state, exactly ONE investigation row (reused), and a
        # risk assessment per scan run (historical rows are by design).
        assert status == "COMPLETED", status
        assert inv_count == 1, f"investigations must stay 1:1, got {inv_count}"
        assert risk_count == 2, risk_count

    def test_failed_investigation_then_rescan_still_recovers(
        self, session_factory, test_user, monkeypatch
    ):
        from app.services.investigation import InvestigationError

        seed = _run(
            _seed_rescan_tenant(session_factory, test_user)
        )
        self.fingerprint = f"fp-rescan-{uuid4().hex[:12]}"

        calls = {"n": 0}

        async def _flaky_llm(*a, **k):
            calls["n"] += 1
            if calls["n"] == 1:
                raise InvestigationError("simulated LLM outage")
            from app.schemas import InvestigationResult
            return InvestigationResult(
                verdict="LIKELY", exploitability="HIGH", exposure="EXTERNAL",
                confidence=0.7, summary="recovered investigation",
                recommendation="upgrade the dependency",
            )

        self._stub_pipeline(monkeypatch, session_factory, seed["scan_id"])
        monkeypatch.setattr(
            self.worker_tasks, "_run_investigation_with_context", _flaky_llm
        )

        # Scan 1: LLM fails (investigation row still exists, scan completes).
        result1 = self.worker_tasks.run_scan(str(seed["scan_id"]))
        assert result1 == {"ok": True, "findings": 1}, result1

        # Scan 2: must reuse the FAILED investigation row (not insert a
        # duplicate) and complete.
        scan2 = _run(
            _seed_rescan_scan(session_factory, seed["repo_id"])
        )
        self._stub_pipeline(monkeypatch, session_factory, scan2["scan_id"])
        monkeypatch.setattr(
            self.worker_tasks, "_run_investigation_with_context", _flaky_llm
        )
        result2 = self.worker_tasks.run_scan(str(scan2["scan_id"]))
        assert result2 == {"ok": True, "findings": 1}, result2
        assert calls["n"] == 2, calls

        async def _assert_db():
            from sqlalchemy import func
            from app.models import Investigation as Inv
            async with session_factory() as s:
                scan_row = await s.get(Scan, scan2["scan_id"])
                inv_count = (await s.execute(
                    select(func.count()).select_from(Inv)
                )).scalar_one()
            return scan_row.status, inv_count

        status, inv_count = _run(_assert_db())
        assert status == "COMPLETED", status
        assert inv_count == 1, inv_count

    def test_scan_failure_handler_survives_poisoned_session(
        self, session_factory, test_user, monkeypatch
    ):
        """The outer failure handler must rollback a poisoned session
        before writing terminal state: the scan always ends FAILED with a
        reason, and run_scan returns an error instead of raising (a raise
        dead-letters the RQ job and leaves the scan non-terminal)."""
        seed = _run(
            _seed_rescan_tenant(session_factory, test_user)
        )
        self.fingerprint = f"fp-rescan-{uuid4().hex[:12]}"
        self._stub_pipeline(
            monkeypatch, session_factory, seed["scan_id"], poison=True
        )

        result = self.worker_tasks.run_scan(str(seed["scan_id"]))
        assert "error" in result, result

        async def _assert_db():
            async with session_factory() as s:
                scan_row = await s.get(Scan, seed["scan_id"])
                return scan_row.status, scan_row.error_reason

        status, error_reason = _run(_assert_db())
        assert status == "FAILED", status
        assert error_reason and "SCAN_FAILED" in error_reason, error_reason
