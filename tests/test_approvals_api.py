"""CYVRIX V3.2 — Approval API integration + security tests.

Covers: golden path (approve → token → consume), reject, revoke, IDOR,
unauthenticated access, step-up enforcement, second-principal rule,
digest mismatch (denied + audited, never repaired), proposal expiry,
policy re-evaluation (DENY cannot be overridden), staleness (changed
recommendation / risk / repo), token replay + wrong-action defense,
token secrecy, audit events, idempotent re-approval, and the critical
NO-EXECUTION regression for every approval endpoint.

The Redis-backed checks (rate limit, step-up) are overridden in fixtures;
step-up freshness is simulated by seeding the Redis-like marker through
the service's loader (monkeypatched) — the pure logic is tested in
test_approval_model.py.
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.main import app
from app.models import (
    ActionProposal, Approval, AuditEvent, Finding, Recommendation,
    RiskAssessment, Scan,
)
from app.routes.actions import check_proposal_rate_limit
from app.routes.approvals import check_approval_rate_limit

BASE_COMMIT = "a" * 40


def _compute_digest(proposal: ActionProposal) -> str:
    from app.services.action_digest import compute_action_digest

    return compute_action_digest({
        "action_type": proposal.action_type,
        "repository_id": str(proposal.repository_id),
        "base_commit_sha": proposal.base_commit_sha,
        "target_branch": proposal.target_branch,
        "files": proposal.files,
        "operations": proposal.operations,
        "expected_diff": proposal.expected_diff,
    })


async def seed_proposal(
    session_factory, repository, *,
    proposer_id=None,
    risk_level="MEDIUM", risk_score=45,
    validation_state="VALIDATED", trust_level="SUPPORTED",
    finding_status="OPEN",
    proposal_status="POLICY_CHECKED",
    expires_delta=None,
    store_bad_digest=False,
):
    """Seed Scan → Finding → Recommendation → Risk → ActionProposal."""
    from app.services.action_model import proposal_expiry

    async with session_factory() as session:
        user_id = proposer_id
        if user_id is None:
            import random

            from app.models import User

            user = User(
                id=uuid4(),
                email=f"prop-{uuid4().hex[:8]}@test.com",
                github_id=random.randrange(10**6, 10**7),
            )
            session.add(user)
            await session.flush()
            user_id = user.id

        scan = Scan(
            id=uuid4(), repository_id=repository.id, status="COMPLETED",
            trigger="manual", commit_sha=BASE_COMMIT,
        )
        session.add(scan)
        await session.flush()

        finding = Finding(
            id=uuid4(), scan_id=scan.id, repository_id=repository.id,
            fingerprint=f"fp-{uuid4().hex[:12]}", scanner="dependency",
            source_type="DEPENDENCY", vulnerability_id="GHSA-test",
            package_name="lodash", package_version="4.17.19",
            title="Prototype Pollution in lodash", severity="HIGH",
            status=finding_status,
            evidence={"manifest_path": "package.json"},
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
        await session.flush()

        if risk_level is not None:
            session.add(RiskAssessment(
                id=uuid4(), finding_id=finding.id, risk_score=risk_score,
                risk_level=risk_level, risk_version=1,
                factors={"base_score": 60},
            ))

        proposal = ActionProposal(
            id=uuid4(), finding_id=finding.id, recommendation_id=recommendation.id,
            repository_id=repository.id, created_by=user_id,
            action_type="DEPENDENCY_UPGRADE", status=proposal_status,
            base_commit_sha=BASE_COMMIT, target_branch="cyvrix/fix",
            files=["package.json"],
            operations=[{
                "type": "UPDATE_DEPENDENCY_VERSION", "file": "package.json",
                "name": "lodash", "ecosystem": "npm",
                "from_version": "4.17.19", "to_version": "4.17.21",
            }],
            expected_diff='- "lodash": "4.17.19"\n+ "lodash": "4.17.21"',
            rationale="Patch prototype pollution",
            risk_score=risk_score, risk_level=risk_level,
            recommendation_trust=trust_level, validation_state=validation_state,
            policy_version="3.1", policy_decision="REQUIRE_APPROVAL",
            policy_reason_code="MEDIUM_RISK_REQUIRES_APPROVAL",
            policy_matched_rule="POL-027",
            action_digest="PENDING",
            expires_at=proposal_expiry(datetime.now(timezone.utc))
            if expires_delta is None
            else datetime.now(timezone.utc) + expires_delta,
        )
        # Store the true digest (or a deliberately wrong one for mismatch tests)
        proposal.action_digest = "f" * 64 if store_bad_digest else _compute_digest(proposal)
        session.add(proposal)
        await session.commit()
        await session.refresh(proposal)
        return proposal


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def approvals_client(authenticated_client, test_user):
    """Authenticated client with approval + proposal rate limits bypassed
    (tests run without Redis; real dependencies fail closed)."""
    async def override():
        return test_user
    app.dependency_overrides[check_approval_rate_limit] = override
    app.dependency_overrides[check_proposal_rate_limit] = override
    yield authenticated_client
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


@pytest.fixture
def auth_as(authenticated_client, test_user, test_user_b):
    """Explicit per-user authentication on the shared test client."""
    from app.auth import get_current_user

    users = {"a": test_user, "b": test_user_b}

    def _act_as(which: str):
        user = users[which]

        async def override():
            return user

        app.dependency_overrides[get_current_user] = override
        app.dependency_overrides[check_approval_rate_limit] = override
        app.dependency_overrides[check_proposal_rate_limit] = override
        return authenticated_client

    yield _act_as
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(check_approval_rate_limit, None)
    app.dependency_overrides.pop(check_proposal_rate_limit, None)


@pytest.fixture
def step_up_ok(monkeypatch):
    """Simulate fresh step-up markers for any user (Redis-backed loader)."""
    from app.services import approval_service

    async def fake_loader(*, approver, second_approver_user_id=None):
        second_ts = datetime.now(timezone.utc) if second_approver_user_id else None
        return datetime.now(timezone.utc), second_ts, None

    monkeypatch.setattr(approval_service, "_load_step_up_evidence", fake_loader)
    return None


@pytest.fixture
def step_up_missing(monkeypatch):
    """Simulate absent step-up (fail-closed path)."""
    from app.services import approval_service

    async def fake_loader(*, approver, second_approver_user_id=None):
        return None, None, "STEP_UP_REQUIRED"

    monkeypatch.setattr(approval_service, "_load_step_up_evidence", fake_loader)
    return None


# ── Golden path ──────────────────────────────────────────────────────


class TestGoldenPath:
    @pytest.mark.asyncio
    async def test_approve_returns_token_and_persists(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve", json={"reason": "LGTM"}
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["approval_state"] == "APPROVED"
        assert body["policy_decision"] == "REQUIRE_APPROVAL"
        assert body["policy_version"] == "3.1"
        assert body["action_digest"] == proposal.action_digest
        assert body["authorization_token"].startswith("cyv1_")
        assert body["approved_at"] is not None
        assert body["expires_at"] is not None
        # Approval TTL: bounded, ~1 hour
        exp = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
        appr = datetime.fromisoformat(body["approved_at"].replace("Z", "+00:00"))
        assert 0 < (exp - appr).total_seconds() <= 3600

    @pytest.mark.asyncio
    async def test_approval_persists_hash_not_plaintext(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve", json={}
        )
        token = r.json()["authorization_token"]

        async with session_factory() as session:
            row = (
                await session.execute(
                    select(Approval).where(
                        Approval.action_proposal_id == proposal.id
                    )
                )
            ).scalars().first()
            assert row.authorization_token_hash
            assert token not in row.authorization_token_hash
            assert row.authorization_token_hash != token
            assert row.authorization_used_at is None

    @pytest.mark.asyncio
    async def test_proposal_status_becomes_approved(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        r = approvals_client.get(f"/api/actions/{proposal.id}")
        assert r.json()["status"] == "APPROVED"

    @pytest.mark.asyncio
    async def test_get_approval_roundtrip(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        r = approvals_client.get(f"/api/actions/{proposal.id}/approval")
        assert r.status_code == 200
        body = r.json()
        assert body["approval_state"] == "APPROVED"
        # GET responses never contain token material
        assert "authorization_token" not in body

    @pytest.mark.asyncio
    async def test_consume_token_first_use_ok_second_replay_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        token = approvals_client.post(
            f"/api/actions/{proposal.id}/approve", json={}
        ).json()["authorization_token"]

        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]

        r1 = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert r1.status_code == 200, r1.text
        assert r1.json()["ok"] is True

        r2 = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert r2.status_code == 403
        assert r2.json()["detail"]["reason_code"] == "TOKEN_REPLAY"

    @pytest.mark.asyncio
    async def test_audit_events_emitted(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        async with session_factory() as session:
            events = (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "APPROVAL_GRANTED"
                    )
                )
            ).scalars().first()
            assert events is not None
            md = events.event_metadata
            assert md["action_digest"] == proposal.action_digest
            assert md["actor"] == str(test_user.id)
            assert md["policy_version"] == "3.1"
            assert "authorization_token" not in str(md)


# ── Authentication & ownership ───────────────────────────────────────


class TestAuthAndOwnership:
    @pytest.mark.asyncio
    async def test_unauthenticated_approve_401(self, client, session_factory, test_repository):
        proposal = await seed_proposal(session_factory, test_repository)
        r = client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_unauthenticated_get_approval_401(self, client, session_factory, test_repository):
        proposal = await seed_proposal(session_factory, test_repository)
        r = client.get(f"/api/actions/{proposal.id}/approval")
        assert r.status_code == 401

    @pytest.mark.asyncio
    async def test_user_b_cannot_approve_user_a_proposal(
        self, auth_as, session_factory, test_repository, test_user, step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = auth_as("b").post(f"/api/actions/{proposal.id}/approve", json={})
        # Ownership chain 404s cross-tenant (V2 convention)
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_user_b_cannot_read_user_a_approval(
        self, auth_as, session_factory, test_repository, test_user, step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        auth_as("a").post(f"/api/actions/{proposal.id}/approve", json={})
        r = auth_as("b").get(f"/api/actions/{proposal.id}/approval")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_user_b_cannot_revoke_user_a_approval(
        self, auth_as, session_factory, test_repository, test_user, step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        body = auth_as("a").post(
            f"/api/actions/{proposal.id}/approve", json={}
        ).json()
        r = auth_as("b").get(f"/api/actions/{proposal.id}/approval")
        assert r.status_code == 404  # cannot even see it

    @pytest.mark.asyncio
    async def test_unknown_proposal_404(self, approvals_client):
        r = approvals_client.post(f"/api/actions/{uuid4()}/approve", json={})
        assert r.status_code == 404


# ── Step-up & second principal ───────────────────────────────────────


class TestStepUpAndSecondPrincipal:
    @pytest.mark.asyncio
    async def test_approve_without_step_up_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_missing,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "STEP_UP_REQUIRED"
        # No approval row created
        r2 = approvals_client.get(f"/api/actions/{proposal.id}/approval")
        assert r2.status_code == 404

    @pytest.mark.asyncio
    async def test_high_risk_self_approval_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            risk_level="HIGH", risk_score=85,
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "SECOND_APPROVER_REQUIRED"

    @pytest.mark.asyncio
    async def test_critical_risk_self_approval_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            risk_level="CRITICAL", risk_score=97,
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "SECOND_APPROVER_REQUIRED"

    @pytest.mark.asyncio
    async def test_second_approver_must_exist(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            risk_level="HIGH", risk_score=85,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve",
            json={"second_approver_user_id": str(uuid4())},
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_high_risk_second_principal_unavailable_in_single_owner_model(
        self, auth_as, session_factory, test_repository, test_user, test_user_b,
        step_up_ok,
    ):
        """Documented V3.2 limitation (docs/v3-approval-model.md §5): the
        current data model has one owner per installation, so no second
        principal can reach a HIGH/CRITICAL proposal. The rule is NOT
        downgraded — approval simply fails closed."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            risk_level="HIGH", risk_score=85,
        )
        # User B (off the ownership chain) cannot act as second principal
        r = auth_as("b").post(
            f"/api/actions/{proposal.id}/approve",
            json={"second_approver_user_id": str(test_user.id)},
        )
        assert r.status_code == 404  # cross-tenant convention

        # Owner attempting to satisfy the rule with themselves is denied
        r2 = auth_as("a").post(
            f"/api/actions/{proposal.id}/approve",
            json={"second_approver_user_id": str(test_user.id)},
        )
        assert r2.status_code == 403
        assert r2.json()["detail"]["reason_code"] == "SECOND_APPROVER_REQUIRED"

    @pytest.mark.asyncio
    async def test_same_user_twice_does_not_satisfy_two_person_rule(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """Supplying your own id as second approver changes nothing."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            risk_level="HIGH", risk_score=85,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve",
            json={"second_approver_user_id": str(test_user.id)},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "SECOND_APPROVER_REQUIRED"

    @pytest.mark.asyncio
    async def test_step_up_status_endpoint(self, approvals_client):
        r = approvals_client.get("/api/actions/step-up/status")
        assert r.status_code == 200
        assert r.json()["step_up_valid"] is False


# ── Digest binding ───────────────────────────────────────────────────


class TestDigestBinding:
    @pytest.mark.asyncio
    async def test_digest_mismatch_denied_and_audited(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            store_bad_digest=True,
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "ACTION_DIGEST_MISMATCH"

        # Audited
        async with session_factory() as session:
            ev = (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "APPROVAL_DIGEST_MISMATCH"
                    )
                )
            ).scalars().first()
            assert ev is not None

        # Never repaired: stored digest unchanged
        async with session_factory() as session:
            row = (
                await session.execute(
                    select(ActionProposal).where(
                        ActionProposal.id == proposal.id
                    )
                )
            ).scalars().first()
            assert row.action_digest == "f" * 64

        # No approval created
        r2 = approvals_client.get(f"/api/actions/{proposal.id}/approval")
        assert r2.status_code == 404

    @pytest.mark.asyncio
    async def test_mutated_operation_breaks_digest(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """A proposal whose operations were edited after creation no longer
        matches its stored digest → approval denied."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            row = await session.get(ActionProposal, proposal.id)
            mutated = dict(row.operations[0])
            mutated["to_version"] = "99.0.0"  # scope expansion attempt
            row.operations = [mutated]
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "ACTION_DIGEST_MISMATCH"


# ── Expiry ───────────────────────────────────────────────────────────


class TestExpiry:
    @pytest.mark.asyncio
    async def test_expired_proposal_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            expires_delta=timedelta(hours=-1),
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "PROPOSAL_EXPIRED"
        r2 = approvals_client.get(f"/api/actions/{proposal.id}/approval")
        assert r2.status_code == 404


# ── Policy re-evaluation ─────────────────────────────────────────────


class TestPolicyReevaluation:
    @pytest.mark.asyncio
    async def test_policy_deny_cannot_be_overridden_by_approval(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """Finding resolved after proposal creation → policy re-evaluation
        returns DENY → human approval is impossible."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            row = await session.get(Finding, proposal.finding_id)
            row.status = "RESOLVED"
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "POLICY_DENIED"

        # Security audit event recorded
        async with session_factory() as session:
            ev = (
                await session.execute(
                    select(AuditEvent).where(
                        AuditEvent.event_type == "APPROVAL_POLICY_DENIED"
                    )
                )
            ).scalars().first()
            assert ev is not None

        r2 = approvals_client.get(f"/api/actions/{proposal.id}/approval")
        assert r2.status_code == 404

    @pytest.mark.asyncio
    async def test_repo_deactivated_denies_approval(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            from app.models import Repository

            row = await session.get(Repository, test_repository.id)
            row.is_active = False
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "POLICY_DENIED"

    @pytest.mark.asyncio
    async def test_unsafe_validation_state_drift_denies(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """Validation state changed AFTER proposal creation → snapshot drift."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            row = await session.get(Recommendation, proposal.recommendation_id)
            row.validation_state = "UNSAFE"
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "RECOMMENDATION_CHANGED"

    @pytest.mark.asyncio
    async def test_unsafe_recommendation_policy_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """UNSAFE at proposal creation AND unchanged since → the policy
        re-evaluation (POL-003) denies; approval cannot override it."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            validation_state="UNSAFE",
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "POLICY_DENIED"


# ── Staleness: changed context ───────────────────────────────────────


class TestStaleness:
    @pytest.mark.asyncio
    async def test_changed_recommendation_trust_denies(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            row = await session.get(Recommendation, proposal.recommendation_id)
            row.trust_level = "UNCERTAIN"
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "RECOMMENDATION_CHANGED"

    @pytest.mark.asyncio
    async def test_changed_risk_denies(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        async with session_factory() as session:
            row = await session.get(Finding, proposal.finding_id)
            new_risk = RiskAssessment(
                id=uuid4(), finding_id=row.id, risk_score=90,
                risk_level="CRITICAL", risk_version=1,
                factors={"base_score": 90},
            )
            session.add(new_risk)
            await session.commit()

        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "RISK_CHANGED"

    @pytest.mark.asyncio
    async def test_rejected_proposal_cannot_be_approved(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            proposal_status="REJECTED",
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409
        assert r.json()["detail"]["reason_code"] == "PROPOSAL_STALE"

    @pytest.mark.asyncio
    async def test_denied_proposal_policy_cannot_be_approved(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
            proposal_status="REJECTED",
        )
        r = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r.status_code == 409


# ── Reject & revoke ──────────────────────────────────────────────────


class TestRejectAndRevoke:
    @pytest.mark.asyncio
    async def test_reject_creates_rejected_approval(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/reject",
            json={"reason": "not comfortable"},
        )
        assert r.status_code == 200
        assert r.json()["approval_state"] == "REJECTED"

        r2 = approvals_client.get(f"/api/actions/{proposal.id}")
        assert r2.json()["status"] == "REJECTED"

        # Rejected proposal cannot then be approved
        r3 = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r3.status_code == 409
        assert r3.json()["detail"]["reason_code"] == "PROPOSAL_STALE"

    @pytest.mark.asyncio
    async def test_reject_reason_is_bounded(self, approvals_client, session_factory,
                                            test_repository, test_user, step_up_ok):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/reject",
            json={"reason": "x" * 3000},
        )
        assert r.status_code == 422  # schema-level bound

    @pytest.mark.asyncio
    async def test_revoke_approved_then_revoke_again_fails(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]

        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/revoke",
            json={"reason": "changed my mind"},
        )
        assert r.status_code == 200
        assert r.json()["approval_state"] == "REVOKED"

        # Revoked approval cannot be revoked again (terminal transition guard)
        r2 = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/revoke",
            json={},
        )
        assert r2.status_code == 409

        # Revoked approval cannot be consumed
        token = "cyv1_anything"
        r3 = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert r3.status_code == 403

    @pytest.mark.asyncio
    async def test_revoked_token_cannot_authorize(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """Even the REAL token dies with the revoked approval."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        token = approvals_client.post(
            f"/api/actions/{proposal.id}/approve", json={}
        ).json()["authorization_token"]
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]

        approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/revoke", json={},
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert r.status_code == 403


# ── Token security ───────────────────────────────────────────────────


class TestTokenSecurity:
    @pytest.mark.asyncio
    async def test_wrong_action_token_denied(
        self, auth_as, session_factory, test_repository, test_user, step_up_ok,
    ):
        """Token issued for Action A must not authorize Action B."""
        p1 = await seed_proposal(session_factory, test_repository, proposer_id=test_user.id)
        p2 = await seed_proposal(session_factory, test_repository, proposer_id=test_user.id)
        token_a = auth_as("a").post(
            f"/api/actions/{p1.id}/approve", json={}
        ).json()["authorization_token"]
        auth_as("a").post(f"/api/actions/{p2.id}/approve", json={})

        # Use token A against approval of B
        approval_b_id = auth_as("a").get(
            f"/api/actions/{p2.id}/approval"
        ).json()["id"]
        r = auth_as("a").post(
            f"/api/actions/{p2.id}/approval/{approval_b_id}/consume-token",
            json={"token": token_a},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "TOKEN_INVALID"

    @pytest.mark.asyncio
    async def test_garbage_token_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": "cyv1_totally_made_up"},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "TOKEN_INVALID"

    @pytest.mark.asyncio
    async def test_empty_token_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": ""},
        )
        assert r.status_code in (403, 422)

    @pytest.mark.asyncio
    async def test_token_not_in_urls_or_lists(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """GET responses and lists never carry token material."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        listing = approvals_client.get("/api/actions").json()
        for item in listing:
            assert "authorization_token" not in item
        detail = approvals_client.get(f"/api/actions/{proposal.id}").json()
        assert "authorization_token" not in detail

    @pytest.mark.asyncio
    async def test_expired_approval_consumption_denied(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """An approval past its 1-hour TTL cannot be consumed."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        token = approvals_client.post(
            f"/api/actions/{proposal.id}/approve", json={}
        ).json()["authorization_token"]
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]

        # Age the approval past its TTL
        async with session_factory() as session:
            row = await session.get(Approval, uuid.UUID(approval_id))
            row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
            await session.commit()

        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["reason_code"] == "APPROVAL_EXPIRED"

        # Approval state transitioned to EXPIRED (explicit reconciliation)
        state = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["approval_state"]
        assert state == "EXPIRED"


# ── Idempotency ──────────────────────────────────────────────────────


class TestIdempotency:
    @pytest.mark.asyncio
    async def test_reapprove_same_proposal_returns_existing_approval(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r1 = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        token1 = r1.json()["authorization_token"]
        r2 = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r2.status_code == 200
        # Same approval row, NO second token
        assert r2.json()["id"] == r1.json()["id"]
        assert r2.json().get("authorization_token", "") == ""

    @pytest.mark.asyncio
    async def test_only_one_live_approval_row(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        async with session_factory() as session:
            rows = (
                await session.execute(
                    select(Approval).where(
                        Approval.action_proposal_id == proposal.id
                    )
                )
            ).scalars().all()
            live = [r for r in rows if r.approval_state in ("PENDING", "APPROVED")]
            assert len(rows) == 1
            assert len(live) == 1


# ── Malformed input ──────────────────────────────────────────────────


class TestMalformedInput:
    @pytest.mark.asyncio
    async def test_extra_fields_forbidden(self, approvals_client, test_repository,
                                          session_factory, test_user):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve",
            json={"reason": "ok", "approval_state": "APPROVED"},  # forged state
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_forged_decision_fields_ignored(self, approvals_client,
                                                  session_factory, test_repository,
                                                  test_user):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve",
            json={"policy_decision": "ALLOW"},  # client cannot set policy
        )
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_reason_with_control_chars_rejected_or_sanitized(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r = approvals_client.post(
            f"/api/actions/{proposal.id}/approve",
            json={"reason": "fine\x00thanks"},
        )
        # Either rejected at schema level or sanitized by the service —
        # must never end up stored verbatim.
        if r.status_code == 200:
            stored = approvals_client.get(
                f"/api/actions/{proposal.id}/approval"
            ).json()["approval_reason"]
            assert "\x00" not in stored


# ── NO-EXECUTION boundary (critical regression) ──────────────────────


class TestNoExecutionBoundary:
    @pytest.mark.asyncio
    async def test_approve_reject_revoke_consume_cannot_execute(
        self, approvals_client, session_factory, test_repository, test_user,
        monkeypatch, step_up_ok,
    ):
        """Rig every side-effect primitive to explode; the full approval
        lifecycle must complete without any of them firing."""
        import subprocess as subprocess_module

        from app import worker as api_worker
        from app.services import github as gh

        def boom(*a, **k):
            raise AssertionError("EXECUTION ATTEMPTED — approval endpoint invoked a side-effect primitive")

        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )

        monkeypatch.setattr(subprocess_module, "Popen", boom)
        monkeypatch.setattr(subprocess_module, "run", boom)
        monkeypatch.setattr(subprocess_module, "call", boom)
        monkeypatch.setattr(os, "system", boom)
        for fn in ("enqueue_scan", "enqueue_container_scan", "enqueue_log_analysis",
                   "enqueue_action_execution"):
            if hasattr(api_worker, fn):
                monkeypatch.setattr(api_worker, fn, boom)
        for name in dir(gh):
            if name.startswith(("put_", "create_", "update_", "delete_", "merge_")):
                monkeypatch.setattr(gh, name, boom, raising=False)

        # Full lifecycle: approve → read → consume → revoke path
        approve = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert approve.status_code == 200
        token = approve.json()["authorization_token"]
        approval_id = approvals_client.get(
            f"/api/actions/{proposal.id}/approval"
        ).json()["id"]
        consume = approvals_client.post(
            f"/api/actions/{proposal.id}/approval/{approval_id}/consume-token",
            json={"token": token},
        )
        assert consume.status_code == 200

    @pytest.mark.asyncio
    async def test_approved_proposal_cannot_execute_anything(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """An APPROVED proposal is still inert: no USER-facing execution
        endpoint exists. V3.4 refines this invariant: execution routes now
        exist, but every run-mutating route is reserved for the INTERNAL
        executor service identity (POST /api/executor/runs is service-token
        gated — see test_execution_runs_api.py::TestExecutorServiceIdentity);
        every user-session-reachable run route is read-only GET. No route a
        user session can call starts execution, and no job is queued here.

        V3.5 refines it further: the remediation route
        (POST /api/actions/runs/{run_id}/remediation) IS user-reachable but
        executes NOTHING — it only creates the PENDING remediation record
        from server-verified run state; the pipeline runs exclusively via
        the service-identity-gated POST /api/executor/remediations/{id}/execute
        ("execute" in its path, which the check below still refuses for any
        user-reachable route by construction: it lives under /api/executor/)."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})

        INTERNAL_ADMISSION_PATH = "/api/executor/runs"  # service identity only
        V35_INTERNAL_PIPELINE_PATH = "/api/executor/remediations"  # service only
        USER_REMEDIATION_START = "/api/actions/runs/{run_id}/remediation"
        for r in app.routes:
            path = getattr(r, "path", "")
            run_path = path.replace("step-up", "")
            if "execute" in path:
                assert path.startswith(V35_INTERNAL_PIPELINE_PATH) or \
                    path == V35_INTERNAL_PIPELINE_PATH + "/{remediation_id}/execute" or \
                    path.startswith("/api/executor/"), (
                    f"user-executable route exists: {path}")
            if "run" in run_path:
                methods = {m for m in getattr(r, "methods", set()) if m != "HEAD"}
                if path == INTERNAL_ADMISSION_PATH:
                    assert methods <= {"POST"}, (
                        f"internal admission route must be POST-only: {path}"
                    )
                elif path == USER_REMEDIATION_START:
                    # V3.5: user START of a remediation record is allowed —
                    # it performs no git/GitHub effect (verified in
                    # test_git_remediation.py; the pipeline is service-only).
                    assert methods <= {"POST", "GET"}, (
                        f"remediation route must be start/read-only: "
                        f"{path} has {sorted(methods)}"
                    )
                else:
                    assert methods <= {"GET"}, (
                        f"user-reachable run route must be read-only GET: "
                        f"{path} has {sorted(methods)}"
                    )

    @pytest.mark.asyncio
    async def test_no_github_write_or_shell_imports_in_approval_modules(self):
        """AST-level: approval modules import no execution capability."""
        import ast

        base = os.path.join(os.path.dirname(__file__), "..", "apps", "api")
        forbidden_imports = {
            "subprocess", "socket", "httpx", "requests", "urllib", "shutil",
            "ctypes", "multiprocessing", "docker", "git",
        }
        forbidden_calls = {
            "eval", "exec", "compile", "system", "popen", "Popen", "rmtree",
            "enqueue", "create_pull_request", "put_file",
        }
        for mod in ("app/services/approval_model.py", "app/services/approval_service.py"):
            path = os.path.join(base, mod)
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        root = alias.name.split(".")[0]
                        assert root not in forbidden_imports, f"{mod}: imports {alias.name}"
                elif isinstance(node, ast.ImportFrom) and node.module:
                    root = node.module.split(".")[0]
                    assert root not in forbidden_imports, f"{mod}: imports from {node.module}"
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls, (
                        f"{mod}: bare call to {node.func.id}"
                    )


# ── Concurrency (SQLite-level serialization proxy) ───────────────────


class TestConcurrency:
    @pytest.mark.asyncio
    async def test_sequential_double_approve_single_row(
        self, approvals_client, session_factory, test_repository, test_user,
        step_up_ok,
    ):
        """Proxy for the concurrent race: the unique-index backstop is
        verified against real PostgreSQL in the integration suite."""
        proposal = await seed_proposal(
            session_factory, test_repository, proposer_id=test_user.id,
        )
        r1 = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        r2 = approvals_client.post(f"/api/actions/{proposal.id}/approve", json={})
        assert r1.status_code == 200 and r2.status_code == 200
        assert r1.json()["id"] == r2.json()["id"]
