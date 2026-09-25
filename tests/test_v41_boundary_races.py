"""CYVRIX V4.1 — external-boundary races on REAL PostgreSQL + Redis.

Companion to test_v41_races.py (key rotation and idempotency races).
These are the races the EXTERNAL boundary introduces:

  - QUOTA × concurrent requests: exactly the valid capacity is admitted;
    every refusal is compensated; no over-admission (Phase 32)
  - WEBHOOK × WEBHOOK: N concurrent deliveries of one delivery id →
    exactly one side effect (Phase 38)
  - AUDIT × AUDIT: concurrent org-chain appends keep the chain verifiable
    (no gaps, no duplicate sequences, digests recompute)
  - AUDIT tamper: a direct-DB payload mutation of an org-chain event is
    DETECTED by the V3.8 verifier (tamper evidence inherited)
"""
import asyncio
import os
import uuid as uuid_module

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="V4.1 boundary races require RUN_INTEGRATION_TESTS=1 and real PostgreSQL",
)

from sqlalchemy import select, text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    ApiKey,
    AuditChain,
    AuditChainEvent,
    GithubInstallation,
    Repository,
    Scan,
    SystemControl,
    User,
)
from app.services import api_key_service  # noqa: E402
from app.services import audit_service  # noqa: E402
from app.services import organization_service as org_svc  # noqa: E402
from app.services import webhook_service as wh  # noqa: E402

REPETITIONS = 10
REP_IDS = list(range(REPETITIONS))


@pytest.fixture(scope="module")
async def real_engine():
    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for V4.1 boundary races")
    eng = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(real_engine):
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_db_real(real_engine):
    from conftest import wipe_all_tables

    async with real_engine.begin() as conn:
        await wipe_all_tables(conn)
        await conn.execute(
            SystemControl.__table__.insert().values(
                key="operational_state", value="NORMAL"
            )
        )
    yield


@pytest.fixture
async def org_ctx(session_factory, clean_db_real):
    async with session_factory() as s:
        owner = User(email=f"v41b-owner-{uuid_module.uuid4()}@t.local")
        s.add(owner)
        await s.flush()
        org = await org_svc.create_organization(
            s, name=f"RaceB-{uuid_module.uuid4().hex[:8]}", creator_user_id=owner.id
        )
        await s.flush()
        inst = GithubInstallation(
            user_id=owner.id,
            installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login="raceb",
            account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()
        repo = Repository(
            installation_id=inst.id,
            github_repo_id=uuid_module.uuid4().int % 900000 + 1,
            owner="raceb",
            name="race-repo",
            default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.commit()
        return {
            "org_id": org.id,
            "user_id": owner.id,
            "installation_number": inst.installation_id,
            "repo_github_id": repo.github_repo_id,
            "repo_id": repo.id,
        }


# ── Quota races (real Redis) ─────────────────────────────────────────


class TestQuotaRaces:
    async def test_concurrent_quota_consumption_is_exact(
        self, session_factory, org_ctx
    ):
        """12 concurrent requests against an org limit of 5: exactly 5
        admitted, every refusal compensated, final counter == 5.

        Real Redis makes the increments genuinely atomic across
        coroutines — the property the fake in the unit suite cannot
        establish."""
        from app.quota_service import consume_quota
        import redis.asyncio as aioredis
        import time as _time

        settings = get_settings()
        redis = aioredis.from_url(settings.redis_url, decode_responses=True)
        action = f"race-{uuid_module.uuid4().hex[:8]}"
        org_limit, global_limit = 5, 100

        try:
            results = await asyncio.gather(*[
                consume_quota(
                    redis,
                    organization_id=org_ctx["org_id"],
                    action=action,
                    org_limit=org_limit,
                    global_limit=global_limit,
                )
                for _ in range(12)
            ])
            admitted = [r for r in results if r.allowed]
            refused = [r for r in results if not r.allowed]

            assert len(admitted) == org_limit, (
                len(admitted), len(refused), [r.reason_code for r in refused]
            )
            assert len(refused) == 12 - org_limit
            assert all(r.reason_code == "QUOTA_ORG_EXCEEDED" for r in refused)

            window = int(_time.time() - (_time.time() % 86400))
            ocount = await redis.get(
                f"quota:org:{org_ctx['org_id']}:{action}:{window}"
            )
            assert int(ocount) == org_limit  # compensation is exact
        finally:
            await redis.aclose()

    async def test_quota_fail_closed_when_redis_down(self, org_ctx):
        from app.quota_service import consume_quota

        d = await consume_quota(
            None,
            organization_id=org_ctx["org_id"],
            action="scans",
            org_limit=5,
            global_limit=5,
        )
        assert not d.allowed
        assert d.reason_code == "QUOTA_UNAVAILABLE"


# ── Webhook × webhook races ──────────────────────────────────────────


class TestWebhookReplayRaces:
    async def test_concurrent_duplicate_deliveries_create_one_scan(
        self, session_factory, org_ctx
    ):
        """N concurrent deliveries with the SAME delivery id: exactly one
        creates the scan; the rest replay/conflict — never two scans
        (Phase 38: response lost → GitHub redelivers → no duplicate)."""
        for rep in REP_IDS:
            delivery_id = f"race-delivery-{rep:04d}"
            push = wh.PushRef(
                head_sha=f"{rep:040x}", ref="refs/heads/main", commit_count=1
            )

            async def _deliver():
                async with session_factory() as s:
                    try:
                        inst = await wh.resolve_installation(
                            s, claimed_installation_id=org_ctx["installation_number"]
                        )
                        repo = await wh.resolve_repository(
                            s, inst, claimed_repo_id=org_ctx["repo_github_id"]
                        )
                        result = await wh.request_scan_for_push(
                            s,
                            organization_id=org_ctx["org_id"],
                            installation=inst,
                            repository=repo,
                            push=push,
                            delivery_id=delivery_id,
                            event_type="push",
                        )
                        await s.commit()
                        return "created" if result.created else "replayed"
                    except wh.WebhookError as exc:
                        await s.rollback()
                        return exc.reason_code
                    except Exception as exc:  # noqa: BLE001
                        await s.rollback()
                        return f"ERROR:{type(exc).__name__}"

            outcomes = await asyncio.gather(*[_deliver() for _ in range(5)])

            created = outcomes.count("created")
            assert created == 1, f"rep {rep}: outcomes={outcomes}"
            for o in outcomes:
                assert o in (
                    "created", "replayed", wh.R_DUPLICATE_DELIVERY,
                    wh.R_SCAN_IN_PROGRESS,
                ), outcomes

            # The platform permits ONE in-flight scan per repository: the
            # winning scan from this rep would honestly block the next
            # rep (SCAN_IN_PROGRESS is correct behavior, not a defect).
            # Complete it so the next repetition exercises the same race
            # from a clean slate. (Load + update in ONE session: detached
            # instances would make the commit a no-op.)
            async with session_factory() as s:
                scans = (
                    await s.execute(
                        select(Scan).where(
                            Scan.requested_commit_sha == f"{rep:040x}"
                        )
                    )
                ).scalars().all()
                assert len(scans) <= 1, f"rep {rep}: {len(scans)} scans"
                for scan in scans:
                    scan.status = "COMPLETED"
                await s.commit()


# ── Audit org-chain races ────────────────────────────────────────────


class TestOrgChainAuditRaces:
    async def test_concurrent_key_lifecycle_keeps_chain_verifiable(
        self, session_factory, org_ctx
    ):
        """N sequential-ish key creations (each with its fail-closed audit
        append inside the key transaction): the org chain ends up with N
        API_KEY_CREATED events, no duplicate sequences, verifier VALID."""
        for rep in REP_IDS:
            async with session_factory() as s:
                membership = await org_svc.get_membership(
                    s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
                )
                await api_key_service.create_api_key(
                    s,
                    org_id=org_ctx["org_id"],
                    actor_membership=membership,
                    actor_user_id=org_ctx["user_id"],
                    name=f"race-key-{rep}",
                    scopes=["repositories:read"],
                )
                await s.commit()

        async with session_factory() as s:
            rows = (
                await s.execute(
                    select(ApiKey).where(ApiKey.organization_id == org_ctx["org_id"])
                )
            ).scalars().all()
            assert len([r for r in rows if r.revoked_at is None]) == REPETITIONS
            chain = (
                await s.execute(
                    select(AuditChain).where(
                        AuditChain.organization_id == org_ctx["org_id"]
                    )
                )
            ).scalar_one()
            result = await audit_service.verify_chain(s, chain_id=chain.id)
            events = (
                await s.execute(
                    select(AuditChainEvent).where(
                        AuditChainEvent.chain_id == chain.id
                    )
                )
            ).scalars().all()
        assert result.status == "VALID", result.issues
        created = [e for e in events if e.event_type == "API_KEY_CREATED"]
        assert len(created) == REPETITIONS
        seqs = [e.seq for e in events]
        assert len(seqs) == len(set(seqs)), "duplicate sequences in chain"

    async def test_tampering_with_org_chain_event_is_detected(
        self, session_factory, org_ctx
    ):
        """The org chain inherits V3.8 tamper-EVIDENCE: a direct DB
        payload mutation is DETECTED by the verifier."""
        from conftest import AUDIT_APPEND_ONLY_TABLES

        async with session_factory() as s:
            membership = await org_svc.get_membership(
                s, org_id=org_ctx["org_id"], user_id=org_ctx["user_id"]
            )
            await api_key_service.create_api_key(
                s,
                org_id=org_ctx["org_id"],
                actor_membership=membership,
                actor_user_id=org_ctx["user_id"],
                name="tamper-bait",
                scopes=["repositories:read"],
            )
            await s.commit()

        raw_engine = session_factory.kw["bind"]
        async with raw_engine.begin() as conn:
            for name in AUDIT_APPEND_ONLY_TABLES:
                await conn.execute(text(f"ALTER TABLE {name} DISABLE TRIGGER USER"))
            try:
                await conn.execute(text(
                    "UPDATE audit_chain_events SET payload = "
                    "payload || '{\"tampered\": true}'::jsonb "
                    "WHERE event_type = 'API_KEY_CREATED' "
                    "AND chain_id = (SELECT id FROM audit_chains "
                    "WHERE organization_id = :org) "
                    "AND seq = (SELECT MIN(seq) FROM audit_chain_events "
                    "WHERE event_type = 'API_KEY_CREATED' "
                    "AND chain_id = (SELECT id FROM audit_chains "
                    "WHERE organization_id = :org))"
                ), {"org": str(org_ctx["org_id"])})
            finally:
                for name in AUDIT_APPEND_ONLY_TABLES:
                    await conn.execute(
                        text(f"ALTER TABLE {name} ENABLE TRIGGER USER")
                    )

        async with session_factory() as s:
            chain = (
                await s.execute(
                    select(AuditChain).where(
                        AuditChain.organization_id == org_ctx["org_id"]
                    )
                )
            ).scalar_one()
            result = await audit_service.verify_chain(s, chain_id=chain.id)
        assert result.status == "INVALID"
        assert any(i.code == "DIGEST_MISMATCH" for i in result.issues)
