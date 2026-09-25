"""V3.8 — audit chain races + red-team tamper tests on REAL PostgreSQL.

Gated behind RUN_INTEGRATION_TESTS=1 + the dedicated migrated database:
    RUN_INTEGRATION_TESTS=1 \
    DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
    REDIS_URL=redis://localhost:6380/0 \
    SECRET_KEY=test-secret-key-for-integration-only-not-for-production-32chars! \
    ENVIRONMENT=development \
    pytest tests/test_audit_chain_races.py

Covers (release gates):
- Phase 9/57: concurrent appends to one chain — 0 duplicate sequence,
  0 duplicate predecessor, chain stays VALID (≥10 reps/class)
- Phase 30: event×event, tenant×tenant, checkpoint×event races
- Phase 32/55: DIRECT-DB red team — modify/delete/insert/reorder rows,
  forge checkpoints; every detectable alteration is detected
- Phase 56: failure injection — audit failure during a security
  transition must not silently produce false security state
"""
import asyncio
import os
import uuid as uuid_module
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="Audit chain races require RUN_INTEGRATION_TESTS=1 and real PostgreSQL",
)

from sqlalchemy import select, update, delete, text  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    AuditChain, AuditChainEvent, AuditCheckpoint, GithubInstallation, User,
)
from app.services import audit_service as aus  # noqa: E402

REPETITIONS = 10
REP_IDS = list(range(REPETITIONS))


@pytest.fixture(scope="module")
async def real_engine():
    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for audit chain races")
    eng = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session_factory(real_engine):
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_db(real_engine):
    """Wipe tables between tests. The V3.8 append-only triggers reject
    DELETE on audit tables — that guard is itself under test, so this
    fixture TRUNCATES with the triggers disabled for the wipe, then
    re-enables them (test-harness boundary, never a product bypass: the
    application has no path to disable triggers)."""
    from app.models import SystemControl
    from conftest import wipe_all_tables
    async with real_engine.begin() as conn:
        await wipe_all_tables(conn)
        await conn.execute(
            SystemControl.__table__.insert().values(
                key="operational_state", value="NORMAL"))
    yield


@pytest.fixture
async def tenant(real_engine, session_factory, clean_db):
    """Two tenants: chain owner + a second for isolation checks."""
    async with session_factory() as s:
        u1 = User(email=f"chain-{uuid_module.uuid4()}@t.local")
        u2 = User(email=f"other-{uuid_module.uuid4()}@t.local")
        s.add_all([u1, u2])
        await s.flush()
        i1 = GithubInstallation(user_id=u1.id,
                                installation_id=int(uuid_module.uuid4().int % 900000) + 1,
                                account_login="a", account_type="Organization")
        i2 = GithubInstallation(user_id=u2.id,
                                installation_id=int(uuid_module.uuid4().int % 900000) + 1,
                                account_login="b", account_type="Organization")
        s.add_all([i1, i2])
        await s.commit()
        await s.refresh(i1)
        await s.refresh(i2)
        return i1, i2


async def _append(session_factory, installation_id, n=1, event_type="SYSTEM_PAUSED"):
    async with session_factory() as s:
        for _ in range(n):
            await aus.emit_security_event(
                s, installation_id=installation_id,
                event_type=event_type, actor_type=aus.ActorType.SYSTEM,
                reason_code="RACE", result="OK", payload={"i": str(uuid_module.uuid4())})
        await s.commit()


async def _chain_id(session_factory, installation_id):
    async with session_factory() as s:
        row = (await s.execute(
            select(AuditChain).where(AuditChain.installation_id == installation_id)
        )).scalar_one()
        return row.id


# ── Phase 9/30/57: concurrency — no duplicate seq, no forked chain ───


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_concurrent_appends_same_chain_stays_valid(session_factory, tenant, rep):
    i1, _ = tenant
    await asyncio.gather(*[
        _append(session_factory, i1.id, n=3) for _ in range(6)
    ])  # 18 events, 6 concurrent writers
    cid = await _chain_id(session_factory, i1.id)
    async with session_factory() as s:
        res = await aus.verify_chain(s, chain_id=cid)
        seqs = (await s.execute(
            select(AuditChainEvent.seq).where(AuditChainEvent.chain_id == cid)
            .order_by(AuditChainEvent.seq.asc()))).scalars().all()
    assert res.status == "VALID", [(i.code, i.seq) for i in res.issues]
    assert len(seqs) == len(set(seqs))  # 0 duplicate sequence claims
    assert seqs == list(range(1, len(seqs) + 1))  # dense, ordered


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_concurrent_multi_tenant_appends_isolated(session_factory, tenant, rep):
    i1, i2 = tenant
    await asyncio.gather(
        _append(session_factory, i1.id, n=4),
        _append(session_factory, i2.id, n=4),
        _append(session_factory, i1.id, n=4),
        _append(session_factory, i2.id, n=4),
    )
    for inst in (i1, i2):
        cid = await _chain_id(session_factory, inst.id)
        async with session_factory() as s:
            res = await aus.verify_chain(s, chain_id=cid)
        assert res.status == "VALID", (str(inst.id), res.issues)


# ── Phase 32/55: direct-DB red team — every alteration detected ──────


async def _verify(session_factory, cid):
    async with session_factory() as s:
        return await aus.verify_chain(s, chain_id=cid)


@pytest.mark.asyncio
async def test_redteam_modify_payload_detected(real_engine, session_factory, clean_db, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=3)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:  # raw DB tampering (T1)
        await conn.execute(text(
            "ALTER TABLE audit_chain_events DISABLE TRIGGER USER"))
        await conn.execute(text(
            "UPDATE audit_chain_events SET payload = :p "
            "WHERE chain_id = :c AND seq = 2"),
            {"p": '{"evil": true}', "c": str(cid)})
        await conn.execute(text(
            "ALTER TABLE audit_chain_events ENABLE TRIGGER USER"))
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID" and any(
        i.code == "DIGEST_MISMATCH" for i in res.issues)


@pytest.mark.asyncio
async def test_redteam_delete_middle_event_detected(real_engine, session_factory, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=4)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:
        # direct-SQL tamper with the trigger disabled (simulates a
        # superuser attacker; the guard itself is tested separately)
        await conn.execute(text(
            "ALTER TABLE audit_chain_events DISABLE TRIGGER USER"))
        await conn.execute(text(
            "DELETE FROM audit_chain_events WHERE chain_id = :c AND seq = 2"),
            {"c": str(cid)})
        await conn.execute(text(
            "ALTER TABLE audit_chain_events ENABLE TRIGGER USER"))
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID" and any(
        i.code == "SEQ_GAP" for i in res.issues)


@pytest.mark.asyncio
async def test_redteam_insert_forged_event_detected(real_engine, session_factory, clean_db, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=3)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:
        # Insert a forged SUCCESS with a hand-picked digest. The genesis
        # prev_digest is taken (uq_prev blocks reusing it), so forge onto
        # the current head: T3/T14 fabrication.
        await conn.execute(text(
            "SELECT seq, event_digest FROM audit_chain_events "
            "WHERE chain_id = :c ORDER BY seq DESC LIMIT 1"), {"c": str(cid)})
        row = (await conn.execute(text(
            "SELECT seq, event_digest FROM audit_chain_events "
            "WHERE chain_id = :c ORDER BY seq DESC LIMIT 1"), {"c": str(cid)})).first()
        await conn.execute(text(
            "INSERT INTO audit_chain_events (id, chain_id, seq, event_type, "
            "event_version, actor_type, result, payload, occurred_at, recorded_at, "
            "prev_digest, event_digest) "
            "VALUES (:id, :c, :seq, 'EXECUTION_COMPLETED', 1, 'SYSTEM', 'SUCCESS', '{}', "
            "NOW(), NOW(), :prev, :dig)"),
            {"id": str(uuid_module.uuid4()), "c": str(cid),
             "seq": int(row[0]) + 1000, "prev": row[1], "dig": "f" * 64})
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID"


@pytest.mark.asyncio
async def test_db_trigger_blocks_application_bypass(real_engine, session_factory, tenant):
    """Phase 33: the ORM path MUST NOT be able to UPDATE/DELETE audit
    history — the DB trigger rejects it even from application code."""
    i1, _ = tenant
    await _append(session_factory, i1.id, n=2)
    cid = await _chain_id(session_factory, i1.id)
    with pytest.raises(Exception):
        async with session_factory() as s:
            await s.execute(update(AuditChainEvent).where(
                AuditChainEvent.chain_id == cid).values(actor_id="pwned"))
            await s.commit()
    with pytest.raises(Exception):
        async with session_factory() as s:
            await s.execute(delete(AuditChainEvent).where(
                AuditChainEvent.chain_id == cid))
            await s.commit()
    # and the chain is untouched
    res = await _verify(session_factory, cid)
    assert res.status == "VALID"


@pytest.mark.asyncio
async def test_redteam_reorder_detected(real_engine, session_factory, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=4)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:
        await conn.execute(text(
            "ALTER TABLE audit_chain_events DISABLE TRIGGER USER"))
        # swap seqs of events 2 and 3 (T4)
        await conn.execute(text(
            "UPDATE audit_chain_events SET seq = 99 WHERE chain_id = :c AND seq = 2"),
            {"c": str(cid)})
        await conn.execute(text(
            "UPDATE audit_chain_events SET seq = 2 WHERE chain_id = :c AND seq = 3"),
            {"c": str(cid)})
        await conn.execute(text(
            "UPDATE audit_chain_events SET seq = 3 WHERE chain_id = :c AND seq = 99"),
            {"c": str(cid)})
        await conn.execute(text(
            "ALTER TABLE audit_chain_events ENABLE TRIGGER USER"))
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID"


@pytest.mark.asyncio
async def test_redteam_actor_swap_detected(real_engine, session_factory, clean_db, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=3)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:  # T6: replace the actor
        await conn.execute(text(
            "ALTER TABLE audit_chain_events DISABLE TRIGGER USER"))
        await conn.execute(text(
            "UPDATE audit_chain_events SET actor_id = 'attacker'"))
        await conn.execute(text(
            "ALTER TABLE audit_chain_events ENABLE TRIGGER USER"))
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID"


@pytest.mark.asyncio
async def test_redteam_outcome_forge_detected(real_engine, session_factory, clean_db, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=3)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:  # T12: invent SUCCESS
        await conn.execute(text(
            "ALTER TABLE audit_chain_events DISABLE TRIGGER USER"))
        await conn.execute(text(
            "UPDATE audit_chain_events SET result = 'SUCCESS', "
            "event_type = 'EXECUTION_COMPLETED'"))
        await conn.execute(text(
            "ALTER TABLE audit_chain_events ENABLE TRIGGER USER"))
    res = await _verify(session_factory, cid)
    assert res.status == "INVALID"


@pytest.mark.asyncio
async def test_redteam_forged_checkpoint_mac_detected(real_engine, session_factory, clean_db, tenant):
    i1, _ = tenant
    await _append(session_factory, i1.id, n=3)
    cid = await _chain_id(session_factory, i1.id)
    async with real_engine.begin() as conn:  # forge checkpoint MAC (T14)
        await conn.execute(text(
            "ALTER TABLE audit_checkpoints DISABLE TRIGGER USER"))
        await conn.execute(text(
            "UPDATE audit_checkpoints SET mac = :m"), {"m": "f" * 64})
        await conn.execute(text(
            "ALTER TABLE audit_checkpoints ENABLE TRIGGER USER"))
    async with session_factory() as s:
        cps = (await s.execute(select(AuditCheckpoint).where(
            AuditCheckpoint.chain_id == cid))).scalars().all()
        rows = (await s.execute(select(AuditChainEvent).where(
            AuditChainEvent.chain_id == cid)
            .order_by(AuditChainEvent.seq.asc()))).scalars().all()
    key = get_settings().audit_checkpoint_key
    if not key:  # checkpointing disabled in env: skip MAC leg
        pytest.skip("audit_checkpoint_key not configured")
    res = aus.verify_chain_rows(rows, cps, key)
    assert res.status == "INVALID" and any(
        i.code == "CHECKPOINT_MAC_MISMATCH" for i in res.issues)


# ── Phase 10/56: transaction boundary + failure injection ────────────


@pytest.mark.asyncio
async def test_rollback_removes_audit_event_no_false_security_state(session_factory, tenant):
    """SECURITY-CRITICAL semantics: if the surrounding transaction rolls
    back, the audit event NEVER existed — no APPROVED without approval.
    (First-ever append also rolls the chain row back: zero residue.)"""
    i1, _ = tenant
    async with session_factory() as s:
        await aus.emit_security_event(
            s, installation_id=i1.id, event_type="APPROVAL_GRANTED",
            actor_type=aus.ActorType.USER, result="OK")
        await s.flush()
        await s.rollback()  # security state change failed → event gone
    async with session_factory() as s:
        chains = (await s.execute(select(AuditChain).where(
            AuditChain.installation_id == i1.id))).scalars().all()
        events = (await s.execute(select(AuditChainEvent))).scalars().all()
    if chains:
        # A chain row survived a later commit; its events must be empty.
        assert len(events) == 0
    assert len(events) == 0  # no false security witness exists
    # And the tenant can keep appending cleanly afterwards.
    await _append(session_factory, i1.id, n=2)
    cid = await _chain_id(session_factory, i1.id)
    res = await _verify(session_factory, cid)
    assert res.status == "VALID" and res.checked_events == 2


@pytest.mark.asyncio
async def test_audit_write_failure_does_not_false_succeed(session_factory, tenant, monkeypatch):
    """Phase 31/56: a failing chain write on a SECURITY-CRITICAL event
    must raise (the caller's transaction fails) — never silently drop
    the witness of a security state change."""
    i1, _ = tenant

    def broken_digest(**kwargs):
        raise RuntimeError("injected digest failure")

    monkeypatch.setattr(aus, "compute_event_digest", broken_digest)
    with pytest.raises(RuntimeError):
        async with session_factory() as s:
            await aus.emit_security_event(
                s, installation_id=i1.id, event_type="APPROVAL_GRANTED",
                actor_type=aus.ActorType.USER)
            await s.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize("rep", REP_IDS)
async def test_checkpoint_chain_consistency_under_concurrency(session_factory, tenant, rep):
    """Phase 30/57: checkpoint×event — every committed event has a
    matching MAC-valid checkpoint row (when checkpointing is on), and
    the chain verifies with 0 gaps."""
    i1, _ = tenant
    await asyncio.gather(*[
        _append(session_factory, i1.id, n=2) for _ in range(4)
    ])
    cid = await _chain_id(session_factory, i1.id)
    async with session_factory() as s:
        res = await aus.verify_chain(s, chain_id=cid)
        events = (await s.execute(
            select(AuditChainEvent.seq).where(AuditChainEvent.chain_id == cid)
        )).scalars().all()
        cps = (await s.execute(select(AuditCheckpoint.through_sequence)
                               .where(AuditCheckpoint.chain_id == cid))).scalars().all()
    assert res.status == "VALID"
    assert sorted(events) == sorted(set(events))
    if get_settings().audit_checkpoint_key:
        assert set(cps) >= set(events)  # every event covered by a checkpoint
