"""V3.8 export certification driver — REAL stack.

Generates a live audit export from the real database and independently
verifies the artifact WITHOUT the database (Phase 27/28/50), including
tampering with the exported file itself.

Usage (real stack up, migrated to 011):
  RUN_INTEGRATION_TESTS=1 \
  DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
  REDIS_URL=redis://localhost:6380/0 \
  SECRET_KEY=test-secret-key-for-integration-only-not-for-production-32chars! \
  ENVIRONMENT=development \
  python tests/cert_v38_audit.py
"""
import asyncio
import json
import os
import sys
import uuid as uuid_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession, create_async_engine

from app.models import AuditChain, AuditChainEvent, GithubInstallation
from app.services import audit_service as aus

RESULTS = []


def record(name, ok, evidence=""):
    RESULTS.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  |  {evidence}")


async def main() -> int:
    settings = get_settings_safe()
    engine = create_async_engine(settings["db"], echo=False)
    SF = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # 1. Live tenant + events through the real service path.
    tag = uuid_mod.uuid4().hex[:8]
    async with SF() as s:
        from app.models import User
        u = User(email=f"v38cert-{tag}@cyvrix.local")
        s.add(u)
        await s.flush()
        inst = GithubInstallation(user_id=u.id,
                                  installation_id=8_000_000 + int(tag, 16) % 100000,
                                  account_login="cert-org", account_type="Organization")
        s.add(inst)
        await s.commit()
        await s.refresh(inst)
        iid = inst.id
    for et in ("ACTION_PROPOSED", "APPROVAL_GRANTED", "AUTHORIZATION_CREATED",
               "EXECUTION_STARTED", "EXECUTION_COMPLETED"):
        async with SF() as s:
            await aus.emit_security_event(
                s, installation_id=iid, event_type=et,
                actor_type=aus.ActorType.USER, reason_code="OK", result="OK",
                payload={"step": et})
            await s.commit()

    # 2. Export through the service (same code the API route uses).
    async with SF() as s:
        chain = (await s.execute(
            select(AuditChain).where(AuditChain.installation_id == iid))).scalar_one()
        rows = (await s.execute(
            select(AuditChainEvent).where(AuditChainEvent.chain_id == chain.id)
            .order_by(AuditChainEvent.seq.asc()))).scalars().all()
        export = aus.export_chain_ndjson(rows, [], chain)
        cid = chain.id
    record("E2E export generated (5 events)", len(rows) == 5, f"n={len(rows)}")

    # 3. Independent verification — NO database.
    res = aus.verify_export_ndjson(export)
    record("E2E standalone verification VALID (no DB)", res.status == "VALID",
           f"status={res.status} checked={res.checked_events}")

    # 4. Tamper with the export artifact — every mutation detected.
    lines = export.strip().splitlines()
    rec = json.loads(lines[2]); rec["result"] = "FORGED"; lines[2] = aus.canonical_json(rec)
    record("E2E forged outcome in export detected",
           aus.verify_export_ndjson("\n".join(lines)).status == "INVALID")
    lines = export.strip().splitlines()
    rec = json.loads(lines[1]); rec["actor_type"] = "ADMIN"; lines[1] = aus.canonical_json(rec)
    record("E2E forged actor in export detected",
           aus.verify_export_ndjson("\n".join(lines)).status == "INVALID")
    lines = export.strip().splitlines()
    del lines[3]
    record("E2E event removal in export detected",
           aus.verify_export_ndjson("\n".join(lines)).status == "INVALID")
    lines = export.strip().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    record("E2E reordering in export detected",
           aus.verify_export_ndjson("\n".join(lines)).status == "INVALID")

    # 5. Live chain verifies server-side too.
    async with SF() as s:
        live = await aus.verify_chain(s, chain_id=cid)
    record("E2E live chain verification VALID", live.status == "VALID",
           f"checked={live.checked_events}")

    await engine.dispose()
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n== V3.8 export certification: {len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed ==")
    return 1 if failed else 0


def get_settings_safe():
    return {
        "db": os.environ["DATABASE_URL"],
    }


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
