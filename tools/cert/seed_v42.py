"""CYVRIX V4.2 — seed realistic data into the v42 test database so the
backup/restore certification validates REAL data integrity, not an empty
schema. Creates two tenants, repositories, scans, findings, and audit
chain events (via the V3.8 service so the chain is genuinely verifiable
after restore), plus API keys and webhook deliveries.
"""
import asyncio
import os
import sys
import uuid as uuid_module
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "apps" / "api"))

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://cyvrix:cyvrix_dev@localhost:5434/cyvrix")
os.environ.setdefault("REDIS_URL", "redis://localhost:6381/0")


async def main() -> None:
    from sqlalchemy import select

    import app.models as m
    from app.database import Base, async_session, engine
    from app.services.audit_service import emit_security_event, ActorType

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as s:
        existing = (await s.execute(select(m.User).limit(1))).scalar_one_or_none()
        if existing is not None:
            print("seed: data already present, skipping")
            return

        for t in ("alpha", "beta"):
            user = m.User(email=f"seed-{t}@v42.local", github_id=hash(t) % 100000)
            s.add(user)
            await s.flush()

            org = m.Organization(
                name=f"SeedOrg-{t}", slug=f"seedorg-{t}-" + uuid_module.uuid4().hex[:6],
            )
            s.add(org)
            await s.flush()

            s.add(m.OrganizationMembership(
                organization_id=org.id, user_id=user.id, role="owner",
                state="ACTIVE",
            ))

            inst = m.GithubInstallation(
                user_id=user.id,
                installation_id=uuid_module.uuid4().int % 900000 + 1,
                account_login=f"seed-{t}",
                account_type="Organization",
                organization_id=org.id,
            )
            s.add(inst)
            await s.flush()

            repo = m.Repository(
                installation_id=inst.id,
                github_repo_id=uuid_module.uuid4().int % 900000 + 1,
                owner=f"seed-{t}",
                name="repo",
                default_branch="main",
                is_active=True,
            )
            s.add(repo)
            await s.flush()

            scan = m.Scan(repository_id=repo.id, status="COMPLETED", trigger="seed")
            s.add(scan)
            await s.flush()

            finding = m.Finding(
                scan_id=scan.id,
                repository_id=repo.id,
                fingerprint=f"fp-seed-{t}-{uuid_module.uuid4().hex[:8]}",
                scanner="seed",
                source_type="DEPENDENCY",
                vulnerability_id="GHSA-0000-seed",
                package_name="left-pad",
                package_version="1.0.0",
                title="Seed finding",
                severity="HIGH",
                status="OPEN",
            )
            s.add(finding)

            # API key + webhook delivery records for restore checks.
            key = m.ApiKey(
                organization_id=org.id,
                name=f"seed-{t}-key",
                prefix=f"cyvseed{t}"
                + uuid_module.uuid4().hex[:6],
                key_hash=f"seedhash-{t}-{uuid_module.uuid4().hex[:16]}",
                scopes=["scans:read", "scans:create"],
            )
            s.add(key)
            delivery = m.WebhookDelivery(
                organization_id=org.id,
                github_delivery_id=uuid_module.uuid4().hex,
                event_type="push",
                signature_state="VALID",
                outcome="ACCEPTED",
            )
            s.add(delivery)

            # Audit chain events through the V3.8 service so the chain
            # links are real and verifiable after restore.
            await emit_security_event(
                s,
                organization_id=org.id,
                event_type="SCAN_REQUESTED",
                actor_type=ActorType.SYSTEM,
                repository_id=repo.id,
                payload={"seed": t, "n": 1},
            )
            await emit_security_event(
                s,
                organization_id=org.id,
                event_type="SCAN_REQUESTED",
                actor_type=ActorType.SYSTEM,
                repository_id=repo.id,
                payload={"seed": t, "n": 2},
            )
            await s.commit()
            print(f"seed: tenant {t} ok (org={org.id})")

    await engine.dispose()
    print("seed: done")


if __name__ == "__main__":
    asyncio.run(main())
