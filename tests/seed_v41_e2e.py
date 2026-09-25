"""CYVRIX V4.1 — E2E seed: org + memberships + API key for Playwright.

Creates (idempotently per run):
  - one OWNER user + organization ("V4.1 E2E Org") + installation + repo
  - one VIEWER user with an ACTIVE membership in the same organization
  - one API key with scans:read (the secret is written to /tmp so the
    browser test can call the public API with it)
  - one COMPLETED scan for the repository (job-state surface)

Writes /tmp/v41_e2e_seed.json consumed by
apps/web/e2e/v41-external-boundary.spec.ts. Run against the real
integration stack (infra/docker-compose.integration.yml).
"""
import asyncio
import json
import os
import sys
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import get_settings
from app.models import (
    GithubInstallation,
    Repository,
    Scan,
    User,
)
from app.services import api_key_service, organization_service as org_svc

SEED_PATH = os.path.join(os.path.abspath(os.sep), "tmp", "v41_e2e_seed.json")


async def main() -> None:
    settings = get_settings()
    engine = create_async_engine(settings.database_url, poolclass=NullPool)
    Session = async_sessionmaker(engine, class_=__import__(
        "sqlalchemy.ext.asyncio", fromlist=["AsyncSession"]).AsyncSession,
        expire_on_commit=False,
    )

    async with Session() as s:
        marker = f"v41-e2e-{uuid4().hex[:8]}"

        owner = User(email=f"{marker}-owner@test.local", github_id=None)
        s.add(owner)
        await s.flush()

        viewer = User(email=f"{marker}-viewer@test.local", github_id=None)
        s.add(viewer)
        await s.flush()

        org = await org_svc.create_organization(
            s, name=f"V4.1 E2E {marker}", creator_user_id=owner.id
        )
        await s.flush()

        s.add(__import__("app.models", fromlist=[
            "OrganizationMembership"]).OrganizationMembership(
            organization_id=org.id,
            user_id=viewer.id,
            role="VIEWER",
            state="ACTIVE",
        ))
        await s.flush()

        inst = GithubInstallation(
            user_id=owner.id,
            installation_id=uuid4().int % 900000 + 1,
            account_login="v41-e2e",
            account_type="Organization",
            organization_id=org.id,
        )
        s.add(inst)
        await s.flush()

        repo = Repository(
            installation_id=inst.id,
            github_repo_id=uuid4().int % 900000 + 1,
            owner="v41-e2e",
            name="repo",
            default_branch="main",
            is_active=True,
        )
        s.add(repo)
        await s.flush()

        scan = Scan(
            repository_id=repo.id,
            status="COMPLETED",
            trigger="api",
            commit_sha="a" * 40,
            requested_commit_sha="a" * 40,
        )
        s.add(scan)
        await s.flush()

        owner_membership = await org_svc.get_membership(
            s, org_id=org.id, user_id=owner.id
        )
        row, secret = await api_key_service.create_api_key(
            s,
            org_id=org.id,
            actor_membership=owner_membership,
            actor_user_id=owner.id,
            name="e2e-ci",
            scopes=["scans:read", "repositories:read"],
        )
        await s.commit()

        payload = {
            "owner": {
                "user_id": str(owner.id),
                "email": owner.email,
                "org_id": str(org.id),
                "org_name": org.name,
            },
            "viewer": {
                "user_id": str(viewer.id),
                "email": viewer.email,
            },
            "repository_id": str(repo.id),
            "scan_id": str(scan.id),
            "api_key_secret": secret,
            "api_key_prefix": row.prefix,
        }

    await engine.dispose()

    with open(SEED_PATH, "w") as f:
        json.dump(payload, f)
    print(f"seed written: {SEED_PATH}")
    print(f"  owner: {payload['owner']['email']}")
    print(f"  viewer: {payload['viewer']['email']}")


if __name__ == "__main__":
    asyncio.run(main())
