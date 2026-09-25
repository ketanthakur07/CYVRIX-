"""CYVRIX V4.0 — multi-tenancy / RBAC races, red team and failure injection
on REAL PostgreSQL (+ Redis for quota checks).

Gated behind RUN_INTEGRATION_TESTS=1 and the migrated database:
    RUN_INTEGRATION_TESTS=1 \
    DATABASE_URL=postgresql+asyncpg://cyvrix_test:cyvrix_test_password@localhost:5433/cyvrix_test \
    REDIS_URL=redis://localhost:6380/0 \
    SECRET_KEY=test-secret-key-for-integration-only-not-for-production-32chars! \
    ENVIRONMENT=development \
    pytest tests/test_v4_races.py

Covers (V4 release gates):
- Phase 4/53: one-time invitation accepts race — exactly one membership,
  replay is refused
- Phase 7/53: last-owner protection under concurrent demotions — the
  organization is never left with zero active owners
- Phase 7/53: an actor demoted by a concurrent transaction cannot complete
  a management action with its stale role (TOCTOU at the org lock)
- Phase 14/53: concurrent policy updates keep versions unique + monotonic
- Phase 23/53: API key revocation races never leave a live key
- Phase 8/10/53: tenant isolation holds under concurrent writes
- Phase 29/30/53: organization rate limit under concurrency (noisy neighbor)
- Phase 52: client-supplied organization id / spoofed tenant never grants
  access; DELETED organization is a 404 even for its members
- Phase 54: failure injection (DB outage, Redis outage) fails CLOSED
"""
import asyncio
import os
import uuid as uuid_module
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_INTEGRATION_TESTS") != "1",
    reason="V4 tenancy races require RUN_INTEGRATION_TESTS=1 and real PostgreSQL",
)

from fastapi import HTTPException  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.models import (  # noqa: E402
    ApiKey,
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
    OrganizationPolicyRevision,
    User,
)
from app.services import api_key_service, org_auth  # noqa: E402
from app.services import organization_service as org_svc  # noqa: E402
from app.services import v4_rbac as rbac  # noqa: E402
from app.services.organization_service import OrgError  # noqa: E402

REPETITIONS = 10
REP_IDS = list(range(REPETITIONS))


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
async def real_engine():
    settings = get_settings()
    if "sqlite" in settings.database_url:
        pytest.skip("PostgreSQL required for V4 tenancy races")
    eng = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(real_engine):
    return async_sessionmaker(real_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
async def clean_db_real(real_engine):
    """Wipe tables between tests (audit triggers are disabled only here, as in
    the V3.8 race suite — the application has no path to do this)."""
    from app.models import SystemControl
    from conftest import wipe_all_tables
    async with real_engine.begin() as conn:
        await wipe_all_tables(conn)
        await conn.execute(SystemControl.__table__.insert().values(
            key="operational_state", value="NORMAL"))
    yield


@pytest.fixture
async def users(session_factory, clean_db_real):
    async with session_factory() as s:
        a = User(email=f"owner-a-{uuid_module.uuid4()}@t.local")
        b = User(email=f"owner-b-{uuid_module.uuid4()}@t.local")
        c = User(email=f"member-{uuid_module.uuid4()}@t.local")
        s.add_all([a, b, c])
        await s.commit()
        await s.refresh(a)
        await s.refresh(b)
        await s.refresh(c)
        return a, b, c


# ── Helpers ──────────────────────────────────────────────────────────


async def _make_org(session_factory, creator, name="Acme"):
    async with session_factory() as s:
        org = await org_svc.create_organization(s, name=name, creator_user_id=creator.id)
        await s.commit()
        return org


async def _add_member(session_factory, org, user, role, state="ACTIVE"):
    async with session_factory() as s:
        s.add(OrganizationMembership(
            organization_id=org.id, user_id=user.id, role=role, state=state))
        await s.commit()


async def _membership(session_factory, org, user):
    async with session_factory() as s:
        return await org_svc.get_membership(s, org_id=org.id, user_id=user.id)


async def _active_owners(session_factory, org):
    async with session_factory() as s:
        return int((await s.execute(
            select(func.count()).select_from(OrganizationMembership).where(
                OrganizationMembership.organization_id == org.id,
                OrganizationMembership.role == rbac.OrgRole.ORG_OWNER,
                OrganizationMembership.state == rbac.MembershipState.ACTIVE,
            )
        )).scalar() or 0)


async def _membership_count(session_factory, org, user=None):
    """Membership rows in the organization (optionally for one user)."""
    stmt = select(func.count()).select_from(OrganizationMembership).where(
        OrganizationMembership.organization_id == org.id)
    if user is not None:
        stmt = stmt.where(OrganizationMembership.user_id == user.id)
    async with session_factory() as s:
        return int((await s.execute(stmt)).scalar() or 0)


async def _accept(session_factory, token, user):
    """Accept an invitation in its own transaction; returns None on refusal."""
    async with session_factory() as s:
        try:
            membership = await org_svc.accept_invitation(s, token=token, user=user)
            await s.commit()
            return membership
        except Exception:
            await s.rollback()
            return None


async def _demote(session_factory, org, actor_user, target_user, new_role):
    """Demote in its own transaction; returns the reason code on refusal."""
    async with session_factory() as s:
        try:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=actor_user.id)
            await org_svc.change_member_role(
                s, org_id=org.id, actor_membership=actor,
                target_user_id=target_user.id, new_role=new_role,
            )
            await s.commit()
            return None
        except OrgError as exc:
            await s.rollback()
            return exc.reason_code
        except Exception:
            await s.rollback()
            return "INTEGRITY_REFUSED"


# ── Phase 4/53: invitation single-use under concurrency ──────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_invitation_single_use_under_concurrency(
    session_factory, users, rep
):
    owner, _, invitee = users
    org = await _make_org(session_factory, owner, f"Race{rep}")
    async with session_factory() as s:
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        _, token = await org_svc.create_invitation(
            s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
            email=None, role=rbac.OrgRole.DEVELOPER)
        await s.commit()

    results = await asyncio.gather(*[
        _accept(session_factory, token, invitee) for _ in range(6)
    ])
    assert sum(1 for r in results if r is not None) == 1
    assert await _membership_count(session_factory, org, invitee) == 1
    assert await _membership_count(session_factory, org) == 2  # owner + invitee
    membership = await _membership(session_factory, org, invitee)
    assert membership.role == rbac.OrgRole.DEVELOPER


@pytest.mark.parametrize("rep", REP_IDS)
async def test_concurrent_accepts_of_different_tokens_yield_one_membership(
    session_factory, users, rep
):
    """Two valid invitations for the same user must not double-create a
    membership row (uq_org_membership is the backstop)."""
    owner, _, invitee = users
    org = await _make_org(session_factory, owner, f"Multi{rep}")
    tokens = []
    async with session_factory() as s:
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        for _ in range(2):
            _, token = await org_svc.create_invitation(
                s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
                email=None, role=rbac.OrgRole.VIEWER)
            tokens.append(token)
        await s.commit()

    await asyncio.gather(*[_accept(session_factory, t, invitee) for t in tokens])
    assert await _membership_count(session_factory, org, invitee) == 1


# ── Phase 7: last-owner protection races ─────────────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_last_owner_race_never_leaves_zero_owners(
    session_factory, users, rep
):
    """Two owners concurrently demote each other: at most one wins and the
    organization always keeps an active owner."""
    owner_a, owner_b, _ = users
    org = await _make_org(session_factory, owner_a, f"Owners{rep}")
    await _add_member(session_factory, org, owner_b, rbac.OrgRole.ORG_OWNER)

    results = await asyncio.gather(
        _demote(session_factory, org, owner_a, owner_b, rbac.OrgRole.VIEWER),
        _demote(session_factory, org, owner_b, owner_a, rbac.OrgRole.VIEWER),
    )
    winners = [r for r in results if r is None]
    assert len(winners) == 1, results
    assert await _active_owners(session_factory, org) == 1


@pytest.mark.parametrize("rep", REP_IDS)
async def test_demoted_actor_cannot_manage_with_stale_role(
    session_factory, users, rep
):
    """TOCTOU: the actor's role is re-read AFTER the organization lock, so a
    concurrently demoted admin cannot finish an admin-only action."""
    owner, admin, _ = users
    org = await _make_org(session_factory, owner, f"Stale{rep}")
    await _add_member(session_factory, org, admin, rbac.OrgRole.ORG_ADMIN)

    results = await asyncio.gather(
        _demote(session_factory, org, owner, admin, rbac.OrgRole.VIEWER),
        _demote(session_factory, org, admin, owner, rbac.OrgRole.VIEWER),
    )
    # Exactly one demotion commits; the other is refused because either the
    # freshly-read actor is no longer an admin, or a non-owner tried to change
    # an owner's role. Zero active owners is impossible either way.
    assert results[0] is None
    assert results[1] in (
        "MEMBER_MANAGEMENT_NOT_PERMITTED", "OWNER_CHANGE_REQUIRES_OWNER",
        "LAST_OWNER_PROTECTED",
    ), results
    assert await _active_owners(session_factory, org) == 1
    assert (await _membership(session_factory, org, admin)).role == rbac.OrgRole.VIEWER


# ── Phase 14/53: policy versions under concurrency ───────────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_concurrent_policy_updates_keep_unique_monotonic_versions(
    session_factory, users, rep
):
    owner, _, _ = users
    org = await _make_org(session_factory, owner, f"Policy{rep}")

    async def _set(policy):
        async with session_factory() as s:
            try:
                actor = await org_svc.get_membership(
                    s, org_id=org.id, user_id=owner.id)
                await org_svc.set_policy(
                    s, org_id=org.id, actor_membership=actor,
                    actor_user_id=owner.id, policy=policy)
                await s.commit()
                return True
            except Exception:
                await s.rollback()
                return False

    outcomes = await asyncio.gather(*[
        _set({"max_risk_level": lvl}) for lvl in
        ("LOW", "MEDIUM", "HIGH", "LOW", "MEDIUM", "HIGH")
    ])
    async with session_factory() as s:
        org_row = (await s.execute(
            select(Organization).where(Organization.id == org.id))).scalar_one()
        versions = sorted((await s.execute(
            select(OrganizationPolicyRevision.version).where(
                OrganizationPolicyRevision.organization_id == org.id)
        )).scalars().all())
    assert any(outcomes)
    # Monotonic, gap-free history that matches the live version.
    assert versions == list(range(1, int(org_row.policy_version) + 1))
    assert len(versions) == len(set(versions))


# ── Phase 23/53: API key revocation races ────────────────────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_api_key_revoke_race_never_leaves_live_key(
    session_factory, users, rep
):
    owner, _, _ = users
    org = await _make_org(session_factory, owner, f"Keys{rep}")
    async with session_factory() as s:
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        row, secret = await api_key_service.create_api_key(
            s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
            name="ci", scopes=["findings:read"])
        await s.commit()
        key_id = row.id

    async def _auth():
        async with session_factory() as s:
            resolved = await api_key_service.authenticate_api_key(s, secret)
            await s.commit()
            return resolved is not None

    async def _revoke():
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
            await api_key_service.revoke_api_key(
                s, org_id=org.id, actor_membership=actor, key_id=key_id)
            await s.commit()
            return True

    await asyncio.gather(_auth(), _revoke(), _auth(), _revoke())
    assert await _auth() is False  # after revocation, no live key remains


@pytest.mark.parametrize("rep", REP_IDS)
async def test_concurrent_api_key_creation_distinct_prefixes(
    session_factory, users, rep
):
    owner, _, _ = users
    org = await _make_org(session_factory, owner, f"Prefix{rep}")

    async def _create():
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
            row, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
                name="ci", scopes=["findings:read"])
            await s.commit()
            return row.prefix

    prefixes = await asyncio.gather(*[_create() for _ in range(6)])
    assert len(set(prefixes)) == 6
    async with session_factory() as s:
        stored = (await s.execute(
            select(ApiKey.prefix).where(ApiKey.organization_id == org.id)
        )).scalars().all()
    assert len(stored) == 6


# ── Phase 8/10/53: isolation under concurrent writes ─────────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_tenant_isolation_holds_under_concurrent_writes(
    session_factory, users, rep
):
    owner_a, owner_b, other = users
    org_a = await _make_org(session_factory, owner_a, f"TenantA{rep}")
    org_b = await _make_org(session_factory, owner_b, f"TenantB{rep}")
    await _add_member(session_factory, org_a, other, rbac.OrgRole.VIEWER)
    await _add_member(session_factory, org_b, other, rbac.OrgRole.AUDITOR)

    def _write(org, actor_user, role):
        async def inner():
            async with session_factory() as s:
                actor = await org_svc.get_membership(
                    s, org_id=org.id, user_id=actor_user.id)
                await org_svc.change_member_role(
                    s, org_id=org.id, actor_membership=actor,
                    target_user_id=other.id, new_role=role)
                await s.commit()
        return inner

    async def _read(org):
        async with session_factory() as s:
            rows = await org_svc.list_memberships(s, org_id=org.id)
            return {r.organization_id for r in rows}

    reads = await asyncio.gather(
        _read(org_a), _read(org_b), _read(org_a), _read(org_b),
        _write(org_a, owner_a, rbac.OrgRole.DEVELOPER)(),
        _write(org_b, owner_b, rbac.OrgRole.VIEWER)(),
        _read(org_a), _read(org_b),
    )
    for org_ids in reads[:4] + reads[6:]:
        assert len(org_ids) == 1  # only one tenant ever appeared in a read
    assert (await _membership(session_factory, org_a, other)).role == rbac.OrgRole.DEVELOPER
    assert (await _membership(session_factory, org_b, other)).role == rbac.OrgRole.VIEWER


# ── Phase 29/30/53: organization quota under concurrency ─────────────


@pytest.mark.parametrize("rep", REP_IDS)
async def test_org_rate_limit_bounds_concurrent_requests(rep):
    """A noisy organization cannot exceed its server-side quota even when it
    fires the whole burst concurrently (real Redis, fresh client so the check
    is not invalidated by the process-wide cached connection's event loop)."""
    import redis.asyncio as aioredis

    r = aioredis.from_url(get_settings().redis_url)
    try:
        await r.ping()
    except Exception:
        await r.aclose()
        pytest.skip("Redis required for organization quota race")
    bucket = f"race-{uuid_module.uuid4()}"
    limit = 10
    try:
        results = await asyncio.gather(*[_allow(r, bucket, limit) for _ in range(40)])
    finally:
        await r.aclose()
    assert sum(1 for x in results if x is True) == limit


async def _allow(redis_client, bucket, limit):
    from app.rate_limit import check_rate_limit
    allowed, _ = await check_rate_limit(
        f"org:{bucket}:bin", limit, 3600, r=redis_client)
    return allowed


# ── Phase 52: client-supplied tenant is never authority ──────────────


async def test_deleted_organization_is_404_for_members(session_factory, users):
    owner, _, _ = users
    org = await _make_org(session_factory, owner, "Doomed")
    async with session_factory() as s:
        membership = await org_auth._load_membership(s, owner, org.id)
        assert membership.state == rbac.MembershipState.ACTIVE
        org_row = (await s.execute(
            select(Organization).where(Organization.id == org.id))).scalar_one()
        org_row.state = "DELETED"
        await s.commit()
    async with session_factory() as s:
        with pytest.raises(HTTPException) as exc:
            await org_auth._load_membership(s, owner, org.id)
        assert exc.value.status_code == 404


async def test_suspended_member_membership_is_404(session_factory, users):
    owner, _, member = users
    org = await _make_org(session_factory, owner, "Suspend")
    await _add_member(session_factory, org, member, rbac.OrgRole.ORG_ADMIN,
                      state=rbac.MembershipState.SUSPENDED)
    async with session_factory() as s:
        with pytest.raises(HTTPException) as exc:
            await org_auth._load_membership(s, member, org.id)
        assert exc.value.status_code == 404


async def test_cross_tenant_org_id_never_grants_access(session_factory, users):
    """A foreign organization id (as a path/header selector) yields 404 for a
    user with no membership, even when the id is well-formed and real."""
    owner_a, owner_b, _ = users
    org_a = await _make_org(session_factory, owner_a, "Mine")
    org_b = await _make_org(session_factory, owner_b, "Theirs")
    async with session_factory() as s:
        assert await org_auth._load_membership(s, owner_a, org_a.id) is not None
        with pytest.raises(HTTPException) as exc:
            await org_auth._load_membership(s, owner_a, org_b.id)
        assert exc.value.status_code == 404


# ── Phase 54: failure injection must fail closed ─────────────────────


class _BrokenSession:
    """Simulates a database outage: every query raises."""

    async def execute(self, *args, **kwargs):
        raise RuntimeError("injected database outage")

    async def commit(self):
        raise RuntimeError("injected database outage")


async def test_db_outage_fails_closed_on_tenant_resolution(users):
    owner, _, _ = users
    with pytest.raises(Exception):
        await org_auth._load_membership(_BrokenSession(), owner, uuid_module.uuid4())


async def test_db_outage_fails_closed_on_api_key_auth():
    with pytest.raises(Exception):
        await org_auth.api_key_auth(
            authorization="Bearer cyv_deadbeef_secret", db=_BrokenSession())


async def test_redis_outage_fails_closed(monkeypatch):
    import app.session as app_session
    from app.rate_limit import check_rate_limit

    def _boom():
        raise ConnectionError("injected redis outage")

    monkeypatch.setattr(app_session, "get_redis", _boom)
    allowed, remaining = await check_rate_limit("org:x:y", 10, 60)
    assert allowed is False and remaining == 0
    with pytest.raises(HTTPException) as exc:
        await org_auth.rate_limit_org(None, org_id=uuid_module.uuid4(),
                                      bucket="org-read", limit=10)
    assert exc.value.status_code == 429


# ── Phase 19/53: integration tenancy binding ─────────────────────────


async def test_installation_binding_is_organization_scoped(session_factory, users):
    """A repository/installation carries its organization; a foreign
    organization's id never matches another tenant's installation."""
    from app.models import GithubInstallation, Repository

    owner_a, owner_b, _ = users
    org_a = await _make_org(session_factory, owner_a, "InstA")
    org_b = await _make_org(session_factory, owner_b, "InstB")
    async with session_factory() as s:
        inst_a = GithubInstallation(
            user_id=owner_a.id, installation_id=uuid_module.uuid4().int % 900000 + 1,
            account_login="a", account_type="Organization", organization_id=org_a.id)
        inst_b = GithubInstallation(
            user_id=owner_b.id, installation_id=uuid_module.uuid4().int % 900000 + 2,
            account_login="b", account_type="Organization", organization_id=org_b.id)
        s.add_all([inst_a, inst_b])
        await s.flush()
        s.add(Repository(installation_id=inst_a.id,
                         github_repo_id=uuid_module.uuid4().int % 900000 + 11,
                         owner="a", name="a-repo", default_branch="main", is_active=True))
        s.add(Repository(installation_id=inst_b.id,
                         github_repo_id=uuid_module.uuid4().int % 900000 + 12,
                         owner="b", name="b-repo", default_branch="main", is_active=True))
        await s.commit()

    async with session_factory() as s:
        scoped = (await s.execute(
            select(Repository.name)
            .join(GithubInstallation, GithubInstallation.id == Repository.installation_id)
            .where(GithubInstallation.organization_id == org_a.id)
        )).scalars().all()
    assert scoped == ["a-repo"]


async def test_expired_invitation_is_refused_on_real_db(session_factory, users):
    owner, _, invitee = users
    org = await _make_org(session_factory, owner, "Expiry")
    async with session_factory() as s:
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        invitation, token = await org_svc.create_invitation(
            s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
            email=None, role=rbac.OrgRole.VIEWER)
        invitation.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await s.commit()
    async with session_factory() as s:
        with pytest.raises(OrgError) as exc:
            await org_svc.accept_invitation(s, token=token, user=invitee)
        assert exc.value.reason_code == "INVITATION_EXPIRED"
    assert await _membership_count(session_factory, org, invitee) == 0


async def test_hashed_invitation_token_only_in_database(session_factory, users):
    """Nothing but the SHA-256 hash may ever be persisted for a token."""
    owner, _, invitee = users
    org = await _make_org(session_factory, owner, "Hashed")
    async with session_factory() as s:
        actor = await org_svc.get_membership(s, org_id=org.id, user_id=owner.id)
        _, token = await org_svc.create_invitation(
            s, org_id=org.id, actor_membership=actor, actor_user_id=owner.id,
            email=None, role=rbac.OrgRole.VIEWER)
        await s.commit()
    async with session_factory() as s:
        row = (await s.execute(
            select(OrganizationInvitation).where(
                OrganizationInvitation.organization_id == org.id))).scalar_one()
    assert row.token_hash != token
    dumped = " ".join(str(c) for c in row.__dict__.values())
    assert token not in dumped
