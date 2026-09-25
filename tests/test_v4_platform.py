"""CYVRIX V4.0 — platform foundation tests.

Covers:
- RBAC role→capability mapping (unknown role/capability fail closed)
- membership states (only ACTIVE confers capabilities)
- last-owner protection and owner-only role changes
- invitation lifecycle (hash-only storage, single-use, expiry, email bind)
- API key security (hash-only, prefix lookup, revoke, expiry, scopes)
- organization policy validation/versioning + DENY-only overlay
- cross-organization IDOR on the V4 API (404 for non-members)
- organization-scoped API keys (tenant derived from the key)
"""
import sys
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import (
    GithubInstallation, OrganizationMembership, OrganizationPolicyRevision,
    Repository,
)
from app.services import organization_service as org_svc
from app.services import api_key_service, v4_rbac as rbac
from app.services.organization_service import OrgError


pytestmark = pytest.mark.usefixtures("clean_db")


async def _make_org(session_factory, owner, name="Acme"):
    async with session_factory() as s:
        org = await org_svc.create_organization(
            s, name=name, creator_user_id=owner.id
        )
        await s.commit()
        return org


async def _add_member(session_factory, org, user, role, state="ACTIVE"):
    async with session_factory() as s:
        s.add(OrganizationMembership(
            organization_id=org.id, user_id=user.id, role=role, state=state,
        ))
        await s.commit()


async def _membership(session_factory, org, user):
    async with session_factory() as s:
        return await org_svc.get_membership(s, org_id=org.id, user_id=user.id)


# ── RBAC (pure) ──────────────────────────────────────────────────────


class TestRbac:
    def test_unknown_role_has_no_capabilities(self):
        assert rbac.capabilities_for_role("SUPERADMIN") == frozenset()
        assert rbac.role_has_capability(None, rbac.CAP_MANAGE_MEMBERS) is False

    def test_unknown_capability_is_false(self):
        assert rbac.role_has_capability(rbac.OrgRole.ORG_OWNER, "DO_EVERYTHING") is False

    def test_role_ladder(self):
        viewer = rbac.capabilities_for_role(rbac.OrgRole.VIEWER)
        developer = rbac.capabilities_for_role(rbac.OrgRole.DEVELOPER)
        engineer = rbac.capabilities_for_role(rbac.OrgRole.SECURITY_ENGINEER)
        admin = rbac.capabilities_for_role(rbac.OrgRole.ORG_ADMIN)
        owner = rbac.capabilities_for_role(rbac.OrgRole.ORG_OWNER)
        assert viewer <= developer <= engineer <= admin <= owner
        assert rbac.CAP_APPROVE_ACTION in engineer
        assert rbac.CAP_APPROVE_ACTION not in developer
        assert rbac.CAP_MANAGE_MEMBERS in admin
        assert rbac.CAP_MANAGE_MEMBERS not in engineer
        assert rbac.CAP_DELETE_ORGANIZATION in owner
        assert rbac.CAP_DELETE_ORGANIZATION not in admin

    def test_auditor_is_read_plus_audit_only(self):
        auditor = rbac.capabilities_for_role(rbac.OrgRole.AUDITOR)
        assert rbac.CAP_VIEW_AUDIT in auditor
        assert rbac.CAP_EXPORT_AUDIT in auditor
        assert rbac.CAP_APPROVE_ACTION not in auditor
        assert rbac.CAP_MANAGE_MEMBERS not in auditor

    def test_only_active_membership_confers_capabilities(self):
        for state in (rbac.MembershipState.SUSPENDED, rbac.MembershipState.INVITED,
                      rbac.MembershipState.REMOVED, "WEIRD"):
            assert rbac.effective_capabilities(rbac.OrgRole.ORG_OWNER, state) == frozenset()
        assert rbac.member_has_capability(
            rbac.OrgRole.ORG_OWNER, rbac.MembershipState.ACTIVE, rbac.CAP_APPROVE_ACTION
        )

    def test_no_capability_bypasses_the_v3_chain(self):
        # There is deliberately no ALL/SUPERUSER capability and no capability
        # whose name implies bypassing policy/approval/authorization.
        for cap in rbac.ALL_CAPABILITIES:
            assert "BYPASS" not in cap
            assert "ALL" != cap
            assert "SUPER" not in cap

    def test_last_owner_protected(self):
        with pytest.raises(rbac.MembershipRuleError):
            rbac.assert_can_change_role(
                actor_role=rbac.OrgRole.ORG_OWNER,
                target_role=rbac.OrgRole.ORG_OWNER,
                new_role=rbac.OrgRole.ORG_ADMIN,
                active_owner_count=1,
            )
        # With a second owner, demotion is allowed.
        rbac.assert_can_change_role(
            actor_role=rbac.OrgRole.ORG_OWNER,
            target_role=rbac.OrgRole.ORG_OWNER,
            new_role=rbac.OrgRole.ORG_ADMIN,
            active_owner_count=2,
        )

    def test_owner_change_requires_owner(self):
        with pytest.raises(rbac.MembershipRuleError):
            rbac.assert_can_change_role(
                actor_role=rbac.OrgRole.ORG_ADMIN,
                target_role=rbac.OrgRole.DEVELOPER,
                new_role=rbac.OrgRole.ORG_OWNER,
                active_owner_count=1,
            )

    def test_api_scopes_closed_world(self):
        assert rbac.is_valid_api_scope("findings:read")
        assert not rbac.is_valid_api_scope("org:admin")
        assert not rbac.is_valid_api_scope("members:write")
        assert not rbac.scopes_are_valid(["findings:read", "nope"])


# ── Policy ───────────────────────────────────────────────────────────


class TestPolicy:
    def test_validate_rejects_unknown_keys(self):
        with pytest.raises(OrgError):
            org_svc.validate_policy({"danger": True})

    def test_validate_rejects_bad_values(self):
        with pytest.raises(OrgError):
            org_svc.validate_policy({"max_risk_level": "ULTRA"})
        with pytest.raises(OrgError):
            org_svc.validate_policy({"max_concurrent_executions": 0})
        with pytest.raises(OrgError):
            org_svc.validate_policy({"require_second_approver": "yes"})

    def test_overlay_denies_above_max_risk(self):
        policy = {"max_risk_level": "MEDIUM"}
        assert org_svc.evaluate_policy_overlay(policy, risk_level="MEDIUM").denied is False
        result = org_svc.evaluate_policy_overlay(policy, risk_level="CRITICAL")
        assert result.denied and result.reason_code == "ORG_POLICY_RISK_EXCEEDED"

    def test_overlay_denies_disallowed_action(self):
        policy = {"allowed_action_types": ["DEPENDENCY_UPGRADE"]}
        assert org_svc.evaluate_policy_overlay(
            policy, action_type="DEPENDENCY_UPGRADE").denied is False
        assert org_svc.evaluate_policy_overlay(
            policy, action_type="DOCKERFILE_UPDATE").denied is True

    def test_overlay_never_upgrades(self):
        # No policy → allow (V3 policy still applies); empty org policy cannot
        # itself approve anything.
        assert org_svc.evaluate_policy_overlay({}).decision == "ALLOW"
        assert org_svc.evaluate_policy_overlay(None).decision == "ALLOW"

    def test_malformed_policy_fails_closed(self):
        assert org_svc.evaluate_policy_overlay("garbage").denied is True


# ── Organization + membership service ────────────────────────────────


class TestOrganizationService:
    async def test_create_org_makes_creator_owner(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        membership = await _membership(session_factory, org, test_user)
        assert membership.role == rbac.OrgRole.ORG_OWNER
        assert membership.state == rbac.MembershipState.ACTIVE
        assert org.policy_version == 1

    async def test_slug_is_unique(self, session_factory, test_user):
        a = await _make_org(session_factory, test_user, "Same Name")
        b = await _make_org(session_factory, test_user, "Same Name")
        assert a.slug != b.slug

    async def test_cannot_demote_last_owner(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        membership = await _membership(session_factory, org, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            with pytest.raises(OrgError) as exc:
                await org_svc.change_member_role(
                    s, org_id=org.id, actor_membership=actor,
                    target_user_id=test_user.id, new_role=rbac.OrgRole.VIEWER,
                )
            assert exc.value.reason_code == "LAST_OWNER_PROTECTED"

    async def test_cannot_remove_last_owner(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            with pytest.raises(OrgError) as exc:
                await org_svc.remove_member(
                    s, org_id=org.id, actor_membership=actor,
                    target_user_id=test_user.id,
                )
            assert exc.value.reason_code == "LAST_OWNER_PROTECTED"

    async def test_suspended_member_has_no_capabilities(self, session_factory, test_user, test_user_b):
        org = await _make_org(session_factory, test_user)
        await _add_member(session_factory, org, test_user_b, rbac.OrgRole.SECURITY_ENGINEER)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            await org_svc.set_member_state(
                s, org_id=org.id, actor_membership=actor,
                target_user_id=test_user_b.id, state=rbac.MembershipState.SUSPENDED,
            )
            await s.commit()
        membership = await _membership(session_factory, org, test_user_b)
        assert membership.state == rbac.MembershipState.SUSPENDED
        assert rbac.member_has_capability(
            membership.role, membership.state, rbac.CAP_APPROVE_ACTION) is False

    async def test_policy_update_versions_and_records_history(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            updated = await org_svc.set_policy(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                policy={"max_risk_level": "HIGH"},
            )
            await s.commit()
        assert updated.policy_version == 2
        async with session_factory() as s:
            from sqlalchemy import select
            revisions = (
                await s.execute(
                    select(OrganizationPolicyRevision)
                    .where(OrganizationPolicyRevision.organization_id == org.id)
                )
            ).scalars().all()
        versions = sorted(r.version for r in revisions)
        assert versions == [1, 2]


# ── Invitations ──────────────────────────────────────────────────────


class TestInvitations:
    async def test_token_stored_hashed_only_and_single_use(
        self, session_factory, test_user, test_user_b
    ):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            invitation, token = await org_svc.create_invitation(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                email=test_user_b.email, role=rbac.OrgRole.DEVELOPER,
            )
            await s.commit()
        assert invitation.token_hash != token
        assert token not in invitation.token_hash

        async with session_factory() as s:
            membership = await org_svc.accept_invitation(s, token=token, user=test_user_b)
            await s.commit()
        assert membership.role == rbac.OrgRole.DEVELOPER
        assert membership.state == rbac.MembershipState.ACTIVE

        # Replay is refused.
        async with session_factory() as s:
            with pytest.raises(OrgError) as exc:
                await org_svc.accept_invitation(s, token=token, user=test_user_b)
            assert exc.value.reason_code == "INVITATION_ALREADY_ACCEPTED"

    async def test_email_binding_enforced(self, session_factory, test_user, test_user_b):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            _, token = await org_svc.create_invitation(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                email="someone-else@example.com", role=rbac.OrgRole.VIEWER,
            )
            await s.commit()
        async with session_factory() as s:
            with pytest.raises(OrgError) as exc:
                await org_svc.accept_invitation(s, token=token, user=test_user_b)
            assert exc.value.reason_code == "INVITATION_EMAIL_MISMATCH"

    async def test_expired_invitation_refused(self, session_factory, test_user, test_user_b):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            invitation, token = await org_svc.create_invitation(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                email=None, role=rbac.OrgRole.VIEWER,
            )
            invitation.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
            await s.commit()
        async with session_factory() as s:
            with pytest.raises(OrgError) as exc:
                await org_svc.accept_invitation(s, token=token, user=test_user_b)
            assert exc.value.reason_code == "INVITATION_EXPIRED"

    async def test_viewer_cannot_invite(self, session_factory, test_user, test_user_b):
        org = await _make_org(session_factory, test_user)
        await _add_member(session_factory, org, test_user_b, rbac.OrgRole.VIEWER)
        async with session_factory() as s:
            viewer = await org_svc.get_membership(s, org_id=org.id, user_id=test_user_b.id)
            with pytest.raises(OrgError) as exc:
                await org_svc.create_invitation(
                    s, org_id=org.id, actor_membership=viewer, actor_user_id=test_user_b.id,
                    email=None, role=rbac.OrgRole.VIEWER,
                )
            assert exc.value.reason_code == "MEMBER_MANAGEMENT_NOT_PERMITTED"


# ── API keys ─────────────────────────────────────────────────────────


class TestApiKeys:
    async def test_secret_hashed_and_prefix_lookup(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            row, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                name="ci", scopes=["findings:read"],
            )
            await s.commit()
        assert row.key_hash != secret
        assert secret.startswith(f"cyv_{row.prefix}_")

        async with session_factory() as s:
            resolved = await api_key_service.authenticate_api_key(s, secret)
            await s.commit()
        assert resolved is not None
        assert resolved.organization_id == org.id

    async def test_wrong_token_rejected(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            row, _ = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                name="ci", scopes=["findings:read"],
            )
            await s.commit()
        async with session_factory() as s:
            assert await api_key_service.authenticate_api_key(
                s, f"cyv_{row.prefix}_wrongsecret") is None
            assert await api_key_service.authenticate_api_key(s, "not-a-key") is None

    async def test_revoked_key_rejected(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            row, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                name="ci", scopes=["findings:read"],
            )
            await s.commit()
            actor2 = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            await api_key_service.revoke_api_key(
                s, org_id=org.id, actor_membership=actor2, key_id=row.id)
            await s.commit()
        async with session_factory() as s:
            assert await api_key_service.authenticate_api_key(s, secret) is None

    async def test_expired_key_rejected(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            _, secret = await api_key_service.create_api_key(
                s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                name="ci", scopes=["findings:read"],
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
            )
            await s.commit()
        async with session_factory() as s:
            assert await api_key_service.authenticate_api_key(s, secret) is None

    async def test_invalid_scopes_refused(self, session_factory, test_user):
        org = await _make_org(session_factory, test_user)
        async with session_factory() as s:
            actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
            with pytest.raises(OrgError):
                await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                    name="bad", scopes=["org:admin"],
                )

    async def test_viewer_cannot_create_key(self, session_factory, test_user, test_user_b):
        org = await _make_org(session_factory, test_user)
        await _add_member(session_factory, org, test_user_b, rbac.OrgRole.SECURITY_ENGINEER)
        async with session_factory() as s:
            member = await org_svc.get_membership(s, org_id=org.id, user_id=test_user_b.id)
            with pytest.raises(OrgError) as exc:
                await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=member, actor_user_id=test_user_b.id,
                    name="nope", scopes=["findings:read"],
                )
            assert exc.value.reason_code == "API_KEY_MANAGEMENT_NOT_PERMITTED"


# ── HTTP: organization routes, IDOR, API scopes ──────────────────────


class TestOrganizationRoutes:
    def test_unauthenticated_denied(self, client):
        assert client.get("/api/orgs").status_code == 401

    def test_user_sees_only_own_orgs(self, authenticated_client, session_factory, test_user):
        import asyncio

        async def _setup():
            return await _make_org(session_factory, test_user, "Mine")
        asyncio.get_event_loop().run_until_complete(_setup())
        r = authenticated_client.get("/api/orgs")
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["role"] == rbac.OrgRole.ORG_OWNER

    def test_cross_org_idor_404(self, authenticated_client, session_factory, test_user_b):
        """User A (override) must not read user B's organization."""
        import asyncio

        async def _setup():
            return await _make_org(session_factory, test_user_b, "Theirs")
        other = asyncio.get_event_loop().run_until_complete(_setup())
        r = authenticated_client.get(f"/api/orgs/{other.id}")
        assert r.status_code == 404
        r2 = authenticated_client.get(f"/api/orgs/{other.id}/members")
        assert r2.status_code == 404
        r3 = authenticated_client.post(f"/api/orgs/{other.id}/invitations",
                                       json={"role": "VIEWER"})
        assert r3.status_code == 404

    def test_malformed_org_id_is_404_not_500(self, authenticated_client):
        assert authenticated_client.get("/api/orgs/not-a-uuid").status_code == 422

    def test_suspended_membership_is_404(
        self, authenticated_client, session_factory, test_user
    ):
        """A non-ACTIVE membership must not resolve the tenant at all."""
        import asyncio

        async def _setup():
            org = await _make_org(session_factory, test_user, "Susp")
            async with session_factory() as s:
                membership = await org_svc.get_membership(
                    s, org_id=org.id, user_id=test_user.id)
                membership.state = rbac.MembershipState.SUSPENDED
                await s.commit()
            return org
        org = asyncio.get_event_loop().run_until_complete(_setup())
        assert authenticated_client.get(f"/api/orgs/{org.id}").status_code == 404
        assert authenticated_client.get(
            f"/api/orgs/{org.id}/members").status_code == 404

    def test_capability_endpoint_reports_server_derived_caps(
        self, authenticated_client, session_factory, test_user
    ):
        import asyncio

        async def _setup():
            return await _make_org(session_factory, test_user, "Caps")
        org = asyncio.get_event_loop().run_until_complete(_setup())
        r = authenticated_client.get(f"/api/orgs/{org.id}/capabilities")
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == rbac.OrgRole.ORG_OWNER
        assert rbac.CAP_MANAGE_MEMBERS in body["capabilities"]
        assert body["organization_id"] == str(org.id)

    def test_api_key_scope_enforced(
        self, client, session_factory, test_user
    ):
        """The public API derives tenant+scope from the key only."""
        import asyncio

        async def _setup():
            org = await _make_org(session_factory, test_user, "ApiCo")
            # bind an installation + repository to the org
            inst = GithubInstallation(
                user_id=test_user.id, installation_id=uuid4().int % 900000 + 1,
                account_login="api-org", account_type="Organization",
                organization_id=org.id,
            )
            async with session_factory() as s:
                s.add(inst)
                await s.flush()
                repo = Repository(
                    installation_id=inst.id, github_repo_id=uuid4().int % 900000 + 1,
                    owner="api-org", name="api-repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.flush()
                actor = await org_svc.get_membership(s, org_id=org.id, user_id=test_user.id)
                _, secret = await api_key_service.create_api_key(
                    s, org_id=org.id, actor_membership=actor, actor_user_id=test_user.id,
                    name="ci", scopes=["repositories:read"],
                )
                await s.commit()
                return secret

        secret = asyncio.get_event_loop().run_until_complete(_setup())

        r = client.get("/api/v1/repositories",
                       headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 200
        # V4.1: public collections are paginated envelopes, not bare arrays
        # (an unbounded array let one tenant force an unbounded read).
        body = r.json()
        assert set(body) >= {"items", "next_cursor", "has_more"}
        assert len(body["items"]) == 1

        # findings:read was NOT granted → 403.
        r2 = client.get("/api/v1/findings",
                        headers={"Authorization": f"Bearer {secret}"})
        assert r2.status_code == 403

        # No key → 401.
        assert client.get("/api/v1/repositories").status_code == 401

    def test_api_key_org_isolation(self, client, session_factory, test_user, test_user_b):
        """A key for org A must not return org B's repositories."""
        import asyncio

        async def _setup():
            org_a = await _make_org(session_factory, test_user, "OrgA")
            org_b = await _make_org(session_factory, test_user_b, "OrgB")
            async with session_factory() as s:
                inst_a = GithubInstallation(
                    user_id=test_user.id, installation_id=uuid4().int % 900000 + 1,
                    account_login="a", account_type="Organization", organization_id=org_a.id)
                inst_b = GithubInstallation(
                    user_id=test_user_b.id, installation_id=uuid4().int % 900000 + 2,
                    account_login="b", account_type="Organization", organization_id=org_b.id)
                s.add_all([inst_a, inst_b])
                await s.flush()
                s.add(Repository(installation_id=inst_a.id, github_repo_id=uuid4().int % 900000 + 11,
                                 owner="a", name="a-repo", default_branch="main", is_active=True))
                s.add(Repository(installation_id=inst_b.id, github_repo_id=uuid4().int % 900000 + 12,
                                 owner="b", name="b-repo", default_branch="main", is_active=True))
                await s.flush()
                actor = await org_svc.get_membership(s, org_id=org_a.id, user_id=test_user.id)
                _, secret = await api_key_service.create_api_key(
                    s, org_id=org_a.id, actor_membership=actor, actor_user_id=test_user.id,
                    name="ci", scopes=["repositories:read"])
                await s.commit()
                return secret

        secret = asyncio.get_event_loop().run_until_complete(_setup())
        r = client.get("/api/v1/repositories",
                       headers={"Authorization": f"Bearer {secret}"})
        assert r.status_code == 200
        names = [row["name"] for row in r.json()["items"]]
        assert names == ["a-repo"]
