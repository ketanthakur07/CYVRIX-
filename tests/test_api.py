import os
import sys
import pytest
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.models import User


class TestHealthEndpoint:
    def test_health_check(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "1.0.0"


class TestDashboardEndpoint:
    def test_dashboard_empty(self, authenticated_client):
        resp = authenticated_client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_repositories" in data
        assert "total_scans" in data
        assert "total_findings" in data
        assert "findings_by_severity" in data
        assert "recent_scans" in data

    def test_dashboard_requires_auth(self, client):
        resp = client.get("/api/dashboard")
        assert resp.status_code == 401


class TestRepositoryEndpoints:
    def test_list_repositories_empty(self, authenticated_client):
        resp = authenticated_client.get("/api/repositories")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 0

    def test_list_repositories_requires_auth(self, client):
        resp = client.get("/api/repositories")
        assert resp.status_code == 401

    def test_get_repository_not_found(self, authenticated_client):
        resp = authenticated_client.get(f"/api/repositories/{uuid4()}")
        assert resp.status_code == 404

    def test_activate_repository_not_found(self, authenticated_client):
        resp = authenticated_client.post(f"/api/repositories/{uuid4()}/activate")
        assert resp.status_code == 404

    def test_deactivate_repository_not_found(self, authenticated_client):
        resp = authenticated_client.post(f"/api/repositories/{uuid4()}/deactivate")
        assert resp.status_code == 404


class TestScanEndpoints:
    def test_create_scan_requires_auth(self, client):
        resp = client.post("/api/scans", json={"repository_id": str(uuid4())})
        assert resp.status_code == 401

    def test_create_scan_requires_active_repository(self, authenticated_client):
        resp = authenticated_client.post(
            "/api/scans",
            json={"repository_id": str(uuid4())},
        )
        # 404 because repository doesn't exist
        assert resp.status_code == 404


class TestFindingEndpoints:
    def test_get_finding_requires_auth(self, client):
        resp = client.get(f"/api/findings/{uuid4()}")
        assert resp.status_code == 401

    def test_get_finding_not_found(self, authenticated_client):
        resp = authenticated_client.get(f"/api/findings/{uuid4()}")
        assert resp.status_code == 404


class TestGitHubEndpoints:
    def test_connect_redirects(self, client):
        resp = client.get("/api/github/connect", follow_redirects=False)
        # Should redirect to GitHub or return error if not configured
        assert resp.status_code in (307, 500, 503)

    def test_installations_requires_auth(self, client):
        resp = client.get("/api/github/installations")
        assert resp.status_code == 401


class TestScanIDOR:
    def test_scan_requires_auth(self, client):
        resp = client.get(f"/api/scans/{uuid4()}")
        assert resp.status_code == 401

    def test_scan_findings_requires_auth(self, client):
        resp = client.get(f"/api/scans/{uuid4()}/findings")
        assert resp.status_code == 401


class TestAuthEndpoints:
    def test_auth_me_requires_auth(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_auth_me_returns_user(self, authenticated_client, test_user):
        resp = authenticated_client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == test_user.email
        assert "id" in data

    def test_auth_logout(self, authenticated_client):
        resp = authenticated_client.post("/api/auth/logout")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True


class TestRecommendationEndpoints:
    def test_get_recommendation_requires_auth(self, client):
        resp = client.get(f"/api/findings/{uuid4()}/recommendation")
        assert resp.status_code == 401

    def test_get_recommendation_not_found(self, authenticated_client):
        resp = authenticated_client.get(f"/api/findings/{uuid4()}/recommendation")
        assert resp.status_code == 404

    def test_get_recommendation_readonly(self, authenticated_client, session_factory):
        """GET must be read-only — must NOT create a recommendation."""
        import asyncio
        from app.main import app
        from app.auth import get_current_user
        from app.models import (
            User, GithubInstallation, Repository, Scan, Finding, Recommendation,
        )
        from sqlalchemy.ext.asyncio import AsyncSession

        async def _setup():
            async with session_factory() as s:
                user = User(id=uuid4(), email="rec-get@test.local", github_id=44444)
                s.add(user)
                await s.flush()
                inst = GithubInstallation(
                    id=uuid4(), user_id=user.id, installation_id=44445,
                    account_login="rec-org", account_type="Organization",
                )
                s.add(inst)
                await s.flush()
                repo = Repository(
                    id=uuid4(), installation_id=inst.id, github_repo_id=44446,
                    owner="rec-org", name="rec-repo", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.flush()
                scan = Scan(
                    id=uuid4(), repository_id=repo.id, status="COMPLETED",
                    trigger="manual", commit_sha="abc",
                )
                s.add(scan)
                await s.flush()
                finding = Finding(
                    id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                    fingerprint="rec-fp-001", scanner="dependency",
                    source_type="DEPENDENCY",
                    vulnerability_id="CVE-2024-9999",
                    package_name="test-pkg", package_version="1.0.0",
                    title="Test vuln", severity="HIGH", status="OPEN",
                )
                s.add(finding)
                await s.commit()
                return str(finding.id), user

        loop = asyncio.new_event_loop()
        finding_id, user = loop.run_until_complete(_setup())
        loop.close()

        async def override():
            return user
        app.dependency_overrides[get_current_user] = override

        try:
            # GET when no recommendation exists → 404
            resp = authenticated_client.get(f"/api/findings/{finding_id}/recommendation")
            assert resp.status_code == 404

            # Verify no recommendation was created by GET
            async def _check_no_rec():
                from sqlalchemy import select as sel
                from uuid import UUID as U
                async with session_factory() as s:
                    recs = await s.execute(
                        sel(Recommendation).where(Recommendation.finding_id == U(finding_id))
                    )
                    return recs.scalar_one_or_none()
            loop2 = asyncio.new_event_loop()
            result = loop2.run_until_complete(_check_no_rec())
            loop2.close()
            assert result is None, "GET created a recommendation — should be read-only"
        finally:
            app.dependency_overrides.pop(get_current_user, None)

    def test_post_recommendation_creates(self, authenticated_client, session_factory):
        """POST creates a recommendation when one doesn't exist."""
        import asyncio
        from uuid import UUID
        from sqlalchemy import select
        from app.main import app
        from app.auth import get_current_user
        from app.models import (
            User, GithubInstallation, Repository, Scan, Finding, Recommendation,
        )

        async def _setup():
            async with session_factory() as s:
                user = User(id=uuid4(), email="rec-post@test.local", github_id=44447)
                s.add(user)
                await s.flush()
                inst = GithubInstallation(
                    id=uuid4(), user_id=user.id, installation_id=44448,
                    account_login="rec-org2", account_type="Organization",
                )
                s.add(inst)
                await s.flush()
                repo = Repository(
                    id=uuid4(), installation_id=inst.id, github_repo_id=44449,
                    owner="rec-org2", name="rec-repo2", default_branch="main",
                    is_active=True,
                )
                s.add(repo)
                await s.flush()
                scan = Scan(
                    id=uuid4(), repository_id=repo.id, status="COMPLETED",
                    trigger="manual", commit_sha="def",
                )
                s.add(scan)
                await s.flush()
                finding = Finding(
                    id=uuid4(), scan_id=scan.id, repository_id=repo.id,
                    fingerprint="rec-fp-002", scanner="dependency",
                    source_type="DEPENDENCY",
                    vulnerability_id="CVE-2024-8888",
                    package_name="test-pkg2", package_version="2.0.0",
                    title="Test vuln 2", severity="HIGH", status="OPEN",
                )
                s.add(finding)
                await s.commit()
                return str(finding.id), user

        loop = asyncio.new_event_loop()
        finding_id, user = loop.run_until_complete(_setup())
        loop.close()

        async def override():
            return user
        app.dependency_overrides[get_current_user] = override

        try:
            # POST when no recommendation exists → creates one
            resp = authenticated_client.post(f"/api/findings/{finding_id}/recommendation")
            assert resp.status_code == 200
            data = resp.json()
            assert "id" in data
            assert data["status"] == "COMPLETED"
            assert data["trust_level"] is not None

            # Verify DB has the recommendation
            async def _check_rec():
                from sqlalchemy import select as sel
                from uuid import UUID as U
                async with session_factory() as s:
                    recs = await s.execute(
                        sel(Recommendation).where(Recommendation.finding_id == U(finding_id))
                    )
                    return recs.scalar_one_or_none()
            loop2 = asyncio.new_event_loop()
            rec = loop2.run_until_complete(_check_rec())
            loop2.close()
            assert rec is not None, "POST did not persist recommendation"
            assert rec.status == "COMPLETED"
            assert rec.created_at is not None, "created_at not set"

            # GET afterward → retrieves it
            resp = authenticated_client.get(f"/api/findings/{finding_id}/recommendation")
            assert resp.status_code == 200
            assert resp.json()["id"] == data["id"]

            # Repeated POST → idempotent (returns same recommendation)
            resp2 = authenticated_client.post(f"/api/findings/{finding_id}/recommendation")
            assert resp2.status_code == 200
            assert resp2.json()["id"] == data["id"]

            # Verify only one recommendation in DB
            async def _check_count():
                from sqlalchemy import select as sel
                from uuid import UUID as U
                async with session_factory() as s:
                    recs = await s.execute(
                        sel(Recommendation).where(Recommendation.finding_id == U(finding_id))
                    )
                    return recs.scalars().all()
            loop3 = asyncio.new_event_loop()
            all_recs = loop3.run_until_complete(_check_count())
            loop3.close()
            assert len(all_recs) == 1, f"Expected 1 recommendation, got {len(all_recs)}"
        finally:
            app.dependency_overrides.pop(get_current_user, None)
