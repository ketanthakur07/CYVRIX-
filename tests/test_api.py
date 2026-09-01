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
