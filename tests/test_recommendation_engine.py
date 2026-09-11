"""CYVRIX V2 Recommendation Engine Tests.

Tests for deterministic recommendations, trust levels,
evidence requirements, and safety constraints.
"""
import os
import sys
import pytest
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.recommendation_engine import (
    generate_deterministic_recommendation,
    DETERMINISTIC_RULES,
)


# ═══════════════════════════════════════════════════════════════════
# Dependency Recommendation Tests
# ═══════════════════════════════════════════════════════════════════

class TestDependencyRecommendations:
    def test_dependency_upgrade_recommendation(self):
        finding = {
            "scanner": "dependency",
            "source_type": "DEPENDENCY",
            "title": "Prototype Pollution in lodash",
            "description": "Lodash versions before 4.17.21 are vulnerable.",
            "severity": "HIGH",
            "vulnerability_id": "GHSA-jf85-cpcp-j695",
            "package_name": "lodash",
            "package_version": "4.17.15",
            "evidence": {},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "SUPPORTED"
        assert "lodash" in rec["what"]
        assert "GHSA-jf85-cpcp-j695" in rec["what"]
        assert "upgrade" in rec["change"].lower()

    def test_no_recommendation_for_unknown_scanner(self):
        finding = {
            "scanner": "unknown_scanner",
            "source_type": "DEPENDENCY",
            "title": "Some issue",
            "severity": "LOW",
            "evidence": {},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is None


# ═══════════════════════════════════════════════════════════════════
# Container Recommendation Tests
# ═══════════════════════════════════════════════════════════════════

class TestContainerRecommendations:
    def test_root_user_recommendation(self):
        finding = {
            "scanner": "container",
            "source_type": "CONTAINER",
            "title": "Container runs as root",
            "severity": "MEDIUM",
            "evidence": {"dockerfile": "Dockerfile"},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "SUPPORTED"
        assert "root" in rec["what"].lower()

    def test_latest_tag_recommendation(self):
        finding = {
            "scanner": "container",
            "source_type": "CONTAINER",
            "title": "Unpinned base image uses 'latest' tag",
            "severity": "MEDIUM",
            "evidence": {"dockerfile": "Dockerfile", "image": "python:latest"},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "SUPPORTED"
        assert "pin" in rec["change"].lower()

    def test_curl_sh_recommendation(self):
        finding = {
            "scanner": "container",
            "source_type": "CONTAINER",
            "title": "Suspicious curl pipe to shell",
            "severity": "HIGH",
            "evidence": {"dockerfile": "Dockerfile", "command": "curl http://example.com | sh"},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "SUPPORTED"

    def test_secret_env_recommendation(self):
        finding = {
            "scanner": "container",
            "source_type": "CONTAINER",
            "title": "Potential secret in ENV instruction",
            "severity": "HIGH",
            "evidence": {"dockerfile": "Dockerfile", "env": "APP_SECRET=secret123"},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "SUPPORTED"


# ═══════════════════════════════════════════════════════════════════
# Log Recommendation Tests
# ═══════════════════════════════════════════════════════════════════

class TestLogRecommendations:
    def test_brute_force_recommendation(self):
        finding = {
            "scanner": "log_analyzer",
            "source_type": "LOG",
            "title": "Potential brute-force pattern",
            "severity": "HIGH",
            "evidence": {"log_source": "access.log", "event_count": 10, "correlation_value": "10.0.0.50"},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "LIKELY"
        assert "brute" in rec["what"].lower() or "auth" in rec["what"].lower()

    def test_admin_access_recommendation(self):
        finding = {
            "scanner": "log_analyzer",
            "source_type": "LOG",
            "title": "Suspicious administrative access",
            "severity": "MEDIUM",
            "evidence": {"log_source": "security.log", "event_count": 1},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        assert rec["trust_level"] == "LIKELY"


# ═══════════════════════════════════════════════════════════════════
# Safety Constraint Tests
# ═══════════════════════════════════════════════════════════════════

class TestSafetyConstraints:
    def test_recommendations_have_required_fields(self):
        """All recommendations must have the required fields."""
        finding = {
            "scanner": "dependency",
            "source_type": "DEPENDENCY",
            "title": "Test vulnerability",
            "severity": "HIGH",
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "test-pkg",
            "package_version": "1.0.0",
            "evidence": {},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        required_fields = ["title", "what", "why", "change", "uncertainty", "risk", "validation", "trust_level"]
        for field in required_fields:
            assert field in rec, f"Missing required field: {field}"
            assert rec[field] is not None, f"Field {field} is None"

    def test_trust_level_is_valid(self):
        """Trust level must be one of the valid values."""
        finding = {
            "scanner": "dependency",
            "source_type": "DEPENDENCY",
            "title": "Test vulnerability",
            "severity": "HIGH",
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "test-pkg",
            "package_version": "1.0.0",
            "evidence": {},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        valid_trust = {"SUPPORTED", "LIKELY", "UNCERTAIN"}
        assert rec["trust_level"] in valid_trust

    def test_recommendations_are_advisory_only(self):
        """Verify recommendations don't contain any modification instructions."""
        finding = {
            "scanner": "dependency",
            "source_type": "DEPENDENCY",
            "title": "Test vulnerability",
            "severity": "HIGH",
            "vulnerability_id": "CVE-2024-12345",
            "package_name": "test-pkg",
            "package_version": "1.0.0",
            "evidence": {},
        }

        rec = generate_deterministic_recommendation(finding)
        assert rec is not None
        # Should not contain dangerous actions
        dangerous_terms = ["git push", "rm -rf", "DROP TABLE", "exec(", "eval("]
        for term in dangerous_terms:
            assert term not in rec.get("change", ""), f"Recommendation contains dangerous term: {term}"
