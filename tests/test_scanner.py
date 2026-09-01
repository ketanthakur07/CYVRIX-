import os
import json
import pytest

from app.services.scanner import (
    compute_fingerprint,
    detect_manifests,
    parse_package_json,
    parse_package_lock,
    parse_requirements_txt,
    parse_poetry_lock,
    normalize_severity,
    normalize_findings,
)


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


class TestFingerprint:
    def test_deterministic(self):
        fp1 = compute_fingerprint("repo1", "CVE-123", "lodash", "package.json")
        fp2 = compute_fingerprint("repo1", "CVE-123", "lodash", "package.json")
        assert fp1 == fp2

    def test_different_inputs_different_fingerprints(self):
        fp1 = compute_fingerprint("repo1", "CVE-123", "lodash", "package.json")
        fp2 = compute_fingerprint("repo1", "CVE-456", "lodash", "package.json")
        assert fp1 != fp2

    def test_is_sha256(self):
        fp = compute_fingerprint("repo1", "CVE-123", "lodash", "package.json")
        assert len(fp) == 64  # SHA-256 hex length


class TestManifestDetection:
    def test_vulnerable_node_app(self):
        manifests = detect_manifests(os.path.join(FIXTURES_DIR, "vulnerable-node-app"))
        ecosystems = [m[0] for m in manifests]
        assert "npm" in ecosystems

    def test_vulnerable_python_app(self):
        manifests = detect_manifests(os.path.join(FIXTURES_DIR, "vulnerable-python-app"))
        ecosystems = [m[0] for m in manifests]
        assert "PyPI" in ecosystems

    def test_clean_app(self):
        manifests = detect_manifests(os.path.join(FIXTURES_DIR, "clean-app"))
        ecosystems = [m[0] for m in manifests]
        assert "npm" in ecosystems

    def test_malformed_lockfile(self):
        manifests = detect_manifests(os.path.join(FIXTURES_DIR, "malformed-lockfile-app"))
        ecosystems = [m[0] for m in manifests]
        assert "npm" in ecosystems


class TestPackageJsonParsing:
    def test_parse_package_json(self):
        path = os.path.join(FIXTURES_DIR, "vulnerable-node-app", "package.json")
        deps = parse_package_json(path)
        assert len(deps) == 3
        names = [d["name"] for d in deps]
        assert "lodash" in names
        assert "express" in names
        assert "minimist" in names
        for d in deps:
            assert d["ecosystem"] == "npm"

    def test_parse_package_lock(self):
        path = os.path.join(FIXTURES_DIR, "vulnerable-node-app", "package-lock.json")
        deps = parse_package_lock(path)
        assert len(deps) == 3
        names = [d["name"] for d in deps]
        assert "lodash" in names

    def test_malformed_lockfile_no_crash(self):
        path = os.path.join(FIXTURES_DIR, "malformed-lockfile-app", "package-lock.json")
        deps = parse_package_lock(path)
        # Should parse without crashing, may have partial results
        assert isinstance(deps, list)


class TestRequirementsTxtParsing:
    def test_parse_requirements_txt(self):
        path = os.path.join(FIXTURES_DIR, "vulnerable-python-app", "requirements.txt")
        deps = parse_requirements_txt(path)
        assert len(deps) == 3
        names = [d["name"] for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "jinja2" in names
        for d in deps:
            assert d["ecosystem"] == "PyPI"


class TestSeverityNormalization:
    def test_cvss_network(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]}
        assert normalize_severity(vuln) == "HIGH"

    def test_database_specific(self):
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        assert normalize_severity(vuln) == "CRITICAL"

    def test_unknown_fallback(self):
        vuln = {}
        assert normalize_severity(vuln) == "UNKNOWN"


class TestFindingNormalization:
    def test_normalize_findings(self):
        osv_results = [
            {
                "vulns": [
                    {
                        "id": "GHSA-123",
                        "summary": "Test vulnerability",
                        "details": "A test vulnerability",
                        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
                    }
                ]
            }
        ]
        deps = [{"name": "test-pkg", "version": "1.0.0", "ecosystem": "npm"}]
        findings = normalize_findings(osv_results, deps, "repo1", "scan1", "package.json")
        assert len(findings) == 1
        assert findings[0]["vulnerability_id"] == "GHSA-123"
        assert findings[0]["package_name"] == "test-pkg"
        assert findings[0]["severity"] == "HIGH"

    def test_empty_osv_results(self):
        findings = normalize_findings([], [], "repo1", "scan1", "package.json")
        assert len(findings) == 0

    def test_deduplication(self):
        osv_results = [
            {"vulns": [{"id": "GHSA-123", "summary": "Test"}]},
            {"vulns": [{"id": "GHSA-123", "summary": "Test"}]},
        ]
        deps = [
            {"name": "test-pkg", "version": "1.0.0", "ecosystem": "npm"},
            {"name": "test-pkg", "version": "1.0.0", "ecosystem": "npm"},
        ]
        findings = normalize_findings(osv_results, deps, "repo1", "scan1", "package.json")
        assert len(findings) == 1
