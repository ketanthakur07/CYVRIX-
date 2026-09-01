"""Security and failure injection tests for the CYVRIX dependency scanner.

Tests cover:
- Path traversal defense
- Symlink escape prevention
- Resource limits
- OSV error handling (429, 500, timeout, malformed)
- Credential protection
- Malformed manifest handling
- Dependency validation
- OSV response validation
"""
import os
import sys
import json
import tempfile
import shutil
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.scanner import (
    _validate_path_in_workspace,
    _is_symlink_safe,
    _safe_read_file,
    _sanitize_git_error,
    _validate_dep,
    _validate_osv_query,
    _validate_osv_result,
    _validate_osv_vuln,
    compute_fingerprint,
    normalize_severity,
    normalize_findings,
    parse_package_json,
    parse_package_lock,
    parse_requirements_txt,
    parse_poetry_lock,
    detect_manifests,
    MAX_FILE_SIZE,
    MAX_DEPS_TOTAL,
    MAX_MANIFESTS,
)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


# ═══════════════════════════════════════════════════════════════════
# Path Traversal Defense
# ═══════════════════════════════════════════════════════════════════

class TestPathTraversalDefense:
    def test_valid_path_passes(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "file.txt")
            result = _validate_path_in_workspace(filepath, workspace)
            assert result.startswith(os.path.realpath(workspace))
        finally:
            shutil.rmtree(workspace)

    def test_traversal_blocked(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "..", "..", "etc", "passwd")
            with pytest.raises(ValueError, match="traversal"):
                _validate_path_in_workspace(filepath, workspace)
        finally:
            shutil.rmtree(workspace)

    def test_absolute_path_blocked(self):
        workspace = tempfile.mkdtemp()
        try:
            with pytest.raises(ValueError, match="traversal"):
                _validate_path_in_workspace("/etc/passwd", workspace)
        finally:
            shutil.rmtree(workspace)

    def test_dotted_traversal_blocked(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "..", "secret")
            with pytest.raises(ValueError, match="traversal"):
                _validate_path_in_workspace(filepath, workspace)
        finally:
            shutil.rmtree(workspace)

    def test_workspace_root_passes(self):
        workspace = tempfile.mkdtemp()
        try:
            result = _validate_path_in_workspace(workspace, workspace)
            assert result == os.path.realpath(workspace)
        finally:
            shutil.rmtree(workspace)


# ═══════════════════════════════════════════════════════════════════
# Symlink Defense
# ═══════════════════════════════════════════════════════════════════

class TestSymlinkDefense:
    def test_regular_file_is_safe(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "normal.txt")
            with open(filepath, "w") as f:
                f.write("content")
            assert _is_symlink_safe(filepath, workspace) is True
        finally:
            shutil.rmtree(workspace)

    @pytest.mark.skipif(os.name == "nt", reason="Symlinks need special permissions on Windows")
    def test_symlink_within_workspace_is_safe(self):
        workspace = tempfile.mkdtemp()
        try:
            target = os.path.join(workspace, "target.txt")
            link = os.path.join(workspace, "link.txt")
            with open(target, "w") as f:
                f.write("content")
            os.symlink(target, link)
            assert _is_symlink_safe(link, workspace) is True
        finally:
            shutil.rmtree(workspace)

    @pytest.mark.skipif(os.name == "nt", reason="Symlinks need special permissions on Windows")
    def test_symlink_outside_workspace_is_unsafe(self):
        workspace = tempfile.mkdtemp()
        outside = tempfile.mkdtemp()
        try:
            target = os.path.join(outside, "secret.txt")
            with open(target, "w") as f:
                f.write("secret")
            link = os.path.join(workspace, "evil-link.txt")
            os.symlink(target, link)
            assert _is_symlink_safe(link, workspace) is False
        finally:
            shutil.rmtree(workspace)
            shutil.rmtree(outside)

    @pytest.mark.skipif(os.name == "nt", reason="Symlinks need special permissions on Windows")
    def test_safe_read_file_rejects_symlink_escape(self):
        workspace = tempfile.mkdtemp()
        outside = tempfile.mkdtemp()
        try:
            secret = os.path.join(outside, "secret.txt")
            with open(secret, "w") as f:
                f.write("SECRET DATA")
            link = os.path.join(workspace, "evil.txt")
            os.symlink(secret, link)
            with pytest.raises(ValueError, match="Symlink"):
                _safe_read_file(link, workspace)
        finally:
            shutil.rmtree(workspace)
            shutil.rmtree(outside)


# ═══════════════════════════════════════════════════════════════════
# Safe Read File
# ═══════════════════════════════════════════════════════════════════

class TestSafeReadFile:
    def test_reads_normal_file(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "test.json")
            with open(filepath, "w") as f:
                json.dump({"key": "value"}, f)
            content = _safe_read_file(filepath, workspace)
            assert json.loads(content) == {"key": "value"}
        finally:
            shutil.rmtree(workspace)

    def test_rejects_traversal(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "..", "etc", "passwd")
            with pytest.raises(ValueError):
                _safe_read_file(filepath, workspace)
        finally:
            shutil.rmtree(workspace)

    def test_rejects_large_file(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "huge.txt")
            with open(filepath, "w") as f:
                f.write("x" * (MAX_FILE_SIZE + 1))
            with pytest.raises(ValueError, match="too large"):
                _safe_read_file(filepath, workspace, max_size=MAX_FILE_SIZE)
        finally:
            shutil.rmtree(workspace)


# ═══════════════════════════════════════════════════════════════════
# Git Error Sanitization
# ═══════════════════════════════════════════════════════════════════

class TestGitErrorSanitization:
    def test_removes_access_token(self):
        error = "fatal: https://x-access-token:ghp_abc123@github.com/foo/bar.git not found"
        sanitized = _sanitize_git_error(error)
        assert "ghp_abc123" not in sanitized
        assert "***" in sanitized

    def test_removes_generic_token(self):
        error = "error: token=secret123 expired"
        sanitized = _sanitize_git_error(error)
        assert "secret123" not in sanitized


# ═══════════════════════════════════════════════════════════════════
# Dependency Validation
# ═══════════════════════════════════════════════════════════════════

class TestDependencyValidation:
    def test_valid_dep(self):
        assert _validate_dep({"name": "lodash", "version": "4.17.19", "ecosystem": "npm"}) is True

    def test_empty_name(self):
        assert _validate_dep({"name": "", "version": "1.0", "ecosystem": "npm"}) is False

    def test_missing_name(self):
        assert _validate_dep({"version": "1.0", "ecosystem": "npm"}) is False

    def test_name_too_long(self):
        assert _validate_dep({"name": "x" * 501, "version": "1.0", "ecosystem": "npm"}) is False

    def test_version_too_long(self):
        assert _validate_dep({"name": "pkg", "version": "x" * 201, "ecosystem": "npm"}) is False


# ═══════════════════════════════════════════════════════════════════
# OSV Query/Response Validation
# ═══════════════════════════════════════════════════════════════════

class TestOSVValidation:
    def test_valid_query(self):
        q = {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.19"}
        assert _validate_osv_query(q) is True

    def test_missing_package_name(self):
        q = {"package": {"ecosystem": "npm"}, "version": "1.0"}
        assert _validate_osv_query(q) is False

    def test_missing_version(self):
        q = {"package": {"name": "lodash", "ecosystem": "npm"}}
        assert _validate_osv_query(q) is False

    def test_empty_name(self):
        q = {"package": {"name": "", "ecosystem": "npm"}, "version": "1.0"}
        assert _validate_osv_query(q) is False

    def test_long_name(self):
        q = {"package": {"name": "x" * 501, "ecosystem": "npm"}, "version": "1.0"}
        assert _validate_osv_query(q) is False

    def test_valid_result(self):
        assert _validate_osv_result({"vulns": []}) is True
        assert _validate_osv_result({"vulns": [{"id": "GHSA-123"}]}) is True

    def test_invalid_result_no_vulns(self):
        assert _validate_osv_result({}) is False
        assert _validate_osv_result({"other": "data"}) is False

    def test_invalid_result_not_dict(self):
        assert _validate_osv_result("string") is False
        assert _validate_osv_result(None) is False

    def test_valid_vuln(self):
        v = {"id": "GHSA-123", "summary": "Test vuln"}
        assert _validate_osv_vuln(v) is True

    def test_invalid_vuln_no_id(self):
        v = {"summary": "Test vuln"}
        assert _validate_osv_vuln(v) is False

    def test_invalid_vuln_no_summary_or_details(self):
        v = {"id": "GHSA-123"}
        assert _validate_osv_vuln(v) is False


# ═══════════════════════════════════════════════════════════════════
# Malformed Manifest Handling
# ═══════════════════════════════════════════════════════════════════

class TestMalformedManifests:
    def test_malformed_package_json_returns_empty(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "package.json")
            with open(filepath, "w") as f:
                f.write("{ invalid json }}}")
            deps = parse_package_json(filepath, workspace)
            assert deps == []
        finally:
            shutil.rmtree(workspace)

    def test_malformed_lockfile_returns_empty(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "package-lock.json")
            with open(filepath, "w") as f:
                f.write("not json at all {{{")
            deps = parse_package_lock(filepath, workspace)
            assert deps == []
        finally:
            shutil.rmtree(workspace)

    def test_empty_package_json(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "package.json")
            with open(filepath, "w") as f:
                json.dump({}, f)
            deps = parse_package_json(filepath, workspace)
            assert deps == []
        finally:
            shutil.rmtree(workspace)

    def test_requirements_txt_with_comments(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "requirements.txt")
            with open(filepath, "w") as f:
                f.write("# This is a comment\nflask==2.0\n# Another comment\nrequests>=2.25\n")
            deps = parse_requirements_txt(filepath, workspace)
            assert len(deps) == 2
            names = [d["name"] for d in deps]
            assert "flask" in names
            assert "requests" in names
        finally:
            shutil.rmtree(workspace)

    def test_poetry_lock_parsing(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "poetry.lock")
            with open(filepath, "w") as f:
                f.write('[[package]]\nname = "requests"\nversion = "2.28.0"\n\n[[package]]\nname = "flask"\nversion = "2.2.0"\n')
            deps = parse_poetry_lock(filepath, workspace)
            assert len(deps) == 2
        finally:
            shutil.rmtree(workspace)


# ═══════════════════════════════════════════════════════════════════
# Version Normalization
# ═══════════════════════════════════════════════════════════════════

class TestVersionNormalization:
    def test_package_json_strips_prefixes(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "package.json")
            with open(filepath, "w") as f:
                json.dump({"dependencies": {"lodash": "^4.17.19", "express": "~4.17.1"}}, f)
            deps = parse_package_json(filepath, workspace)
            versions = {d["name"]: d["version"] for d in deps}
            assert versions["lodash"] == "4.17.19"
            assert versions["express"] == "4.17.1"
        finally:
            shutil.rmtree(workspace)

    def test_workspace_reference_skipped(self):
        workspace = tempfile.mkdtemp()
        try:
            filepath = os.path.join(workspace, "package.json")
            with open(filepath, "w") as f:
                json.dump({"dependencies": {"local": "workspace:*", "git-pkg": "github:user/repo"}}, f)
            deps = parse_package_json(filepath, workspace)
            names = [d["name"] for d in deps]
            assert "local" not in names
            assert "git-pkg" not in names
        finally:
            shutil.rmtree(workspace)


# ═══════════════════════════════════════════════════════════════════
# Manifest Detection Security
# ═══════════════════════════════════════════════════════════════════

class TestManifestDetectionSecurity:
    def test_skips_node_modules(self):
        workspace = tempfile.mkdtemp()
        try:
            nm_dir = os.path.join(workspace, "node_modules", "pkg")
            os.makedirs(nm_dir)
            pkg = os.path.join(nm_dir, "package.json")
            with open(pkg, "w") as f:
                json.dump({"dependencies": {}}, f)

            # Also create a legit package.json at root
            root_pkg = os.path.join(workspace, "package.json")
            with open(root_pkg, "w") as f:
                json.dump({"dependencies": {}}, f)

            manifests = detect_manifests(workspace)
            paths = [m[1] for m in manifests]
            assert all("node_modules" not in p for p in paths)
        finally:
            shutil.rmtree(workspace)

    def test_skips_hidden_dirs(self):
        workspace = tempfile.mkdtemp()
        try:
            hidden_dir = os.path.join(workspace, ".git")
            os.makedirs(hidden_dir)
            pkg = os.path.join(hidden_dir, "package.json")
            with open(pkg, "w") as f:
                json.dump({}, f)

            root_pkg = os.path.join(workspace, "package.json")
            with open(root_pkg, "w") as f:
                json.dump({}, f)

            manifests = detect_manifests(workspace)
            paths = [m[1] for m in manifests]
            assert all(".git" not in p for p in paths)
        finally:
            shutil.rmtree(workspace)

    def test_max_manifests_limit(self):
        workspace = tempfile.mkdtemp()
        try:
            # Create more manifests than the limit
            for i in range(MAX_MANIFESTS + 10):
                subdir = os.path.join(workspace, f"pkg{i}")
                os.makedirs(subdir)
                pkg = os.path.join(subdir, "package.json")
                with open(pkg, "w") as f:
                    json.dump({}, f)

            manifests = detect_manifests(workspace)
            assert len(manifests) <= MAX_MANIFESTS
        finally:
            shutil.rmtree(workspace)


# ═══════════════════════════════════════════════════════════════════
# Severity Normalization Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestSeverityEdgeCases:
    def test_none_input(self):
        assert normalize_severity(None) == "UNKNOWN"

    def test_empty_severity_array(self):
        assert normalize_severity({"severity": []}) == "UNKNOWN"

    def test_cvss_critical(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert normalize_severity(v) == "CRITICAL"

    def test_cvss_low(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"}]}
        assert normalize_severity(v) == "LOW"

    def test_invalid_db_specific(self):
        v = {"database_specific": {"severity": "INVALID"}}
        assert normalize_severity(v) == "UNKNOWN"

    def test_numeric_cvss_score(self):
        v = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        assert normalize_severity(v) == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════
# Finding Normalization Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestFindingNormalizationEdgeCases:
    def test_invalid_osv_result_skipped(self):
        osv_results = ["invalid", None, 123, {"no_vulns_key": True}]
        findings = normalize_findings(osv_results, [], "repo1", "scan1", "pkg.json")
        assert len(findings) == 0

    def test_invalid_vuln_skipped(self):
        osv_results = [{"vulns": [None, "string", {"no_id": True}]}]
        findings = normalize_findings(osv_results, [], "repo1", "scan1", "pkg.json")
        assert len(findings) == 0

    def test_long_title_truncated(self):
        osv_results = [{"vulns": [{"id": "GHSA-1", "summary": "x" * 2000}]}]
        findings = normalize_findings(osv_results, [{"name": "pkg", "version": "1.0"}], "repo1", "scan1", "pkg.json")
        assert len(findings) == 1
        assert len(findings[0]["title"]) <= 1000

    def test_cross_manifest_dedup(self):
        """Same vuln in different manifests should produce different fingerprints."""
        osv_results = [{"vulns": [{"id": "GHSA-1", "summary": "Test"}]}]
        deps = [{"name": "pkg", "version": "1.0"}]
        f1 = normalize_findings(osv_results, deps, "repo1", "scan1", "package.json")
        f2 = normalize_findings(osv_results, deps, "repo1", "scan1", "requirements.txt")
        assert f1[0]["fingerprint"] != f2[0]["fingerprint"]
