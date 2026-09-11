"""CYVRIX V2 Log Analyzer Tests.

Tests for log file detection, parsing, pattern detection,
path traversal defense, and resource limits.
"""
import os
import sys
import json
import tempfile
import pytest
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.log_analyzer import (
    detect_log_files,
    parse_log_line,
    analyze_log_events,
    analyze_text_log,
    analyze_json_log,
    compute_log_fingerprint,
    analyze_logs,
    _validate_path_in_workspace,
    DETECTION_PATTERNS,
)


FIXTURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "fixtures"))


# ═══════════════════════════════════════════════════════════════════
# Path Traversal Defense Tests
# ═══════════════════════════════════════════════════════════════════

class TestPathTraversal:
    def test_safe_path_passes(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        filepath = os.path.join(workspace, "access.log")
        result = _validate_path_in_workspace(filepath, workspace)
        assert result == os.path.realpath(filepath)

    def test_traversal_blocked(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        filepath = os.path.join(workspace, "..", "..", "etc", "passwd")
        with pytest.raises(ValueError, match="Path traversal"):
            _validate_path_in_workspace(filepath, workspace)


# ═══════════════════════════════════════════════════════════════════
# Log File Detection Tests
# ═══════════════════════════════════════════════════════════════════

class TestLogDetection:
    def test_detects_log_files(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        log_files = detect_log_files(workspace)
        assert len(log_files) >= 1
        assert any("access.log" in f or "security.log" in f for f in log_files)

    def test_no_logs_in_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_files = detect_log_files(tmpdir)
            assert len(log_files) == 0


# ═══════════════════════════════════════════════════════════════════
# Log Line Parsing Tests
# ═══════════════════════════════════════════════════════════════════

class TestLogParsing:
    def test_parse_valid_line(self):
        line = "2026-09-01T10:00:01Z INFO GET /api/users 200 user=admin source_ip=192.168.1.100"
        result = parse_log_line(line)
        assert result is not None
        assert result["timestamp"] == "2026-09-01T10:00:01Z"
        assert result["level"] == "INFO"
        assert result["source_ip"] == "192.168.1.100"
        assert result["method"] == "GET"

    def test_parse_error_line(self):
        line = "2026-09-01T10:00:02Z ERROR Authentication failed user=unknown source_ip=10.0.0.50"
        result = parse_log_line(line)
        assert result is not None
        assert result["level"] == "ERROR"
        assert result["source_ip"] == "10.0.0.50"

    def test_parse_empty_line(self):
        result = parse_log_line("")
        assert result is None

    def test_parse_long_line(self):
        line = "A" * 20000
        result = parse_log_line(line)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# Pattern Detection Tests
# ═══════════════════════════════════════════════════════════════════

class TestPatternDetection:
    def test_brute_force_detection(self):
        events = []
        for i in range(6):
            events.append({
                "raw": f"2026-09-01T10:00:{i:02d}Z ERROR Authentication failed source_ip=10.0.0.50",
                "source_ip": "10.0.0.50",
                "timestamp": f"2026-09-01T10:00:{i:02d}Z",
            })

        findings = analyze_log_events(events, "repeated_auth_failure", str(uuid4()), "test.log")
        assert len(findings) >= 1
        assert "brute" in findings[0]["title"].lower()

    def test_admin_access_detection(self):
        events = [{
            "raw": "2026-09-01T10:00:01Z INFO Admin access detected user=admin",
            "source_ip": "192.168.1.100",
        }]

        findings = analyze_log_events(events, "admin_access_anomaly", str(uuid4()), "test.log")
        assert len(findings) >= 1

    def test_path_probing_detection(self):
        events = []
        for path in ["/etc/passwd", "/etc/shadow", "/.env"]:
            events.append({
                "raw": f"2026-09-01T10:00:01Z WARN GET {path} 403",
                "source_ip": "10.0.0.50",
            })

        findings = analyze_log_events(events, "path_probing", str(uuid4()), "test.log")
        assert len(findings) >= 1

    def test_no_detection_on_clean_logs(self):
        events = [{
            "raw": "2026-09-01T10:00:01Z INFO Application started",
            "source_ip": "192.168.1.100",
        }]

        findings = analyze_log_events(events, "repeated_auth_failure", str(uuid4()), "test.log")
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════
# Text Log Analysis Tests
# ═══════════════════════════════════════════════════════════════════

class TestTextLogAnalysis:
    def test_analyze_access_log(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("access.log", workspace, str(uuid4()))
        # Should detect brute-force pattern from the access log
        assert len(findings) >= 1

    def test_analyze_normal_log(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("normal.log", workspace, str(uuid4()))
        # Normal log should have fewer or no findings
        assert len(findings) == 0


# ═══════════════════════════════════════════════════════════════════
# JSON Log Analysis Tests
# ═══════════════════════════════════════════════════════════════════

class TestJsonLogAnalysis:
    def test_analyze_json_security_log(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_json_log("security.log", workspace, str(uuid4()))
        # Should detect brute-force pattern from the JSON log
        assert len(findings) >= 1


# ═══════════════════════════════════════════════════════════════════
# Fingerprint Tests
# ═══════════════════════════════════════════════════════════════════

class TestFingerprinting:
    def test_deterministic_fingerprint(self):
        fp1 = compute_log_fingerprint("repo1", "brute_force", "test.log")
        fp2 = compute_log_fingerprint("repo1", "brute_force", "test.log")
        assert fp1 == fp2

    def test_different_inputs_different_fingerprints(self):
        fp1 = compute_log_fingerprint("repo1", "brute_force", "test.log")
        fp2 = compute_log_fingerprint("repo2", "brute_force", "test.log")
        assert fp1 != fp2


# ═══════════════════════════════════════════════════════════════════
# Finding Format Tests
# ═══════════════════════════════════════════════════════════════════

class TestFindingFormat:
    def test_finding_has_required_fields(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("access.log", workspace, str(uuid4()))
        for f in findings:
            assert "fingerprint" in f
            assert "title" in f
            assert "severity" in f
            assert "scanner" in f
            assert f["scanner"] == "log_analyzer"
            assert "source_type" in f
            assert f["source_type"] == "LOG"

    def test_severity_is_valid(self):
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("access.log", workspace, str(uuid4()))
        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}
        for f in findings:
            assert f["severity"] in valid_severities


class TestV1Regression:
    """Regression tests proving V1 dependency persistence still works."""

    def test_log_finding_source_type_and_evidence(self):
        """Log findings must have source_type=LOG and evidence."""
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("access.log", workspace, str(uuid4()))
        for f in findings:
            assert f["source_type"] == "LOG", f"Expected LOG, got {f['source_type']} for {f['title']}"
            assert f.get("evidence") is not None, f"Missing evidence for {f['title']}"
            assert isinstance(f["evidence"], dict), f"Evidence should be dict, got {type(f['evidence'])}"

    def test_log_finding_persistence_fields_complete(self):
        """All required persistence fields are present in log findings."""
        workspace = os.path.join(FIXTURES_DIR, "log-app")
        findings = analyze_text_log("access.log", workspace, str(uuid4()))
        required_fields = {"fingerprint", "title", "severity", "scanner", "source_type", "evidence"}
        for f in findings:
            missing = required_fields - set(f.keys())
            assert not missing, f"Missing fields {missing} in finding: {f.get('title', 'unknown')}"


# ═══════════════════════════════════════════════════════════════════
# Malicious Input Tests
# ═══════════════════════════════════════════════════════════════════

class TestMaliciousInput:
    def test_prompt_injection_in_log(self):
        """Verify that prompt injection in log content doesn't alter detection behavior."""
        workspace = os.path.join(FIXTURES_DIR, "malicious-log")
        findings = analyze_text_log("injection.log", workspace, str(uuid4()))
        # Should not crash and should return a list
        assert isinstance(findings, list)
        # Verify prompt injection text does not become a finding title/description
        for f in findings:
            title_lower = f.get("title", "").lower()
            desc_lower = f.get("description", "").lower()
            assert "ignore previous" not in title_lower, f"Prompt injection leaked into title: {f['title']}"
            assert "ignore previous" not in desc_lower, f"Prompt injection leaked into description: {f.get('description', '')}"
            # Findings should have valid scanner and source_type
            assert f.get("scanner") == "log_analyzer"
            assert f.get("source_type") == "LOG"

    def test_huge_line_handled(self):
        """Verify that very long lines are handled safely."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("A" * 100000 + "\n")
            f.write("normal log line\n")
            tmpfile = f.name

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.rename(tmpfile, os.path.join(tmpdir, "test.log"))
                findings = analyze_text_log("test.log", tmpdir, str(uuid4()))
                assert isinstance(findings, list)
        except Exception:
            # Clean up if test fails
            try:
                os.unlink(tmpfile)
            except OSError:
                pass
            raise
