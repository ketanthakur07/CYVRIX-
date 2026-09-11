"""CYVRIX V2 Report Engine Tests.

Tests for report generation, format, content, and safety.
"""
import os
import sys
import json
import pytest
from uuid import uuid4

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.report_engine import (
    generate_scan_report,
    _escape_md,
)


# ═══════════════════════════════════════════════════════════════════
# Markdown Report Tests
# ═══════════════════════════════════════════════════════════════════

class TestMarkdownReport:
    def test_generates_basic_report(self):
        scan = {
            "id": str(uuid4()),
            "repository_name": "test/repo",
            "status": "COMPLETED",
            "commit_sha": "abc123",
        }
        findings = [
            {
                "id": str(uuid4()),
                "severity": "HIGH",
                "source_type": "DEPENDENCY",
                "scanner": "dependency",
                "title": "Test vulnerability",
                "vulnerability_id": "CVE-2024-12345",
                "package_name": "test-pkg",
                "package_version": "1.0.0",
            }
        ]

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        assert "Security Scan Report" in report
        assert "test/repo" in report
        assert "HIGH" in report
        assert "Test vulnerability" in report

    def test_report_includes_severity_distribution(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "CRITICAL", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Critical vuln"},
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "High vuln"},
            {"id": str(uuid4()), "severity": "MEDIUM", "source_type": "CONTAINER", "scanner": "container", "title": "Medium vuln"},
        ]

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        assert "CRITICAL" in report
        assert "HIGH" in report
        assert "MEDIUM" in report

    def test_report_includes_source_type_distribution(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Dep vuln"},
            {"id": str(uuid4()), "severity": "MEDIUM", "source_type": "CONTAINER", "scanner": "container", "title": "Container vuln"},
        ]

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        assert "Dependency" in report
        assert "Container" in report

    def test_report_with_investigations(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Test vuln"}
        ]
        investigations = [
            {"finding_id": findings[0]["id"], "status": "COMPLETED", "verdict": "CONFIRMED", "confidence": 0.85}
        ]

        report = generate_scan_report(scan, findings, investigations, [], format="markdown")
        assert "Investigation" in report
        assert "CONFIRMED" in report

    def test_report_with_risk_assessments(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Test vuln"}
        ]
        risks = [
            {"finding_id": findings[0]["id"], "risk_score": 75, "risk_level": "HIGH"}
        ]

        report = generate_scan_report(scan, findings, [], risks, format="markdown")
        assert "Risk" in report
        assert "75" in report

    def test_report_includes_limitations(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = []

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        assert "Limitations" in report


# ═══════════════════════════════════════════════════════════════════
# JSON Report Tests
# ═══════════════════════════════════════════════════════════════════

class TestJsonReport:
    def test_generates_valid_json(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Test vuln"}
        ]

        report = generate_scan_report(scan, findings, [], [], format="json")
        data = json.loads(report)
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["total_findings"] == 1

    def test_json_report_includes_severity_counts(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "CRITICAL", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Critical"},
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "CONTAINER", "scanner": "container", "title": "High"},
        ]

        report = generate_scan_report(scan, findings, [], [], format="json")
        data = json.loads(report)
        assert data["summary"]["by_severity"]["CRITICAL"] == 1
        assert data["summary"]["by_severity"]["HIGH"] == 1


# ═══════════════════════════════════════════════════════════════════
# Safety Tests
# ═══════════════════════════════════════════════════════════════════

class TestReportSafety:
    def test_no_secrets_in_report(self):
        """Reports should not contain secrets or credentials."""
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = [
            {"id": str(uuid4()), "severity": "HIGH", "source_type": "DEPENDENCY", "scanner": "dependency", "title": "Test vuln"}
        ]

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        # Check for common secret patterns
        assert "password=" not in report.lower()
        assert "secret_key=" not in report.lower()
        assert "api_key=" not in report.lower()
        assert "PRIVATE KEY" not in report

    def test_empty_findings_report(self):
        scan = {"id": str(uuid4()), "repository_name": "test/repo", "status": "COMPLETED"}
        findings = []

        report = generate_scan_report(scan, findings, [], [], format="markdown")
        assert "0" in report or "Total Findings: 0" in report


# ═══════════════════════════════════════════════════════════════════
# Markdown Escaping Tests
# ═══════════════════════════════════════════════════════════════════

class TestMarkdownEscaping:
    def test_escapes_pipe(self):
        result = _escape_md("test|value")
        assert "\\|" in result

    def test_escapes_newline(self):
        result = _escape_md("line1\nline2")
        assert "\n" not in result

    def test_truncates_long_text(self):
        result = _escape_md("A" * 1000)
        assert len(result) <= 500

    def test_handles_empty_string(self):
        result = _escape_md("")
        assert result == ""
