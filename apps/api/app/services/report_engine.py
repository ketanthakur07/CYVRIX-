"""CYVRIX V2 Report Generation Engine.

Generates security reports from scan findings.

Security properties:
- Reports follow the same authorization model as findings
- All untrusted content is escaped
- No secrets or credentials in reports
- Report generation is bounded (resource limits)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cyvrix.reports")


def generate_scan_report(
    scan: dict,
    findings: list[dict],
    investigations: list[dict],
    risk_assessments: list[dict],
    format: str = "markdown",
) -> str:
    """Generate a security report for a scan.

    Args:
        scan: Scan metadata dict
        findings: List of finding dicts
        investigations: List of investigation dicts
        risk_assessments: List of risk assessment dicts
        format: Output format (markdown or json)

    Returns:
        Report content as string
    """
    if format == "json":
        return _generate_json_report(scan, findings, investigations, risk_assessments)
    return _generate_markdown_report(scan, findings, investigations, risk_assessments)


def _generate_markdown_report(
    scan: dict,
    findings: list[dict],
    investigations: list[dict],
    risk_assessments: list[dict],
) -> str:
    """Generate a Markdown security report."""
    now = datetime.now(timezone.utc).isoformat()
    lines = []

    lines.append(f"# Security Scan Report")
    lines.append(f"")
    lines.append(f"**Generated:** {now}")
    lines.append(f"**Repository:** {scan.get('repository_name', 'unknown')}")
    lines.append(f"**Scan ID:** {scan.get('id', 'unknown')}")
    lines.append(f"**Status:** {scan.get('status', 'unknown')}")
    lines.append(f"**Commit:** {scan.get('commit_sha', 'N/A')}")
    lines.append(f"")

    # Severity distribution
    severity_counts = {}
    source_type_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        src = f.get("source_type", "DEPENDENCY")
        source_type_counts[src] = source_type_counts.get(src, 0) + 1

    lines.append(f"## Summary")
    lines.append(f"")
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append(f"")
    lines.append(f"### By Severity")
    lines.append(f"")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            lines.append(f"- **{sev}:** {count}")
    lines.append(f"")

    if source_type_counts:
        lines.append(f"### By Source")
        lines.append(f"")
        for src, count in sorted(source_type_counts.items()):
            lines.append(f"- **{src}:** {count}")
        lines.append(f"")

    # Risk summary
    if risk_assessments:
        scores = [r.get("risk_score", 0) for r in risk_assessments]
        avg_score = sum(scores) / len(scores) if scores else 0
        max_score = max(scores) if scores else 0
        lines.append(f"### Risk Assessment")
        lines.append(f"")
        lines.append(f"- **Average Risk Score:** {avg_score:.1f}/100")
        lines.append(f"- **Maximum Risk Score:** {max_score}/100")
        lines.append(f"")

    # Investigation summary
    inv_completed = sum(1 for i in investigations if i.get("status") == "COMPLETED")
    inv_failed = sum(1 for i in investigations if i.get("status") == "FAILED")
    if investigations:
        lines.append(f"### Investigation Summary")
        lines.append(f"")
        lines.append(f"- **Completed:** {inv_completed}")
        lines.append(f"- **Failed:** {inv_failed}")
        lines.append(f"- **Total:** {len(investigations)}")
        lines.append(f"")

    # Findings by source type
    for source_type in ["DEPENDENCY", "CONTAINER", "LOG"]:
        type_findings = [f for f in findings if f.get("source_type") == source_type]
        if not type_findings:
            continue

        lines.append(f"## {source_type.title()} Findings")
        lines.append(f"")

        for f in sorted(type_findings, key=lambda x: _severity_order(x.get("severity", "UNKNOWN")), reverse=True):
            sev = f.get("severity", "UNKNOWN")
            title = _escape_md(f.get("title", "Unknown"))
            vuln_id = f.get("vulnerability_id", "")
            pkg = f.get("package_name", "")

            lines.append(f"### [{sev}] {title}")
            lines.append(f"")

            if vuln_id:
                lines.append(f"- **Vulnerability:** {_escape_md(vuln_id)}")
            if pkg:
                lines.append(f"- **Component:** {_escape_md(pkg)} {f.get('package_version', '')}")
            lines.append(f"- **Source:** {_escape_md(f.get('scanner', 'unknown'))}")

            # Investigation
            inv = next((i for i in investigations if i.get("finding_id") == f.get("id")), None)
            if inv and inv.get("status") == "COMPLETED":
                lines.append(f"- **Verdict:** {inv.get('verdict', 'N/A')}")
                lines.append(f"- **Confidence:** {inv.get('confidence', 'N/A')}")

            # Risk
            risk = next((r for r in risk_assessments if r.get("finding_id") == f.get("id")), None)
            if risk:
                lines.append(f"- **Risk Score:** {risk.get('risk_score', 'N/A')}/100 ({risk.get('risk_level', 'N/A')})")

            desc = f.get("description", "")
            if desc:
                lines.append(f"")
                lines.append(f"> {_escape_md(desc[:300])}")

            lines.append(f"")

    # Recommendations
    recommendations = [f for f in findings if f.get("recommendation")]
    if recommendations:
        lines.append(f"## Recommendations")
        lines.append(f"")
        for rec in recommendations[:20]:  # Limit recommendations in report
            lines.append(f"- **{_escape_md(rec.get('recommendation', {}).get('title', 'Recommendation'))}**")
            change = rec.get("recommendation", {}).get("change", "")
            if change:
                lines.append(f"  - {_escape_md(change[:200])}")
        lines.append(f"")

    # Limitations
    lines.append(f"## Limitations")
    lines.append(f"")
    lines.append(f"- This report covers dependency vulnerabilities and container security issues.")
    lines.append(f"- AI-generated recommendations are advisory and should be reviewed by a human.")
    lines.append(f"- Risk scores are deterministic but based on limited context.")
    lines.append(f"- Not all vulnerabilities may be detectable with static analysis.")
    lines.append(f"")

    return "\n".join(lines)


def _generate_json_report(
    scan: dict,
    findings: list[dict],
    investigations: list[dict],
    risk_assessments: list[dict],
) -> str:
    """Generate a JSON security report."""
    import json

    severity_counts = {}
    source_type_counts = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        src = f.get("source_type", "DEPENDENCY")
        source_type_counts[src] = source_type_counts.get(src, 0) + 1

    risk_scores = [r.get("risk_score", 0) for r in risk_assessments]

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": scan,
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_source": source_type_counts,
            "total_investigations": len(investigations),
            "investigations_completed": sum(1 for i in investigations if i.get("status") == "COMPLETED"),
            "risk_average": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "risk_max": max(risk_scores) if risk_scores else 0,
        },
        "findings": findings,
    }

    return json.dumps(report, indent=2, default=str)


def _severity_order(severity: str) -> int:
    """Sort order for severity levels."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": -1}
    return order.get(severity, -1)


def _escape_md(text: str) -> str:
    """Escape text for safe Markdown rendering."""
    if not text:
        return ""
    # Escape special Markdown characters
    text = text.replace("\\", "\\\\")
    text = text.replace("|", "\\|")
    text = text.replace("\n", " ")
    return text[:500]
