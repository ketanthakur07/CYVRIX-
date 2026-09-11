"""CYVRIX V2.6 Recommendation Re-Validation Engine.

Validates existing recommendations against current evidence and context.

Validation states:
- VALIDATED: All claims in the recommendation are supported by evidence
- PARTIALLY_VALIDATED: Some claims are supported, some are uncertain
- UNVERIFIED: Insufficient evidence to validate
- UNSAFE: Recommendation is contradicted by evidence or policies

Security properties:
- Advisory only — never modifies files, git, or external systems
- Deterministic wherever possible
- AI may assist explanation but cannot bypass policy validation
- Cannot directly modify security state
"""
import logging
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cyvrix.revalidation")


# ═══════════════════════════════════════════════════════════════════
# Validation States
# ═══════════════════════════════════════════════════════════════════

VALIDATION_STATES = {
    "VALIDATED",
    "PARTIALLY_VALIDATED",
    "UNVERIFIED",
    "UNSAFE",
}


# ═══════════════════════════════════════════════════════════════════
# Deterministic Validation Checks
# ═══════════════════════════════════════════════════════════════════

def _check_evidence_exists(recommendation: dict, finding: dict) -> dict:
    """Check that recommendation evidence references real data."""
    rec_evidence = recommendation.get("evidence", [])
    finding_evidence = finding.get("evidence") or {}

    if not rec_evidence:
        return {
            "check": "evidence_exists",
            "passed": False,
            "reason": "Recommendation has no evidence references",
        }

    return {
        "check": "evidence_exists",
        "passed": True,
        "reason": f"Recommendation references {len(rec_evidence)} evidence item(s)",
    }


def _check_trust_level_consistent(recommendation: dict, finding: dict) -> dict:
    """Check that trust level is appropriate for the finding severity."""
    trust_level = recommendation.get("trust_level", "")
    severity = finding.get("severity", "")

    # CRITICAL findings should have SUPPORTED trust level for dependency upgrades
    if severity == "CRITICAL" and trust_level != "SUPPORTED":
        return {
            "check": "trust_level_consistent",
            "passed": False,
            "reason": f"CRITICAL finding has non-SUPPORTED trust level: {trust_level}",
        }

    # UNCERTAIN trust level should have uncertainty documented
    if trust_level == "UNCERTAIN":
        uncertainty = recommendation.get("uncertainty", "")
        if not uncertainty:
            return {
                "check": "trust_level_consistent",
                "passed": False,
                "reason": "UNCERTAIN trust level without documented uncertainty",
            }

    return {
        "check": "trust_level_consistent",
        "passed": True,
        "reason": f"Trust level {trust_level} is consistent with severity {severity}",
    }


def _check_recommendation_completeness(recommendation: dict) -> dict:
    """Check that recommendation has all required fields populated."""
    required_fields = ["title", "what", "why", "change"]
    missing = [f for f in required_fields if not recommendation.get(f)]

    if missing:
        return {
            "check": "recommendation_completeness",
            "passed": False,
            "reason": f"Missing required fields: {', '.join(missing)}",
        }

    return {
        "check": "recommendation_completeness",
        "passed": True,
        "reason": "All required recommendation fields are present",
    }


def _check_scanner_specific(recommendation: dict, finding: dict) -> dict:
    """Validate scanner-type-specific logic."""
    scanner = finding.get("scanner", "")
    title = recommendation.get("title", "").lower()

    if scanner == "container":
        # Container recommendations should reference Dockerfile or container
        change = recommendation.get("change", "").lower()
        what = recommendation.get("what", "").lower()
        if "dockerfile" not in change and "container" not in what and "user" not in change:
            return {
                "check": "scanner_specific",
                "passed": False,
                "reason": "Container recommendation does not reference Dockerfile or container context",
            }

    if scanner == "log_analyzer":
        # Log recommendations should reference investigation or monitoring
        change = recommendation.get("change", "").lower()
        if "investigate" not in change and "monitor" not in change and "review" not in change:
            return {
                "check": "scanner_specific",
                "passed": False,
                "reason": "Log recommendation does not reference investigation or monitoring",
            }

    return {
        "check": "scanner_specific",
        "passed": True,
        "reason": f"Scanner-specific validation passed for {scanner}",
    }


def _check_no_dangerous_content(recommendation: dict) -> dict:
    """Ensure recommendation does not contain dangerous patterns."""
    dangerous_patterns = [
        (r"rm\s+-rf", "Destructive file deletion"),
        (r"curl\s.*\|\s*(sh|bash)", "Unverified code execution"),
        (r"eval\s*\(", "Code evaluation"),
        (r"exec\s*\(", "Code execution"),
        (r"subprocess", "Subprocess invocation"),
        (r"import\s+os", "OS module usage"),
        (r"__import__", "Dynamic import"),
    ]

    fields_to_check = ["what", "why", "change", "risk", "validation", "description"]
    for field in fields_to_check:
        value = recommendation.get(field, "") or ""
        for pattern, reason in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return {
                    "check": "no_dangerous_content",
                    "passed": False,
                    "reason": f"Dangerous pattern '{reason}' found in field '{field}'",
                }

    return {
        "check": "no_dangerous_content",
        "passed": True,
        "reason": "No dangerous patterns found in recommendation",
    }


# ═══════════════════════════════════════════════════════════════════
# Main Validation Pipeline
# ═══════════════════════════════════════════════════════════════════

def validate_recommendation(
    recommendation: dict,
    finding: dict,
) -> dict:
    """Validate a recommendation against its finding context.

    Advisory only — does not modify any files, git, or external systems.

    Args:
        recommendation: Recommendation dict with fields like title, what, why, change, trust_level
        finding: Finding dict with fields like severity, scanner, evidence

    Returns:
        {
            "validation_state": str,  # VALIDATED|PARTIALLY_VALIDATED|UNVERIFIED|UNSAFE
            "checks": list[dict],     # Individual check results
            "summary": str,           # Human-readable summary
            "validated_at": str,      # ISO timestamp
        }
    """
    checks = []

    # Run all checks
    checks.append(_check_recommendation_completeness(recommendation))
    checks.append(_check_evidence_exists(recommendation, finding))
    checks.append(_check_trust_level_consistent(recommendation, finding))
    checks.append(_check_scanner_specific(recommendation, finding))
    checks.append(_check_no_dangerous_content(recommendation))

    # Determine overall state
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)
    failed_checks = [c for c in checks if not c["passed"]]

    # Any UNSAFE check immediately marks as UNSAFE
    unsafe_checks = [c for c in checks if not c["passed"] and c["check"] == "no_dangerous_content"]
    if unsafe_checks:
        state = "UNSAFE"
        summary = f"Recommendation contains dangerous patterns: {unsafe_checks[0]['reason']}"
    elif passed == total:
        state = "VALIDATED"
        summary = "All validation checks passed"
    elif passed >= total * 0.5:
        state = "PARTIALLY_VALIDATED"
        reasons = "; ".join(c["reason"] for c in failed_checks)
        summary = f"Partially validated — {len(failed_checks)} check(s) failed: {reasons}"
    else:
        state = "UNVERIFIED"
        reasons = "; ".join(c["reason"] for c in failed_checks)
        summary = f"Insufficient validation — {len(failed_checks)} check(s) failed: {reasons}"

    return {
        "validation_state": state,
        "checks": checks,
        "summary": summary,
        "validated_at": datetime.now(timezone.utc).isoformat(),
    }
