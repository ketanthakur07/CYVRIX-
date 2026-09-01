"""CYVRIX Deterministic Risk Scoring Engine.

Security properties:
- Pure function: zero LLM calls, zero network calls, zero DB calls
- Input validation: rejects NaN, Infinity, invalid types, out-of-range values
- Deterministic: same inputs always produce same outputs
- Versioned: every assessment stores the algorithm version
- Explainable: factors record exactly what was used in scoring
- Safe wrapper: malformed input never crashes the worker

Formula (V1):
    base + exposure_mod + exploit_mod + confidence_mod
    clamped to [0, 100]

Base:     CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20
Exposure: EXTERNAL=+15, INTERNAL=-5, UNKNOWN=0
Exploit:  HIGH=+10, MEDIUM=+5, LOW=0
Confidence: -20 * (1 - confidence)
"""
import logging
import math
from typing import Optional

from app.schemas import RiskFactors, RiskLevel

logger = logging.getLogger("cyvrix.risk_engine")

RISK_ALGO_VERSION = 1

# ── Valid input sets ────────────────────────────────────────────────

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_EXPOSURES = {"INTERNAL", "EXTERNAL", "UNKNOWN"}
VALID_EXPLOITABILITIES = {"LOW", "MEDIUM", "HIGH"}

# ── Base scores ─────────────────────────────────────────────────────

SEVERITY_BASE_SCORES = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 40,
    "LOW": 20,
}

# ── Modifiers ───────────────────────────────────────────────────────

EXPOSURE_MODIFIERS = {
    "EXTERNAL": 15,
    "INTERNAL": -5,
    "UNKNOWN": 0,
}

EXPLOITABILITY_MODIFIERS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 0,
}

# ── Risk level thresholds ───────────────────────────────────────────

RISK_LEVEL_THRESHOLDS = [
    (80, RiskLevel.CRITICAL),
    (60, RiskLevel.HIGH),
    (40, RiskLevel.MEDIUM),
    (20, RiskLevel.LOW),
    (0, RiskLevel.INFO),
]


# ═══════════════════════════════════════════════════════════════════
# Input Validation
# ═══════════════════════════════════════════════════════════════════

def _validate_confidence(confidence) -> float:
    """Validate and normalize confidence value.

    Returns a valid float in [0.0, 1.0].
    Raises ValueError for invalid types/values.
    """
    if confidence is None:
        return 0.5  # Default when no confidence provided

    # Reject non-numeric types
    if isinstance(confidence, bool):
        raise ValueError("Confidence must be a number, not a boolean")
    if not isinstance(confidence, (int, float)):
        raise ValueError(f"Confidence must be numeric, got {type(confidence).__name__}")

    # Reject NaN and Infinity
    if math.isnan(confidence):
        raise ValueError("Confidence cannot be NaN")
    if math.isinf(confidence):
        raise ValueError("Confidence cannot be Infinity")

    # Clamp to valid range
    return max(0.0, min(1.0, float(confidence)))


def _normalize_severity(severity: str) -> str:
    """Normalize and validate severity string."""
    if not isinstance(severity, str):
        raise ValueError(f"Severity must be a string, got {type(severity).__name__}")
    normalized = severity.upper().strip()
    if normalized not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}. Must be one of: {VALID_SEVERITIES}")
    return normalized


def _normalize_exposure(exposure: Optional[str]) -> str:
    """Normalize and validate exposure string. Defaults to UNKNOWN."""
    if exposure is None:
        return "UNKNOWN"
    if not isinstance(exposure, str):
        return "UNKNOWN"
    normalized = exposure.upper().strip()
    return normalized if normalized in VALID_EXPOSURES else "UNKNOWN"


def _normalize_exploitability(exploitability: Optional[str]) -> str:
    """Normalize and validate exploitability string. Defaults to LOW."""
    if exploitability is None:
        return "LOW"
    if not isinstance(exploitability, str):
        return "LOW"
    normalized = exploitability.upper().strip()
    return normalized if normalized in VALID_EXPLOITABILITIES else "LOW"


# ═══════════════════════════════════════════════════════════════════
# Pure Scoring Functions
# ═══════════════════════════════════════════════════════════════════

def severity_to_base_score(severity: str) -> int:
    """Map severity string to base risk score.

    Valid: CRITICAL=80, HIGH=60, MEDIUM=40, LOW=20
    Raises ValueError for invalid severity.
    """
    normalized = _normalize_severity(severity)
    return SEVERITY_BASE_SCORES[normalized]


def score_to_level(score: int) -> str:
    """Map numeric score to risk level.

    Thresholds: ≥80=CRITICAL, ≥60=HIGH, ≥40=MEDIUM, ≥20=LOW, <20=INFO
    Deterministic and centrally defined.
    """
    for threshold, level in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.INFO


def clamp(value: int | float, min_val: int, max_val: int) -> int:
    """Clamp value to [min_val, max_val] and return as int."""
    return int(max(min_val, min(max_val, value)))


# ═══════════════════════════════════════════════════════════════════
# Core Risk Calculation (Pure Function)
# ═══════════════════════════════════════════════════════════════════

def calculate_risk(
    finding_severity: str,
    investigation_exposure: Optional[str] = None,
    investigation_exploitability: Optional[str] = None,
    investigation_confidence: Optional[float] = None,
) -> tuple[int, str, RiskFactors]:
    """Pure deterministic risk scoring function.

    Inputs are validated and normalized before calculation.
    Same inputs always produce same outputs (deterministic).

    Args:
        finding_severity: LOW|MEDIUM|HIGH|CRITICAL
        investigation_exposure: INTERNAL|EXTERNAL|UNKNOWN (or None)
        investigation_exploitability: LOW|MEDIUM|HIGH (or None)
        investigation_confidence: 0.0-1.0 (or None)

    Returns:
        (score: int 0-100, risk_level: str, factors: RiskFactors)

    Raises:
        ValueError: on invalid severity or non-numeric confidence
    """
    # Validate and normalize inputs
    severity = _normalize_severity(finding_severity)
    exposure = _normalize_exposure(investigation_exposure)
    exploitability = _normalize_exploitability(investigation_exploitability)
    confidence = _validate_confidence(investigation_confidence)

    # Calculate base score
    base = SEVERITY_BASE_SCORES[severity]

    # Calculate modifiers
    exposure_mod = EXPOSURE_MODIFIERS[exposure]
    exploit_mod = EXPLOITABILITY_MODIFIERS[exploitability]

    # Determine if AI investigation data is available
    has_investigation = any(
        x is not None
        for x in [investigation_exposure, investigation_exploitability, investigation_confidence]
    )

    if has_investigation:
        confidence_mod = round(-20 * (1 - confidence))
    else:
        confidence_mod = 0

    # Calculate final score
    raw_score = base + exposure_mod + exploit_mod + confidence_mod
    score = clamp(raw_score, 0, 100)
    level = score_to_level(score)

    # Build explainable factors
    factors = RiskFactors(
        base_score=base,
        exposure_mod=exposure_mod,
        exploit_mod=exploit_mod,
        confidence_mod=confidence_mod,
        ai_available=has_investigation,
        degraded=False,
    )

    logger.debug(
        "risk_calculated severity=%s exposure=%s exploit=%s confidence=%.2f "
        "base=%d exp_mod=%d expoit_mod=%d conf_mod=%d score=%d level=%s",
        severity, exposure, exploitability, confidence,
        base, exposure_mod, exploit_mod, confidence_mod, score, level,
    )

    return score, level, factors


# ═══════════════════════════════════════════════════════════════════
# Safe Wrapper
# ═══════════════════════════════════════════════════════════════════

def calculate_risk_safe(
    finding_severity: str,
    investigation_exposure: Optional[str] = None,
    investigation_exploitability: Optional[str] = None,
    investigation_confidence: Optional[float] = None,
) -> tuple[int, str, RiskFactors]:
    """Safe wrapper that catches exceptions and falls back to severity-only scoring.

    Never raises. Always returns a valid (score, level, factors).
    If the pure calculation fails, returns severity-only score with degraded=True.
    """
    try:
        score, level, factors = calculate_risk(
            finding_severity, investigation_exposure, investigation_exploitability, investigation_confidence
        )
        return score, level, factors
    except Exception as e:
        logger.warning(
            "risk_calculation_failed severity=%s error=%s — falling back to severity-only",
            finding_severity, str(e)[:200],
        )
        # Fallback: severity-only score
        try:
            base = severity_to_base_score(finding_severity)
        except Exception:
            base = 20  # Default to LOW if severity is also invalid

        level = score_to_level(base)
        factors = RiskFactors(
            base_score=base,
            exposure_mod=0,
            exploit_mod=0,
            confidence_mod=0,
            ai_available=False,
            degraded=True,
        )
        return base, level, factors
