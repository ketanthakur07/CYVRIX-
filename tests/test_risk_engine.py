"""Comprehensive risk engine tests.

Covers:
- Formula correctness (table-driven with exact scores)
- Boundary testing (0, 1, 19, 20, 39, 40, 59, 60, 79, 80, 99, 100)
- Numeric abuse (NaN, Infinity, None, string, bool, huge values)
- Missing data / fallback behavior
- Determinism (same inputs → same outputs)
- Versioning (version persisted, not mutated)
- Safe wrapper (never crashes)
- Risk level mapping (exact thresholds)
- No LLM/network/DB calls (pure function verification)
"""
import math
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "apps", "api"))

from app.services.risk_engine import (
    calculate_risk,
    calculate_risk_safe,
    severity_to_base_score,
    score_to_level,
    clamp,
    RISK_ALGO_VERSION,
    VALID_SEVERITIES,
    VALID_EXPOSURES,
    VALID_EXPLOITABILITIES,
    SEVERITY_BASE_SCORES,
    EXPOSURE_MODIFIERS,
    EXPLOITABILITY_MODIFIERS,
)


# ═══════════════════════════════════════════════════════════════════
# Base Severity Tests
# ═══════════════════════════════════════════════════════════════════

class TestSeverityToBaseScore:
    def test_critical(self):
        assert severity_to_base_score("CRITICAL") == 80

    def test_high(self):
        assert severity_to_base_score("HIGH") == 60

    def test_medium(self):
        assert severity_to_base_score("MEDIUM") == 40

    def test_low(self):
        assert severity_to_base_score("LOW") == 20

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            severity_to_base_score("UNKNOWN")

    def test_case_insensitive(self):
        assert severity_to_base_score("critical") == 80
        assert severity_to_base_score("High") == 60

    def test_whitespace_handling(self):
        assert severity_to_base_score("  HIGH  ") == 60

    def test_non_string_raises(self):
        with pytest.raises(ValueError):
            severity_to_base_score(123)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            severity_to_base_score("")


# ═══════════════════════════════════════════════════════════════════
# Risk Level Mapping Tests
# ═══════════════════════════════════════════════════════════════════

class TestScoreToLevel:
    def test_critical(self):
        assert score_to_level(80) == "CRITICAL"
        assert score_to_level(95) == "CRITICAL"
        assert score_to_level(100) == "CRITICAL"

    def test_high(self):
        assert score_to_level(60) == "HIGH"
        assert score_to_level(79) == "HIGH"

    def test_medium(self):
        assert score_to_level(40) == "MEDIUM"
        assert score_to_level(59) == "MEDIUM"

    def test_low(self):
        assert score_to_level(20) == "LOW"
        assert score_to_level(39) == "LOW"

    def test_info(self):
        assert score_to_level(0) == "INFO"
        assert score_to_level(19) == "INFO"


# ═══════════════════════════════════════════════════════════════════
# Clamp Tests
# ═══════════════════════════════════════════════════════════════════

class TestClamp:
    def test_within_bounds(self):
        assert clamp(50, 0, 100) == 50

    def test_below_min(self):
        assert clamp(-10, 0, 100) == 0

    def test_above_max(self):
        assert clamp(150, 0, 100) == 100

    def test_float_input(self):
        assert clamp(50.7, 0, 100) == 50

    def test_exact_boundaries(self):
        assert clamp(0, 0, 100) == 0
        assert clamp(100, 0, 100) == 100


# ═══════════════════════════════════════════════════════════════════
# Table-Driven Formula Tests (Exact Scores)
# ═══════════════════════════════════════════════════════════════════

# (severity, exposure, exploitability, confidence, expected_score, expected_level)
EXACT_RISK_TABLE = [
    # CRITICAL base=80
    ("CRITICAL", "EXTERNAL", "HIGH", 1.0,   100, "CRITICAL"),       # 80+15+10+0=105→100
    ("CRITICAL", "EXTERNAL", "HIGH", 0.5,    95, "CRITICAL"),       # 80+15+10-10=95
    ("CRITICAL", "EXTERNAL", "HIGH", 0.0,    85, "CRITICAL"),       # 80+15+10-20=85
    ("CRITICAL", "EXTERNAL", "MEDIUM", 0.75, 95, "CRITICAL"),       # 80+15+5-5=95
    ("CRITICAL", "EXTERNAL", "LOW", 1.0,     95, "CRITICAL"),       # 80+15+0+0=95
    ("CRITICAL", "INTERNAL", "HIGH", 1.0,    85, "CRITICAL"),       # 80-5+10+0=85
    ("CRITICAL", "INTERNAL", "LOW", 0.5,     65, "HIGH"),           # 80-5+0-10=65
    ("CRITICAL", "INTERNAL", "LOW", 0.0,     55, "MEDIUM"),         # 80-5+0-20=55
    ("CRITICAL", "UNKNOWN", "LOW", 0.5,      70, "HIGH"),           # 80+0+0-10=70
    ("CRITICAL", "UNKNOWN", "LOW", 0.0,      60, "HIGH"),           # 80+0+0-20=60

    # HIGH base=60
    ("HIGH", "EXTERNAL", "HIGH", 1.0,        85, "CRITICAL"),       # 60+15+10+0=85
    ("HIGH", "EXTERNAL", "HIGH", 0.5,        75, "HIGH"),           # 60+15+10-10=75
    ("HIGH", "EXTERNAL", "HIGH", 0.0,        65, "HIGH"),           # 60+15+10-20=65
    ("HIGH", "EXTERNAL", "MEDIUM", 0.75,     75, "HIGH"),           # 60+15+5-5=75
    ("HIGH", "EXTERNAL", "LOW", 1.0,         75, "HIGH"),           # 60+15+0+0=75
    ("HIGH", "INTERNAL", "HIGH", 1.0,        65, "HIGH"),           # 60-5+10+0=65
    ("HIGH", "INTERNAL", "LOW", 0.5,         45, "MEDIUM"),         # 60-5+0-10=45
    ("HIGH", "INTERNAL", "LOW", 0.0,         35, "LOW"),            # 60-5+0-20=35
    ("HIGH", "UNKNOWN", "LOW", 0.5,          50, "MEDIUM"),         # 60+0+0-10=50
    ("HIGH", "UNKNOWN", "LOW", 0.0,          40, "MEDIUM"),         # 60+0+0-20=40

    # MEDIUM base=40
    ("MEDIUM", "EXTERNAL", "HIGH", 1.0,      65, "HIGH"),           # 40+15+10+0=65
    ("MEDIUM", "EXTERNAL", "HIGH", 0.5,      55, "MEDIUM"),         # 40+15+10-10=55
    ("MEDIUM", "EXTERNAL", "HIGH", 0.0,      45, "MEDIUM"),         # 40+15+10-20=45
    ("MEDIUM", "EXTERNAL", "MEDIUM", 0.75,   55, "MEDIUM"),         # 40+15+5-5=55
    ("MEDIUM", "EXTERNAL", "LOW", 1.0,       55, "MEDIUM"),         # 40+15+0+0=55
    ("MEDIUM", "INTERNAL", "HIGH", 1.0,      45, "MEDIUM"),         # 40-5+10+0=45
    ("MEDIUM", "INTERNAL", "LOW", 0.5,       25, "LOW"),            # 40-5+0-10=25
    ("MEDIUM", "INTERNAL", "LOW", 0.0,       15, "INFO"),           # 40-5+0-20=15
    ("MEDIUM", "UNKNOWN", "LOW", 0.5,        30, "LOW"),            # 40+0+0-10=30
    ("MEDIUM", "UNKNOWN", "LOW", 0.0,        20, "LOW"),            # 40+0+0-20=20

    # LOW base=20
    ("LOW", "EXTERNAL", "HIGH", 1.0,         45, "MEDIUM"),         # 20+15+10+0=45
    ("LOW", "EXTERNAL", "HIGH", 0.5,         35, "LOW"),            # 20+15+10-10=35
    ("LOW", "EXTERNAL", "HIGH", 0.0,         25, "LOW"),            # 20+15+10-20=25
    ("LOW", "EXTERNAL", "MEDIUM", 0.75,      35, "LOW"),            # 20+15+5-5=35
    ("LOW", "EXTERNAL", "LOW", 1.0,          35, "LOW"),            # 20+15+0+0=35
    ("LOW", "INTERNAL", "HIGH", 1.0,         25, "LOW"),            # 20-5+10+0=25
    ("LOW", "INTERNAL", "LOW", 0.5,          5, "INFO"),            # 20-5+0-10=5
    ("LOW", "INTERNAL", "LOW", 0.0,          0, "INFO"),            # 20-5+0-20=-5→0
    ("LOW", "UNKNOWN", "LOW", 0.5,           10, "INFO"),           # 20+0+0-10=10
    ("LOW", "UNKNOWN", "LOW", 0.0,           0, "INFO"),            # 20+0+0-20=0
]


class TestRiskCalculation:
    @pytest.mark.parametrize(
        "severity,exposure,exploitability,confidence,expected_score,expected_level",
        EXACT_RISK_TABLE,
    )
    def test_exact_risk_score(
        self, severity, exposure, exploitability, confidence, expected_score, expected_level,
    ):
        score, level, factors = calculate_risk(severity, exposure, exploitability, confidence)
        assert score == expected_score, (
            f"Expected {expected_score}, got {score} "
            f"({severity}+{exposure}+{exploitability}+conf={confidence})"
        )
        assert level == expected_level
        assert factors.ai_available is True
        assert factors.degraded is False

    def test_no_investigation_severity_only(self):
        score, level, factors = calculate_risk("HIGH")
        assert score == 60
        assert level == "HIGH"
        assert factors.ai_available is False
        assert factors.exposure_mod == 0
        assert factors.exploit_mod == 0
        assert factors.confidence_mod == 0

    def test_all_severities_no_investigation(self):
        for sev, expected in [("CRITICAL", 80), ("HIGH", 60), ("MEDIUM", 40), ("LOW", 20)]:
            score, _, factors = calculate_risk(sev)
            assert score == expected
            assert factors.ai_available is False


# ═══════════════════════════════════════════════════════════════════
# Boundary Tests
# ═══════════════════════════════════════════════════════════════════

class TestBoundaryScores:
    """Test scores around exact level boundaries."""

    @pytest.mark.parametrize("score", [0, 1, 19, 20, 39, 40, 59, 60, 79, 80, 99, 100])
    def test_score_to_level_at_boundaries(self, score):
        level = score_to_level(score)
        if score >= 80:
            assert level == "CRITICAL"
        elif score >= 60:
            assert level == "HIGH"
        elif score >= 40:
            assert level == "MEDIUM"
        elif score >= 20:
            assert level == "LOW"
        else:
            assert level == "INFO"

    def test_minimum_possible_score(self):
        # LOW + INTERNAL + LOW + confidence=0 → 20-5+0-20 = -5 → clamped to 0
        score, level, _ = calculate_risk("LOW", "INTERNAL", "LOW", 0.0)
        assert score == 0
        assert level == "INFO"

    def test_maximum_possible_score(self):
        # CRITICAL + EXTERNAL + HIGH + confidence=1.0 → 80+15+10+0 = 105 → clamped to 100
        score, level, _ = calculate_risk("CRITICAL", "EXTERNAL", "HIGH", 1.0)
        assert score == 100
        assert level == "CRITICAL"


# ═══════════════════════════════════════════════════════════════════
# Numeric Abuse Tests
# ═══════════════════════════════════════════════════════════════════

class TestNumericAbuse:
    def test_nan_confidence_raises(self):
        with pytest.raises(ValueError, match="NaN"):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", float("nan"))

    def test_positive_infinity_raises(self):
        with pytest.raises(ValueError, match="Infinity"):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", float("inf"))

    def test_negative_infinity_raises(self):
        with pytest.raises(ValueError, match="Infinity"):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", float("-inf"))

    def test_string_confidence_raises(self):
        with pytest.raises(ValueError, match="numeric"):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", "0.5")

    def test_bool_confidence_raises(self):
        with pytest.raises(ValueError, match="boolean"):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", True)

    def test_none_confidence_defaults(self):
        # None confidence should default to 0.5
        score, _, _ = calculate_risk("HIGH", "EXTERNAL", "HIGH", None)
        expected = 60 + 15 + 10 + round(-20 * (1 - 0.5))  # 60+15+10-10=75
        assert score == expected

    def test_negative_confidence_clamped(self):
        score1, _, _ = calculate_risk("HIGH", "EXTERNAL", "HIGH", -0.1)
        score2, _, _ = calculate_risk("HIGH", "EXTERNAL", "HIGH", 0.0)
        assert score1 == score2  # Clamped to 0.0

    def test_over_one_confidence_clamped(self):
        score1, _, _ = calculate_risk("HIGH", "EXTERNAL", "HIGH", 1.5)
        score2, _, _ = calculate_risk("HIGH", "EXTERNAL", "HIGH", 1.0)
        assert score1 == score2  # Clamped to 1.0

    def test_huge_severity_string_raises(self):
        with pytest.raises(ValueError):
            calculate_risk("A" * 10000)

    def test_numeric_severity_raises(self):
        with pytest.raises(ValueError):
            calculate_risk(80)

    def test_score_never_nan(self):
        """Score must always be a valid integer, never NaN."""
        for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            score, _, _ = calculate_risk(sev, "EXTERNAL", "HIGH", 0.5)
            assert isinstance(score, int)
            assert not math.isnan(score)
            assert not math.isinf(score)

    def test_score_always_integer(self):
        score, _, _ = calculate_risk("HIGH", "EXTERNAL", "MEDIUM", 0.33)
        assert isinstance(score, int)


# ═══════════════════════════════════════════════════════════════════
# Missing Data / Fallback Tests
# ═══════════════════════════════════════════════════════════════════

class TestMissingData:
    def test_no_investigation(self):
        score, level, factors = calculate_risk("HIGH")
        assert score == 60
        assert factors.ai_available is False

    def test_partial_investigation_exposure_only(self):
        score, level, factors = calculate_risk("HIGH", "EXTERNAL")
        assert score > 60  # Exposure adds +15
        assert factors.ai_available is True

    def test_partial_investigation_exploit_only(self):
        score, level, factors = calculate_risk("HIGH", None, "HIGH")
        assert score == 60  # Exploit adds +10 but default confidence=0.5 adds -10, net=60
        assert factors.ai_available is True

    def test_unknown_exposure(self):
        score, _, factors = calculate_risk("HIGH", "UNKNOWN", "LOW", 0.5)
        assert factors.exposure_mod == 0

    def test_unknown_exploitability(self):
        score, _, factors = calculate_risk("HIGH", "EXTERNAL", "UNKNOWN", 0.5)
        # UNKNOWN exploitability defaults to LOW (0 modifier)
        assert factors.exploit_mod == 0

    def test_invalid_exposure_defaults_unknown(self):
        score1, _, f1 = calculate_risk("HIGH", "BOGUS", "LOW", 0.5)
        score2, _, f2 = calculate_risk("HIGH", "UNKNOWN", "LOW", 0.5)
        assert score1 == score2
        assert f1.exposure_mod == f2.exposure_mod

    def test_invalid_exploitability_defaults_low(self):
        score1, _, f1 = calculate_risk("HIGH", "EXTERNAL", "BOGUS", 0.5)
        score2, _, f2 = calculate_risk("HIGH", "EXTERNAL", "LOW", 0.5)
        assert score1 == score2
        assert f1.exploit_mod == f2.exploit_mod


# ═══════════════════════════════════════════════════════════════════
# Determinism Tests
# ═══════════════════════════════════════════════════════════════════

class TestDeterminism:
    def test_same_inputs_same_output(self):
        """Run 1000 times, must always produce identical result."""
        inputs = ("CRITICAL", "EXTERNAL", "HIGH", 0.85)
        results = [calculate_risk(*inputs) for _ in range(1000)]
        scores = [r[0] for r in results]
        levels = [r[1] for r in results]
        assert len(set(scores)) == 1, "Scores vary across identical runs"
        assert len(set(levels)) == 1, "Levels vary across identical runs"

    def test_no_time_dependency(self):
        """Score must not depend on current time."""
        import time
        r1 = calculate_risk("HIGH", "EXTERNAL", "MEDIUM", 0.7)
        time.sleep(0.01)
        r2 = calculate_risk("HIGH", "EXTERNAL", "MEDIUM", 0.7)
        assert r1[0] == r2[0]

    def test_no_randomness(self):
        """Score must not use random values."""
        results = set()
        for _ in range(100):
            score, _, _ = calculate_risk("MEDIUM", "INTERNAL", "LOW", 0.5)
            results.add(score)
        assert len(results) == 1


# ═══════════════════════════════════════════════════════════════════
# Versioning Tests
# ═══════════════════════════════════════════════════════════════════

class TestVersioning:
    def test_version_is_positive_integer(self):
        assert isinstance(RISK_ALGO_VERSION, int)
        assert RISK_ALGO_VERSION >= 1

    def test_version_is_constant(self):
        """Version should not change during a run."""
        v1 = RISK_ALGO_VERSION
        v2 = RISK_ALGO_VERSION
        assert v1 == v2

    def test_factors_include_version_info(self):
        """Factors should be storable alongside version."""
        _, _, factors = calculate_risk("HIGH", "EXTERNAL", "HIGH", 0.9)
        record = {
            "risk_version": RISK_ALGO_VERSION,
            "factors": factors.model_dump(),
        }
        assert record["risk_version"] == 1
        assert record["factors"]["base_score"] == 60
        assert record["factors"]["ai_available"] is True


# ═══════════════════════════════════════════════════════════════════
# Explainability / Factors Tests
# ═══════════════════════════════════════════════════════════════════

class TestExplainability:
    def test_factors_record_all_components(self):
        score, _, factors = calculate_risk("HIGH", "EXTERNAL", "HIGH", 0.9)
        assert factors.base_score == 60
        assert factors.exposure_mod == 15
        assert factors.exploit_mod == 10
        assert factors.confidence_mod == round(-20 * (1 - 0.9))  # -2
        assert factors.ai_available is True
        assert factors.degraded is False
        # Verify sum matches score
        assert factors.base_score + factors.exposure_mod + factors.exploit_mod + factors.confidence_mod == score

    def test_factors_for_no_investigation(self):
        _, _, factors = calculate_risk("MEDIUM")
        assert factors.base_score == 40
        assert factors.exposure_mod == 0
        assert factors.exploit_mod == 0
        assert factors.confidence_mod == 0
        assert factors.ai_available is False

    def test_factors_serializable(self):
        """Factors must be JSON-serializable for database storage."""
        _, _, factors = calculate_risk("HIGH", "EXTERNAL", "MEDIUM", 0.75)
        import json
        dumped = json.dumps(factors.model_dump())
        loaded = json.loads(dumped)
        assert loaded["base_score"] == 60
        assert loaded["ai_available"] is True


# ═══════════════════════════════════════════════════════════════════
# Safe Wrapper Tests
# ═══════════════════════════════════════════════════════════════════

class TestRiskSafe:
    def test_exception_returns_safe_default(self):
        score, level, factors = calculate_risk_safe("INVALID_SEVERITY", "EXTERNAL", "HIGH", 1.0)
        assert 0 <= score <= 100
        assert factors.degraded is True
        assert factors.ai_available is False

    def test_nan_confidence_safe_default(self):
        score, level, factors = calculate_risk_safe("HIGH", "EXTERNAL", "HIGH", float("nan"))
        assert 0 <= score <= 100
        assert factors.degraded is True

    def test_string_confidence_safe_default(self):
        score, level, factors = calculate_risk_safe("HIGH", "EXTERNAL", "HIGH", "bad")
        assert 0 <= score <= 100
        assert factors.degraded is True

    def test_valid_input_passes_through(self):
        score, level, factors = calculate_risk_safe("HIGH", "EXTERNAL", "HIGH", 0.9)
        assert score == 83  # 60+15+10-2=83
        assert factors.degraded is False

    def test_always_returns_tuple_of_three(self):
        result = calculate_risk_safe("LOW")
        assert len(result) == 3
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)
        assert hasattr(result[2], "model_dump")


# ═══════════════════════════════════════════════════════════════════
# Purity Verification (No LLM, No Network, No DB)
# ═══════════════════════════════════════════════════════════════════

class TestPurity:
    def test_no_external_imports_in_core(self):
        """The core calculate_risk function should not import network/DB/LLM modules."""
        import inspect
        source = inspect.getsource(calculate_risk)
        forbidden = ["httpx", "requests", "openai", "anthropic", "asyncpg", "psycopg", "redis"]
        for module in forbidden:
            assert module not in source, f"Risk engine core references forbidden module: {module}"

    def test_calculate_risk_has_no_side_effects(self):
        """Calling calculate_risk should not modify any external state."""
        import os
        before = os.listdir("/tmp") if os.path.exists("/tmp") else []
        for _ in range(10):
            calculate_risk("HIGH", "EXTERNAL", "HIGH", 0.8)
        after = os.listdir("/tmp") if os.path.exists("/tmp") else []
        # No new files should be created
        assert len(after) <= len(before) + 1  # Allow for pytest temp dirs
