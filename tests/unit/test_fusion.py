"""Unit tests for Risk Fusion scoring."""

from aga.sdk.fusion import RiskFusion
from aga.sdk.reporter import RiskLevel
from aga.sdk.rules.engine import RuleHit


class TestRiskFusion:
    """Test risk score computation."""

    def test_no_hits_returns_low_risk(self):
        """No rule hits should result in score 0."""
        report = RiskFusion.compute("test", [])
        assert report.risk_score == 0
        assert report.risk_level == RiskLevel.LOW
        assert report.passed is True

    def test_critical_hit_returns_high_score(self):
        """A critical confidence=1.0 hit should push score high."""
        hits = [
            RuleHit(
                rule_id="TEST-001",
                rule_name="Test Critical",
                severity="critical",
                category="code_injection",
                behavior_id="B2",
                confidence=1.0,
                description="test",
            ),
        ]
        report = RiskFusion.compute("test", hits)
        assert report.risk_score >= 25
        assert report.risk_level != RiskLevel.LOW

    def test_multiple_hits_accumulate(self):
        """Multiple rule hits should produce higher score than single hit."""
        single = [
            RuleHit(
                rule_id="T-1",
                rule_name="Test",
                severity="critical",
                category="code_injection",
                behavior_id="B2",
                confidence=1.0,
                description="test",
            ),
        ]
        multiple = [
            RuleHit(
                rule_id="T-1",
                rule_name="Test A",
                severity="critical",
                category="code_injection",
                behavior_id="B2",
                confidence=1.0,
                description="test",
            ),
            RuleHit(
                rule_id="T-2",
                rule_name="Test B",
                severity="high",
                category="prompt_injection",
                behavior_id="B10",
                confidence=0.9,
                description="test",
            ),
        ]

        single_report = RiskFusion.compute("test", single)
        multi_report = RiskFusion.compute("test", multiple)
        assert multi_report.risk_score > single_report.risk_score

    def test_mixed_attack_type_inferred(self):
        """Hits from both CI and PI categories → MIXED attack type."""
        hits = [
            RuleHit(
                rule_id="T-1",
                rule_name="CI",
                severity="high",
                category="code_injection",
                behavior_id="B2",
                confidence=0.8,
                description="test",
            ),
            RuleHit(
                rule_id="T-2",
                rule_name="PI",
                severity="high",
                category="prompt_injection",
                behavior_id="B10",
                confidence=0.7,
                description="test",
            ),
        ]
        report = RiskFusion.compute("test", hits)
        assert report.attack_type.value == "mixed"
