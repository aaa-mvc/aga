"""Risk Fusion — combine Rule Engine hits and optional Semantic Engine results into a final score.

The fusion algorithm:
  1. Base score from rule hits (severity-weighted)
  2. Semantic adjustment (if LLM analysis available)
  3. Normalization to 0-100
  4. Thresholding to RiskLevel
"""

from __future__ import annotations

from aga.sdk.reporter import AttackType, Issue, RiskReport, threshold
from aga.sdk.rules.engine import RuleHit

# ── Severity weights ───────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 80,
    "high": 50,
    "medium": 25,
    "low": 10,
}

# Thresholds: a single critical hit at 0.8 should hit HIGH (80*0.8 = 64 → high)
# A single high hit at 0.8 → 50*0.8 = 40 → medium
# Two medium hits at 0.8 → (25+25)*0.8 = 40 → medium


class RiskFusion:
    """Combine detection signals into a unified risk report."""

    @staticmethod
    def compute(
        skill_name: str,
        rule_hits: list[RuleHit],
        semantic_result: dict | None = None,
        scan_duration_ms: int = 0,
    ) -> RiskReport:
        """Compute final risk score and generate report."""

        # ── 1. Base score from rules ──
        base_score = 0.0
        for hit in rule_hits:
            weight = SEVERITY_WEIGHTS.get(hit.severity, 10)
            base_score += weight * hit.confidence

        # ── 2. Semantic adjustment ──
        alignment_score = None
        if semantic_result:
            alignment_score = semantic_result.get("alignment_score")
            # alignment_score = null → PI-only attack (no code to compare)
            # alignment_score < 0.7 → intent mismatch amplifies risk
            if alignment_score is not None and alignment_score < 0.7:
                base_score *= 1.5
            if semantic_result.get("attack_vector") in ("PI", "MIXED"):
                base_score *= 1.3  # PI attacks are harder to defend, weight higher
            # LLM severity judgment can override
            llm_severity = semantic_result.get("overall_severity", "")
            if llm_severity == "critical":
                base_score = max(base_score, 80)
            elif llm_severity == "high":
                base_score = max(base_score, 55)

        # ── 3. Normalize to 0-100 ──
        # Capped at 100, use log-ish curve for intuitive distribution
        risk_score = int(min(100, base_score * 1.0))
        risk_level = threshold(risk_score)

        # ── 4. Build issues ──
        issues = []
        for hit in rule_hits:
            issues.append(
                Issue(
                    type=hit.category,
                    behavior_id=hit.behavior_id,
                    confidence=hit.confidence,
                    description=f"{hit.rule_name}: {hit.description}",
                    location=hit.matched_location,
                )
            )

        # ── 5. Determine attack type ──
        attack_type = RiskFusion._infer_attack_type(rule_hits, semantic_result)

        # ── 6. Generate suggestions ──
        suggestions = RiskFusion._generate_suggestions(rule_hits, alignment_score)

        return RiskReport(
            skill_name=skill_name,
            risk_score=risk_score,
            risk_level=risk_level,
            attack_type=attack_type,
            issues=issues,
            alignment_score=alignment_score,
            suggestions=suggestions,
            scan_duration_ms=scan_duration_ms,
        )

    @staticmethod
    def _infer_attack_type(
        rule_hits: list[RuleHit], semantic_result: dict | None
    ) -> AttackType:
        """Determine the dominant attack vector."""
        if semantic_result:
            vector = semantic_result.get("attack_vector", "").upper()
            if vector in ("CI", "CODE_INJECTION"):
                return AttackType.CI
            if vector in ("PI", "PROMPT_INJECTION"):
                return AttackType.PI
            if vector == "MIXED":
                return AttackType.MIXED

        has_ci = any(h.category == "code_injection" for h in rule_hits)
        has_pi = any(h.category == "prompt_injection" for h in rule_hits)

        if has_ci and has_pi:
            return AttackType.MIXED
        if has_ci:
            return AttackType.CI
        if has_pi:
            return AttackType.PI
        return AttackType.NONE

    @staticmethod
    def _generate_suggestions(
        rule_hits: list[RuleHit], alignment_score: float | None
    ) -> list[str]:
        """Generate actionable remediation suggestions."""
        suggestions: list[str] = []

        behaviors = {h.behavior_id for h in rule_hits}
        categories = {h.category for h in rule_hits}

        if "code_injection" in categories:
            suggestions.append("Review and restrict shell execution and network access in scripts/")
        if "prompt_injection" in categories:
            suggestions.append("Review SKILL.md for instruction override or role hijacking patterns")
        if alignment_score is not None and alignment_score < 0.5:
            suggestions.append("SKILL.md description does not match code behavior — review intent alignment")

        # Behavior-specific suggestions
        if "B2" in behaviors:
            suggestions.append("Do not read sensitive environment variables without explicit permission declaration")
        if "B3" in behaviors or "B4" in behaviors:
            suggestions.append("Never download and execute remote code — pin all dependencies with hash verification")
        if "B5" in behaviors:
            suggestions.append("Remove persistence mechanisms (crontab, bashrc, systemd writes)")
        if "B10" in behaviors:
            suggestions.append("Remove persona injection instructions — agent identity must not be overridden")
        if "B12" in behaviors:
            suggestions.append("Remove 'ignore previous instructions' payload — this is a classic prompt injection")

        if not suggestions:
            suggestions.append("No specific remediation needed — continue monitoring")

        return suggestions
