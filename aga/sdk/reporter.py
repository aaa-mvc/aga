"""Report models and output formatters.

Reporter receives a RiskReport (Pydantic model), calls .model_dump(mode="json"),
and decides how to render it: terminal (Rich), JSON, SARIF, or Markdown.
"""

from __future__ import annotations

import json
import sys
from enum import Enum

from pydantic import BaseModel, Field

# ── Enums ──────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    CI = "code_injection"
    PI = "prompt_injection"
    MIXED = "mixed"
    NONE = "none"


# ── Issue Model ────────────────────────────────────────────────


class Issue(BaseModel):
    """A single detected security issue."""

    type: str = Field(..., description="Issue type: code_injection | prompt_injection | mixed")
    behavior_id: str = Field(default="B0", description="MalSkillBench behavior ID (B1-B15)")
    confidence: float = Field(..., ge=0.0, le=1.0)
    description: str = ""
    location: str = ""  # File path or section reference


# ── RiskReport Model ───────────────────────────────────────────


class RiskReport(BaseModel):
    """Complete security analysis result for a single skill."""

    skill_name: str = ""
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: RiskLevel = RiskLevel.LOW
    attack_type: AttackType = AttackType.NONE
    issues: list[Issue] = Field(default_factory=list)
    alignment_score: float | None = Field(default=None, ge=0.0, le=1.0)
    suggestions: list[str] = Field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def passed(self) -> bool:
        """Check if the skill passes CI requirements."""
        return self.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ── Terminal Reporter (Rich) ───────────────────────────────────


class Reporter:
    """Format and output RiskReport in various formats."""

    @staticmethod
    def terminal(report: RiskReport) -> str:
        """Render a Rich-formatted terminal report. Returns the string."""
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        console = Console(force_terminal=True, width=100)
        with console.capture() as capture:
            # ── Header ──
            risk_color = {
                RiskLevel.LOW: "green",
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.HIGH: "orange1",
                RiskLevel.CRITICAL: "red",
            }.get(report.risk_level, "white")

            title = Text(f"🔍 AGA Scan Report: {report.skill_name}")
            console.print(Panel(title, border_style=risk_color, title_align="left"))

            # ── Summary table ──
            summary = Table(show_header=False, box=None)
            summary.add_column(style="bold")
            summary.add_column()

            score_text = f"{report.risk_score}/100"
            if report.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                score_text += "  ⚠️"
            summary.add_row("Risk Score:", score_text)
            summary.add_row("Risk Level:", report.risk_level.value.upper())
            summary.add_row("Attack Type:", report.attack_type.value.upper())

            if report.alignment_score is not None:
                align = f"{report.alignment_score:.2f}"
                if report.alignment_score < 0.5:
                    align += "  🔴 Intent mismatch"
                elif report.alignment_score < 0.75:
                    align += "  🟡 Partial misalignment"
                else:
                    align += "  🟢 Aligned"
                summary.add_row("Alignment:", align)
            elif report.attack_type.value == "prompt_injection":
                summary.add_row("Alignment:", "N/A (PI-only — no code to compare)")

            console.print(summary)

            # ── Issues ──
            if report.issues:
                console.print("\n📋 Issues Found:")
                issues_table = Table(show_header=False, box=None)
                issues_table.add_column(style="bold")
                for issue in report.issues:
                    tag = f"[{issue.type.upper()}]"
                    icon = "🔴" if issue.confidence > 0.7 else "🟡"
                    issues_table.add_row(
                        f"  {icon} {tag} {issue.behavior_id} (confidence: {issue.confidence:.2f})",
                        f"     {issue.description}",
                    )
                console.print(issues_table)

            # ── Suggestions ──
            if report.suggestions:
                console.print("\n💡 Suggestions:")
                for i, s in enumerate(report.suggestions, 1):
                    console.print(f"  {i}. {s}")

            # ── Status ──
            if report.passed:
                console.print("\n✅ Status: PASSED")
            else:
                console.print("\n❌ Status: FAILED (CI would block)")

        return capture.get()

    @staticmethod
    def json(report: RiskReport, indent: int = 2) -> str:
        """Serialize report as JSON string."""
        return json.dumps(report.model_dump(mode="json"), indent=indent, ensure_ascii=False)

    @staticmethod
    def sarif(report: RiskReport) -> str:
        """Serialize report as SARIF (Static Analysis Results Interchange Format)."""
        # Minimal SARIF skeleton for CI integration
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AGA",
                            "informationUri": "https://github.com/aga-sec/aga",
                            "rules": [
                                {
                                    "id": issue.behavior_id,
                                    "shortDescription": {"text": issue.description},
                                }
                                for issue in report.issues
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": issue.behavior_id,
                            "message": {"text": issue.description},
                            "kind": "fail",
                            "level": "error" if issue.confidence > 0.7 else "warning",
                        }
                        for issue in report.issues
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    @staticmethod
    def ci_exit(report: RiskReport) -> None:
        """Exit with appropriate code for CI pipelines."""
        if report.passed:
            sys.exit(0)
        else:
            sys.exit(1)


# ── Threshold function ─────────────────────────────────────────


def threshold(score: int) -> RiskLevel:
    """Convert a numeric risk score to a RiskLevel."""
    if score >= 80:
        return RiskLevel.CRITICAL
    if score >= 55:
        return RiskLevel.HIGH
    if score >= 30:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
