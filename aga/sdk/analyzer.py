"""Main Analyzer — orchestrate Parser → Rule Engine → (optional Semantic) → Fusion → Report.

This is the primary public API for programmatic use:

    from aga import Analyzer
    report = Analyzer().scan("./my-skill")
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from aga.sdk.fusion import RiskFusion
from aga.sdk.parser import Parser
from aga.sdk.reporter import RiskReport
from aga.sdk.rules.engine import RuleEngine, RuleLoader, RuleSet

logger = logging.getLogger(__name__)


class Analyzer:
    """Main entry point for security analysis of AI Agent Skills.

    Usage:
        analyzer = Analyzer()
        report = analyzer.scan("./my-skill")
        print(f"Risk: {report.risk_score}/100")

        # Batch mode
        reports = analyzer.batch_scan(["./skill-a", "./skill-b"])
    """

    def __init__(
        self,
        rules: RuleSet | None = None,
        load_builtin: bool = True,
        enable_semantic: bool = False,
        semantic_provider: str = "deepseek",
        semantic_model: str | None = None,
        semantic_api_key: str | None = None,
    ) -> None:
        """Initialize the Analyzer.

        Args:
            rules: Pre-loaded RuleSet, or None to auto-load built-in rules.
            load_builtin: Whether to load built-in rules from aga/sdk/rules/builtin/.
            enable_semantic: Whether to enable LLM semantic analysis by default.
            semantic_provider: LLM provider name (deepseek, openai, anthropic, ollama).
            semantic_model: Model name override.
            semantic_api_key: API key override.
        """
        self.parser = Parser()
        self.rule_engine: RuleEngine | None = None
        self.fusion = RiskFusion()
        self.enable_semantic = enable_semantic
        self._semantic_provider = semantic_provider
        self._semantic_model = semantic_model
        self._semantic_api_key = semantic_api_key
        self._semantic_engine = None

        if rules:
            self.rule_engine = RuleEngine(rules)
        elif load_builtin:
            self._load_builtin_rules()

    def scan(
        self,
        path: str | Path,
        deep: bool = False,
    ) -> RiskReport:
        """Scan a single skill directory and return a risk report.

        Args:
            path: Path to the skill directory (must contain SKILL.md).
            deep: If True, run LLM semantic analysis in addition to rule matching.

        Returns:
            RiskReport with risk_score, risk_level, issues, and suggestions.
        """
        start = time.monotonic()

        # 1. Parse
        ir = self.parser.parse(path)

        # 2. Rule Engine
        if not self.rule_engine:
            self._load_builtin_rules()

        rule_hits = self.rule_engine.analyze(ir)  # type: ignore[union-attr]

        # 3. Semantic (optional)
        semantic_result = None
        if deep or self.enable_semantic:
            semantic_result = self._run_semantic(ir, rule_hits)

        # 4. Fusion
        elapsed_ms = int((time.monotonic() - start) * 1000)
        report = self.fusion.compute(
            skill_name=ir.meta.name,
            rule_hits=rule_hits,
            semantic_result=semantic_result,
            scan_duration_ms=elapsed_ms,
        )

        logger.info(
            f"Scanned {ir.meta.name}: score={report.risk_score}, "
            f"level={report.risk_level.value}, issues={len(report.issues)}, "
            f"duration={elapsed_ms}ms"
        )
        return report

    def batch_scan(
        self,
        paths: list[str | Path],
        deep: bool = False,
    ) -> list[RiskReport]:
        """Scan multiple skill directories and return reports sorted by risk score (descending).

        Args:
            paths: List of paths to skill directories.
            deep: If True, run LLM semantic analysis on each skill.

        Returns:
            Sorted list of RiskReport (highest risk first).
        """
        reports = []
        for p in paths:
            try:
                report = self.scan(p, deep=deep)
                reports.append(report)
            except Exception as exc:
                logger.warning(f"Failed to scan {p}: {exc}")
                # Create an error report
                reports.append(
                    RiskReport(
                        skill_name=str(p),
                        risk_score=0,
                        suggestions=[f"Scan failed: {exc}"],
                    )
                )

        reports.sort(key=lambda r: r.risk_score, reverse=True)
        return reports

    # ── Private ─────────────────────────────────────────────────

    def _load_builtin_rules(self) -> None:
        """Load built-in rules from the package directory."""
        builtin_path = Path(__file__).parent / "rules" / "builtin"
        rules = RuleLoader.load_from(builtin_path)
        if not rules:
            logger.warning("No built-in rules found — rule engine will produce empty results")
        self.rule_engine = RuleEngine(RuleSet())
        for rule in rules:
            self.rule_engine.rule_set.add(rule)

    def _run_semantic(self, ir, rule_hits) -> dict | None:
        """Run LLM semantic analysis via configured provider."""
        if self._semantic_engine is None:
            from aga.sdk.semantic.engine import SemanticEngine

            try:
                self._semantic_engine = SemanticEngine(
                    provider=self._semantic_provider,
                    model=self._semantic_model,
                    api_key=self._semantic_api_key,
                )
            except Exception as exc:
                logger.error(f"Failed to initialize SemanticEngine: {exc}")
                return None

        try:
            return self._semantic_engine.analyze(ir, rule_hits)
        except Exception as exc:
            logger.error(f"Semantic analysis failed: {exc}")
            return None
