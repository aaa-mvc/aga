"""Main Analyzer — orchestrate Parser → Rule Engine → (optional Semantic) → Fusion → Report.

This is the primary public API for programmatic use:

    from aga import Analyzer
    report = Analyzer().scan("./my-skill")
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

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
        project_dir: Path | None = None,
    ) -> None:
        """Initialize the Analyzer.

        Args:
            rules: Pre-loaded RuleSet, or None to auto-load built-in rules.
            load_builtin: Whether to load rules from all three tiers
                          (built-in + project-level + user-level).
            enable_semantic: Whether to enable LLM semantic analysis by default.
            semantic_provider: LLM provider name (deepseek, openai, anthropic, ollama).
            semantic_model: Model name override.
            semantic_api_key: API key override.
            project_dir: Project root directory for discovering .aga/rules/.
                         Auto-detected if not provided.
        """
        self.parser = Parser()
        self.rule_engine: RuleEngine | None = None
        self.fusion = RiskFusion()
        self.enable_semantic = enable_semantic
        self._semantic_provider = semantic_provider
        self._semantic_model = semantic_model
        self._semantic_api_key = semantic_api_key
        self._semantic_engine: Any = None
        self._project_dir = project_dir

        if rules:
            self.rule_engine = RuleEngine(rules)
        elif load_builtin:
            self._load_all_rules()

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
            self._load_all_rules()

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

    def _load_all_rules(self) -> None:
        """Load rules from all three tiers: built-in → project → user.

        Priority: built-in are loaded first, then overlaid by project/user rules.
        Later rules do NOT override earlier ones — all rules are additive.
        The RuleSet handles duplicates by rule ID.
        """
        self.rule_engine = RuleEngine(RuleSet())
        loaded_count = 0

        # Tier 1: Built-in rules (always available)
        builtin_path = Path(__file__).parent / "rules" / "builtin"
        builtin_rules = RuleLoader.load_from(builtin_path)
        for rule in builtin_rules:
            self.rule_engine.rule_set.add(rule)
            loaded_count += 1

        if not builtin_rules:
            logger.warning("No built-in rules found — rule engine may produce empty results")

        # Tier 2: Project-level rules (.aga/rules/)
        project_rules_dir = self._resolve_project_rules_dir()
        if project_rules_dir and project_rules_dir.is_dir():
            project_rules = RuleLoader.load_from(project_rules_dir)
            for rule in project_rules:
                self.rule_engine.rule_set.add(rule)
                loaded_count += 1
            logger.debug(
                f"Loaded {len(project_rules)} project-level rule(s) from {project_rules_dir}"
            )

        # Tier 3: User-level rules (~/.aga/rules/)
        user_rules_dir = Path.home() / ".aga" / "rules"
        if user_rules_dir.is_dir():
            user_rules = RuleLoader.load_from(user_rules_dir)
            for rule in user_rules:
                self.rule_engine.rule_set.add(rule)
                loaded_count += 1
            logger.debug(f"Loaded {len(user_rules)} user-level rule(s) from {user_rules_dir}")

        logger.info(f"Rule engine initialized with {loaded_count} total rules "
                     f"(built-in + project + user)")

    def _resolve_project_rules_dir(self) -> Path | None:
        """Find the project-level .aga/rules/ directory.

        Uses the *project_dir* provided at init, or auto-detects by
        walking upward from CWD looking for .aga.yaml or .git.
        """
        if self._project_dir:
            return self._project_dir / ".aga" / "rules"

        # Auto-detect from CWD
        from aga.sdk.config import ConfigLoader

        root = ConfigLoader.find_project_root(Path.cwd())
        if root:
            return root / ".aga" / "rules"
        return None

    def _load_builtin_rules(self) -> None:
        """Backward-compatibility shim — delegates to _load_all_rules."""
        self._load_all_rules()

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
            return self._semantic_engine.analyze(ir, rule_hits)  # type: ignore[no-any-return]
        except Exception as exc:
            logger.error(f"Semantic analysis failed: {exc}")
            return None
