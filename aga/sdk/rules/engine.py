"""Rule Engine — load, match, and score YAML rules against a SkillIR.

Rules are loaded from multiple sources with a priority chain:
  1. Built-in rules (aga/sdk/rules/builtin/)
  2. Project-level rules (.aga/rules/)
  3. User-level rules (~/.aga/rules/)
  4. CLI-specified paths

Each rule is an independent YAML file. Directories encode behavior IDs.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aga.sdk.parser import SkillIR

logger = logging.getLogger(__name__)


# ── Rule Data Model ────────────────────────────────────────────

@dataclass
class RuleHit:
    """A single rule match against a skill."""

    rule_id: str
    rule_name: str
    severity: str  # critical | high | medium | low
    category: str  # code_injection | prompt_injection | mixed
    behavior_id: str  # B1-B15
    confidence: float  # 0.0 - 1.0
    description: str = ""
    matched_location: str = ""  # e.g., "scripts/main.py:15" or "SKILL.md:paragraph 3"


@dataclass
class Rule:
    """A detection rule loaded from a YAML file."""

    id: str
    name: str
    severity: str
    category: str
    behavior_id: str
    description: str
    match: dict[str, Any] = field(default_factory=dict)
    false_positives: list[dict[str, str]] = field(default_factory=list)
    file_path: Path | None = None


# ── Rule Set ───────────────────────────────────────────────────

class RuleSet:
    """Collection of loaded rules with indexing by behavior and severity."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._by_behavior: dict[str, list[Rule]] = {}
        self._by_severity: dict[str, list[Rule]] = {}

    def add(self, rule: Rule) -> None:
        self._rules.append(rule)
        self._by_behavior.setdefault(rule.behavior_id, []).append(rule)
        self._by_severity.setdefault(rule.severity, []).append(rule)

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules)

    def by_behavior(self, behavior_id: str) -> list[Rule]:
        return self._by_behavior.get(behavior_id, [])

    def by_severity(self, severity: str) -> list[Rule]:
        return self._by_severity.get(severity, [])

    def all(self) -> list[Rule]:
        return list(self._rules)


# ── Rule Loader ────────────────────────────────────────────────

class RuleLoader:
    """Load rules from YAML files with directory-name-based behavior inference."""

    @staticmethod
    def load_from(path: Path) -> list[Rule]:
        """Load all rule YAML files from a directory (recursive)."""
        if not path.is_dir():
            logger.warning(f"Rule path not found: {path}")
            return []

        rules: list[Rule] = []
        for yaml_file in sorted(path.rglob("*.yaml")):
            # Skip files starting with _ (e.g., _categories.yaml)
            if yaml_file.name.startswith("_"):
                continue
            try:
                rule = RuleLoader._parse_rule_file(yaml_file)
                if rule:
                    rules.append(rule)
                    logger.debug(f"Loaded rule: {rule.id} ({rule.name})")
            except Exception as exc:
                logger.warning(f"Failed to load rule {yaml_file}: {exc}")

        logger.info(f"Loaded {len(rules)} rules from {path}")
        return rules

    @staticmethod
    def _parse_rule_file(path: Path) -> Rule | None:
        """Parse a single rule YAML file."""
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None

        # Behavior ID from parent directory name
        behavior_id = RuleLoader._infer_behavior_id(path)

        return Rule(
            id=data.get("id", path.stem),
            name=data.get("name", path.stem),
            severity=data.get("severity", "medium"),
            category=data.get("category", "code_injection"),
            behavior_id=behavior_id,
            description=data.get("description", ""),
            match=data.get("match", {}),
            false_positives=data.get("false_positives", []),
            file_path=path,
        )

    @staticmethod
    def _infer_behavior_id(path: Path) -> str:
        """Extract behavior ID from directory name, e.g. B2_credential_theft → B2."""
        parent = path.parent.name
        match = re.match(r"^(B\d{1,2})_", parent)
        if match:
            return match.group(1)
        return "B0"  # Unknown


# ── Rule Engine ────────────────────────────────────────────────

class RuleEngine:
    """Match loaded rules against a SkillIR and produce RuleHit list."""

    def __init__(self, rule_set: RuleSet | None = None) -> None:
        self.rule_set = rule_set or RuleSet()

    def analyze(self, ir: SkillIR) -> list[RuleHit]:
        """Run all loaded rules against a skill IR. Returns hits sorted by severity."""
        hits: list[RuleHit] = []

        for rule in self.rule_set:
            hit = self._match_rule(rule, ir)
            if hit:
                hits.append(hit)

        # Sort: critical first, then by confidence
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        hits.sort(key=lambda h: (severity_order.get(h.severity, 9), -h.confidence))

        return hits

    def _match_rule(self, rule: Rule, ir: SkillIR) -> RuleHit | None:
        """Attempt to match a single rule against the IR. Returns a RuleHit or None."""
        confidence = 0.0
        matched_location = ""

        # ── Check instruction text ──
        for pattern in rule.match.get("instructions", []):
            if re.search(pattern, ir.instructions_raw, re.IGNORECASE):
                confidence += 0.75
                matched_location = "SKILL.md"

        # ── Check code artifacts ──
        for artifact in ir.code_artifacts:
            for pattern in rule.match.get("code_patterns", []):
                if re.search(pattern, artifact.content, re.IGNORECASE):
                    confidence += 0.8
                    matched_location = f"{artifact.path}"

            for pattern in rule.match.get("file_paths", []):
                if re.search(pattern, str(artifact.path), re.IGNORECASE):
                    confidence += 0.4
                    if not matched_location:
                        matched_location = str(artifact.path)

        # ── Check dependencies ──
        for pattern in rule.match.get("dependencies", []):
            for _ecosystem, pkgs in ir.dependencies.items():
                for pkg in pkgs:
                    if re.search(pattern, pkg, re.IGNORECASE):
                        confidence += 0.3
                        if not matched_location:
                            matched_location = f"dependency: {pkg}"

        # ── Check false positives ──
        if confidence > 0 and rule.false_positives:
            for fp in rule.false_positives:
                fp_text = ir.meta.declared_intent + " " + ir.instructions_raw
                if fp.get("pattern") and re.search(fp["pattern"], fp_text, re.IGNORECASE):
                    confidence *= 0.3  # Reduce confidence significantly

        # ── Threshold ──
        confidence = min(confidence, 1.0)
        if confidence < 0.3:
            return None

        return RuleHit(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            behavior_id=rule.behavior_id,
            confidence=round(confidence, 2),
            description=rule.description,
            matched_location=matched_location,
        )
