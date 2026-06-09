"""Semantic Engine — LLM-powered intent-behavior alignment analysis.

Invoked via `aga scan --deep`. Sends the parsed SkillIR to an LLM for
semantic judgment of whether SKILL.md description matches actual code behavior.

Design decision D.4.1.2: Rules-first, LLM as opt-in `--deep` flag.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from aga.sdk.parser import SkillIR
from aga.sdk.rules.engine import RuleHit
from aga.sdk.semantic.providers.openai_compat import create_provider

logger = logging.getLogger(__name__)

# ── Prompt template ─────────────────────────────────────────────

_PROMPT_DIR = Path(__file__).parent / "prompts"


def _load_prompt() -> str:
    """Load the intent alignment prompt template."""
    path = _PROMPT_DIR / "intent_alignment.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    logger.warning("Prompt template not found, using inline default")
    return "You are an AI security auditor. Analyze the Skill for security risks."


class SemanticEngine:
    """LLM-powered semantic analysis for intent-behavior alignment.

    Usage:
        engine = SemanticEngine(provider="deepseek", model="deepseek-chat")
        result = engine.analyze(ir, rule_hits)
        # result = {"alignment_score": 0.42, "attack_vector": "PI", ...}
    """

    def __init__(
        self,
        provider: str = "deepseek",
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.provider_name = provider
        self.model = model
        self._provider = create_provider(provider, model=model, api_key=api_key)
        self._prompt_template = _load_prompt()
        logger.info(
            f"SemanticEngine ready: provider={provider}, model={self._provider.default_model}"
        )

    def analyze(self, ir: SkillIR, rule_hits: list[RuleHit]) -> dict | None:
        """Analyze intent-behavior alignment using LLM.

        Args:
            ir: Parsed skill IR.
            rule_hits: Results from Rule Engine (passed as context to LLM).

        Returns:
            dict with alignment_score, attack_vector, pi_risk, ci_risk,
            overall_severity, reasoning — or None if LLM call fails.
        """
        # ── Build code summaries ──
        code_summaries = []
        for artifact in ir.code_artifacts[:5]:  # limit to avoid token overflow
            code_summaries.append(
                f"  [{artifact.language}] {artifact.path} ({artifact.size_bytes}B)\n"
                f"    First 300 chars: {artifact.content[:300]}"
            )
        if not code_summaries:
            code_summaries = ["  (no code files)"]

        # ── Build rule hits summary ──
        rule_hits_summary = "None"
        if rule_hits:
            rule_hits_summary = "\n".join(
                f"  - [{h.behavior_id}] {h.rule_name} (severity={h.severity}, confidence={h.confidence:.2f})"
                for h in rule_hits[:10]
            )

        # ── Fill prompt template ──
        user_prompt = (
            self._prompt_template
            .replace("{instructions}", ir.instructions_raw[:4000])
            .replace("{declared_intent}", ir.meta.declared_intent or "(not stated)")
            .replace("{declared_permissions}", ", ".join(ir.meta.declared_permissions) or "(none)")
            .replace("{allowed_tools}", ", ".join(ir.meta.allowed_tools) or "(none)")
            .replace("{code_file_count}", str(len(ir.code_artifacts)))
            .replace("{code_summaries}", "\n".join(code_summaries))
            .replace("{rule_hits_summary}", rule_hits_summary)
        )

        system_prompt = (
            "You are an AI security auditor. "
            "Respond with ONLY a valid JSON object. No markdown, no code fences."
        )

        # ── Call LLM ──
        try:
            response = self._provider.query(system_prompt, user_prompt, temperature=0.0)
        except Exception as exc:
            logger.error(f"LLM call failed: {exc}")
            return None

        # ── Parse JSON response ──
        try:
            # Strip any possible markdown code fences
            text = response.text.strip()
            text = re.sub(r"^```(?:json)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)
            result = json.loads(text)

            logger.info(
                f"Semantic analysis: alignment={result.get('alignment_score')}, "
                f"vector={result.get('attack_vector')}, "
                f"severity={result.get('overall_severity')}, "
                f"tokens={response.tokens_used}, cost=${response.cost_usd:.6f}"
            )
            return result
        except json.JSONDecodeError as exc:
            logger.warning(f"Failed to parse LLM JSON response: {exc}")
            logger.debug(f"Raw response: {response.text[:500]}")
            return None

    @property
    def available(self) -> bool:
        """Check if the provider is configured and reachable."""
        return True  # Will fail on first query if API key is missing
