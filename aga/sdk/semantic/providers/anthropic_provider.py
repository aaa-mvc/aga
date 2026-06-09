"""Anthropic provider (Claude API)."""

from __future__ import annotations

import logging
import os

from .base import LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class AnthropicProvider(LLMProvider):
    """Provider for Anthropic Claude API."""

    name = "anthropic"
    default_model = "claude-sonnet-4-6"

    def __init__(
        self,
        default_model: str = "claude-sonnet-4-6",
        api_key: str | None = None,
    ) -> None:
        self.default_model = default_model
        self._api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")

    def query(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> LLMResponse:
        """Send a query to Anthropic Claude API."""
        try:
            from anthropic import Anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install aga-sec[deep]"
            ) from None

        client = Anthropic(api_key=self._api_key)
        model_name = model or self.default_model

        response = client.messages.create(
            model=model_name,
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
        )

        usage = response.usage
        tokens = usage.input_tokens + usage.output_tokens if usage else 0

        # Claude Sonnet pricing (USD per 1M tokens)
        cost = (usage.input_tokens * 3.0 + usage.output_tokens * 15.0) / 1_000_000 if usage else 0.0

        logger.info(
            f"[anthropic] {model_name}: {tokens} tokens, ${cost:.6f}"
        )

        return LLMResponse(
            text=response.content[0].text if response.content else "",
            model=model_name,
            tokens_used=tokens,
            cost_usd=cost,
        )
