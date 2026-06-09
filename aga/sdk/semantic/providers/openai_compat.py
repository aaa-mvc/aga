"""OpenAI-compatible provider (DeepSeek, Ollama, Groq, custom endpoints)."""

from __future__ import annotations

import logging
import os

from .base import LLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class OpenAICompatProvider(LLMProvider):
    """Provider for any OpenAI-compatible API (DeepSeek, Ollama, Groq, etc.).

    Usage:
        # DeepSeek
        provider = OpenAICompatProvider(
            name="deepseek",
            default_model="deepseek-chat",
            base_url="https://api.deepseek.com/v1",
            api_key_env="DEEPSEEK_API_KEY",
        )

        # Ollama (local)
        provider = OpenAICompatProvider(
            name="ollama",
            default_model="qwen2.5:7b",
            base_url="http://localhost:11434/v1",
            api_key_env=None,  # Ollama doesn't require auth
        )
    """

    def __init__(
        self,
        name: str = "deepseek",
        default_model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com/v1",
        api_key_env: str | None = "DEEPSEEK_API_KEY",
        api_key: str | None = None,
    ) -> None:
        self.name = name
        self.default_model = default_model
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key or (os.getenv(api_key_env) if api_key_env else "ollama")

    def query(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> LLMResponse:
        """Send a query to the OpenAI-compatible API."""
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai package required. Install with: pip install aga-sec[deep]"
            ) from None

        client = OpenAI(api_key=self._api_key, base_url=self.base_url)
        model_name = model or self.default_model

        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
        )

        usage = response.usage
        tokens = usage.total_tokens if usage else 0

        # DeepSeek pricing (USD per 1M tokens, as of 2026-06)
        # deepseek-chat: $0.14 input / $0.28 output
        input_tokens = usage.prompt_tokens if usage else 0
        output_tokens = usage.completion_tokens if usage else 0
        cost = (input_tokens * 0.14 + output_tokens * 0.28) / 1_000_000

        logger.info(
            f"[{self.name}] {model_name}: {tokens} tokens, ${cost:.6f}, "
            f"input={input_tokens}, output={output_tokens}"
        )

        return LLMResponse(
            text=response.choices[0].message.content or "",
            model=model_name,
            tokens_used=tokens,
            cost_usd=cost,
        )


# ── Factory ─────────────────────────────────────────────────────

def create_provider(name: str = "deepseek", **kwargs) -> LLMProvider:
    """Create an LLM provider by name.

    Supported: deepseek, openai, anthropic, ollama

    Args:
        name: Provider name.
        **kwargs: Passed to the provider constructor.
    """
    if name == "deepseek":
        return OpenAICompatProvider(
            name="deepseek",
            default_model=kwargs.get("model") or "deepseek-chat",
            base_url="https://api.deepseek.com/v1",
            api_key_env="DEEPSEEK_API_KEY",
            api_key=kwargs.get("api_key"),
        )
    elif name == "openai":
        return OpenAICompatProvider(
            name="openai",
            default_model=kwargs.get("model") or "gpt-4o-mini",
            base_url="https://api.openai.com/v1",
            api_key_env="OPENAI_API_KEY",
            api_key=kwargs.get("api_key"),
        )
    elif name == "ollama":
        return OpenAICompatProvider(
            name="ollama",
            default_model=kwargs.get("model") or "qwen2.5:7b",
            base_url=kwargs.get("base_url", "http://localhost:11434/v1"),
            api_key_env=None,
        )
    elif name == "anthropic":
        # Deferred import to avoid hard dependency
        try:
            from .anthropic_provider import AnthropicProvider
        except ImportError:
            raise ImportError(
                "anthropic package required. Install with: pip install aga-sec[deep]"
            ) from None
        return AnthropicProvider(
            default_model=kwargs.get("model") or "claude-sonnet-4-6",
            api_key=kwargs.get("api_key"),
        )
    else:
        raise ValueError(f"Unknown provider: {name}. Supported: deepseek, openai, anthropic, ollama")
