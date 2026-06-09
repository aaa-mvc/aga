"""Abstract base for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class LLMResponse:
    """Standardized LLM response across providers."""

    text: str
    model: str
    tokens_used: int = 0
    cost_usd: float = 0.0


class LLMProvider(ABC):
    """Interface for LLM backends."""

    name: str
    default_model: str

    @abstractmethod
    def query(
        self, system_prompt: str, user_prompt: str, *, temperature: float = 0.0
    ) -> LLMResponse:
        """Send a system + user message and return the response."""
        ...
