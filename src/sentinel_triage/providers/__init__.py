"""LLM provider adapters.

The triage pipeline works fully offline with MockProvider. Real providers
(Anthropic Claude, any OpenAI-compatible endpoint) are optional and are
only contacted when explicitly selected. Providers receive redacted
finding metadata, never raw file contents and never unmasked secrets.
"""

from .anthropic import AnthropicProvider
from .base import Provider, ProviderError
from .mock import MockProvider
from .openai_compat import OpenAICompatProvider

PROVIDERS = {
    "mock": MockProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAICompatProvider,
}


def get_provider(name: str, model: str = None) -> Provider:
    if name not in PROVIDERS:
        raise ProviderError(f"unknown provider '{name}'; choose from: {', '.join(PROVIDERS)}")
    return PROVIDERS[name](model=model)


__all__ = ["Provider", "ProviderError", "get_provider", "PROVIDERS"]
