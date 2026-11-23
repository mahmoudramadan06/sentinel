"""Provider abstraction."""

from __future__ import annotations


class ProviderError(Exception):
    """Configuration or transport failure for a provider."""


class Provider:
    """Minimal chat-completion interface.

    Implementations must set `name` and `is_mock`. `is_mock` is surfaced
    in every report so nobody can mistake a deterministic offline run for
    a real model call.
    """

    name = "base"
    is_mock = False

    def __init__(self, model: str = None):
        self.model = model

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError
