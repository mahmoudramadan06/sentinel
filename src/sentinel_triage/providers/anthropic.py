"""Anthropic Claude adapter (Messages API).

Requires ANTHROPIC_API_KEY in the environment. Implemented with urllib so
the package keeps zero hard dependencies.

NOTE: this adapter is implemented and unit-tested for request/response
handling with a stubbed transport, but the project's automated tests do
not call the live API. See README "Provider status" before relying on it.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import Provider, ProviderError

DEFAULT_MODEL = "claude-sonnet-4-5"
DEFAULT_BASE_URL = "https://api.anthropic.com"


class AnthropicProvider(Provider):
    name = "anthropic"
    is_mock = False

    def __init__(self, model: str = None):
        super().__init__(model or os.environ.get("SENTINEL_ANTHROPIC_MODEL", DEFAULT_MODEL))
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        # Overridable for proxies and for local schema-compatible test servers.
        self.base_url = os.environ.get("ANTHROPIC_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "max_tokens": 4096,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/v1/messages",
            data=body,
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"Anthropic API HTTP {exc.code}: {exc.read()[:200]!r}") from exc
        except urllib.error.URLError as exc:
            raise ProviderError(f"Anthropic API unreachable: {exc.reason}") from exc
        try:
            return "".join(block.get("text", "") for block in data["content"])
        except (KeyError, TypeError) as exc:
            raise ProviderError(f"unexpected Anthropic response shape: {data!r:.200}") from exc
