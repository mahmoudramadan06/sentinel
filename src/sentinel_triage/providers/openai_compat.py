"""OpenAI-compatible chat-completions adapter.

Works with OpenAI and any endpoint that speaks the /chat/completions
schema: OpenRouter, Ollama (http://localhost:11434/v1), LM Studio, and
provider relays. Configure with OPENAI_API_KEY and, for non-OpenAI
endpoints, OPENAI_BASE_URL.

NOTE: unit-tested with a stubbed transport only; automated tests do not
call a live endpoint. See README "Provider status".
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .base import Provider, ProviderError

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_BASE_URL = "https://api.openai.com/v1"


class OpenAICompatProvider(Provider):
    name = "openai"
    is_mock = False

    def __init__(self, model: str = None):
        super().__init__(model or os.environ.get("OPENAI_MODEL", DEFAULT_MODEL))
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.base_url = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
        if not self.api_key:
            raise ProviderError("OPENAI_API_KEY is not set")

    def complete(self, system: str, user: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "temperature": 0.2,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise ProviderError(f"endpoint HTTP {exc.code}: {exc.read()[:200]!r}") from exc
        except urllib.error.URLError as exc:
            raise ProviderError(f"endpoint unreachable: {exc.reason}") from exc
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"unexpected response shape: {data!r:.200}") from exc
