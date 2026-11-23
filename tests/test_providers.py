"""Provider tests. No live API calls: transports are stubbed."""

import json

import pytest

from sentinel_triage.providers import ProviderError, get_provider
from sentinel_triage.providers.anthropic import AnthropicProvider
from sentinel_triage.providers.mock import MockProvider
from sentinel_triage.providers.openai_compat import OpenAICompatProvider


def test_mock_provider_is_deterministic_and_labeled():
    p = MockProvider()
    assert p.is_mock is True
    payload = json.dumps({"findings": [{
        "fingerprint": "abc123", "rule_id": "r", "severity": "high",
        "confidence": "high", "file": "a.py", "line": 1,
        "remediation": "fix it",
    }]})
    out1 = p.complete("sys", payload)
    out2 = p.complete("sys", payload)
    assert out1 == out2
    data = json.loads(out1)
    assert data["triage"][0]["fingerprint"] == "abc123"
    assert "[offline template]" in data["triage"][0]["priority_rationale"]


def test_anthropic_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        AnthropicProvider()


def test_openai_requires_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ProviderError):
        OpenAICompatProvider()


def test_anthropic_response_parsing(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    class FakeResp:
        def read(self):
            return json.dumps({"content": [{"type": "text", "text": "hello"}]}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: FakeResp())
    p = AnthropicProvider()
    assert p.complete("sys", "user") == "hello"
    assert p.is_mock is False


def test_openai_response_parsing(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    class FakeResp:
        def read(self):
            return json.dumps({"choices": [{"message": {"content": "hi"}}]}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=None: FakeResp())
    p = OpenAICompatProvider()
    assert p.complete("sys", "user") == "hi"


def test_unknown_provider_rejected():
    with pytest.raises(ProviderError):
        get_provider("not-a-provider")
