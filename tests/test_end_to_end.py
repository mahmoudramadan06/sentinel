"""End-to-end CLI tests: full pipeline on the fixture app."""

import json
import os

import pytest

from sentinel_triage.cli import main
from sentinel_triage.providers.base import Provider
from sentinel_triage.triager import collect_findings, triage_with_llm
from sentinel_triage.providers.mock import MockProvider

FIXTURES = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_app"))


def test_collect_findings_consolidates():
    result = collect_findings(FIXTURES)
    assert result.files_scanned >= 4
    assert len(result.findings) >= 10
    assert result.duplicates_removed >= 1  # AWS key: specific + generic on same line
    sevs = result.severity_counts()
    assert sevs["critical"] >= 2


def test_mock_triage_marks_reports_honestly():
    result = collect_findings(FIXTURES)
    result = triage_with_llm(result, MockProvider())
    assert result.llm_used is True
    assert result.llm_is_mock is True
    assert result.llm_provider == "mock"
    assert result.triage_notes, "expected triage notes for top findings"


class BrokenProvider(Provider):
    name = "broken"
    is_mock = False

    def complete(self, system, user):
        raise RuntimeError("boom")


class HallucinatingProvider(Provider):
    name = "hallucinating"
    is_mock = False

    def complete(self, system, user):
        return '{"triage": [{"fingerprint": "does-not-exist", "priority_rationale": "x", "fix_guidance": "y"}]}'


def test_broken_provider_falls_back_cleanly():
    from sentinel_triage.providers.base import ProviderError

    class Raising(Provider):
        name = "raising"

        def complete(self, system, user):
            raise ProviderError("simulated outage")

    result = triage_with_llm(collect_findings(FIXTURES), Raising())
    assert result.llm_used is False
    assert "_error" in result.triage_notes


def test_hallucinated_fingerprints_are_dropped():
    result = triage_with_llm(collect_findings(FIXTURES), HallucinatingProvider())
    assert result.llm_used is True
    assert result.triage_notes == {}


def test_cli_end_to_end(tmp_path, capsys):
    out_dir = tmp_path / "out"
    rc = main(["scan", FIXTURES, "--provider", "mock", "--format", "both", "--out", str(out_dir)])
    assert rc == 0

    md = (out_dir / "triage-report.md").read_text(encoding="utf-8")
    doc = json.loads((out_dir / "triage-report.json").read_text(encoding="utf-8"))

    # Report metadata is honest about the mock provider.
    assert doc["metadata"]["llm_is_mock"] is True
    assert doc["metadata"]["llm_used"] is True
    assert "offline mock" in md

    # No raw secret anywhere in either report.
    assert "AKIAIOSFODNN7EXAMPLE" not in md
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(doc)

    # Findings are ranked descending by risk score.
    scores = [f["risk_score"] for f in doc["findings"]]
    assert scores == sorted(scores, reverse=True)


def test_cli_no_llm_mode(tmp_path):
    out_dir = tmp_path / "out2"
    rc = main(["scan", FIXTURES, "--no-llm", "--out", str(out_dir)])
    assert rc == 0
    doc = json.loads((out_dir / "triage-report.json").read_text(encoding="utf-8"))
    assert doc["metadata"]["llm_used"] is False
    assert doc["metadata"]["llm_provider"] == "none"


def test_cli_rejects_missing_target(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "nope"), "--out", str(tmp_path / "o")])
    assert rc == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_missing_api_key_fails_loudly(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = main(["scan", FIXTURES, "--provider", "anthropic", "--out", str(tmp_path / "o")])
    assert rc == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err
