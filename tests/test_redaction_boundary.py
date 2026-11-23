"""Release-blocking redaction boundary tests.

Regression coverage for the audit finding that a code-pattern finding
could carry an unmasked secret (in its raw source-line snippet) into the
JSON report, the Markdown report, and the LLM provider payload, and that
same-line dedup could discard the masked secrets finding.

Every ingest path (secrets, patterns, deps, SARIF) and every output path
(JSON report, Markdown report, provider payload) is asserted clean.
"""

import json
import os

from sentinel_triage.models import Finding
from sentinel_triage.dedup import deduplicate
from sentinel_triage.providers.base import Provider
from sentinel_triage.report import to_json, to_markdown
from sentinel_triage.triager import collect_findings, triage_with_llm

# Fake but pattern-matching secrets planted in adversarial inputs.
AWS = "AKIAZZZZTOPSECRET000"
# Synthetic Slack webhook built at runtime: secret scanners (correctly) flag
# even fake webhook literals, so the fixture is assembled, not written out.
SLACK = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24
ALL_SECRETS = [AWS, SLACK]


def write_leaky_app(tmp_path):
    """One file whose single line trips BOTH a secret rule and a pattern rule."""
    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        f'subprocess.run("curl {SLACK} -d ping", shell=True)\n'
        f'KEY = "{AWS}"\n',
        encoding="utf-8",
    )
    return str(tmp_path)


class RecordingProvider(Provider):
    """Captures exactly what would be sent to a model."""

    name = "recorder"
    is_mock = False

    def __init__(self):
        self.payloads = []

    def complete(self, system, user):
        self.payloads.append({"system": system, "user": user})
        return '{"triage": []}'


def assert_clean(*texts):
    for text in texts:
        for secret in ALL_SECRETS:
            assert secret not in text


def test_same_line_secret_and_pattern_both_kept_and_both_masked(tmp_path):
    target = write_leaky_app(tmp_path)
    result = collect_findings(target)

    # Cross-family collision on one line must keep BOTH findings.
    sources_on_curl_line = {
        f.source for f in result.findings if f.file == "app.py" and f.line == 2
    }
    assert "secrets" in sources_on_curl_line, "secrets finding must survive dedup"
    assert "patterns" in sources_on_curl_line, "pattern finding must survive dedup"

    # And every finding's fields are masked.
    for f in result.findings:
        d = f.to_dict()
        assert_clean(d["snippet"], d["title"], d["description"], d["remediation"])


def test_reports_carry_no_raw_secret(tmp_path):
    target = write_leaky_app(tmp_path)
    result = collect_findings(target)
    assert_clean(to_json(result), to_markdown(result))


def test_provider_payload_carries_no_raw_secret(tmp_path):
    target = write_leaky_app(tmp_path)
    result = collect_findings(target)
    recorder = RecordingProvider()
    triage_with_llm(result, recorder)
    assert recorder.payloads, "provider was not called"
    for payload in recorder.payloads:
        assert_clean(payload["system"], payload["user"])


def test_sarif_ingest_path_also_scrubbed_centrally(tmp_path):
    target = write_leaky_app(tmp_path)
    sarif = tmp_path / "leak.sarif"
    sarif.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "t", "rules": []}},
            "results": [{
                "ruleId": "x", "level": "error",
                "message": {"text": f"evidence {AWS}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 2, "snippet": {"text": f"curl {SLACK}"}}}}],
            }],
        }],
    }), encoding="utf-8")
    result = collect_findings(target, sarif_files=[str(sarif)])
    assert_clean(to_json(result), to_markdown(result))


def test_boundary_scrub_catches_unredacted_detector(tmp_path):
    """A hypothetically broken detector emitting raw secrets is still caught."""
    from sentinel_triage.triager import sanitize_finding

    leaky = Finding(
        rule_id="broken.detector", title=f"title {AWS}", severity="high",
        confidence="high", file="a.py", line=1, snippet=f"run {SLACK}",
        description=f"desc {AWS}", remediation=f"fix {SLACK}", source="patterns",
    )
    clean = sanitize_finding(leaky)
    assert_clean(clean.title, clean.snippet, clean.description, clean.remediation)


class MaliciousProvider(Provider):
    """Returns notes carrying a planted secret and active markup."""

    name = "malicious"
    is_mock = False

    def complete(self, system, user):
        payload = json.loads(user)
        fp = payload["findings"][0]["fingerprint"]
        return json.dumps({"triage": [{
            "fingerprint": fp,
            "priority_rationale": f"exfil ![p](https://evil.example/p.png) key {AWS}",
            "fix_guidance": f"see [docs](https://evil.example) <img src=x> `{SLACK}`",
        }]})


def test_provider_return_text_is_scrubbed_and_neutralized(tmp_path):
    target = write_leaky_app(tmp_path)
    result = collect_findings(target)
    result = triage_with_llm(result, MaliciousProvider())
    assert result.llm_used is True
    md = to_markdown(result)
    js = to_json(result)
    # Secret-pattern text from the provider never lands in outputs.
    assert_clean(md, js)
    # Active markup from the provider is neutralized.
    for doc in (md, js):
        assert "![" not in doc
        assert "evil.example/p.png" not in doc
        assert "<img" not in doc
        assert "](https://evil.example)" not in doc


def test_sarif_markup_is_neutralized(tmp_path):
    sarif = tmp_path / "md.sarif"
    sarif.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "t", "rules": [{
                "id": "r1",
                "shortDescription": {"text": "click [here](https://evil.example) now"},
                "help": {"text": "<script>alert(1)</script> upgrade"},
            }]}},
            "results": [{
                "ruleId": "r1", "level": "warning",
                "message": {"text": "m"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": 1, "snippet": {"text": "x = 1"}}}}],
            }],
        }],
    }), encoding="utf-8")
    result = collect_findings(str(tmp_path), sarif_files=[str(sarif)])
    md = to_markdown(result)
    assert "](https://evil.example)" not in md
    assert "<script>" not in md
    assert "click here now" in md  # visible text survives


def test_dedup_same_family_still_merges():
    generic = Finding(rule_id="secret.generic-assignment", title="g", severity="high",
                      confidence="medium", file="a.py", line=1, snippet="x",
                      description="d", remediation="r", source="secrets")
    specific = Finding(rule_id="secret.aws-access-key", title="s", severity="critical",
                       confidence="high", file="a.py", line=1, snippet="y",
                       description="d", remediation="r", source="secrets")
    unique, removed = deduplicate([generic, specific])
    assert len(unique) == 1 and unique[0].rule_id == "secret.aws-access-key"
    assert removed == 1
