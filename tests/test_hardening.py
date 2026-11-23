"""Adversarial and failure-case tests: untrusted input must fail safely.

Includes real-HTTP provider tests: the adapters talk to a local
schema-compatible HTTP server (stdlib http.server in a thread), so the
urllib request/response code runs for real over the wire, without any
vendor API, key, or spend.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel_triage.cli import main
from sentinel_triage.importers import SarifImportError, import_sarif, redact_text
from sentinel_triage.redact import secret_patterns as _secret_patterns
from sentinel_triage.triager import collect_findings
from sentinel_triage.providers.anthropic import AnthropicProvider
from sentinel_triage.providers.openai_compat import OpenAICompatProvider

FIXTURES = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
APP_DIR = os.path.join(FIXTURES, "vulnerable_app")

# A realistic-looking but fake AWS secret planted in untrusted input.
# Matches the AWS key pattern: AKIA + exactly 16 uppercase alphanumerics.
FAKE_SECRET = "AKIAZZZZTOPSECRET000"


def test_malformed_sarif_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{not json at all", encoding="utf-8")
    rc = main(["scan", APP_DIR, "--sarif", str(bad), "--no-llm", "--out", str(tmp_path / "o")])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not valid JSON" in err
    assert "Traceback" not in err


def test_non_sarif_json_rejected(tmp_path):
    doc = tmp_path / "other.json"
    doc.write_text('{"results": []}', encoding="utf-8")
    with pytest.raises(SarifImportError, match="not a SARIF 2.x"):
        import_sarif(str(doc))


def test_sarif_missing_runs_rejected(tmp_path):
    doc = tmp_path / "noruns.sarif"
    doc.write_text('{"version": "2.1.0"}', encoding="utf-8")
    with pytest.raises(SarifImportError, match="no 'runs'"):
        import_sarif(str(doc))


def test_sarif_weird_shapes_do_not_crash(tmp_path):
    doc = tmp_path / "weird.sarif"
    doc.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [
            "not-a-dict",
            {"tool": {"driver": {"name": "t", "rules": "oops"}},
             "results": "not-a-list"},
            {"tool": {"driver": {"name": "t"}},
             "results": ["junk", {"ruleId": 1, "level": 7,
                                   "locations": [{"physicalLocation": None}]}]},
        ],
    }), encoding="utf-8")
    findings = import_sarif(str(doc))
    assert len(findings) <= 1  # only the last dict-ish result may survive


def test_secret_inside_sarif_snippet_is_masked(tmp_path):
    doc = tmp_path / "leaky.sarif"
    doc.write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "leakytool", "rules": []}},
            "results": [{
                "ruleId": "x",
                "level": "error",
                "message": {"text": f"found key {FAKE_SECRET} in source"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "leak.py"},
                    "region": {"startLine": 3,
                               "snippet": {"text": f'KEY = "{FAKE_SECRET}"'}}}}],
            }],
        }],
    }), encoding="utf-8")
    findings = import_sarif(str(doc))
    assert len(findings) == 1
    f = findings[0]
    assert FAKE_SECRET not in f.snippet
    assert FAKE_SECRET not in f.description
    assert "AKIA" in f.snippet and "*" in f.snippet

    # And it stays masked all the way into the JSON report.
    out_dir = tmp_path / "out"
    rc = main(["scan", APP_DIR, "--sarif", str(doc), "--no-llm",
               "--format", "json", "--out", str(out_dir)])
    assert rc == 0
    report_text = (out_dir / "triage-report.json").read_text(encoding="utf-8")
    assert FAKE_SECRET not in report_text


def test_redact_text_masks_every_match():
    patterns = _secret_patterns()
    text = f'a = "{FAKE_SECRET}"\nb = "{FAKE_SECRET}"'
    redacted = redact_text(text, patterns)
    assert FAKE_SECRET not in redacted
    assert redacted.count("AKIA") == 2


def test_symlink_escape_is_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text(f'KEY = "{FAKE_SECRET}"\n', encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / "ok.py").write_text("print('fine')\n", encoding="utf-8")
    os.symlink(str(outside / "secret.py"), str(target / "linked.py"))
    result = collect_findings(str(target))
    assert all("linked.py" != f.file for f in result.findings)
    assert result.files_skipped >= 1


def test_oversized_file_skipped(tmp_path, monkeypatch):
    from sentinel_triage import guards
    monkeypatch.setattr(guards, "MAX_FILE_BYTES", 100)
    big = tmp_path / "big.py"
    big.write_text("x = 1\n" * 500, encoding="utf-8")
    result = collect_findings(str(tmp_path))
    assert result.files_scanned == 0 and result.files_skipped == 1


def test_minified_artifacts_skipped(tmp_path):
    (tmp_path / "jquery.min.js").write_text(
        "x.innerHTML = y; eval(z);" * 3, encoding="utf-8")
    (tmp_path / "app.js").write_text("document.body.innerHTML = t;\n", encoding="utf-8")
    result = collect_findings(str(tmp_path))
    assert [f.file for f in result.findings] == ["app.js"]


def test_empty_target_produces_valid_empty_report(tmp_path):
    out_dir = tmp_path / "out"
    rc = main(["scan", str(tmp_path), "--no-llm", "--format", "both", "--out", str(out_dir)])
    assert rc == 0
    doc = json.loads((out_dir / "triage-report.json").read_text(encoding="utf-8"))
    assert doc["findings"] == []
    assert doc["metadata"]["files_scanned"] == 0
    md = (out_dir / "triage-report.md").read_text(encoding="utf-8")
    assert "Security Triage Report" in md


def test_clean_project_has_no_findings(tmp_path):
    (tmp_path / "safe.py").write_text(
        "import hashlib, sqlite3, subprocess\n\n"
        "def hash_pw(pw: str, salt: bytes) -> bytes:\n"
        "    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 200_000)\n\n"
        "def get_user(conn: sqlite3.Connection, name: str):\n"
        "    return conn.execute('SELECT * FROM users WHERE name = ?', (name,))\n\n"
        "def run_tool():\n"
        "    subprocess.run(['tool', '--flag'], shell=False, check=True)\n",
        encoding="utf-8")
    result = collect_findings(str(tmp_path))
    assert result.findings == [], f"false positives on clean code: {result.findings}"


def test_baseline_suppresses_and_discloses(tmp_path):
    first = collect_findings(APP_DIR)
    fp = first.findings[0].fingerprint()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"suppressed": [fp]}), encoding="utf-8")
    second = collect_findings(APP_DIR, baseline_path=str(baseline))
    assert second.baseline_suppressed == 1
    assert len(second.findings) == len(first.findings) - 1
    assert all(f.fingerprint() != fp for f in second.findings)


def test_baseline_bad_file_clean_error(tmp_path, capsys):
    bad = tmp_path / "baseline.json"
    bad.write_text("not json", encoding="utf-8")
    rc = main(["scan", APP_DIR, "--no-llm", "--baseline", str(bad), "--out", str(tmp_path / "o")])
    assert rc == 2
    assert "baseline" in capsys.readouterr().err


class _StubHandler(BaseHTTPRequestHandler):
    """Schema-compatible stub for both provider APIs."""

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.last_request = {
            "path": self.path,
            "authorization": self.headers.get("authorization"),
            "x-api-key": self.headers.get("x-api-key"),
            "body": body,
        }
        if self.path.endswith("/chat/completions"):
            payload = {"choices": [{"message": {"content": '{"triage": []}'}}]}
        else:
            payload = {"content": [{"type": "text", "text": '{"triage": []}'}]}
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture()
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server
    server.shutdown()
    thread.join(timeout=5)


def test_openai_adapter_over_real_http(local_server, monkeypatch):
    base_url, server = local_server
    monkeypatch.setenv("OPENAI_API_KEY", "dummy")
    monkeypatch.setenv("OPENAI_BASE_URL", base_url)
    p = OpenAICompatProvider(model="test-model")
    assert p.complete("system prompt", '{"findings": []}') == '{"triage": []}'
    req = server.last_request
    assert req["path"] == "/chat/completions"
    assert req["authorization"] == "Bearer dummy"
    assert req["body"]["model"] == "test-model"
    assert req["body"]["messages"][0]["role"] == "system"


def test_anthropic_adapter_over_real_http(local_server, monkeypatch):
    base_url, server = local_server
    monkeypatch.setenv("ANTHROPIC_API_KEY", "dummy")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", base_url)
    p = AnthropicProvider(model="test-model")
    assert p.complete("system prompt", '{"findings": []}') == '{"triage": []}'
    req = server.last_request
    assert req["path"] == "/v1/messages"
    assert req["x-api-key"] == "dummy"
    assert req["body"]["model"] == "test-model"
    assert req["body"]["system"] == "system prompt"
