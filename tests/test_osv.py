"""OSV client tests: real HTTP against a local schema-compatible stub.

No call to the live api.osv.dev; the stub returns a recorded response in
the documented OSV querybatch shape.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel_triage.osv_client import OsvError, query_osv
from sentinel_triage.triager import collect_findings

RECORDED_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "GHSA-j8r2-6x86-q33q",
                    "summary": "Requests sends Authorization header on redirect",
                    "database_specific": {"severity": "HIGH"},
                },
                {
                    "id": "PYSEC-2018-67",
                    "details": "Second record without a severity label.",
                },
            ]
        },
        {"vulns": []},
    ]
}

DEPS = [
    ("PyPI", "requests", "2.19.0", "requirements.txt", 1),
    ("npm", "some-safe-package", "9.9.9", "package.json", 0),
]


class _OsvStub(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.last_request = {"path": self.path, "body": body}
        raw = json.dumps(RECORDED_RESPONSE).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


@pytest.fixture()
def osv_stub():
    server = HTTPServer(("127.0.0.1", 0), _OsvStub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server
    server.shutdown()
    thread.join(timeout=5)


def test_querybatch_request_shape(osv_stub):
    base_url, server = osv_stub
    query_osv(DEPS, base_url=base_url)
    req = server.last_request
    assert req["path"] == "/v1/querybatch"
    assert req["body"]["queries"][0] == {
        "package": {"name": "requests", "ecosystem": "PyPI"},
        "version": "2.19.0",
    }
    assert len(req["body"]["queries"]) == 2


def test_findings_mapped_with_severity(osv_stub):
    base_url, _ = osv_stub
    findings = query_osv(DEPS, base_url=base_url)
    assert len(findings) == 2
    by_id = {f.rule_id: f for f in findings}
    assert by_id["dep.osv.ghsa-j8r2-6x86-q33q"].severity == "high"
    # No severity label in OSV entry -> conservative medium default.
    assert by_id["dep.osv.pysec-2018-67"].severity == "medium"
    assert all(f.source == "deps:osv" for f in findings)
    assert all(f.file == "requirements.txt" for f in findings)


def test_osv_http_error_raises_clean(osv_stub, monkeypatch):
    base_url, server = osv_stub

    class Boom(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args):
            pass

    server.RequestHandlerClass = Boom  # not retroactive; use a fresh server instead
    bad = HTTPServer(("127.0.0.1", 0), Boom)
    t = threading.Thread(target=bad.serve_forever, daemon=True)
    t.start()
    try:
        with pytest.raises(OsvError, match="HTTP 500"):
            query_osv(DEPS, base_url=f"http://127.0.0.1:{bad.server_address[1]}")
    finally:
        bad.shutdown()
        t.join(timeout=5)


def test_pipeline_osv_failure_warns_and_falls_back(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    # Point OSV at a dead port: lookup fails, pipeline must still produce
    # the built-in offline result with a disclosed warning.
    monkeypatch.setenv("OSV_BASE_URL", "http://127.0.0.1:9")
    result = collect_findings(str(tmp_path), use_osv=True)
    assert any("OSV lookup failed" in w for w in result.warnings)
    assert any(f.source == "deps" for f in result.findings), "offline fallback must remain"
    assert not [f for f in result.findings if f.source == "deps:osv"]


def test_pipeline_osv_success_merges(tmp_path, osv_stub, monkeypatch):
    base_url, _ = osv_stub
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    monkeypatch.setenv("OSV_BASE_URL", base_url)
    result = collect_findings(str(tmp_path), use_osv=True)
    sources = {f.source for f in result.findings}
    assert "deps:osv" in sources
    assert result.warnings == []
