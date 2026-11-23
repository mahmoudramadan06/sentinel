"""SARIF importer tests."""

import os

from sentinel_triage.importers import import_sarif
from sentinel_triage.triager import collect_findings

FIXTURES = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "fixtures"))
SARIF_FILE = os.path.join(FIXTURES, "semgrep-output.sarif")
APP_DIR = os.path.join(FIXTURES, "vulnerable_app")


def test_sarif_import_maps_fields():
    findings = import_sarif(SARIF_FILE)
    assert len(findings) == 3
    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    eval_f = by_rule["sarif.semgrep.python.lang.security.audit.eval-detected.eval-detected"][0]
    assert eval_f.severity == "high"            # SARIF error -> high
    assert eval_f.file == "app.py"
    assert eval_f.line == 41
    assert eval_f.source == "sarif:semgrep"
    assert "eval" in eval_f.title.lower()
    shell_f = by_rule["sarif.semgrep.python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"][0]
    assert shell_f.severity == "medium"         # SARIF warning -> medium


def test_sarif_results_flow_through_dedup():
    result = collect_findings(APP_DIR, sarif_files=[SARIF_FILE])
    sarif_findings = [f for f in result.findings if f.source == "sarif:semgrep"]
    # The duplicate eval() result in the fixture must be deduplicated away.
    assert len(sarif_findings) == 2
    assert result.duplicates_removed >= 2


def test_sarif_and_internal_findings_coexist():
    result = collect_findings(APP_DIR, sarif_files=[SARIF_FILE])
    sources = {f.source for f in result.findings}
    assert "sarif:semgrep" in sources
    assert "secrets" in sources
    assert "deps" in sources
