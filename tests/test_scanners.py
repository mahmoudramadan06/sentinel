"""Scanner tests against the bundled synthetic fixture app."""

import os

import pytest

from sentinel_triage.guards import load_target
from sentinel_triage.scanners import scan_code_patterns, scan_dependencies, scan_secrets

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures", "vulnerable_app")
CONTENTS = load_target(FIXTURES)[0]


@pytest.fixture(scope="module")
def secrets():
    return scan_secrets(CONTENTS)


@pytest.fixture(scope="module")
def patterns():
    return scan_code_patterns(CONTENTS)


@pytest.fixture(scope="module")
def deps():
    return scan_dependencies(CONTENTS)


def test_aws_example_key_detected(secrets):
    hits = [f for f in secrets if f.rule_id == "secret.aws-access-key"]
    assert hits, "expected the AWS example key to be flagged"
    assert hits[0].severity == "critical"


def test_secret_values_are_redacted(secrets):
    for f in secrets:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
        assert "sk-live-fake0000000000000000" not in f.snippet
        if "AKIA" in f.snippet:
            assert "*" in f.snippet


def test_generic_credential_assignment_detected(secrets):
    assert any(f.rule_id == "secret.generic-assignment" for f in secrets)


def test_dangerous_python_patterns(patterns):
    ids = {f.rule_id for f in patterns}
    assert "code.python-shell-true" in ids
    assert "code.python-eval" in ids
    assert "code.python-pickle-load" in ids
    assert "code.sql-string-interpolation" in ids
    assert "code.sql-percent-format" in ids
    assert "code.weak-hash-password-context" in ids
    assert "code.debug-mode-enabled" in ids


def test_js_patterns(patterns):
    ids = {f.rule_id for f in patterns}
    assert "code.js-innerhtml" in ids
    assert "code.js-child-process-template" in ids


def test_dependency_advisories(deps):
    ids = {f.rule_id for f in deps}
    assert "dep.pypi.cve-2018-18074" in ids          # requests 2.19.0
    assert "dep.pypi.cve-2021-33503" in ids          # urllib3 1.24.1
    assert "dep.pypi.cve-2020-14343" in ids          # pyyaml 5.3.1
    assert "dep.npm.cve-2019-10744" in ids           # lodash 4.17.11
    assert "dep.npm.cve-2021-44906" in ids           # minimist 1.2.5


def test_safe_version_not_flagged():
    findings = scan_dependencies([("requirements.txt", "requests==2.31.0\n")])
    assert not [f for f in findings if "requests" in f.title]


def test_requirements_extras_are_checked_not_ignored():
    findings = scan_dependencies([("requirements.txt", "requests[security]==2.19.0  # legacy pin\n")])
    assert any(f.rule_id == "dep.pypi.cve-2018-18074" for f in findings), \
        "extras and inline comments must not cause a pinned vulnerable version to be skipped"


def test_scanners_skip_binary(tmp_path):
    contents, scanned, skipped = load_target(str(tmp_path))
    assert (contents, scanned, skipped) == ([], 0, 0)
    (tmp_path / "blob.py").write_bytes(b"\xff\xfe\x00\x01" * 10)
    contents, scanned, skipped = load_target(str(tmp_path))
    # Binary file: not scanned, counted as skipped (never overstates scans).
    assert scanned == 0 and skipped == 1
    assert scan_code_patterns(contents) == []
