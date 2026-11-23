"""Tests for passive OSINT builders: pure, offline, scope-gated."""

import pytest

from sentinel_triage.osint import OsintError, build_osint_plan, crt_sh_url, google_dork
from sentinel_triage.scope import Scope


def make_scope():
    return Scope.from_dict({"targets": ["example.com"], "exclusions": []})


def test_plan_is_offline_strings_for_scoped_domain():
    plan = build_osint_plan(make_scope())
    assert plan
    for label, value in plan:
        assert "example.com" in value


def test_out_of_scope_subject_refused():
    scope = make_scope()
    with pytest.raises(OsintError):
        crt_sh_url(scope, "evil.net")
    with pytest.raises(OsintError):
        google_dork(scope, "evil.net")
    with pytest.raises(OsintError):
        build_osint_plan(scope, subject="evil.net")


def test_subdomain_subject_allowed():
    assert "example.com" in crt_sh_url(make_scope(), "api.example.com")


def test_unknown_dork_kind_rejected():
    with pytest.raises(OsintError):
        google_dork(make_scope(), "example.com", kind="passwords")
