"""Tests for recon orchestration: dry-run, gating, injection resistance."""

import ipaddress

from sentinel_triage import recon
from sentinel_triage.recon import ReconError
from sentinel_triage.scope import Scope


def make_scope(**overrides):
    data = {"targets": ["example.com"], "exclusions": [], "allow_active": False}
    data.update(overrides)
    return Scope.from_dict(data)


def test_dry_run_is_the_default_and_runs_nothing():
    scope = make_scope()
    results = recon.run(scope)
    assert results
    assert all(not r.ran for r in results)
    assert all("dry-run" in r.skipped_reason or "refused" in r.skipped_reason
               for r in results)
    passive = [r for r in results if r.plan.plugin.category == recon.PASSIVE]
    assert all("dry-run" in r.skipped_reason for r in passive)


def test_active_plugins_parked_without_allow_active():
    scope = make_scope()
    plans = recon.plan(scope)
    passive = [p for p in plans if p.plugin.category == recon.PASSIVE]
    active = [p for p in plans if p.plugin.category == recon.ACTIVE]
    assert all(p.gate.allowed for p in passive)
    assert all(not p.gate.allowed for p in active)
    assert any("allow_active" in p.gate.reason for p in active)


def test_active_plugins_allowed_when_scope_allows():
    scope = make_scope(allow_active=True)
    plans = recon.plan(scope)
    assert all(p.gate.allowed for p in plans)


def test_out_of_scope_target_refused_even_with_execute():
    scope = make_scope(allow_active=True)
    results = recon.run(scope, targets=["evil.net"], execute=True)
    assert results
    assert all(not r.ran for r in results)
    assert all("refused by scope" in r.skipped_reason for r in results)


def test_execution_time_dns_recheck_refuses_out_of_scope_resolution():
    scope = Scope.from_dict({
        "targets": ["example.com", "10.0.0.0/24"],
        "allow_active": True,
    })
    resolver = lambda host: [ipaddress.ip_address("203.0.113.66")]
    results = recon.run(scope, plugin_names=["dig"], execute=True, resolver=resolver)
    assert len(results) == 1
    assert not results[0].ran
    assert "execution time" in results[0].skipped_reason


def test_missing_binary_is_a_clean_skip():
    scope = make_scope()
    results = recon.run(scope, plugin_names=["amass-passive"], execute=True,
                        resolver=lambda h: [])
    # amass is not installed in the test environment; if it ever is, the
    # run is allowed to proceed, so only assert the contract shape.
    assert len(results) == 1
    if not results[0].ran:
        assert results[0].skipped_reason


def test_option_injection_and_shell_metacharacters_rejected():
    for bad in ["-d evil.net", "example.com; rm -rf /", "ex$(whoami)ample.com",
                "example.com|cat", "--resolver=x", "example.com@evil.net"]:
        try:
            recon.plan(make_scope(), targets=[bad])
        except ReconError:
            continue
        raise AssertionError(f"unsafe target accepted: {bad!r}")


def test_url_userinfo_trick_fails_closed_in_scope_check():
    # http://example.com@evil.net connects to evil.net; the scope check
    # must see the real host. urlparse handles the scheme form; the bare
    # form is denied because it is not a valid scoped hostname.
    scope = make_scope()
    assert not scope.check("http://example.com@evil.net/").allowed
    assert not scope.check("example.com@evil.net").allowed


def test_plugin_flags_are_allowlisted():
    for plugin in recon.REGISTRY:
        argv = plugin.argv("example.com")
        joined = " ".join(argv)
        for banned in ["--script", "-A ", "vuln", "brute", "fuzz", "-iL"]:
            assert banned not in joined, f"{plugin.name} exposes {banned}"


def test_registry_has_no_intrusive_categories():
    assert {p.category for p in recon.REGISTRY} <= {recon.PASSIVE, recon.ACTIVE}


def test_output_filtering_drops_out_of_scope_discoveries():
    scope = make_scope()
    text = ("api.example.com 200\n"
            "cdn-shared-host.net 200\n"
            "10.9.9.9 open\n"
            "www.example.com 301\n")
    findings = recon.filter_output(scope, text)
    by_value = {f.value: f for f in findings}
    assert by_value["api.example.com"].allowed
    assert by_value["www.example.com"].allowed
    assert not by_value["cdn-shared-host.net"].allowed
    assert not by_value["10.9.9.9"].allowed


def test_output_filtering_dedupes_and_is_offline_by_default():
    scope = make_scope()
    findings = recon.filter_output(scope, "a.example.com a.example.com a.example.com")
    assert len(findings) == 1
    assert findings[0].allowed
