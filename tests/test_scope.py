"""Tests for the scope gate: parsing, matching, exclusions, live checks."""

import ipaddress

import pytest

from sentinel_triage.scope import Scope, ScopeError


def make_scope(**overrides):
    data = {
        "engagement": "demo",
        "targets": ["example.com", "10.0.0.0/24", "192.0.2.10"],
        "exclusions": ["admin.example.com", "10.0.0.99"],
        "allow_active": False,
    }
    data.update(overrides)
    return Scope.from_dict(data)


def test_domain_rule_matches_subdomains():
    scope = make_scope()
    assert scope.check("example.com").allowed
    assert scope.check("api.example.com").allowed
    assert scope.check("deep.api.example.com").allowed


def test_domain_rule_rejects_lookalikes():
    scope = make_scope()
    assert not scope.check("notexample.com").allowed
    assert not scope.check("example.com.evil.net").allowed
    assert not scope.check("examplexcom").allowed


def test_network_rules_and_literals():
    scope = make_scope()
    assert scope.check("10.0.0.5").allowed
    assert scope.check("192.0.2.10").allowed
    assert not scope.check("10.0.1.5").allowed
    assert not scope.check("192.0.2.11").allowed


def test_exclusions_always_win():
    scope = make_scope()
    decision = scope.check("admin.example.com")
    assert not decision.allowed and "excluded" in decision.reason
    assert not scope.check("10.0.0.99").allowed
    # Exclusion of one subdomain must not sink the rest.
    assert scope.check("www.example.com").allowed


def test_url_targets_are_reduced_to_host():
    scope = make_scope()
    assert scope.check("https://app.example.com/login?next=/x").allowed
    assert scope.check("https://evil.net/").allowed is False


def test_wildcards_and_bad_input_rejected():
    with pytest.raises(ScopeError):
        make_scope(targets=["*.example.com"])
    with pytest.raises(ScopeError):
        Scope.from_dict({"targets": []})
    assert not make_scope().check("").allowed


def test_minimal_yaml_subset(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text(
        "engagement: acme q4\n"
        "allow_active: true\n"
        "targets:\n"
        "  - example.org\n"
        "  - 172.16.0.0/28\n"
        "exclusions:\n"
        "  - mail.example.org\n"
    )
    scope = Scope.from_file(str(path))
    assert scope.engagement == "acme q4"
    assert scope.allow_active is True
    assert scope.check("app.example.org").allowed
    assert scope.check("172.16.0.9").allowed
    assert not scope.check("mail.example.org").allowed


def test_yaml_subset_rejects_complex_syntax(tmp_path):
    path = tmp_path / "scope.yaml"
    path.write_text("targets: {a: 1}\n")
    # inline maps are not part of the supported subset; must not silently parse
    with pytest.raises(ScopeError):
        Scope.from_file(str(path))


def test_live_resolution_outside_networks_refused():
    scope = make_scope()  # has network rules
    resolver = lambda host: [ipaddress.ip_address("203.0.113.9")]
    decision = scope.resolve_and_check("example.com", resolver=resolver)
    assert not decision.allowed
    assert "outside scoped networks" in decision.reason


def test_live_resolution_inside_networks_allowed():
    scope = make_scope()
    resolver = lambda host: [ipaddress.ip_address("10.0.0.7")]
    decision = scope.resolve_and_check("example.com", resolver=resolver)
    assert decision.allowed


def test_domain_only_scope_accepts_any_resolution():
    scope = make_scope(targets=["example.com"], exclusions=[])
    resolver = lambda host: [ipaddress.ip_address("203.0.113.9")]
    assert scope.resolve_and_check("example.com", resolver=resolver).allowed


def test_resolution_failure_is_a_refusal():
    scope = make_scope()

    def broken(host):
        raise OSError("name or service not known")

    decision = scope.resolve_and_check("example.com", resolver=broken)
    assert not decision.allowed


def test_rebinding_style_resolutions_always_refused():
    # Even a domain-only scope must refuse loopback/link-local/metadata
    # style answers: a public engagement never legitimately resolves there.
    scope = make_scope(targets=["example.com"], exclusions=[])
    for bad in ["127.0.0.1", "169.254.169.254", "0.0.0.0"]:
        resolver = lambda host, _b=bad: [ipaddress.ip_address(_b)]
        decision = scope.resolve_and_check("example.com", resolver=resolver)
        assert not decision.allowed, bad
        assert "forbidden" in decision.reason
    # Literal scoped lab networks still work: they skip DNS entirely.
    lab = make_scope(targets=["10.0.0.0/24"], exclusions=[])
    assert lab.check("10.0.0.5").allowed
