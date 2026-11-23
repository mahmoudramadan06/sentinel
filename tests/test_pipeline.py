"""Dedup, ranking, redaction, and version-comparison tests."""

from sentinel_triage.dedup import deduplicate
from sentinel_triage.models import Finding
from sentinel_triage.rank import rank_findings
from sentinel_triage.redact import mask_secret
from sentinel_triage.scanners.deps import parse_version, version_lt


def make_finding(rule_id="r", severity="low", confidence="high", file="a.py", line=1):
    return Finding(
        rule_id=rule_id, title=f"t-{rule_id}", severity=severity,
        confidence=confidence, file=file, line=line, snippet="x",
        description="d", remediation="r", source="test",
    )


def test_exact_duplicates_removed():
    f1 = make_finding()
    f2 = make_finding()
    unique, removed = deduplicate([f1, f2])
    assert len(unique) == 1 and removed == 1


def test_same_location_collision_prefers_specific_and_severe():
    generic = make_finding(rule_id="secret.generic-assignment", severity="high")
    specific = make_finding(rule_id="secret.aws-access-key", severity="critical")
    unique, removed = deduplicate([generic, specific])
    assert len(unique) == 1
    assert unique[0].rule_id == "secret.aws-access-key"
    assert removed == 1


def test_ranking_orders_by_risk():
    low = make_finding(rule_id="low", severity="low")
    crit = make_finding(rule_id="crit", severity="critical", line=2)
    med = make_finding(rule_id="med", severity="medium", line=3)
    ranked = rank_findings([low, crit, med])
    assert [f.rule_id for f in ranked] == ["crit", "med", "low"]


def test_ranking_is_deterministic():
    fs = [make_finding(rule_id=f"r{i}", severity="medium", line=i) for i in range(10)]
    assert [f.fingerprint() for f in rank_findings(fs)] == \
           [f.fingerprint() for f in rank_findings(list(reversed(fs)))]


def test_mask_secret_short_and_long():
    assert "secret123" not in mask_secret("secret123")
    masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
    assert masked.startswith("AKIA") and masked.endswith("MPLE")
    assert "SFODNN" not in masked


def test_version_comparison():
    assert version_lt(parse_version("2.19.0"), parse_version("2.20.0"))
    assert not version_lt(parse_version("2.20.0"), parse_version("2.20.0"))
    assert version_lt(parse_version("1.2.5"), parse_version("1.2.6"))
    assert not version_lt(parse_version("4.17.12"), parse_version("4.17.12"))
