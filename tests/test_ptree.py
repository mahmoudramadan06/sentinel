"""Tests for the forked PTT core: model, planner, scope gating."""

import pytest

from sentinel_triage.ptree import (
    PTTNode,
    build_initial_tree,
    expand_recon_task,
    parse_ptt,
    render_ptt,
)
from sentinel_triage.ptree.model import PTTParseError
from sentinel_triage.ptree.planner import ScopeGateError, gate_llm_revision
from sentinel_triage.scope import Scope


def make_scope(**overrides):
    data = {"targets": ["example.com", "10.0.0.0/24"], "exclusions": []}
    data.update(overrides)
    return Scope.from_dict(data)


SAMPLE = """1. Reconnaissance - (to-do)
    1.1 Passive Information Gathering - (completed)
    1.2 Active Information Gathering - (to-do)
        1.2.1 Perform a port scan - (to-do)
"""


def test_parse_and_render_roundtrip():
    tree = parse_ptt(SAMPLE)
    assert tree.number == "1"
    assert tree.children[0].status == "completed"
    assert tree.find("1.2.1").title == "Perform a port scan"
    rendered = render_ptt(tree)
    again = parse_ptt(rendered)
    assert render_ptt(again) == rendered


def test_strict_numbering_rejected():
    with pytest.raises(PTTParseError):
        parse_ptt("1. Root - (to-do)\n    1.3 Skipped - (to-do)\n")
    with pytest.raises(PTTParseError):
        parse_ptt("2. Wrong root - (to-do)\n")


def test_todo_leaves():
    tree = parse_ptt(SAMPLE)
    leaves = tree.todo_leaves()
    assert [n.number for n in leaves] == ["1.2.1"]


def test_initial_tree_is_recon_only_and_in_scope():
    tree = build_initial_tree(make_scope())
    for node in tree.walk():
        lowered = node.title.lower()
        assert "exploit" not in lowered
        assert "brute" not in lowered
        if node.target:
            assert make_scope().check(node.target).allowed
    todos = [n for n in tree.walk() if n.status == "to-do"]
    assert todos, "expected actionable recon tasks"


def test_active_steps_parked_without_allow_active():
    tree = build_initial_tree(make_scope(allow_active=False))
    parked = [n for n in tree.walk() if n.status == "not applicable"]
    assert any("parked" in n.title for n in parked)
    tree_active = build_initial_tree(make_scope(allow_active=True))
    parked_active = [n for n in tree_active.walk() if "parked" in n.title]
    assert not parked_active


def test_expand_refuses_out_of_scope_target():
    scope = make_scope()
    node = PTTNode(number="9", title="Subdomain enumeration of elsewhere",
                   target="evil.net")
    with pytest.raises(ScopeGateError):
        expand_recon_task(scope, node)


def test_expand_adds_substeps_for_known_task():
    scope = make_scope()
    node = PTTNode(number="1.2",
                   title="Subdomain enumeration with passive sources",
                   target="example.com")
    children = expand_recon_task(scope, node)
    assert [c.number for c in children] == ["1.2.1", "1.2.2", "1.2.3"]


def test_llm_revision_within_scope_accepted():
    scope = make_scope()
    revised = (
        "1. Reconnaissance - (to-do)\n"
        "    1.1 Enumerate subdomains of example.com - (to-do)\n"
        "    1.2 Fingerprint 10.0.0.7 - (to-do)\n"
    )
    tree = gate_llm_revision(scope, revised)
    assert tree.find("1.2").status == "to-do"


def test_llm_revision_out_of_scope_target_refused():
    scope = make_scope()
    revised = (
        "1. Reconnaissance - (to-do)\n"
        "    1.1 Enumerate subdomains of evil.net - (to-do)\n"
    )
    with pytest.raises(ScopeGateError):
        gate_llm_revision(scope, revised)


@pytest.mark.parametrize("title", [
    "Exploit the upload form on example.com",
    "Brute force SSH on 10.0.0.7",
    "Establish persistence on example.com",
    "Dump credentials from the wiki host",
])
def test_llm_revision_offensive_tasks_refused(title):
    scope = make_scope()
    revised = f"1. Reconnaissance - (to-do)\n    1.1 {title} - (to-do)\n"
    with pytest.raises(ScopeGateError):
        gate_llm_revision(scope, revised)
