"""Deterministic, scope-gated PTT planner.

Forked from the PentestGPT approach (MIT) of reasoning over a task tree, but
deterministic and offline: the same scope always produces the same initial
tree, and every task that touches a target is validated against the loaded
scope before it may enter the tree. An LLM can refine the tree later through
sentinel_triage.providers; it can never widen the scope, because the gate
runs on the task list after any LLM output.
"""

from __future__ import annotations

from ..scope import Scope
from .model import PTTNode, STATUS_TODO, parse_ptt, render_ptt


class ScopeGateError(PermissionError):
    """Raised when a task or LLM revision tries to act outside scope."""


# Bounded, reconnaissance-only playbook. Each entry is (title, needs_target).
# Deliberately no exploitation or post-exploitation stages.
_RECON_PLAYBOOK = [
    ("Passive information gathering (OSINT: crt.sh, public DNS, search results)", False),
    ("Subdomain enumeration with passive sources (subfinder/amass passive)", True),
    ("DNS record review for in-scope hosts (A/AAAA/MX/TXT/NS)", True),
    ("Web service fingerprinting on in-scope hosts (httpx: status, title, tech)", True),
    ("Content discovery on in-scope web targets (bounded crawl, katana)", True),
    ("Safe service scan of in-scope hosts (nmap top-100 -sV, no NSE vuln scripts)", True),
    ("Technology exposure check on in-scope web targets (nuclei tech-detect tags only)", True),
    ("Consolidate findings into the engagement report", False),
]

_ACTIVE_TITLES = {
    "Content discovery on in-scope web targets (bounded crawl, katana)",
    "Safe service scan of in-scope hosts (nmap top-100 -sV, no NSE vuln scripts)",
    "Technology exposure check on in-scope web targets (nuclei tech-detect tags only)",
}


def _primary_target(scope: Scope) -> str:
    if scope.domains:
        return scope.domains[0]
    if scope.networks:
        net = scope.networks[0]
        return str(net.network_address) if net.num_addresses > 1 else str(net[0])
    return ""


def build_initial_tree(scope: Scope) -> PTTNode:
    """Build the initial reconnaissance-only PTT for a scoped engagement."""
    target = _primary_target(scope)
    root = PTTNode(number="1", title=f"Reconnaissance for {scope.engagement or target}")
    for title, needs_target in _RECON_PLAYBOOK:
        if title in _ACTIVE_TITLES and not scope.allow_active:
            # Active steps are planned but parked as not-applicable until the
            # scope file explicitly allows active work.
            root.add(title + " [parked: scope.allow_active is false]",
                     status="not applicable")
            continue
        root.add(title, status=STATUS_TODO, target=target if needs_target else "")
    return root


def expand_recon_task(scope: Scope, node: PTTNode) -> list:
    """Expand one to-do recon task into concrete sub-steps, scope-checked.

    Returns the created child nodes. Raises ScopeGateError if the node's
    target is out of scope.
    """
    if node.target:
        decision = scope.check(node.target)
        if not decision.allowed:
            raise ScopeGateError(
                f"task {node.number} target refused by scope: {decision.reason}"
            )
    steps = {
        "Subdomain enumeration": [
            "Run passive subdomain enumeration (dry-run first)",
            "Deduplicate and validate names against scope",
            "Record surviving subdomains as findings",
        ],
        "DNS record review": [
            "Collect A/AAAA records for in-scope names",
            "Collect MX/TXT/NS records for the base domain",
            "Note dangling or unexpected records",
        ],
        "Web service fingerprinting": [
            "Probe in-scope hosts with httpx (status, title, tech)",
            "Flag unusual status codes and exposed panels",
        ],
    }
    children = []
    for prefix, substeps in steps.items():
        if node.title.startswith(prefix):
            for sub in substeps:
                children.append(
                    node.add(sub, status=STATUS_TODO, target=node.target)
                )
            break
    return children


def gate_llm_revision(scope: Scope, revised_text: str) -> PTTNode:
    """Parse an LLM-proposed PTT revision and refuse out-of-scope additions.

    The LLM may reorder, reword and mark statuses, but any task whose title
    mentions a host or address that fails the scope check is rejected, and
    any non-reconnaissance stage (exploitation, post-exploitation, brute
    force, persistence, evasion) is rejected outright.
    """
    tree = parse_ptt(revised_text)
    banned = (
        "exploit", "post-exploitation", "brute", "password spray",
        "persistence", "privesc", "privilege escalation", "evasion",
        "lateral movement", "payload", "shell upload", "reverse shell",
        "credential", "phish",
    )
    import re as _re
    hostish = _re.compile(
        r"(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)|(?:\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)",
        _re.IGNORECASE,
    )
    for node in tree.walk():
        lowered = node.title.lower()
        for word in banned:
            if word in lowered:
                raise ScopeGateError(
                    f"LLM revision contained a non-reconnaissance task "
                    f"({node.number}: {node.title!r}); refused"
                )
        for match in hostish.findall(node.title):
            if match.lower() in ("e.g",):
                continue
            decision = scope.check(match)
            if not decision.allowed:
                raise ScopeGateError(
                    f"LLM revision referenced out-of-scope target {match!r} "
                    f"in task {node.number}; refused ({decision.reason})"
                )
    return tree
