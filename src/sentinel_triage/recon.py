"""Recon tool orchestration with hard safety gates.

This module runs *other people's* open-source tools so the operator does not
have to hand-assemble commands. It is deliberately not a generic tool
runner:

* A fixed plugin registry. Every plugin builds its argv from allowlisted,
  documented flags. There is no way to pass arbitrary flags from the CLI.
* No shell. Commands are executed as argv lists; shell metacharacters in a
  target can never reach a shell, and targets beginning with ``-`` (option
  injection) are refused.
* Dry-run by default. Without ``--execute`` the module only prints the
  exact commands it would run.
* Live execution requires the target to pass both the static scope check
  and the run-time DNS re-check (``Scope.resolve_checked``), and active
  plugins additionally require ``allow_active: true`` in the scope file.
* HTTP egress is proxied. The active web plugins (httpx, katana, nuclei)
  are pointed at Sentinel's loopback egress proxy (see ``egress.py``),
  which re-checks scope on every request and dials only DNS-validated
  addresses, so redirects and DNS flips cannot pull a scan out of scope.
  If the proxy cannot start, those plugins are skipped - never run direct.
* nmap cannot use an HTTP proxy, so its live argv contains only the
  validated IP literals from the execution-time DNS check, never the
  hostname; there is nothing left for nmap to resolve. Note that nmap
  service detection sends real probe traffic: it is active scanning of
  in-scope addresses, not a passive or "safe" read.
* Intrusive tooling is out of scope by policy: no exploitation frameworks,
  no brute forcers, no NSE scripts, and nuclei is dry-run only because
  ``-tags tech`` is a moving upstream tag set rather than a pinned,
  reviewed template allowlist.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

from .egress import EgressProxy
from .scope import Scope, Decision, _host_of

_HOSTISH = None  # compiled lazily


def _hostish_re():
    global _HOSTISH
    if _HOSTISH is None:
        import re
        _HOSTISH = re.compile(
            r"(?:\b\d{1,3}(?:\.\d{1,3}){3}\b)"
            r"|(?:\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b)",
            re.IGNORECASE,
        )
    return _HOSTISH


@dataclass
class OutputFinding:
    value: str
    allowed: bool
    reason: str


class ReconError(RuntimeError):
    pass


PASSIVE = "passive"
ACTIVE = "active"


@dataclass(frozen=True)
class Plugin:
    name: str
    binary: str
    category: str
    description: str
    homepage: str
    arg_builder: object        # callable(target) -> list[str]
    proxy_flag: str = ""       # flag used to inject the egress proxy, if any
    live_enabled: bool = True  # False: dry-run/planning only
    live_disabled_reason: str = ""

    def argv(self, target: str) -> list:
        return [self.binary] + list(self.arg_builder(target))


def _validate_target_token(target: str) -> None:
    target = target.strip()
    if not target:
        raise ReconError("empty target")
    if target.startswith("-"):
        raise ReconError(f"target looks like a flag, refusing: {target!r}")
    if any(ch in target for ch in " \t\n;&|`$<>@\\"):
        raise ReconError(f"target contains unsafe characters: {target!r}")


def _subfinder_args(target: str):
    _validate_target_token(target)
    return ["-d", target, "-silent"]


def _amass_args(target: str):
    _validate_target_token(target)
    return ["enum", "-passive", "-d", target]


def _dig_args(target: str):
    _validate_target_token(target)
    return ["+short", "any", target]


def _whois_args(target: str):
    _validate_target_token(target)
    return [target]


def _httpx_args(target: str):
    _validate_target_token(target)
    return ["-u", target, "-silent", "-status-code", "-title", "-tech-detect", "-disable-update-check"]


def _katana_args(target: str):
    _validate_target_token(target)
    # Bounded crawl: depth 2, 30s timeout, no headless, known-safe defaults.
    return ["-u", target, "-d", "2", "-timeout", "30", "-silent", "-disable-update-check"]


def _nmap_args(target: str):
    _validate_target_token(target)
    # Top-100 service detection only. No -A, no --script vuln, no -O,
    # no timing templates above default.
    return ["-sV", "--top-ports", "100", target]


def _nuclei_args(target: str):
    _validate_target_token(target)
    # Technology identification templates only; intrusive, fuzzing,
    # bruteforce and exploit template families are never enabled here.
    # NOTE: -tags tech is a moving upstream tag set, not a pinned and
    # reviewed template allowlist, so this plugin is dry-run only until
    # specific reviewed templates are vendored (see Plugin.live_enabled).
    return ["-u", target, "-tags", "tech", "-silent", "-no-interactsh",
            "-disable-update-check"]


REGISTRY = [
    Plugin("subfinder", "subfinder", PASSIVE,
           "Passive subdomain enumeration", "https://github.com/projectdiscovery/subfinder",
           _subfinder_args),
    Plugin("amass-passive", "amass", PASSIVE,
           "Passive subdomain enumeration (OWASP Amass)",
           "https://github.com/owasp-amass/amass", _amass_args),
    Plugin("dig", "dig", PASSIVE,
           "DNS record lookup", "https://www.isc.org/bind/", _dig_args),
    Plugin("whois", "whois", PASSIVE,
           "Registration data lookup", "https://github.com/rfc1036/whois", _whois_args),
    Plugin("httpx", "httpx", ACTIVE,
           "Web service fingerprinting (status/title/tech)",
           "https://github.com/projectdiscovery/httpx", _httpx_args,
           proxy_flag="-proxy"),
    Plugin("katana", "katana", ACTIVE,
           "Bounded web crawl (depth 2, 30s cap)",
           "https://github.com/projectdiscovery/katana", _katana_args,
           proxy_flag="-proxy"),
    Plugin("nmap-services", "nmap", ACTIVE,
           "Service/version detection, top 100 ports - sends real probe "
           "traffic to open ports; no NSE scripts are enabled",
           "https://nmap.org/", _nmap_args),
    Plugin("nuclei-tech", "nuclei", ACTIVE,
           "Technology-detection templates only (no exploit/fuzz/bruteforce tags)",
           "https://github.com/projectdiscovery/nuclei", _nuclei_args,
           proxy_flag="-p",
           live_enabled=False,
           live_disabled_reason=(
               "nuclei -tags tech selects whatever templates upstream "
               "currently tags tech, which is not a pinned, reviewed "
               "allowlist; live runs stay disabled until specific reviewed "
               "templates are vendored and selected by path")),
]

# Cap on how many validated addresses a hostname may expand to for nmap.
_MAX_LIVE_ADDRS = 8


def nmap_live_argv(scope: Scope, target: str, resolver=None) -> list:
    """Build the nmap argv with validated IP literals, never the hostname.

    nmap speaks raw sockets and cannot use the egress proxy, so the scope
    race is closed differently: the execution-time DNS check runs first
    and only the approved addresses are handed to nmap. nmap resolves
    nothing itself; there is no window where a changed DNS answer could
    redirect the scan.
    """
    decision, addresses = scope.resolve_checked(target, resolver=resolver)
    if not decision.allowed:
        raise ReconError(f"refused at execution time: {decision.reason}")
    if len(addresses) > _MAX_LIVE_ADDRS:
        raise ReconError(
            f"{target} resolved to {len(addresses)} addresses, over the "
            f"{_MAX_LIVE_ADDRS}-address cap; refusing to widen the scan")
    return ["nmap", "-sV", "--top-ports", "100",
            *[str(a) for a in addresses]]


@dataclass
class PlannedCommand:
    plugin: Plugin
    target: str
    argv: list
    gate: Decision


def filter_output(scope: Scope, text: str, resolver=None) -> list:
    """Re-validate host-like tokens discovered in plugin output.

    Tool output is untrusted input, not scope: passive enumerators return
    names that share infrastructure with the target but are not part of
    the engagement, and fingerprints can surface unrelated virtual hosts.
    Every discovered hostname or address is checked against the scope
    (with a live DNS re-check when a resolver is supplied) and labelled
    accordingly, so downstream reporting can drop or quarantine anything
    the scope does not cover.
    """
    seen = {}
    findings = []
    for match in _hostish_re().findall(text or ""):
        token = match.lower()
        if token in seen:
            continue
        try:
            _host_of(token)
        except Exception:
            continue
        seen[token] = True
        if resolver is not None:
            decision = scope.resolve_and_check(token, resolver=resolver)
        else:
            decision = scope.check(token)
        findings.append(OutputFinding(token, decision.allowed, decision.reason))
    return findings


@dataclass
class CommandResult:
    plan: PlannedCommand
    ran: bool = False
    skipped_reason: str = ""
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    discovered: list = field(default_factory=list)  # OutputFinding entries


def plan(scope: Scope, targets=None, plugin_names=None) -> list:
    """Build the planned command list with gate decisions attached."""
    selected = [p for p in REGISTRY if plugin_names is None or p.name in plugin_names]
    plans = []
    for plugin in selected:
        for target in (targets or list(scope.domains) or [str(n) for n in scope.networks]):
            _validate_target_token(target)
            gate = scope.check(target)
            if gate.allowed and plugin.category == ACTIVE and not scope.allow_active:
                gate = Decision(False, "active plugin but scope.allow_active is false")
            plans.append(PlannedCommand(plugin, target, plugin.argv(target), gate))
    return plans


def run(scope: Scope, targets=None, plugin_names=None, execute: bool = False,
        timeout: int = 120, resolver=None) -> list:
    """Plan, then optionally execute. Returns one CommandResult per plan."""
    plans = plan(scope, targets, plugin_names)
    results = [CommandResult(plan=item) for item in plans]
    proxy = None
    needs_proxy = execute and any(
        item.plugin.proxy_flag and item.gate.allowed for item in plans)
    if needs_proxy:
        try:
            proxy = EgressProxy(scope, resolver=resolver).start()
        except OSError as exc:
            proxy = None
            proxy_error = str(exc)
    for item, result in zip(plans, results):
        if not execute:
            if item.gate.allowed:
                note = "dry-run (pass --execute to run)"
                if item.plugin.proxy_flag and item.plugin.live_enabled:
                    note += "; live runs tunnel via the scope-enforcing egress proxy"
                if not item.plugin.live_enabled:
                    note += "; live execution is disabled for this plugin"
                result.skipped_reason = note
            else:
                result.skipped_reason = f"refused by scope: {item.gate.reason}"
            continue
        if not item.gate.allowed:
            result.skipped_reason = f"refused by scope: {item.gate.reason}"
            continue
        if not item.plugin.live_enabled:
            result.skipped_reason = f"live disabled: {item.plugin.live_disabled_reason}"
            continue
        live = scope.resolve_and_check(item.target, resolver=resolver)
        if not live.allowed:
            result.skipped_reason = f"refused at execution time: {live.reason}"
            continue
        if shutil.which(item.plugin.binary) is None:
            result.skipped_reason = f"{item.plugin.binary} not installed"
            continue
        argv = item.argv
        if item.plugin.proxy_flag:
            if proxy is None:
                # Fail closed: web plugins never talk to the target directly.
                result.skipped_reason = (
                    f"egress proxy unavailable ({proxy_error}); refusing to "
                    "run a live web plugin without scope enforcement")
                continue
            argv = argv + [item.plugin.proxy_flag, proxy.url]
        elif item.plugin.name == "nmap-services":
            try:
                argv = nmap_live_argv(scope, item.target, resolver=resolver)
            except ReconError as exc:
                result.skipped_reason = str(exc)
                continue
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            result.skipped_reason = f"timed out after {timeout}s"
            continue
        result.ran = True
        result.returncode = proc.returncode
        result.stdout = proc.stdout
        result.stderr = proc.stderr
        result.discovered = filter_output(scope, proc.stdout, resolver=resolver)
    if proxy is not None:
        proxy.close()
    return results
