"""Engagement scope parsing and enforcement.

Every live (network-touching) action in sentinel passes through this module.
The rule set is intentionally simple and fail-closed:

* A scope file lists in-scope targets (domains, IPs, CIDR ranges, URLs) and
  optional exclusions. Exclusions always win.
* Domain rules match the exact domain and its subdomains. They never match
  unrelated look-alike domains (``example.com`` does not allow
  ``notexample.com`` or ``example.com.evil.net``).
* Nothing is "in scope" until a rule matches; the default is deny.
* Live execution additionally re-checks the *resolved* IP addresses of the
  target at run time, so a scoped domain that resolves to an out-of-scope
  address is refused at execution time, not just at parse time.

The module performs no network access itself except in
:func:`resolve_and_check`, which is only called on the live path.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a scope file is malformed or a target check fails hard."""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    matched_rule: str = ""


def _host_of(raw: str) -> str:
    """Extract a bare host (or IP literal) from a target string."""
    raw = raw.strip()
    if not raw:
        raise ScopeError("empty target")
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    else:
        # Allow bare domains/IPs and host:port forms.
        host = raw.split("/")[0].split(":")[0]
    host = host.strip(".").lower()
    if not host:
        raise ScopeError(f"could not extract a host from target: {raw!r}")
    return host


def _as_ip(text: str):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


@dataclass
class Scope:
    """Parsed engagement scope."""

    engagement: str = ""
    domains: tuple = ()       # bare domains, match subdomains
    networks: tuple = ()      # ipaddress networks (single IPs become /32, /128)
    excluded_domains: tuple = ()
    excluded_networks: tuple = ()
    allow_active: bool = False
    notes: str = ""
    raw: dict = field(default_factory=dict)

    # -- parsing ---------------------------------------------------------

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        if path.endswith((".yaml", ".yml")):
            data = _parse_minimal_yaml(text)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ScopeError(
                    f"scope file is not valid JSON ({exc}); use JSON, or a "
                    "minimal YAML subset (key: value / lists)"
                )
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        if not isinstance(data, dict):
            raise ScopeError("scope file must contain an object at the top level")
        targets = data.get("targets") or []
        exclusions = data.get("exclusions") or []
        if not isinstance(targets, list) or not targets:
            raise ScopeError("scope must list at least one target")
        domains, networks = _split_rules(targets)
        ex_domains, ex_networks = _split_rules(exclusions)
        return cls(
            engagement=str(data.get("engagement", "")),
            domains=tuple(domains),
            networks=tuple(networks),
            excluded_domains=tuple(ex_domains),
            excluded_networks=tuple(ex_networks),
            allow_active=bool(data.get("allow_active", False)),
            notes=str(data.get("notes", "")),
            raw=data,
        )

    # -- checks ----------------------------------------------------------

    def check(self, target: str) -> Decision:
        """Static check of a target string against the scope rules."""
        try:
            host = _host_of(target)
        except ScopeError as exc:
            return Decision(False, str(exc))
        ip = _as_ip(host)

        # Exclusions win, always.
        if ip is not None:
            for net in self.excluded_networks:
                if ip in net:
                    return Decision(False, f"excluded by {net}", f"!{net}")
        else:
            for dom in self.excluded_domains:
                if _domain_match(host, dom):
                    return Decision(False, f"excluded by {dom}", f"!{dom}")

        if ip is not None:
            for net in self.networks:
                if ip in net:
                    return Decision(True, f"allowed by {net}", str(net))
            return Decision(False, f"no scope rule matches address {ip}")
        for dom in self.domains:
            if _domain_match(host, dom):
                return Decision(True, f"allowed by {dom}", dom)
        return Decision(False, f"no scope rule matches host {host}")

    def resolve_and_check(self, target: str, resolver=None) -> Decision:
        """Live-path check: static rule match plus DNS resolution re-check.

        A scoped domain whose DNS answer points outside the scoped networks
        is refused unless the scope is purely domain-based (the common bug
        bounty case, where the operator owns whatever the name resolves to
        today). When the scope contains network rules, every resolved address
        must additionally fall inside them. Resolution failure is a refusal.
        """
        return self.resolve_checked(target, resolver=resolver)[0]

    def resolve_checked(self, target: str, resolver=None):
        """resolve_and_check that also returns the validated addresses.

        Callers that open connections (the egress proxy, the nmap plugin)
        must dial one of the returned addresses instead of resolving the
        hostname again: the addresses are exactly what this check approved,
        so a DNS answer that changes after the check cannot redirect the
        connection elsewhere (no TOCTOU / DNS-rebinding window). The list
        is empty whenever the decision is a refusal.
        """
        static = self.check(target)
        if not static.allowed:
            return static, []
        host = _host_of(target)
        literal = _as_ip(host)
        if literal is not None:
            return static, [literal]  # literal IP already validated
        resolver = resolver or _default_resolver
        try:
            addresses = sorted(set(resolver(host)))
        except OSError as exc:
            return Decision(False, f"DNS resolution failed for {host}: {exc}"), []
        if not addresses:
            return Decision(False, f"DNS returned no addresses for {host}"), []
        unsafe = [
            a for a in addresses
            if any(a in net for net in _ALWAYS_DENIED_RESOLUTIONS)
        ]
        if unsafe:
            return Decision(
                False,
                f"{host} resolves to a forbidden address "
                f"({', '.join(str(a) for a in unsafe)}); refusing - this "
                "looks like DNS rebinding or misconfiguration",
            ), []
        if not self.networks:
            return static, list(addresses)  # domain-scoped: name match rules
        bad = [a for a in addresses if not any(a in n for n in self.networks)]
        if bad:
            return Decision(
                False,
                f"{host} resolves outside scoped networks: "
                + ", ".join(str(a) for a in bad),
            ), []
        return Decision(
            True,
            f"allowed by {static.matched_rule}; all {len(addresses)} resolved "
            "addresses inside scoped networks",
        ), list(addresses)


# Resolutions to these ranges are never legitimate for a scoped public
# engagement and indicate DNS rebinding or misconfiguration. They are
# refused for domain targets even in domain-only scopes. (Explicitly
# scoped *literal* IPs and networks are unaffected: lab scopes like
# 10.0.0.0/24 still work, because those never go through DNS.)
_ALWAYS_DENIED_RESOLUTIONS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
        "::1/128", "ff00::/8", "fe80::/10",
    )
)


def _default_resolver(host: str):
    results = socket.getaddrinfo(host, None)
    return sorted({ipaddress.ip_address(r[4][0]) for r in results})


def _domain_match(host: str, rule: str) -> bool:
    return host == rule or host.endswith("." + rule)


def _split_rules(entries):
    domains, networks = [], []
    for entry in entries:
        text = str(entry).strip()
        bare = text.split("://")[-1] if "://" in text else text
        if "/" in bare and not bare.split("/", 1)[1].startswith("/") and _as_ip(
            bare.split("/", 1)[0]
        ) is not None:
            try:
                networks.append(ipaddress.ip_network(bare, strict=False))
            except ValueError as exc:
                raise ScopeError(f"invalid network rule {entry!r}: {exc}")
            continue
        host = _host_of(text)
        ip = _as_ip(host)
        if ip is not None:
            networks.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
        else:
            if any(ch in host for ch in "*?"):
                raise ScopeError(
                    f"wildcards are not supported in scope rules: {entry!r}; "
                    "list the bare domain instead (subdomains are included)"
                )
            domains.append(host)
    return domains, networks


def _parse_minimal_yaml(text: str) -> dict:
    """Parse a strict, small YAML subset: flat keys and one nested list level.

    Supported shape::

        engagement: name
        allow_active: false
        targets:
          - example.com
          - 10.0.0.0/24
        exclusions:
          - admin.example.com

    Anything more complex (nested maps, anchors, multiline strings) raises
    ScopeError so nothing is silently misparsed.
    """
    data: dict = {}
    current_list = None
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        if stripped.lstrip().startswith("- "):
            if current_list is None:
                raise ScopeError(f"line {lineno}: list item without a key")
            current_list.append(stripped.lstrip()[2:].strip())
            continue
        if ":" not in stripped:
            raise ScopeError(f"line {lineno}: unsupported YAML syntax: {line!r}")
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        current_list = None
        if value == "":
            data[key] = []
            current_list = data[key]
        elif value.lower() in ("true", "false"):
            data[key] = value.lower() == "true"
        else:
            data[key] = value.strip("\"'")
    return data
