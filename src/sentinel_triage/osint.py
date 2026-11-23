"""Passive OSINT query builders.

Pure functions: they return URLs and query strings for public data sources.
Nothing here performs network access; opening the URLs is the operator's
choice, which keeps the default workflow fully offline and audit-friendly.
Each builder validates that the requested subject is inside the loaded
scope first, so the module cannot be used to profile arbitrary third
parties.
"""

from __future__ import annotations

from urllib.parse import quote

from .scope import Scope


class OsintError(PermissionError):
    pass


def _gated(scope: Scope, subject: str) -> None:
    decision = scope.check(subject)
    if not decision.allowed:
        raise OsintError(f"OSINT subject refused by scope: {decision.reason}")


def crt_sh_url(scope: Scope, domain: str) -> str:
    """Certificate Transparency log search for subdomains of a scoped domain."""
    _gated(scope, domain)
    return f"https://crt.sh/?q=%25.{quote(domain)}&output=json"


def securitytrails_url(scope: Scope, domain: str) -> str:
    _gated(scope, domain)
    return f"https://securitytrails.com/domain/{quote(domain)}/dns"


def github_code_dork(scope: Scope, domain: str) -> str:
    """Search-engine dork for accidental public mentions of a scoped domain."""
    _gated(scope, domain)
    return f'"{domain}" site:github.com'


def google_dork(scope: Scope, domain: str, kind: str = "indexable") -> str:
    _gated(scope, domain)
    kinds = {
        "indexable": f"site:{domain}",
        "documents": f"site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx",
        "login-pages": f"site:{domain} inurl:login OR inurl:signin OR inurl:portal",
        "errors": f"site:{domain} intitle:\"index of\" OR \"error\" OR \"warning\"",
    }
    if kind not in kinds:
        raise OsintError(f"unknown dork kind {kind!r}; choose from {sorted(kinds)}")
    return kinds[kind]


def wayback_url(scope: Scope, domain: str) -> str:
    _gated(scope, domain)
    return f"https://web.archive.org/cdx/search/cdx?url={quote(domain)}/*&output=text&collapse=urlkey&limit=200"


def build_osint_plan(scope: Scope, subject: str = "") -> list:
    """Return (label, value) pairs for the standard passive OSINT checklist."""
    subject = subject or (scope.domains[0] if scope.domains else "")
    if not subject:
        return []
    return [
        ("Certificate Transparency subdomains", crt_sh_url(scope, subject)),
        ("SecurityTrails DNS history", securitytrails_url(scope, subject)),
        ("Wayback Machine URL index", wayback_url(scope, subject)),
        ("GitHub code mentions", github_code_dork(scope, subject)),
        ("Indexed pages", google_dork(scope, subject, "indexable")),
        ("Exposed documents", google_dork(scope, subject, "documents")),
        ("Login portals", google_dork(scope, subject, "login-pages")),
    ]
