"""Offline tests for the scope-enforcing egress proxy and live argv rules.

No real DNS or outbound network is used: resolvers are stubs and outbound
connects are monkeypatched or point at nothing routable.
"""

import socket

import pytest

from sentinel_triage.egress import EgressProxy
from sentinel_triage.recon import nmap_live_argv, run, ReconError
from sentinel_triage.scope import Scope


def stub_resolver(mapping):
    def resolve(host):
        if host not in mapping:
            raise OSError(f"unknown host {host}")
        import ipaddress
        return [ipaddress.ip_address(a) for a in mapping[host]]
    return resolve


def domain_scope(**kw):
    return Scope.from_dict(dict({"targets": ["allowed.example"]}, **kw))


def raw_http(proxy_url, request: bytes) -> bytes:
    host, port = proxy_url[len("http://"):].split(":")
    with socket.create_connection((host, int(port)), timeout=5) as s:
        s.sendall(request)
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    return out


class TestEgressProxy:
    def test_out_of_scope_connect_denied(self):
        scope = domain_scope()
        with EgressProxy(scope, resolver=stub_resolver({})) as proxy:
            resp = raw_http(proxy.url, b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 403")
        assert proxy.denied and "evil.example" in proxy.denied[0][0]

    def test_in_scope_excluded_subdomain_denied(self):
        scope = domain_scope(exclusions=["admin.allowed.example"])
        with EgressProxy(scope, resolver=stub_resolver({})) as proxy:
            resp = raw_http(proxy.url,
                            b"CONNECT admin.allowed.example:443 HTTP/1.1\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 403")

    def test_forbidden_resolution_denied(self):
        scope = domain_scope()
        resolver = stub_resolver({"allowed.example": ["169.254.169.254"]})
        with EgressProxy(scope, resolver=resolver) as proxy:
            resp = raw_http(proxy.url,
                            b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 403")
        assert "forbidden address" in proxy.denied[0][1]

    def test_disallowed_port_denied(self):
        scope = domain_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        with EgressProxy(scope, resolver=resolver) as proxy:
            resp = raw_http(proxy.url, b"CONNECT allowed.example:22 HTTP/1.1\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 403")
        assert "port" in proxy.denied[0][1]

    def test_allow_path_dials_validated_ip(self, monkeypatch):
        """The proxy must connect to the DNS-validated address, not re-resolve."""
        scope = domain_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        dialed = {}
        real_create_connection = socket.create_connection

        def fake_create_connection(address, timeout=None):
            if address[0] in ("127.0.0.1", "::1"):
                return real_create_connection(address, timeout=timeout)
            dialed["address"] = address
            raise OSError("offline test: no real upstream")

        monkeypatch.setattr(socket, "create_connection", fake_create_connection)
        with EgressProxy(scope, resolver=resolver) as proxy:
            resp = raw_http(proxy.url,
                            b"CONNECT allowed.example:443 HTTP/1.1\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 502")  # allowed, upstream unreachable
        assert dialed["address"] == ("93.184.216.34", 443)

    def test_plain_http_out_of_scope_denied(self):
        scope = domain_scope()
        with EgressProxy(scope, resolver=stub_resolver({})) as proxy:
            resp = raw_http(
                proxy.url,
                b"GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n")
        assert resp.startswith(b"HTTP/1.1 403")


class TestNmapLiveArgv:
    def test_uses_validated_ips_not_hostname(self):
        scope = domain_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        argv = nmap_live_argv(scope, "allowed.example", resolver=resolver)
        assert "93.184.216.34" in argv
        assert "allowed.example" not in argv
        assert "--script" not in argv and "-A" not in argv

    def test_out_of_scope_refused(self):
        scope = domain_scope()
        with pytest.raises(ReconError):
            nmap_live_argv(scope, "evil.example", resolver=stub_resolver({}))

    def test_address_cap_refuses(self):
        scope = domain_scope()
        many = [f"93.184.216.{i}" for i in range(1, 12)]
        resolver = stub_resolver({"allowed.example": many})
        with pytest.raises(ReconError):
            nmap_live_argv(scope, "allowed.example", resolver=resolver)


def enable_live(monkeypatch, name):
    """Re-enable a plugin's live path for wiring tests only."""
    import dataclasses
    from sentinel_triage import recon
    patched = [dataclasses.replace(p, live_enabled=True, live_disabled_reason="")
               if p.name == name else p for p in recon.REGISTRY]
    monkeypatch.setattr(recon, "REGISTRY", patched)


class _Proc:
    returncode = 0
    stdout = ""
    stderr = ""


class TestRunProxyWiring:
    def _active_scope(self):
        return Scope.from_dict({
            "targets": ["allowed.example"], "allow_active": True})

    def test_web_plugin_gets_proxy_flag(self, monkeypatch):
        scope = self._active_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        captured = {}
        monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
        import subprocess
        def fake_run(argv, **kw):
            captured["argv"] = argv
            return _Proc()
        monkeypatch.setattr(subprocess, "run", fake_run)

        results = run(scope, plugin_names=["httpx"], execute=True,
                      resolver=resolver)
        assert results[0].ran
        argv = captured["argv"]
        assert "-proxy" in argv
        assert argv[argv.index("-proxy") + 1].startswith("http://127.0.0.1:")

    def test_web_plugin_fails_closed_without_proxy(self, monkeypatch):
        scope = self._active_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
        monkeypatch.setattr(EgressProxy, "start",
                            lambda self: (_ for _ in ()).throw(OSError("no bind")))

        results = run(scope, plugin_names=["httpx"], execute=True,
                      resolver=resolver)
        assert not results[0].ran
        assert "egress proxy unavailable" in results[0].skipped_reason

    def test_nmap_runs_with_ip_argv(self, monkeypatch):
        scope = self._active_scope()
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        captured = {}
        monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
        import subprocess
        def fake_run(argv, **kw):
            captured["argv"] = argv
            return _Proc()
        monkeypatch.setattr(subprocess, "run", fake_run)

        results = run(scope, plugin_names=["nmap-services"], execute=True,
                      resolver=resolver)
        assert results[0].ran
        assert captured["argv"][-1] == "93.184.216.34"
        assert "allowed.example" not in captured["argv"]


class TestLiveDisabledPlugins:
    def test_nuclei_live_refused_even_with_execute(self):
        scope = Scope.from_dict({
            "targets": ["allowed.example"], "allow_active": True})
        resolver = stub_resolver({"allowed.example": ["93.184.216.34"]})
        results = run(scope, plugin_names=["nuclei-tech"], execute=True,
                      resolver=resolver)
        assert not results[0].ran
        assert "live disabled" in results[0].skipped_reason
        assert "pinned" in results[0].skipped_reason

    def test_nuclei_dry_run_marks_live_disabled(self):
        scope = Scope.from_dict({
            "targets": ["allowed.example"], "allow_active": True})
        results = run(scope, plugin_names=["nuclei-tech"], execute=False)
        assert "live execution is disabled" in results[0].skipped_reason
