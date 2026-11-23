"""Scope-enforcing local egress proxy for live recon plugins.

The active web plugins (httpx, katana, nuclei) accept a ``-proxy`` flag.
Sentinel points that flag at a loopback-only proxy it controls, and the
proxy is where engagement scope is enforced at connect time:

* Every CONNECT or absolute-URI request names a destination host. The
  proxy runs the full live scope check (static rules plus a fresh DNS
  re-check via :meth:`Scope.resolve_checked`) and answers 403 for
  anything out of scope.
* When the check passes, the proxy dials one of the *validated* addresses
  itself instead of resolving the name again. A DNS answer that flips
  after the check cannot redirect the connection elsewhere, so the
  TOCTOU / DNS-rebinding window is closed.
* Redirects to out-of-scope hosts die at the proxy, because each redirect
  is a new request that the tool sends through the proxy again.

Only web ports (80, 443, 8080, 8443) are accepted, requests from anything
other than loopback are refused, and the proxy speaks just enough
HTTP/1.1 to tunnel CONNECT and forward plain HTTP. It is not a
general-purpose proxy and is never exposed to the network.

Passive plugins (subfinder, amass-passive, dig, whois) do not use this
proxy: they talk to public resolvers and passive data sources, not to
the target, so their egress is the point of running them.
"""

from __future__ import annotations

import select
import socket
import socketserver
import sys

from .scope import Scope, _host_of

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_HEADER_BYTES = 65536
BUFFER = 65536


class EgressError(RuntimeError):
    pass


def _read_head(sock) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(BUFFER)
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_HEADER_BYTES:
            raise EgressError("request headers too large")
    return data


def _relay(a, b) -> None:
    """Bidirectional copy until both sides close."""
    sockets = [a, b]
    try:
        while True:
            readable, _, _ = select.select(sockets, [], [], 300)
            if not readable:
                break
            done = True
            for src in readable:
                try:
                    data = src.recv(BUFFER)
                except OSError:
                    return
                if data:
                    done = False
                    dst = b if src is a else a
                    try:
                        dst.sendall(data)
                    except OSError:
                        return
            if done:
                return
    finally:
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass


class _Handler(socketserver.BaseRequestHandler):
    def _deny(self, status: str, host: str, reason: str) -> None:
        body = f"sentinel egress proxy: {reason}\n".encode()
        self.server.proxy.denied.append((host, reason))
        try:
            self.request.sendall(
                f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n".encode() + body
            )
        except OSError:
            pass
        print(f"[egress-proxy] DENIED {host}: {reason}", file=sys.stderr)

    def _dial(self, host: str, port: int):
        """Scope-check host and connect to a validated address."""
        if port not in ALLOWED_PORTS:
            self._deny("403 Forbidden", f"{host}:{port}",
                       f"port {port} is not in the allowed web port set")
            return None
        decision, addresses = self.server.proxy.scope.resolve_checked(
            host, resolver=self.server.proxy.resolver)
        if not decision.allowed:
            self._deny("403 Forbidden", host, decision.reason)
            return None
        try:
            return socket.create_connection((str(addresses[0]), port), timeout=30)
        except OSError as exc:
            self._deny("502 Bad Gateway", host, f"upstream connect failed: {exc}")
            return None

    def handle(self) -> None:
        client_ip = self.client_address[0]
        if client_ip != "127.0.0.1" and client_ip != "::1":
            return  # loopback only; drop silently
        try:
            head = _read_head(self.request)
        except (OSError, EgressError):
            return
        if not head:
            return
        try:
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1")
            method, target, _version = first_line.split(" ", 2)
        except ValueError:
            return
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            try:
                port = int(port_text)
            except ValueError:
                port = 0
            upstream = self._dial(host, port)
            if upstream is None:
                return
            try:
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except OSError:
                upstream.close()
                return
            _relay(self.request, upstream)
            return
        # Plain HTTP with an absolute URI (proxy-style request).
        if not target.lower().startswith("http://"):
            self._deny("400 Bad Request", target,
                       "only CONNECT and plain http:// proxy requests are supported")
            return
        rest = target[len("http://"):]
        authority, _, path = rest.partition("/")
        host, _, port_text = authority.partition(":")
        try:
            port = int(port_text) if port_text else 80
        except ValueError:
            port = 0
        upstream = self._dial(host, port)
        if upstream is None:
            return
        # Rewrite to origin form, drop proxy headers, force close semantics.
        lines = head.split(b"\r\n")
        out_lines = [f"{method} /{path} {lines[0].split(b' ')[-1].decode('latin-1')}".encode()]
        for line in lines[1:]:
            if not line:
                continue
            lowered = line.lower()
            if lowered.startswith(b"proxy-connection:") or lowered.startswith(b"connection:"):
                continue
            out_lines.append(line)
        out_lines.append(b"Connection: close")
        try:
            upstream.sendall(b"\r\n".join(out_lines) + b"\r\n\r\n")
            while True:
                chunk = upstream.recv(BUFFER)
                if not chunk:
                    break
                self.request.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                upstream.close()
            except OSError:
                pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class EgressProxy:
    """Context manager: start the loopback proxy, get its URL, stop it."""

    def __init__(self, scope: Scope, resolver=None, host: str = "127.0.0.1",
                 port: int = 0):
        self.scope = scope
        self.resolver = resolver
        self.host = host
        self.requested_port = port
        self.denied: list = []  # (host, reason) pairs, for reporting/tests
        self._server = None

    def start(self) -> "EgressProxy":
        self._server = _Server((self.host, self.requested_port), _Handler)
        self._server.proxy = self
        import threading
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    @property
    def url(self) -> str:
        if self._server is None:
            raise EgressError("proxy not started")
        port = self._server.server_address[1]
        return f"http://{self.host}:{port}"

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "EgressProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()
