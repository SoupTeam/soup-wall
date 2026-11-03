"""SOU-205: actual selected CONNECT route and independent socket witnesses."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import select
import socket
import ssl
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sou205_direct_controls", ROOT / "scripts/tests/test_pilot_provider_preflight.py")
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)


class ConnectProxy:
    def __init__(self, *, upstream=None, response=b"HTTP/1.1 200 Connection Established\r\n\r\n",
                 stall=False, on_accept=None):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.upstream = upstream
        self.response = response
        self.stall = stall
        self.on_accept = on_accept
        self.requests = []
        self.receivers = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=4)

    def _serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.socket.accept()
            except (socket.timeout, OSError):
                continue
            with client:
                try:
                    client.settimeout(3)
                    raw = bytearray()
                    while not raw.endswith(b"\r\n\r\n") and len(raw) < 16384:
                        byte = client.recv(1)
                        if not byte:
                            break
                        raw.extend(byte)
                    self.requests.append(bytes(raw))
                    if self.on_accept:
                        self.on_accept()
                    if self.stall:
                        self.stop.wait(3)
                        continue
                    if self.upstream is None:
                        client.sendall(self.response)
                        continue
                    with socket.create_connection(("127.0.0.1", self.upstream), timeout=2) as provider:
                        self.receivers.append(provider.getpeername())
                        client.sendall(self.response)
                        client.setblocking(False)
                        provider.setblocking(False)
                        until = time.monotonic() + 4
                        while not self.stop.is_set() and time.monotonic() < until:
                            ready, _, _ = select.select([client, provider], [], [], .1)
                            for source in ready:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (provider if source is client else client).sendall(data)
                except (OSError, ssl.SSLError):
                    pass


class ProxyPreflight(BASE.Preflight):
    def proxy_check(self, *, seconds=3):
        output = self.cli("--transport", "--proxy-connect", "--timeout-seconds", str(seconds), "--json",
                          timeout=seconds + 6)
        self.assertLessEqual(len(output.stdout), 2048)
        self.assertLessEqual(len(output.stderr), 2048)
        value = json.loads(output.stdout)
        self.assertEqual(output.returncode, {"transport-observed": 0, "refused": 2,
                                            "unavailable": 3, "incomplete": 4}[value["status"]], output.stderr)
        self.assert_private_report(value)
        return value

    def selected_proxy(self, provider, proxy, ca, *, host="localhost", extras=None):
        public = {"HTTPS_PROXY": f"http://127.0.0.1:{proxy.port}"}
        public.update(extras or {})
        self.select(f"https://{host}:{provider.port}/v1", ca=ca, extras=public)

    def test_connect_success_is_selected_route_without_application_bytes(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, ca)
            before = self.snapshot()
            local = self.check()
            self.assertEqual(local["status"], "configuration-valid")
            self.assertFalse(local["network_attempted"])
            self.assertEqual(self.check(transport=True)["reason"], "proxy_route_unsupported")
            self.assertEqual(proxy.requests, [])
            observed = self.proxy_check()
            self.assertEqual((observed["status"], observed["reason"]),
                             ("transport-observed", "proxy_tls_verified"))
            self.assertTrue(proxy.receivers)
            self.assertEqual(proxy.requests, [
                f"CONNECT localhost:{provider.port} HTTP/1.1\r\nHost: localhost:{provider.port}\r\n\r\n".encode()])
            self.assertNotIn(BASE.SECRET.encode(), proxy.requests[0])
            self.assertNotIn(b"Proxy-Authorization", proxy.requests[0])
            self.assertNotIn(b"/v1", proxy.requests[0])
            self.assertEqual(before, self.snapshot())
            self.assertNotIn(BASE.SECRET.encode(), b"".join(BASE.APPLICATION_PAYLOADS))
            self.assertEqual(BASE.APPLICATION_PAYLOADS, [])

    def test_proxy_auth_required_never_contacts_provider(self):
        ca, cert, key = self.certificates()
        response = b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="private"\r\n\r\n'
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(response=response) as proxy, \
                ConnectProxy(upstream=provider.port) as alternate:
            self.selected_proxy(provider, proxy, ca)
            outcome = self.proxy_check()
            self.assertEqual((outcome["status"], outcome["reason"]), ("refused", "proxy_auth_required"))
            self.assertEqual(provider.received, [])
            self.assertEqual(proxy.receivers, [])
            self.assertEqual(alternate.requests, [])

    def test_proxy_redirect_is_refused_without_following_receiver(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, BASE.Listener() as receiver, \
                ConnectProxy(response=f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{receiver.port}/\r\n\r\n".encode()) as proxy:
            self.selected_proxy(provider, proxy, ca)
            outcome = self.proxy_check()
            self.assertEqual(outcome["reason"], "proxy_redirect_refused")
            self.assertEqual(receiver.received, [])
            self.assertEqual(provider.received, [])

    def test_proxy_oversized_response_is_refused(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, \
                ConnectProxy(response=b"HTTP/1.1 200 OK\r\nX-Fill: " + b"a" * 9000 + b"\r\n\r\n") as proxy:
            self.selected_proxy(provider, proxy, ca)
            self.assertEqual(self.proxy_check()["reason"], "proxy_response_oversized")
            self.assertEqual(provider.received, [])

    def test_proxy_body_or_malformed_response_is_refused(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, \
                ConnectProxy(response=b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789") as proxy:
            self.selected_proxy(provider, proxy, ca)
            self.assertEqual(self.proxy_check()["reason"], "proxy_response_invalid")
            self.assertEqual(provider.received, [])

    def test_proxy_lf_only_response_is_refused(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, \
                ConnectProxy(response=b"HTTP/1.1 200 OK\n\n") as proxy:
            self.selected_proxy(provider, proxy, ca)
            self.assertEqual(self.proxy_check()["reason"], "proxy_response_invalid")
            self.assertEqual(provider.received, [])

    def test_proxy_tunnel_refusal_and_no_direct_fallback(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, \
                ConnectProxy(response=b"HTTP/1.1 503 Unavailable\r\n\r\n") as proxy:
            self.selected_proxy(provider, proxy, ca)
            self.assertEqual(self.proxy_check()["reason"], "proxy_tunnel_refused")
            self.assertEqual(provider.received, [])

    def test_proxy_timeout_is_bounded_and_reaped(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(stall=True) as proxy:
            self.selected_proxy(provider, proxy, ca)
            start = time.monotonic()
            outcome = self.proxy_check(seconds=1)
            self.assertEqual(outcome["status"], "incomplete")
            self.assertLess(time.monotonic() - start, 4)
            self.assertEqual(provider.received, [])

    def test_provider_tls_stall_through_tunnel_is_bounded(self):
        ca, _, _ = self.certificates()
        with BASE.Listener(stall=True) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, ca)
            start = time.monotonic()
            outcome = self.proxy_check(seconds=1)
            self.assertEqual((outcome["status"], outcome["stage"]), ("incomplete", "tls"))
            self.assertLess(time.monotonic() - start, 4)

    def test_proxy_connection_failure_is_distinct(self):
        ca, cert, key = self.certificates()
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            port = unused.getsockname()[1]
        with BASE.Listener(cert=cert, key=key) as provider:
            self.select(f"https://localhost:{provider.port}/v1", ca=ca,
                        extras={"HTTPS_PROXY": f"http://127.0.0.1:{port}"})
            self.assertEqual(self.proxy_check()["reason"], "proxy_connect_failed")
            self.assertEqual(provider.received, [])

    def test_proxy_tls_wrong_hostname_refuses_substitution(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, ca, host="127.0.0.1")
            outcome = self.proxy_check()
            self.assertEqual((outcome["status"], outcome["reason"]), ("refused", "tls_invalid"))
            self.assertTrue(proxy.receivers)

    def test_proxy_substituted_upstream_with_wrong_ca_is_refused(self):
        ca, cert, key = self.certificates()
        _, wrong_cert, wrong_key = self.certificates(expired=True)
        with BASE.Listener(cert=cert, key=key) as selected, \
                BASE.Listener(cert=wrong_cert, key=wrong_key) as substituted, \
                ConnectProxy(upstream=substituted.port) as proxy:
            self.selected_proxy(selected, proxy, ca)
            outcome = self.proxy_check()
            self.assertEqual((outcome["status"], outcome["reason"]), ("refused", "tls_invalid"))
            self.assertTrue(proxy.receivers)
            self.assertEqual(selected.received, [])

    def test_proxy_tls_wrong_ca_refuses(self):
        _, cert, key = self.certificates()
        wrong, _, _ = self.certificates(expired=True)
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, wrong)
            self.assertEqual(self.proxy_check()["reason"], "tls_invalid")

    def test_proxy_tls_expired_certificate_refuses(self):
        ca, cert, key = self.certificates(expired=True)
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, ca)
            self.assertEqual(self.proxy_check()["reason"], "tls_invalid")

    def test_authenticated_proxy_url_is_refused_before_network(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider:
            with self.assertRaises(BASE.PROFILES.Refusal):
                self.select(f"https://localhost:{provider.port}/v1", ca=ca,
                            extras={"HTTPS_PROXY": "http://synthetic:secret@127.0.0.1:8118"})
            self.assertEqual(provider.received, [])

    def test_proxy_opt_in_and_unsupported_scheme_are_local_refusals(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider:
            self.select(f"https://localhost:{provider.port}/v1", ca=ca,
                        extras={"HTTPS_PROXY": "https://127.0.0.1:8118"})
            alone = self.cli("--proxy-connect", "--json")
            self.assertEqual(json.loads(alone.stdout)["reason"], "proxy_opt_in_required")
            self.assertEqual(self.proxy_check()["reason"], "proxy_route_unsupported")
            self.assertEqual(provider.received, [])

    def test_proxy_unselected_or_ambiguous_route_is_local_only(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider, ConnectProxy(upstream=provider.port) as proxy:
            self.selected_proxy(provider, proxy, ca, extras={"NO_PROXY": "localhost"})
            self.assertEqual(self.proxy_check()["reason"], "proxy_route_unsupported")
            self.assertEqual(proxy.requests, [])
            self.assertEqual(provider.received, [])

    def test_proxy_selection_change_refuses_success(self):
        ca, cert, key = self.certificates()
        with BASE.Listener(cert=cert, key=key) as provider:
            def change():
                selected = self.home / BASE.PROFILES.DIRECTORY / "owned.json"
                raw = selected.read_bytes()
                selected.write_bytes(raw.replace(b"synthetic-model", b"changed-modelxx"))
            with ConnectProxy(upstream=provider.port, on_accept=change) as proxy:
                self.selected_proxy(provider, proxy, ca)
                outcome = self.proxy_check()
                self.assertEqual((outcome["status"], outcome["reason"]), ("refused", "selection_changed"))

    def test_worker_proxy_dns_failure_is_finite(self):
        captured = []
        with mock.patch.object(BASE.PREFLIGHT.socket, "getaddrinfo", side_effect=socket.gaierror):
            result = BASE.PREFLIGHT._proxy_probe(
                {"proxy_host": "missing.example", "proxy_port": 80, "host": "localhost", "port": 443,
                 "ca": None}, time.monotonic() + 1, lambda stage: captured.append(stage),
                lambda status, stage, reason: (status, stage, reason))
        self.assertEqual(result, ("unavailable", "proxy_dns", "proxy_dns_failed"))
        self.assertEqual(captured, ["proxy_dns"])


if __name__ == "__main__":
    unittest.main()
