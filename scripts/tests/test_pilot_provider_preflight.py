"""Selected installed-provider preflight: local purity and real socket boundaries."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PROFILES = load("preflight_test_profiles", "pilot_provider_profiles.py")
PREFLIGHT = load("preflight_test", "pilot_provider_preflight.py")
SECRET = "SOU193_SYNTHETIC_CREDENTIAL_DO_NOT_SEND"
APPLICATION_PAYLOADS = []


class Listener:
    def __init__(self, *, cert=None, key=None, on_accept=None, stall=False):
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(.1)
        self.port = self.socket.getsockname()[1]
        self.received = []
        self.errors = []
        self.stall = stall
        self.on_accept = on_accept
        self.stop = threading.Event()
        self.context = None
        if cert is not None:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(cert, key)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=2)

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except (socket.timeout, OSError):
                continue
            with connection:
                try:
                    if self.on_accept is not None:
                        self.on_accept()
                    if self.stall:
                        self.stop.wait(3)
                        continue
                    connection.settimeout(2)
                    if self.context is not None:
                        with self.context.wrap_socket(connection, server_side=True) as secure:
                            try:
                                payload = secure.recv(4096)
                                self.received.append(payload)
                                if payload:
                                    APPLICATION_PAYLOADS.append(payload)
                            except ssl.SSLEOFError:
                                # The probe closes after the handshake without
                                # sending an application record or close_notify.
                                self.received.append(b"")
                    else:
                        payload = connection.recv(4096)
                        self.received.append(payload)
                        if payload:
                            APPLICATION_PAYLOADS.append(payload)
                except (OSError, ssl.SSLError) as error:
                    self.errors.append(type(error).__name__)


class Preflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.installed = os.environ.get("SOU193_INSTALLED_AGENTFW")
        if self.installed:
            component = Path(os.environ["SOU193_INSTALLED_COMPONENT"])
            digest = hashlib.sha256(component.read_bytes()).hexdigest()
            result = subprocess.run([self.installed, "pilot-component", "--home", str(self.home),
                                     "install", str(component), "--sha256", digest, "--python",
                                     os.environ["SOU193_INSTALLED_PYTHON"]],
                                    cwd=self.root, env=self.command_environment(),
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace")[:512])

    @staticmethod
    def command_environment():
        return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "PYTHONDONTWRITEBYTECODE": "1"}

    def cli(self, *words, timeout=10):
        if self.installed:
            command = [self.installed, "pilot", "--home", str(self.home), "provider", "check", *words]
        else:
            command = [sys.executable, "-B", str(ROOT / "scripts/pilot.py"),
                       "--agent-home", str(self.home), "provider", "check", *words]
        return subprocess.run(command, cwd=self.root, env=self.command_environment(),
                              capture_output=True, text=True, timeout=timeout)

    def select(self, endpoint, *, ca=None, extras=None):
        public = {"model": "synthetic-model", "ANTHROPIC_BASE_URL": endpoint}
        if ca is not None:
            public["SSL_CERT_FILE"] = str(ca)
        public.update(extras or {})
        with PROFILES.Store(self.home, create=True) as store:
            store.create("owned", public, {"ANTHROPIC_API_KEY": SECRET})
            store.select("owned")

    def snapshot(self):
        return {str(path.relative_to(self.home)): (path.read_bytes(), path.stat().st_mode,
                                                  path.stat().st_mtime_ns)
                for path in self.home.rglob("*") if path.is_file()}

    def check(self, *, transport=False, seconds=3):
        if self.installed:
            words = ["--json", "--timeout-seconds", str(seconds)]
            if transport:
                words.append("--transport")
            outcome = self.cli(*words, timeout=seconds + 6)
            self.assertLessEqual(len(outcome.stdout), 2048)
            self.assertLessEqual(len(outcome.stderr), 2048)
            result = json.loads(outcome.stdout)
            expected = {"configuration-valid": 0, "transport-observed": 0,
                        "refused": 2, "unavailable": 3, "incomplete": 4}
            self.assertEqual(outcome.returncode, expected[result["status"]], outcome.stderr)
            return result
        return PREFLIGHT.check(self.home, PROFILES, transport=transport, seconds=seconds)

    def certificates(self, *, expired=False):
        folder = self.root / ("expired-certs" if expired else "valid-certs")
        folder.mkdir(mode=0o700)
        ca, key, server_key, request, server = (folder / item for item in
                                             ("ca.pem", "ca.key", "server.key", "server.csr", "server.pem"))

        def openssl(*words):
            subprocess.run(["openssl", *map(str, words)], cwd=folder, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=True)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                "-keyout", key, "-out", ca, "-subj", "/CN=SOU193-synthetic-CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", server_key,
                "-out", request, "-subj", "/CN=localhost")
        extension = folder / "extensions"
        extension.write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
        if expired:
            (folder / "index.txt").write_text("")
            (folder / "serial").write_text("01\n")
            (folder / "issued").mkdir()
            configuration = folder / "ca.cnf"
            configuration.write_text(
                "[ca]\ndefault_ca=local\n[local]\n"
                f"dir={folder}\ndatabase=$dir/index.txt\nnew_certs_dir=$dir/issued\n"
                "certificate=$dir/ca.pem\nprivate_key=$dir/ca.key\nserial=$dir/serial\n"
                "default_md=sha256\npolicy=any\nx509_extensions=server\n"
                "[any]\ncommonName=supplied\n[server]\nsubjectAltName=DNS:localhost\n"
                "extendedKeyUsage=serverAuth\n")
            openssl("ca", "-batch", "-config", configuration, "-in", request,
                    "-out", server, "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                    "-notext")
        else:
            openssl("x509", "-req", "-in", request, "-CA", ca, "-CAkey", key,
                    "-set_serial", "1", "-days", "2", "-out", server,
                    "-extfile", extension)
        ca.chmod(0o600)
        return ca, server, server_key

    def assert_private_report(self, result):
        text = json.dumps(result) + PREFLIGHT.human(result)
        self.assertNotIn(SECRET, text)
        self.assertNotIn(str(self.home), text)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)
        self.assertNotIn(hashlib.sha256(SECRET.encode()).hexdigest(), text)
        self.assertFalse(result["credential_validity_verified"])
        self.assertFalse(result["model_availability_verified"])
        self.assertFalse(result["protected_task_execution_verified"])
        self.assertFalse(result["provider_request_sent"])
        self.assertFalse(result["model_or_tool_executed"])

    def test_default_is_pure_local_and_text_json_are_bounded(self):
        with Listener() as server:
            self.select(f"http://127.0.0.1:{server.port}/v1")
            before = self.snapshot()
            with mock.patch.object(PREFLIGHT, "_probe", side_effect=AssertionError("network")):
                result = self.check()
            self.assertEqual(result["status"], "configuration-valid")
            self.assertFalse(result["network_attempted"])
            self.assertEqual(before, self.snapshot())
            self.assertEqual(server.received, [])
            for extra in ([], ["--json"]):
                output = self.cli(*extra)
                self.assertEqual(output.returncode, 0, output.stderr)
                self.assertNotIn(SECRET, output.stdout + output.stderr)
                self.assertNotIn(str(self.home), output.stdout + output.stderr)
                self.assertNotIn("http://", output.stdout + output.stderr)
                if extra:
                    self.assertEqual(json.loads(output.stdout)["status"], "configuration-valid")
                else:
                    self.assertIn("NOT verified", output.stdout)
            self.assertEqual(before, self.snapshot())
            self.assertEqual(server.received, [])

    def test_missing_and_stale_selected_profile_refuse_without_network(self):
        missing = self.check()
        self.assertEqual((missing["status"], missing["reason"]),
                         ("unavailable", "profile_not_selected"))
        self.assertFalse((self.home / PROFILES.DIRECTORY).exists())
        self.select("http://127.0.0.1:9911/v1")
        selected = self.home / PROFILES.DIRECTORY / "owned.json"
        original = selected.read_bytes()
        selected.write_bytes(original.replace(b"9911", b"9912"))
        stale = self.check()
        self.assertEqual((stale["status"], stale["reason"]),
                         ("refused", "selection_invalid"))
        self.assertFalse(stale["network_attempted"])
        self.assertEqual(selected.read_bytes(), original.replace(b"9911", b"9912"))
        self.assert_private_report(stale)

    def test_loopback_tcp_observation_sends_no_http_or_auth(self):
        with Listener() as server:
            self.select(f"http://127.0.0.1:{server.port}/v1", extras={"NO_PROXY": "127.0.0.1"})
            before = self.snapshot()
            real = PREFLIGHT.subprocess.Popen

            class Audited:
                def __init__(self, *args, **kwargs):
                    self.process = real(*args, **kwargs)
                    self.pid = self.process.pid
                    self.stdout = self.process.stdout
                    self.stdin = self.process.stdin

                def communicate(self, data=None, **kwargs):
                    self_outer.assertNotIn(SECRET.encode(), data or b"")
                    return self.process.communicate(data, **kwargs)

                def poll(self):
                    return self.process.poll()

                @property
                def returncode(self):
                    return self.process.returncode

            self_outer = self
            with mock.patch.object(PREFLIGHT.subprocess, "Popen", side_effect=Audited):
                result = PREFLIGHT.check(self.home, PROFILES, transport=True)
            self.assertEqual(result["status"], "transport-observed")
            self.assertEqual(result["stage"], "connect")
            self.assertTrue(result["network_attempted"])
            self.assertEqual(before, self.snapshot())
            self.assert_private_report(result)
        self.assertTrue(server.received, server.errors)
        self.assertTrue(all(payload == b"" for payload in server.received))
        if self.installed:
            with Listener() as installed_server:
                with PROFILES.Store(self.home) as store:
                    version = store.preview_update("owned", {}, False)["version"]
                    store.update("owned", {"ANTHROPIC_BASE_URL":
                                           f"http://127.0.0.1:{installed_server.port}/v1"}, None, version)
                installed_result = self.check(transport=True)
                self.assertEqual(installed_result["status"], "transport-observed")
                self.assert_private_report(installed_result)
            self.assertTrue(installed_server.received)
            self.assertTrue(all(payload == b"" for payload in installed_server.received))

    def test_unreachable_proxy_unsupported_and_missing_endpoint(self):
        with socket.socket() as temporary:
            temporary.bind(("127.0.0.1", 0))
            port = temporary.getsockname()[1]
        self.select(f"http://127.0.0.1:{port}/v1")
        result = self.check(transport=True)
        self.assertEqual((result["status"], result["stage"], result["reason"]),
                         ("unavailable", "connect", "connect_failed"))
        self.assert_private_report(result)
        with PROFILES.Store(self.home) as store:
            value, _ = store.profile("owned")
            current = store.preview_update("owned", {}, False)["version"]
            store.update("owned", {"HTTPS_PROXY": "http://127.0.0.1:9911"}, None, current)
        result = self.check(transport=True)
        self.assertEqual(result["reason"], "proxy_route_unsupported")
        self.assertFalse(result["network_attempted"])
        self.assert_private_report(result)
        with PROFILES.Store(self.home) as store:
            store.create("implicit", {"model": "synthetic-model"},
                         {"ANTHROPIC_API_KEY": "second-synthetic"})
            store.select("implicit")
        self.assertEqual(self.check()["status"], "configuration-valid")
        missing = self.check(transport=True)
        self.assertEqual((missing["status"], missing["reason"]),
                         ("unavailable", "endpoint_not_explicit"))
        self.assertFalse(missing["network_attempted"])

    def test_stalled_tls_is_bounded_and_cancelled_child_is_reaped(self):
        with Listener(stall=True) as server:
            self.select(f"https://127.0.0.1:{server.port}/v1")
            start = time.monotonic()
            result = self.check(transport=True, seconds=1)
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(result["status"], "incomplete")
            self.assertIn(result["stage"], ("tls", "connect"))
            self.assert_private_report(result)

    def test_sigint_cancels_check_with_bounded_report(self):
        accepted = threading.Event()
        with Listener(stall=True, on_accept=accepted.set) as server:
            self.select(f"https://127.0.0.1:{server.port}/v1")
            if self.installed:
                command = [self.installed, "pilot", "--home", str(self.home), "provider", "check",
                           "--transport", "--timeout-seconds", "5", "--json"]
            else:
                command = [sys.executable, "-B", str(ROOT / "scripts/pilot.py"),
                           "--agent-home", str(self.home), "provider", "check", "--transport",
                           "--timeout-seconds", "5", "--json"]
            process = subprocess.Popen(command, cwd=self.root, env=self.command_environment(),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            try:
                self.assertTrue(accepted.wait(2), "probe never reached owned listener")
                os.kill(process.pid, signal.SIGINT)
                output, errors = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 4, errors[:512])
                value = json.loads(output)
                self.assertEqual((value["status"], value["reason"]), ("incomplete", "cancelled"))
                self.assert_private_report(value)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

    def test_tls_valid_ca_wrong_ca_hostname_and_expiry(self):
        ca, cert, key = self.certificates()
        with Listener(cert=cert, key=key) as server:
            self.select(f"https://localhost:{server.port}/v1", ca=ca)
            before = self.snapshot()
            good = self.check(transport=True)
            self.assertEqual((good["status"], good["stage"], good["reason"]),
                             ("transport-observed", "tls", "tls_verified"))
            self.assert_private_report(good)
            self.assertEqual(before, self.snapshot())
            deadline = time.monotonic() + 1
            while not server.received and time.monotonic() < deadline:
                time.sleep(.01)
        self.assertTrue(all(payload == b"" for payload in server.received))

        wrong_ca, expired_cert, expired_key = self.certificates(expired=True)
        # An unrelated trust root cannot validate the earlier server.
        with Listener(cert=cert, key=key) as server:
            with PROFILES.Store(self.home) as store:
                version = store.preview_update("owned", {}, False)["version"]
                store.update("owned", {"SSL_CERT_FILE": str(wrong_ca),
                                       "ANTHROPIC_BASE_URL": f"https://localhost:{server.port}/v1"},
                             None, version)
            wrong = self.check(transport=True)
            self.assertEqual((wrong["status"], wrong["reason"]), ("refused", "tls_invalid"))
            self.assert_private_report(wrong)

        with Listener(cert=cert, key=key) as server:
            with PROFILES.Store(self.home) as store:
                version = store.preview_update("owned", {}, False)["version"]
                store.update("owned", {"SSL_CERT_FILE": str(ca),
                                       "ANTHROPIC_BASE_URL": f"https://127.0.0.1:{server.port}/v1"},
                             None, version)
            mismatch = self.check(transport=True)
            self.assertEqual((mismatch["status"], mismatch["reason"]), ("refused", "tls_invalid"))
            self.assert_private_report(mismatch)

        with Listener(cert=expired_cert, key=expired_key) as server:
            with PROFILES.Store(self.home) as store:
                version = store.preview_update("owned", {}, False)["version"]
                store.update("owned", {"SSL_CERT_FILE": str(wrong_ca),
                                       "ANTHROPIC_BASE_URL": f"https://localhost:{server.port}/v1"},
                             None, version)
            old = self.check(transport=True)
            self.assertEqual((old["status"], old["reason"]), ("refused", "tls_invalid"))
            self.assert_private_report(old)

    def test_selection_changed_after_probe_refuses(self):
        self.select("http://127.0.0.1:9911/v1")

        def switch(*_args, **_kwargs):
            with PROFILES.Store(self.home) as store:
                store.create("other", {"model": "synthetic-model",
                                       "ANTHROPIC_BASE_URL": "http://127.0.0.1:9912/v1"},
                             {"ANTHROPIC_API_KEY": "second-synthetic"})
                store.select("other")
            return PREFLIGHT.report("transport-observed", "connect", "tcp_connected",
                                    transport=True, network=True)

        with mock.patch.object(PREFLIGHT, "_probe", side_effect=switch):
            result = PREFLIGHT.check(self.home, PROFILES, transport=True)
        self.assertEqual((result["status"], result["reason"]), ("refused", "selection_changed"))
        self.assert_private_report(result)

    def test_real_tls_selection_change_is_refused(self):
        ca, cert, key = self.certificates()
        def switch():
            with PROFILES.Store(self.home) as store:
                store.select("other")

        with Listener(cert=cert, key=key, on_accept=switch) as server:
            self.select(f"https://localhost:{server.port}/v1", ca=ca)
            with PROFILES.Store(self.home) as store:
                store.create("other", {"model": "synthetic-model",
                                       "ANTHROPIC_BASE_URL": "http://127.0.0.1:9912/v1"},
                             {"ANTHROPIC_API_KEY": "second-synthetic"})
            result = self.check(transport=True)
            self.assertEqual((result["status"], result["reason"]),
                             ("refused", "selection_changed"))
            self.assert_private_report(result)

    def test_bad_selected_ca_and_stale_version_refuse_locally(self):
        ca = self.root / "ca.pem"
        ca.write_text("not a certificate")
        ca.chmod(0o600)
        self.select("https://localhost:9911/v1", ca=ca)
        ca.chmod(0o666)
        result = self.check()
        self.assertEqual(result["status"], "refused")
        self.assertFalse(result["network_attempted"])
        self.assert_private_report(result)
        ca.chmod(0o600)
        malformed = self.check()
        self.assertEqual((malformed["status"], malformed["reason"]),
                         ("refused", "ca_invalid"))
        ca.unlink()
        other = self.root / "outside-ca.pem"
        other.write_text("unrelated canary")
        ca.symlink_to(other)
        linked = self.check()
        self.assertEqual(linked["status"], "refused")
        self.assertFalse(linked["network_attempted"])
        self.assertEqual(other.read_text(), "unrelated canary")
        real_parent = self.root / "real-ca-parent"
        real_parent.mkdir(mode=0o700)
        (real_parent / "ca.pem").write_text("owned parent canary")
        alias = self.root / "linked-ca-parent"
        alias.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "ca_unsafe"):
            PREFLIGHT._ca_bytes(alias / "ca.pem")
        self.assertEqual((real_parent / "ca.pem").read_text(), "owned parent canary")

    def test_ambient_provider_conflict_is_refused_without_network(self):
        self.select("http://127.0.0.1:9911/v1")
        with mock.patch.dict(PREFLIGHT.os.environ, {"ANTHROPIC_API_KEY": "ambient-synthetic"}):
            result = PREFLIGHT.check(self.home, PROFILES)
        self.assertEqual((result["status"], result["reason"]),
                         ("refused", "selection_invalid"))
        self.assertFalse(result["network_attempted"])
        self.assert_private_report(result)


if __name__ == "__main__":
    unittest.main()
