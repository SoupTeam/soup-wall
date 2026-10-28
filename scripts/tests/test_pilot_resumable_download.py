#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned, bounded range transfer controls with a local HTTP peer."""
from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_preparation_lock as coordination
import pilot_resumable_download as download

CONTENT = (b"pinned bubblewrap archive fixture\n" * 5000)[:129472]
SHA = hashlib.sha256(CONTENT).hexdigest()
ETAG = '"fixture-v1"'


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, modes):
        self.modes = list(modes)
        self.requests = []
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        owner = self.server
        mode = owner.modes.pop(0) if owner.modes else "normal"
        owner.requests.append((mode, self.headers.get("Range"), self.headers.get("If-Range")))
        if mode == "insecure-redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/unsafe")
            self.end_headers()
            return
        if mode == "unsatisfied":
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{len(CONTENT)}")
            self.end_headers()
            return
        ranged = self.headers.get("Range") is not None and mode not in {"ignored", "missing-validator"}
        offset = int(self.headers["Range"][6:-1]) if ranged else 0
        self.send_response(206 if ranged else 200)
        if mode not in {"missing-validator", "no-validator-disconnect"}:
            self.send_header("ETag", '"changed"' if mode == "changed-validator" else ETAG)
        if ranged:
            begin = offset + 1 if mode == "wrong-range" else offset
            self.send_header("Content-Range", f"bytes {begin}-{len(CONTENT)-1}/{len(CONTENT)}")
        declared = len(CONTENT) - offset + (mode == "over-limit")
        if mode == "truncated":
            declared = 1000
        self.send_header("Content-Length", str(declared))
        self.end_headers()
        if mode in {"slow", "stall"}:
            time.sleep(0.8)
        payload = CONTENT[offset:]
        if mode == "substitution":
            payload = b"X" + payload[1:]
        if mode == "over-limit":
            payload += b"X"
        if mode == "truncated":
            payload = payload[:1000]
        if mode == "drip":
            try:
                for byte in payload[:20]:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if mode in {"disconnect", "no-validator-disconnect", "short-disconnect"}:
            self.wfile.write(payload[:1000] if mode == "short-disconnect" else payload[:65536])
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.wfile.write(payload)


class RedirectHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        hop = int(self.path.removeprefix("/hop/"))
        self.server.requests.append(hop)
        time.sleep(self.server.delay)
        if hop < self.server.hops:
            self.send_response(302)
            self.send_header("Location", f"https://127.0.0.1:{self.server.server_port}/hop/{hop + 1}")
            body = b"redirect"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    if self.server.body_delay:
                        time.sleep(self.server.body_delay)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
        else:
            self.send_response(200)
            self.send_header("Content-Length", str(len(CONTENT)))
            self.end_headers()
            self.wfile.write(CONTENT)


class RedirectServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *, hops, delay, body_delay):
        self.hops, self.delay, self.body_delay, self.requests = hops, delay, body_delay, []
        super().__init__(("127.0.0.1", 0), RedirectHandler)


@unittest.skipUnless(os.name == "posix", "Linux owner lock and descriptor operations")
class RangeTransfer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "output"
        self.root.mkdir(mode=0o700)
        self.dest = Path(self.temp.name) / "archive.tar.xz"

    def server(self, *modes):
        server = Server(modes)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def acquire(self, server, *, offline=False, reset=False):
        with coordination.hold(self.root) as claim:
            return download.acquire(self.root, claim, self.dest,
                url=f"http://127.0.0.1:{server.server_port}/archive", sha256=SHA,
                expected=len(CONTENT), limit=len(CONTENT) + 1,
                allow_download=not offline, reset=reset, fixture_http=True)

    def tls_redirect_server(self, *, hops, delay, body_delay=0, redirect=None):
        if not shutil.which("openssl"):
            self.fail("openssl is required for the owned HTTPS redirect control")
        certificate = Path(self.temp.name) / "fixture.crt"
        key = Path(self.temp.name) / "fixture.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(certificate), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = RedirectServer(hops=hops, delay=delay, body_delay=body_delay)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(certificate), str(key))
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = ssl.create_default_context(cafile=str(certificate))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             redirect or download.SecureRedirect(),
                                             urllib.request.HTTPSHandler(context=client))
        return server, opener

    def test_interrupted_then_206_resume_and_offline_digest_reuse(self):
        server = self.server("disconnect", "normal")
        with self.assertRaises(download.Refusal) as failed:
            self.acquire(server)
        self.assertIn(failed.exception.reason, {"download_interrupted", "download_truncated"})
        self.assertGreater(failed.exception.progress["retained_bytes"], 0)
        self.assertEqual(failed.exception.progress["failed_attempts"][0]["attempt"], 1)
        self.assertEqual(server.requests[0][1], None)
        progress = self.acquire(server)
        self.assertEqual(progress["source"], "resumed-range")
        self.assertEqual(server.requests[1][1], f'bytes={failed.exception.progress["retained_bytes"]}-')
        self.assertEqual(server.requests[1][2], ETAG)
        self.assertEqual(self.dest.read_bytes(), CONTENT)
        evidence = json.loads((self.root / download.DIRECTORY / download.EVIDENCE).read_text())
        self.assertEqual(evidence["progress"]["failed_attempts"][0]["attempt"], 1)
        self.assertEqual(evidence["progress"]["transferred_bytes_total"],
                         failed.exception.progress["transferred_bytes_total"] +
                         progress["transferred_bytes_this_attempt"])
        self.dest.unlink()
        self.assertEqual(self.acquire(server, offline=True)["source"], "verified-cache")
        self.assertEqual(len(server.requests), 2)

    def test_ignored_range_restarts_and_counts_transferred_bytes(self):
        server = self.server("disconnect", "ignored")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        progress = self.acquire(server)
        self.assertEqual(progress["source"], "range-ignored-restarted")
        self.assertGreater(progress["transferred_bytes_total"], len(CONTENT))
        self.assertEqual(self.dest.read_bytes(), CONTENT)

    def test_wrong_range_and_changed_validator_refuse_without_publication(self):
        for mode, reason in (("wrong-range", "download_range_refused"),
                             ("changed-validator", "download_validator_changed")):
            with self.subTest(mode=mode):
                self.acquire(self.server("normal"), reset=True)
                self.dest.unlink()
                server = self.server("disconnect", mode)
                with self.assertRaises(download.Refusal):
                    self.acquire(server, reset=True)
                with self.assertRaises(download.Refusal) as result:
                    self.acquire(server)
                self.assertEqual(result.exception.reason, reason)
                self.assertFalse(self.dest.exists())

    def test_same_size_substitution_and_verified_cache_drift_refuse(self):
        server = self.server("substitution")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_digest_mismatch")
        self.assertFalse(self.dest.exists())
        self.acquire(self.server("normal"), reset=True)
        self.dest.unlink()
        verified = self.root / download.DIRECTORY / download.VERIFIED
        verified.chmod(0o600)
        with verified.open("r+b") as stream:
            stream.write(b"X")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server, offline=True)
        self.assertEqual(result.exception.reason, "download_verified_changed")
        self.assertFalse(self.dest.exists())

    def test_orphan_and_partial_drift_refuse(self):
        server = self.server("disconnect")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        partial = self.root / download.DIRECTORY / download.PARTIAL
        with partial.open("r+b") as stream:
            stream.write(b"X")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_partial_changed")
        record = self.root / download.DIRECTORY / download.RECORD
        record.unlink()
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_orphan_partial")

    def test_no_consent_never_requests_and_insecure_redirect_refuses(self):
        server = self.server("insecure-redirect")
        with self.assertRaises(download.Refusal) as offline:
            self.acquire(server, offline=True)
        self.assertEqual(offline.exception.reason, "download_offline_cache_missing")
        self.assertEqual(server.requests, [])
        with self.assertRaises(download.Refusal) as redirected:
            self.acquire(server)
        self.assertEqual(redirected.exception.reason, "download_insecure_redirect")
        self.assertFalse(self.dest.exists())

    def test_explicit_cleanup_touches_only_cache_names(self):
        server = self.server("disconnect", "normal")
        unrelated = self.root / "other-owned-file"
        unrelated.write_text("keep", encoding="utf-8")
        selected = self.root / "current.json"
        selected.write_text("existing generation", encoding="utf-8")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        with coordination.hold(self.root) as claim, download.Cache(self.root, claim) as cache:
            cache.clear(limit=len(CONTENT) + 1)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")
        self.assertEqual(selected.read_text(encoding="utf-8"), "existing generation")
        self.assertFalse((self.root / download.DIRECTORY / download.PARTIAL).exists())
        self.assertFalse((self.root / download.DIRECTORY / download.EVIDENCE).exists())
        self.assertEqual(self.acquire(server)["source"], "fresh")

    def test_symlink_and_fifo_cache_records_refuse_without_blocking(self):
        server = self.server()
        cache = self.root / download.DIRECTORY
        cache.mkdir(mode=0o700)
        (cache / download.VERIFIED).symlink_to(self.root / "missing")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server, offline=True)
        self.assertEqual(result.exception.reason, "download_cache_unsafe")
        (cache / download.VERIFIED).unlink()
        os.mkfifo(cache / download.RECORD, 0o600)
        started = time.monotonic()
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server, offline=True)
        self.assertEqual(result.exception.reason, "download_cache_unsafe")
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(server.requests, [])

    def test_bad_416_and_over_limit_refuse(self):
        server = self.server("disconnect", "unsatisfied")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_range_refused")
        self.assertFalse(self.dest.exists())
        over = self.server("over-limit")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(over, reset=True)
        self.assertEqual(result.exception.reason, "download_size_limit")
        self.assertEqual(result.exception.progress["transferred_bytes_total"], len(CONTENT) + 1)
        self.assertLess(result.exception.progress["retained_bytes"], len(CONTENT))

    def test_exact_complete_partial_may_use_416_only_after_whole_digest(self):
        server = self.server("unsatisfied")
        with coordination.hold(self.root) as claim, download.Cache(self.root, claim) as cache:
            fd = cache.new_partial()
            try:
                record = download._record(f"http://127.0.0.1:{server.server_port}/archive",
                                          SHA, len(CONTENT), len(CONTENT) + 1, fd)
                os.write(fd, CONTENT)
                os.fsync(fd)
                record.update(offset=len(CONTENT), prefix_sha256=SHA, validator=ETAG,
                              attempts=1, transferred_bytes=len(CONTENT))
                cache.write_record(record)
            finally:
                os.close(fd)
        result = self.acquire(server)
        self.assertEqual(result["source"], "complete-range-416")
        self.assertEqual(self.dest.read_bytes(), CONTENT)

    def test_short_successful_http_message_is_truncated_archive(self):
        server = self.server("truncated")
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_truncated")
        self.assertEqual(result.exception.progress["retained_bytes"], 1000)

    def test_stalled_response_is_bounded_by_socket_and_aggregate_deadline(self):
        server = self.server("stall")
        started = time.monotonic()
        with mock.patch.object(download, "DOWNLOAD_SECONDS", 0.3), \
             mock.patch.object(download, "READ_SECONDS", 0.1):
            with self.assertRaises(download.Refusal) as result:
                self.acquire(server)
        self.assertEqual(result.exception.reason, "download_timeout")
        self.assertLess(time.monotonic() - started, 0.6)

    def test_slow_drip_cannot_refresh_aggregate_deadline(self):
        server = self.server("drip")
        started = time.monotonic()
        with mock.patch.object(download, "DOWNLOAD_SECONDS", 0.3), \
             mock.patch.object(download, "READ_SECONDS", 0.2):
            with self.assertRaises(download.Refusal) as result:
                self.acquire(server)
        self.assertEqual(result.exception.reason, "download_timeout")
        self.assertLess(time.monotonic() - started, 0.7)

    def test_https_redirects_share_the_absolute_download_deadline(self):
        slow, opener = self.tls_redirect_server(hops=7, delay=0.12)
        started = time.monotonic()
        with mock.patch.object(download, "DOWNLOAD_SECONDS", 0.25), \
             mock.patch.object(download, "READ_SECONDS", 0.2):
            with coordination.hold(self.root) as claim:
                with self.assertRaises(download.Refusal) as result:
                    download.acquire(self.root, claim, self.dest,
                        url=f"https://127.0.0.1:{slow.server_port}/hop/0", sha256=SHA,
                        expected=len(CONTENT), limit=len(CONTENT) + 1,
                        allow_download=True,
                        open_request=lambda request, timeout: opener.open(request, timeout=timeout))
        self.assertEqual(result.exception.reason, "download_timeout")
        self.assertLess(time.monotonic() - started, 0.7)
        self.assertGreaterEqual(len(slow.requests), 1)
        self.assertLess(len(slow.requests), 7)
        self.assertFalse(self.dest.exists())
        retained = json.loads((self.root / download.DIRECTORY / download.RECORD).read_text())
        self.assertEqual(retained["failed_attempts"][0]["reason"], "download_timeout")

        self.dest = Path(self.temp.name) / "fast.tar.xz"
        fast, opener = self.tls_redirect_server(hops=1, delay=0.01)
        with coordination.hold(self.root) as claim:
            progress = download.acquire(self.root, claim, self.dest,
                url=f"https://127.0.0.1:{fast.server_port}/hop/0", sha256=SHA,
                expected=len(CONTENT), limit=len(CONTENT) + 1,
                allow_download=True, reset=True,
                open_request=lambda request, timeout: opener.open(request, timeout=timeout))
        self.assertEqual(fast.requests, [0, 1])
        self.assertEqual(progress["transferred_bytes_this_attempt"], len(CONTENT))
        self.assertEqual(hashlib.sha256(self.dest.read_bytes()).hexdigest(), SHA)

    def test_slow_https_redirect_body_cannot_extend_download_deadline(self):
        class ObservingRedirect(download.SecureRedirect):
            response = None

            def http_error_302(self, request, fp, code, msg, headers):
                self.response = fp
                return super().http_error_302(request, fp, code, msg, headers)

        observer = ObservingRedirect()
        server, opener = self.tls_redirect_server(hops=1, delay=0, body_delay=0.06,
                                                 redirect=observer)
        started = time.monotonic()
        with mock.patch.object(download, "DOWNLOAD_SECONDS", 0.25), \
             mock.patch.object(download, "READ_SECONDS", 0.2):
            with coordination.hold(self.root) as claim:
                with self.assertRaises(download.Refusal) as result:
                    download.acquire(self.root, claim, self.dest,
                        url=f"https://127.0.0.1:{server.server_port}/hop/0", sha256=SHA,
                        expected=len(CONTENT), limit=len(CONTENT) + 1,
                        allow_download=True,
                        open_request=lambda request, timeout: opener.open(request, timeout=timeout))
        self.assertEqual(result.exception.reason, "download_timeout")
        self.assertLess(time.monotonic() - started, 0.7)
        self.assertEqual(server.requests, [0])
        self.assertFalse(self.dest.exists())
        self.assertIsNotNone(observer.response)
        self.assertTrue(observer.response.isclosed())

    def test_missing_validator_restarts_from_zero(self):
        server = self.server("no-validator-disconnect", "normal")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        result = self.acquire(server)
        self.assertEqual(result["source"], "range-ignored-restarted")
        self.assertIsNone(server.requests[1][1])
        self.assertEqual(self.dest.read_bytes(), CONTENT)

    def test_cancelled_attempt_keeps_partial_and_failed_history(self):
        server = self.server("disconnect", "normal")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        def cancel(*_):
            raise KeyboardInterrupt
        with mock.patch.object(download, "_secure_open", side_effect=cancel):
            with self.assertRaises(download.Refusal) as result:
                self.acquire(server)
        self.assertEqual(result.exception.reason, "download_interrupted")
        self.assertEqual(len(result.exception.progress["failed_attempts"]), 2)
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.acquire(server)["source"], "resumed-range")

    def test_record_binding_and_exhausted_attempts_are_blocking(self):
        server = self.server("short-disconnect", "short-disconnect", "short-disconnect")
        with self.assertRaises(download.Refusal):
            self.acquire(server)
        with coordination.hold(self.root) as claim:
            with self.assertRaises(download.Refusal) as result:
                download.acquire(self.root, claim, self.dest,
                    url=f"http://127.0.0.1:{server.server_port}/different", sha256=SHA,
                    expected=len(CONTENT), limit=len(CONTENT) + 1,
                    allow_download=True, fixture_http=True)
        self.assertEqual(result.exception.reason, "download_record_binding_changed")
        for _ in range(2):
            with self.assertRaises(download.Refusal):
                self.acquire(server)
        with self.assertRaises(download.Refusal) as result:
            self.acquire(server)
        self.assertEqual(result.exception.reason, "download_budget_exhausted")
        self.assertEqual(len(server.requests), 3)

    def test_one_process_owner_second_process_busy_then_verified_reuse(self):
        server = self.server("slow")
        script = ("import pathlib,sys;sys.path.insert(0,sys.argv[1]);"
                  "import pilot_preparation_lock as l,pilot_resumable_download as d;"
                  "r=pathlib.Path(sys.argv[2]);t=pathlib.Path(sys.argv[3]);"
                  "u=sys.argv[4];h=sys.argv[5];n=int(sys.argv[6]);"
                  "c=l.hold(r);a=c.__enter__();"
                  "d.acquire(r,a,t,url=u,sha256=h,expected=n,limit=n+1,"
                  "allow_download=True,fixture_http=True);c.__exit__(None,None,None)")
        child = subprocess.Popen([sys.executable, "-B", "-c", script,
            str(Path(__file__).resolve().parents[1]), str(self.root), str(self.dest),
            f"http://127.0.0.1:{server.server_port}/archive", SHA, str(len(CONTENT))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 5
            while not server.requests and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(server.requests)
            with self.assertRaises(coordination.Busy):
                with coordination.hold(self.root):
                    pass
            self.assertEqual(child.wait(timeout=5), 0, child.stderr.read().decode())
            self.dest.unlink()
            self.assertEqual(self.acquire(server, offline=True)["source"], "verified-cache")
            self.assertEqual(len(server.requests), 1)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            child.stdout.close()
            child.stderr.close()


if __name__ == "__main__":
    unittest.main()
