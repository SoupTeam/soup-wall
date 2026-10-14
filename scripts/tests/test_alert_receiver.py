# SPDX-License-Identifier: Apache-2.0
"""Protected HTTP boundary and durable receiver regressions using local fixtures."""
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import shutil
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from alert_receiver import MAX_BODY_BYTES, ReceiptStore, ReceiverPolicy, ValidationError, create_server, read_token

TOKEN = b"soup-wall-local-fixture-token-00000000"
POLICY = {"receiver": "soup-wall-protected", "external_url": "http://alertmanager:9093",
          "sources": [{"job": "soup-wall-gateway", "instance": "gateway:8080", "alerts": [
              {"alertname": "LLMFirewallControlPlaneUnavailable", "severity": "critical", "component": "control-plane"},
              {"alertname": "LLMFirewallRedisLimitsUnavailable", "severity": "critical", "component": "admission-limits"}]}],
          "optional_labels": {"environment": ["local"]}}


def payload(status="firing", *, alertname="LLMFirewallControlPlaneUnavailable", start="2026-10-14T10:00:00Z"):
    labels = {"job": "soup-wall-gateway", "instance": "gateway:8080", "alertname": alertname,
              "severity": "critical", "component": "control-plane" if "ControlPlane" in alertname else "admission-limits"}
    alert = {"status": status, "labels": labels, "annotations": {"summary": "Local dependency unavailable"},
             "startsAt": start, "endsAt": "0001-01-01T00:00:00Z" if status == "firing" else "2026-10-14T10:01:00Z",
             "generatorURL": "http://prometheus:9090/graph?g0.expr=up", "fingerprint": "0000000000000001"}
    return {"version": "4", "groupKey": '{}:{alertname="dependency"}', "truncatedAlerts": 0,
            "receiver": "soup-wall-protected", "status": status, "alerts": [alert],
            "groupLabels": {"alertname": alertname}, "commonLabels": labels.copy(),
            "commonAnnotations": {"summary": "Local dependency unavailable"}, "externalURL": "http://alertmanager:9093"}


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


@unittest.skipUnless(os.name == "posix", "protected receiver requires Unix file permissions")
class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="soup-wall-receiver-test-")
        self.root = Path(self.temporary.name)
        self.policy = ReceiverPolicy.from_dict(POLICY)
        self.store = ReceiptStore(self.root / "state")
        self.server = create_server(("127.0.0.1", 0), TOKEN, self.policy, self.store, read_timeout=0.3)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        deadline = time.monotonic() + 1
        while self.server.active_workers and time.monotonic() < deadline:
            time.sleep(0.01)
        self.store.close()
        self.temporary.cleanup()

    def request(self, body=None, *, token=TOKEN, path="/alerts", method="POST", headers=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        fields = {"Content-Type": "application/json"}
        if token is not None:
            fields["Authorization"] = "Bearer " + token.decode()
        fields.update(headers or {})
        conn.request(method, path, body=body, headers=fields)
        response = conn.getresponse()
        status, raw = response.status, response.read()
        conn.close()
        return status, json.loads(raw)

    def test_allowed_firing_resolved_are_correlated_and_sanitized(self):
        first = payload()
        first["alerts"][0]["annotations"]["description"] = "Sensitive annotation\nnot retained"
        first["alerts"][0]["generatorURL"] += "&private=not-retained"
        self.assertEqual(self.request(encoded(first))[0], 200)
        self.assertEqual(self.request(encoded(payload("resolved")))[0], 200)
        status, receipts = self.request(method="GET", path="/receipts?limit=100")
        self.assertEqual(status, 200)
        self.assertEqual(receipts["total_unique_events"], 2)
        records = receipts["records"]
        self.assertEqual({r["status"] for r in records}, {"firing", "resolved"})
        self.assertEqual(len({r["cycle_id"] for r in records}), 1)
        for secret in ("Sensitive", "private=", "generatorURL"):
            self.assertNotIn(secret, json.dumps(receipts))
        self.assertEqual(self.store.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(self.store.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store.directory.stat().st_mode & 0o777, 0o700)
        for state_file in self.store.directory.iterdir():
            self.assertEqual(state_file.stat().st_mode & 0o077, 0)

    def test_missing_wrong_auth_are_rejected_before_body_validation(self):
        class NeverParse:
            def validate(self, _):
                raise AssertionError("unauthorized data reached parser")
        self.server.policy = NeverParse()
        for token in (None, b"wrong-token"):
            self.assertEqual(self.request(b"not JSON", token=token)[0], 401)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)
        self.assertEqual(self.request(method="GET", path="/receipts", token=None)[0], 401)
        self.assertEqual(self.request(method="GET", path="/healthz", token=None), (200, {"status": "serving"}))

    def test_unapproved_sources_and_incomplete_labels_store_nothing(self):
        for field, value in (("job", "unrelated-job"), ("instance", "another:8080"),
                             ("alertname", "ArbitraryAlert"), ("severity", "low"), ("component", "arbitrary")):
            message = payload()
            message["alerts"][0]["labels"][field] = value
            self.assertEqual(self.request(encoded(message))[0], 400)
        for edit in (lambda p: p.update(receiver="unrelated"), lambda p: p.update(externalURL="http://unrelated:9093"),
                     lambda p: p["alerts"][0]["labels"].update(private="secret"),
                     lambda p: p["alerts"][0]["labels"].pop("job"),
                     lambda p: p["alerts"][0]["labels"].update(environment="production")):
            message = payload()
            edit(message)
            self.assertEqual(self.request(encoded(message))[0], 400)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_invalid_batch_has_no_partial_commit(self):
        message = payload()
        invalid = copy.deepcopy(message["alerts"][0])
        invalid["labels"]["job"] = "unapproved"
        message["alerts"].append(invalid)
        self.assertEqual(self.request(encoded(message))[0], 400)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_conflicting_common_and_group_labels_are_refused(self):
        message = payload()
        message["commonLabels"]["alertname"] = "LLMFirewallRedisLimitsUnavailable"
        self.assertEqual(self.request(encoded(message))[0], 400)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_production_rule_runbook_annotation_is_accepted_and_discarded(self):
        message = payload()
        annotations = {"summary": "Gateway cannot reach the tenant control plane",
                       "description": "Tenant storage requests are failing. Admission remains fail-closed.",
                       "runbook": "docs/operations/MONITORING.md#control-plane-unavailable"}
        message["alerts"][0]["annotations"] = annotations
        message["commonAnnotations"] = annotations.copy()
        self.assertEqual(self.request(encoded(message))[0], 200)
        self.assertNotIn("runbook", json.dumps(self.store.receipts()))
        self.assertNotIn("Admission remains", json.dumps(self.store.receipts()))

    def test_pinned_alertmanager_0341_payload_metadata_is_supported_and_discarded(self):
        # Official default webhook embeds template.Data, including these two
        # fields (prometheus/alertmanager v0.34.1 template/template.go).
        message = payload()
        message["notification_reason"] = "first notification"
        message["routeLabels"] = {}
        self.assertEqual(self.request(encoded(message))[0], 200)
        event_id = self.store.receipts()["records"][0]["event_id"]
        message["notification_reason"] = "repeat interval elapsed"
        message["routeLabels"] = {"severity": "critical", "environment": "local"}
        self.assertEqual(self.request(encoded(message))[1]["duplicates"], 1)
        record = self.store.receipts()["records"][0]
        self.assertEqual(record["event_id"], event_id)
        self.assertNotIn("notification_reason", json.dumps(record))
        self.assertNotIn("routeLabels", json.dumps(record))
        # Metadata cannot supply approved alert source labels or change identity.
        self.assertNotIn("environment", record["labels"])
        resolved = payload("resolved")
        resolved.update(notification_reason="all alerts resolved", routeLabels={})
        self.assertEqual(self.request(encoded(resolved))[0], 200)
        self.assertEqual(self.store.receipts()["total_unique_events"], 2)

    def test_pinned_alertmanager_metadata_cannot_bypass_strict_validation(self):
        for value in (None, False, [], {}, "", "unexpected reason", "x" * 65, "\ud800"):
            message = payload()
            message.update(notification_reason=value, routeLabels={})
            self.assertEqual(self.request(encoded(message))[0], 400)
        for value in (None, False, [], "labels", {"private": "secret"},
                      {"severity": "x" * 257}, {"environment": "other"},
                      {"job": 1}, {"severity": "\ud800"}):
            message = payload()
            message.update(notification_reason="first notification", routeLabels=value)
            self.assertEqual(self.request(encoded(message))[0], 400)
        message = payload()
        message.update(notification_reason="first notification", routeLabels={}, unrelatedMetadata="ignored?")
        self.assertEqual(self.request(encoded(message))[0], 400)
        message = payload()
        message.update(notification_reason="first notification", routeLabels={"job": "soup-wall-gateway"})
        message["alerts"][0]["labels"].pop("job")
        self.assertEqual(self.request(encoded(message))[0], 400)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_notification_reason_enum_accepts_only_upstream_wire_values(self):
        for reason in ("none", "first notification", "new alerts added", "some alerts resolved",
                       "all alerts resolved", "repeat interval elapsed", "unknown"):
            message = payload()
            message.update(notification_reason=reason, routeLabels={})
            self.assertEqual(self.request(encoded(message))[0], 200)
        self.assertEqual(self.store.receipts()["total_unique_events"], 1)

    def test_malformed_json_and_protocol_fields_are_refused(self):
        messages = [b"", b"{", b"[]", b"null", b"\xff", b'{"version":"4","version":"4"}',
                    encoded(payload()).replace(b'"truncatedAlerts":0', b'"truncatedAlerts":NaN'),
                    encoded(payload()).replace(b'Local dependency unavailable', b'\\ud800')]
        for alter in (lambda p: p.update(truncatedAlerts=1), lambda p: p.update(truncatedAlerts=False),
                      lambda p: p.update(extra="ignored?"), lambda p: p.pop("version"),
                      lambda p: p.update(status="resolved"), lambda p: p["alerts"][0].update(status="unknown"),
                      lambda p: p["alerts"][0].update(status=[]),
                      lambda p: p["alerts"][0].update(startsAt="2026-10-14 10:00:00"),
                      lambda p: p["alerts"][0].update(startsAt="2026-99-14T10:00:00Z"),
                      lambda p: p["alerts"][0].update(startsAt="2026-10-14T10:00:00+99:00"),
                      lambda p: p["alerts"][0].update(fingerprint="untrusted-id"),
                      lambda p: p["alerts"][0].update(extra="value"), lambda p: p.update(alerts=[])):
            message = payload()
            alter(message)
            messages.append(encoded(message))
        for raw in messages:
            with self.subTest(raw=raw[:70]):
                self.assertIn(self.request(raw)[0], {400, 413})
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_mixed_batch_and_standalone_resolved_are_supported(self):
        message = payload()
        message["alerts"].append(payload("resolved", alertname="LLMFirewallRedisLimitsUnavailable")["alerts"][0])
        message["groupLabels"] = {}
        message["commonLabels"] = {"job": "soup-wall-gateway", "instance": "gateway:8080", "severity": "critical"}
        self.assertEqual(self.request(encoded(message))[0], 200)
        self.assertEqual(self.store.receipts()["total_unique_events"], 2)
        self.assertEqual({r["status"] for r in self.store.receipts()["records"]}, {"firing", "resolved"})

    def test_fingerprint_not_identity_and_body_provenance_is_bounded(self):
        message = payload()
        self.assertEqual(self.request(encoded(message))[0], 200)
        message["alerts"][0]["fingerprint"] = "0000000000000002"
        message["alerts"][0]["annotations"]["summary"] = "Different annotation"
        self.assertEqual(self.request(encoded(message)), (200, {"status": "committed", "accepted": 0, "duplicates": 1}))
        record = self.store.receipts()["records"][0]
        self.assertEqual(record["duplicate_count"], 1)
        self.assertEqual(record["changed_body_count"], 1)
        self.assertNotEqual(record["first_body_sha256"], record["last_body_sha256"])
        self.assertNotIn("Different annotation", json.dumps(record))

    def test_normalized_timestamps_match_but_nanoseconds_and_new_cycles_do_not(self):
        self.assertEqual(self.request(encoded(payload(start="2026-10-14T10:00:00.100000000Z")))[0], 200)
        self.assertEqual(self.request(encoded(payload(start="2026-10-14T12:00:00.1+02:00")))[1]["duplicates"], 1)
        self.assertEqual(self.request(encoded(payload(start="2026-10-14T10:00:00.100000001Z")))[1]["accepted"], 1)
        self.assertEqual(self.request(encoded(payload(start="2026-10-14T10:00:01Z")))[1]["accepted"], 1)
        self.assertEqual(self.store.receipts()["total_unique_events"], 3)

    def test_capacity_refuses_new_events_atomically_and_accepts_duplicates(self):
        self.store.max_events = 1
        raw = encoded(payload())
        self.assertEqual(self.request(raw)[0], 200)
        self.assertEqual(self.request(raw)[1]["duplicates"], 1)
        self.assertEqual(self.request(encoded(payload("resolved")))[0], 503)
        batch = payload()
        batch["alerts"].append(payload("resolved")["alerts"][0])
        self.assertEqual(self.request(encoded(batch))[0], 503)
        self.assertEqual(self.store.receipts()["records"][0]["duplicate_count"], 1)
        self.assertEqual(self.store.receipts()["total_unique_events"], 1)

    def test_reduced_capacity_still_acknowledges_existing_receipts(self):
        firing, resolved = encoded(payload()), encoded(payload("resolved"))
        self.assertEqual(self.request(firing)[0], 200)
        self.assertEqual(self.request(resolved)[0], 200)
        self.store.max_events = 1
        self.assertEqual(self.request(firing)[1]["duplicates"], 1)
        self.assertEqual(self.request(encoded(payload(start="2026-10-14T10:00:01Z")))[0], 503)
        status, receipts = self.request(method="GET", path="/receipts?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(receipts["total_unique_events"], 2)
        self.assertEqual(receipts["returned_records"], 1)
        self.assertTrue(receipts["has_more"])

    def test_storage_failure_never_acknowledges_delivery(self):
        self.store.connection.execute("PRAGMA query_only=ON")
        self.assertEqual(self.request(encoded(payload()))[0], 503)
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)
        self.store.connection.execute("PRAGMA query_only=OFF")
        self.assertEqual(self.request(encoded(payload()))[0], 200)

    def test_body_headers_and_receipt_queries_are_bounded(self):
        self.assertEqual(self.request(b"x" * (MAX_BODY_BYTES + 1))[0], 413)
        self.assertEqual(self.request(encoded(payload()), headers={"Content-Type": "text/plain"})[0], 415)
        for query in ("?limit=0", "?limit=1001", "?limit=x", "?limit=1&limit=2", "?query=sql"):
            self.assertEqual(self.request(method="GET", path="/receipts" + query)[0], 400)
        with socket.create_connection(self.server.server_address, timeout=2) as connection:
            connection.sendall(b"POST /alerts HTTP/1.1\r\nHost: localhost\r\nX-Large: " + b"x" * 8192 + b"\r\n\r\n")
            self.assertIn(b" 431 ", connection.recv(1024))
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_duplicate_authorization_and_content_length_are_refused(self):
        auth = b"Authorization: Bearer " + TOKEN + b"\r\n"
        for headers in (auth + auth, auth + b"Content-Length: 1\r\nContent-Length: 2\r\n"):
            with socket.create_connection(self.server.server_address, timeout=2) as connection:
                connection.sendall(b"POST /alerts HTTP/1.1\r\nHost: localhost\r\n" + headers + b"\r\n")
                self.assertIn(b" 400 ", connection.recv(1024))
        self.assertEqual(self.store.receipts()["total_unique_events"], 0)

    def test_bounded_workers_reject_slow_requests_then_recover(self):
        self.server.worker_slots = threading.BoundedSemaphore(1)
        first = socket.create_connection(self.server.server_address, timeout=2)
        try:
            first.sendall(b"POST /alerts HTTP/1.1\r\n")
            deadline = time.monotonic() + 1
            while not self.server.active_workers and time.monotonic() < deadline:
                time.sleep(0.01)
            with socket.create_connection(self.server.server_address, timeout=2) as second:
                self.assertIn(b" 503 ", second.recv(1024))
            time.sleep(0.4)
        finally:
            first.close()
        self.assertEqual(self.request(encoded(payload()))[0], 200)

    def test_transport_requires_tls_on_nonloopback(self):
        for address in ("0.0.0.0", "localhost"):
            with self.assertRaises(ValidationError):
                create_server((address, 0), TOKEN, self.policy, self.store)
        with self.assertRaises(ValidationError):
            create_server(("127.0.0.1", 0), TOKEN, self.policy, self.store, tls_cert="missing")

    def tls_fixture(self, *, max_workers):
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("OpenSSL is required to generate the disposable TLS fixture")
        cert, key = self.root / "receiver-cert.pem", self.root / "receiver-key.pem"
        generated = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                    "-keyout", str(key), "-out", str(cert), "-days", "1",
                                    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                                   capture_output=True, timeout=15, check=False)
        self.assertEqual(generated.returncode, 0, "disposable TLS certificate generation failed")
        key.chmod(0o600)
        cert.chmod(0o644)
        server = create_server(("127.0.0.1", 0), TOKEN, self.policy, self.store, tls_cert=cert,
                               tls_key=key, read_timeout=2, max_workers=max_workers)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        return server, thread, ssl.create_default_context(cafile=str(cert))

    def tls_post(self, server, context):
        connection = http.client.HTTPSConnection(*server.server_address, timeout=2, context=context)
        try:
            connection.request("POST", "/alerts", body=encoded(payload()), headers={
                "Content-Type": "application/json", "Authorization": "Bearer " + TOKEN.decode()})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["status"], "committed")
        finally:
            connection.close()

    @staticmethod
    def wait_workers(server, expected):
        deadline = time.monotonic() + 1
        while server.active_workers != expected and time.monotonic() < deadline:
            time.sleep(0.01)
        if server.active_workers != expected:
            raise AssertionError("TLS fixture worker count did not reach the expected value")

    def test_half_tls_connection_does_not_block_a_trusted_useful_client(self):
        server, thread, context = self.tls_fixture(max_workers=2)
        slow = socket.create_connection(server.server_address, timeout=2)
        try:
            slow.sendall(b"\x16\x03\x01\x00\x70\x01")
            self.wait_workers(server, 1)
            started = time.monotonic()
            self.tls_post(server, context)
            self.assertLess(time.monotonic() - started, 1.0,
                            "an incomplete TLS handshake blocked the accept loop")
            self.assertEqual(self.store.receipts()["total_unique_events"], 1)
        finally:
            slow.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.wait_workers(server, 0)

    def test_full_tls_worker_pool_refuses_without_accept_thread_handshake(self):
        server, thread, context = self.tls_fixture(max_workers=1)
        slow = socket.create_connection(server.server_address, timeout=2)
        try:
            slow.sendall(b"\x16\x03\x01\x00\x70\x01")
            self.wait_workers(server, 1)
            with socket.create_connection(server.server_address, timeout=0.7) as rejected:
                self.assertEqual(rejected.recv(1024), b"",
                                 "a saturated TLS listener must close without negotiating in the accept thread")
            slow.close()
            self.wait_workers(server, 0)
            self.tls_post(server, context)
            self.assertEqual(self.store.receipts()["total_unique_events"], 1)
        finally:
            slow.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.wait_workers(server, 0)

    def test_optional_labels_accept_only_declared_values(self):
        message = payload()
        message["alerts"][0]["labels"]["environment"] = "local"
        self.assertEqual(self.request(encoded(message))[0], 200)
        self.assertEqual(self.store.receipts()["records"][0]["labels"]["environment"], "local")


@unittest.skipUnless(os.name == "posix", "protected receiver requires Unix file permissions")
class StoreAndProcessTests(unittest.TestCase):
    def test_retention_capacity_limits_and_startup_pruning(self):
        with tempfile.TemporaryDirectory() as directory:
            root, now = Path(directory), [1000000]
            raw = encoded(payload())
            events = ReceiverPolicy.from_dict(POLICY).validate(raw)
            store = ReceiptStore(root / "state", retention_days=1, max_events=1, clock=lambda: now[0])
            self.assertEqual(store.accept(events, hashlib.sha256(raw).hexdigest())["accepted"], 1)
            now[0] += 86399
            store.accept(events, hashlib.sha256(raw).hexdigest())
            store.close()
            now[0] += 86399
            store = ReceiptStore(root / "state", retention_days=1, max_events=1, clock=lambda: now[0])
            self.assertEqual(store.receipts()["total_unique_events"], 1)
            store.close()
            now[0] += 2
            store = ReceiptStore(root / "state", retention_days=1, max_events=1, clock=lambda: now[0])
            self.assertEqual(store.receipts()["total_unique_events"], 0)
            self.assertEqual(store.accept(events, hashlib.sha256(raw).hexdigest())["accepted"], 1)
            store.close()
            for days in (0, 366, True):
                with self.assertRaises(ValidationError):
                    ReceiptStore(root / "invalid", retention_days=days)
            for cap in (0, 1000001, True):
                with self.assertRaises(ValidationError):
                    ReceiptStore(root / "invalid", max_events=cap)

    def test_protected_token_data_and_database_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token_file = root / "token"
            token_file.write_bytes(TOKEN + b"\n")
            token_file.chmod(0o600)
            self.assertEqual(read_token(token_file), TOKEN)
            token_file.chmod(0o644)
            with self.assertRaises(ValidationError):
                read_token(token_file)
            token_file.chmod(0o600)
            linked = root / "linked-token"
            linked.symlink_to(token_file)
            with self.assertRaises(ValidationError):
                read_token(linked)
            token_file.write_bytes(b"x" * 256 + b"\r\nEXTRA")
            with self.assertRaises(ValidationError):
                read_token(token_file)
            bad = root / "bad-state"
            bad.mkdir(mode=0o755)
            with self.assertRaises(ValidationError):
                ReceiptStore(bad)
            linked_state = root / "linked-state"
            linked_state.symlink_to(bad)
            with self.assertRaises(ValidationError):
                ReceiptStore(linked_state)
            safe = root / "safe"
            safe.mkdir(mode=0o700)
            (safe / "receipts.sqlite3").symlink_to(token_file)
            with self.assertRaises(ValidationError):
                ReceiptStore(safe)

    def test_policy_file_rejects_unowned_write_access_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            path.write_text(json.dumps(POLICY))
            path.chmod(0o644)
            self.assertEqual(ReceiverPolicy.from_file(path).receiver, POLICY["receiver"])
            path.chmod(0o666)
            with self.assertRaises(ValidationError):
                ReceiverPolicy.from_file(path)
            path.chmod(0o600)
            link = Path(directory) / "policy-link"
            link.symlink_to(path)
            with self.assertRaises(ValidationError):
                ReceiverPolicy.from_file(link)
            path.write_bytes(b" " * (MAX_BODY_BYTES + 1))
            with self.assertRaises(ValidationError):
                ReceiverPolicy.from_file(path)

    def test_source_policy_rejects_excess_and_invalid_configuration(self):
        for edit in (lambda p: p.update(extra=True), lambda p: p.pop("sources"),
                     lambda p: p.update(sources=[]), lambda p: p.update(external_url="file:///private"),
                     lambda p: p.update(optional_labels={"job": ["other"]}),
                     lambda p: p.update(optional_labels={"environment": ["\ud800"]})):
            value = copy.deepcopy(POLICY)
            edit(value)
            with self.assertRaises(ValidationError):
                ReceiverPolicy.from_dict(value)

    def test_real_process_sigkill_preserves_acknowledged_receipt_and_dedup(self):
        with tempfile.TemporaryDirectory(prefix="soup-wall-receiver-process-") as directory:
            root = Path(directory)
            token_file, policy_file = root / "token", root / "policy.json"
            token_file.write_bytes(TOKEN)
            token_file.chmod(0o600)
            policy_file.write_text(json.dumps(POLICY))
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "alert-receiver.py"),
                       "--port", str(port), "--data-dir", str(root / "state"),
                       "--token-file", str(token_file), "--policy-file", str(policy_file)]
            def start():
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("receiver exited before readiness: " + str(process.communicate()))
                    try:
                        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
                        conn.request("GET", "/healthz")
                        ready = conn.getresponse().status == 200
                        conn.close()
                        if ready:
                            return process
                    except OSError:
                        pass
                    time.sleep(0.03)
                process.kill()
                process.communicate()
                self.fail("receiver readiness timed out")
            def post():
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("POST", "/alerts", body=encoded(payload()), headers={
                    "Authorization": "Bearer " + TOKEN.decode(), "Content-Type": "application/json"})
                response = conn.getresponse()
                status, value = response.status, json.loads(response.read())
                conn.close()
                return status, value
            first = start()
            try:
                self.assertEqual(post(), (200, {"status": "committed", "accepted": 1, "duplicates": 0}))
            finally:
                first.kill()
                output = first.communicate(timeout=3)
            self.assertNotIn(TOKEN, b"".join(output))
            second = start()
            try:
                self.assertEqual(post(), (200, {"status": "committed", "accepted": 0, "duplicates": 1}))
            finally:
                second.terminate()
                second.communicate(timeout=3)
            store = ReceiptStore(root / "state")
            try:
                self.assertEqual(store.receipts()["total_unique_events"], 1)
                self.assertEqual(store.receipts()["records"][0]["duplicate_count"], 1)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
